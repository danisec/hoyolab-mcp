"""MCP tools for the Genshin Battle Chronicle.

DESIGN: PER-USER IDENTITY, NEVER A SHARED COOKIE
Every tool resolves the calling user, looks up that user's own encrypted cookies, and
calls HoYoLAB with them. Three identity sources are accepted (see `resolve_user_id`):
a per-user API token for command-line clients, the signed JWT Open WebUI forwards, and
the plain user-id header for deployments without a signing secret.

There is deliberately no fallback to a server-wide credential: a fallback would mean
that the moment one admin linked an account, every other user of these tools would
silently read that account's data.

If no identity is present the tool fails with a clear instruction rather than guessing.
That case is real and easy to hit: Open WebUI only forwards identity when
`ENABLE_FORWARD_USER_INFO_HEADERS=true`, and a command-line client has no header at all
unless it was given a token.

FAIL CLOSED ON UNKNOWN DATA
Output is assembled from fields that are read defensively. Missing keys produce
"unavailable" markers instead of raising, and no partial or guessed value is ever
presented as if it came from HoYoLAB.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import jwt
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .client import ChronicleClient, HoyolabError, is_overseas_uid, server_for_uid
from .store import (
    ApiTokenStore,
    CredentialError,
    decode_link_token,
    encode_link_token,
    parse_cookie_string,
    redact,
)

log = logging.getLogger('hoyolab_mcp')

USER_ID_HEADER = 'X-OpenWebUI-User-Id'
USER_JWT_HEADER = 'X-OpenWebUI-User-Jwt'


def _secret() -> str:
    return os.environ.get('HOYOLAB_MCP_SECRET', '')


def _jwt_secret() -> Optional[str]:
    return (os.environ.get('FORWARD_USER_INFO_HEADER_JWT_SECRET') or '').strip() or None


def _store() -> ApiTokenStore:
    return ApiTokenStore(
        os.environ.get('HOYOLAB_MCP_DB', '/data/hoyolab.db'),
        _secret(),
    )


def _bearer_token(headers: dict) -> Optional[str]:
    raw = headers.get('authorization') or headers.get('Authorization') or ''
    scheme, _, value = str(raw).partition(' ')
    if scheme.lower() == 'bearer' and value.strip():
        return value.strip()
    return None


def resolve_user_id(headers: dict) -> tuple[Optional[str], Optional[str]]:
    """Return (user_id, error) for the caller.

    Three identity sources, tried in this order:

      1. `Authorization: Bearer <token>` — for clients that are not Open WebUI
         (Claude Code, Codex, opencode). The token was minted for one user id and is
         verified against its stored hash, so it cannot be invented.
      2. `X-OpenWebUI-User-Jwt` — the signed token Open WebUI forwards. Preferred over
         the plain header because it cannot be forged by a client that reaches this
         server directly.
      3. `X-OpenWebUI-User-Id` — the plain header. Only honoured when NO JWT secret is
         configured. When a secret IS configured this header is ignored, otherwise
         anyone who can reach the port could name themselves any user and read that
         person's Genshin data.
    """
    token = _bearer_token(headers)
    if token:
        # A presented token that does not resolve is an error, not a reason to fall
        # back to something weaker -- that would let a revoked token still work.
        user_id = _store().resolve_token(token)
        if not user_id:
            return None, (
                'The API token in the Authorization header is not valid or has been '
                'revoked. Issue a new one with: python -m hoyolab_mcp.cli issue-token'
            )
        return user_id, None

    jwt_secret = _jwt_secret()
    token = headers.get(USER_JWT_HEADER.lower()) or headers.get(USER_JWT_HEADER)
    if token and jwt_secret:
        try:
            claims = jwt.decode(token, jwt_secret, algorithms=['HS256'], issuer='open-webui')
            sub = claims.get('sub')
            if sub:
                return str(sub), None
        except jwt.ExpiredSignatureError:
            return None, 'The forwarded identity token expired. Retry the message.'
        except Exception:
            return None, 'The forwarded identity token could not be verified.'

    if not jwt_secret:
        raw = headers.get(USER_ID_HEADER.lower()) or headers.get(USER_ID_HEADER)
        if raw:
            return str(raw), None

    if not jwt_secret:
        return None, (
            'No user identity was forwarded with this request. Either connect with an '
            'API token (Authorization: Bearer ...), or run Open WebUI with '
            'ENABLE_FORWARD_USER_INFO_HEADERS=true so it forwards the signed identity '
            'header.'
        )

    if headers.get(USER_ID_HEADER.lower()) or headers.get(USER_ID_HEADER):
        # Deliberately refused. Explaining why saves the operator from concluding the
        # server is broken: this is the one configuration that would let anyone who can
        # reach the port read any user's account.
        return None, (
            f'A plain {USER_ID_HEADER} header was sent, but it is ignored because '
            'FORWARD_USER_INFO_HEADER_JWT_SECRET is configured. Unsigned identity cannot '
            'be trusted once a signing secret exists. Either send the signed '
            f'{USER_JWT_HEADER} header Open WebUI forwards, or connect with an API token '
            '(Authorization: Bearer ...).'
        )
    return None, (
        'No user identity was forwarded with this request. Connect with an API token '
        '(Authorization: Bearer ...), or send the X-OpenWebUI-User-Jwt header that '
        'Open WebUI forwards when ENABLE_FORWARD_USER_INFO_HEADERS=true.'
    )


def _headers_from(ctx: Context) -> dict:
    request = getattr(ctx.request_context, 'request', None)
    headers = getattr(request, 'headers', None)
    if headers is None:
        return {}
    return {k.lower(): v for k, v in headers.items()}


def _client_for(ctx: Context) -> tuple[ChronicleClient, str]:
    """Resolve the caller's identity and cookies into a ready client."""
    user_id, error = resolve_user_id(_headers_from(ctx))
    if error:
        raise HoyolabError(error)

    store = _store()
    try:
        cookies = store.load(user_id)
    except CredentialError as exc:
        raise HoyolabError(str(exc)) from exc

    if not cookies:
        token = encode_link_token(user_id, _secret())
        base = os.environ.get('HOYOLAB_MCP_PUBLIC_URL', '').rstrip('/')
        link = f'{base}/link?token={token}' if base else f'/link?token={token}'
        raise HoyolabError(
            'No HoYoLAB account is linked for this user yet. '
            f'Open {link} and paste your HoYoLAB cookies to link it. '
            'This stores credentials for this user only.'
        )
    log.info('chronicle request for user %s (cookie names: %s)', redact(user_id), sorted(cookies))
    return ChronicleClient(cookies), user_id


# The record-card payload names the game UID `game_role_id`. An earlier version read
# `game_uid`, which does not exist on the card, so the resolved UID was always None.
# That surfaced as `UID 'None' is not numeric` because the model then filled the gap
# with the literal string "None".
GAME_UID_FIELDS = ('game_role_id', 'game_uid')


def card_uid(card: dict) -> Optional[str]:
    """Game UID from a record card, tolerating either field name."""
    for field in GAME_UID_FIELDS:
        value = card.get(field)
        if value not in (None, ''):
            return str(value)
    return None


# Values a model may send instead of omitting an optional argument. `if uid:` treats
# these as present because a non-empty string is truthy, so they must be filtered
# explicitly.
_NULLISH = {'', 'none', 'null', 'nil', 'undefined', 'n/a', 'na', '-', '0', 'nan', 'false'}


def normalize_uid(uid: Any) -> Optional[str]:
    """Return a real UID, or None when the value means "not provided"."""
    if uid is None:
        return None
    text = str(uid).strip().strip('"').strip("'")
    if text.lower() in _NULLISH:
        return None
    return text


def _pick(uid: str, cards: list[dict]) -> Optional[dict]:
    """Choose the Genshin card matching `uid`, or the only Genshin card there is."""
    genshin = [c for c in cards if str(c.get('game_id')) == '2']
    if not genshin:
        return None
    for card in genshin:
        if card_uid(card) == str(uid):
            return card
    return genshin[0] if len(genshin) == 1 else None


def _default_uid(client: ChronicleClient) -> Optional[str]:
    """The Genshin UID linked to this HoYoLAB login, if there is exactly one."""
    cards = client.record_cards(_hoyolab_uid_from_cookies(client))
    genshin = [c for c in cards if str(c.get('game_id')) == '2']
    if len(genshin) == 1:
        return card_uid(genshin[0])
    return None


def _hoyolab_uid_from_cookies(client: ChronicleClient) -> str:
    """HoYoLAB account id, taken from the cookie set the user supplied."""
    cookies = client._cookies  # noqa: SLF001 - same package, deliberate
    for key in ('ltuid_v2', 'ltuid', 'account_id_v2', 'account_id'):
        if cookies.get(key):
            return str(cookies[key])
    raise HoyolabError('The stored credential has no HoYoLAB account id (ltuid_v2/ltuid).')


def _require_uid(client: ChronicleClient, uid: Any) -> str:
    """Resolve the UID to query, or explain precisely why it cannot be resolved.

    A model will often pass `"None"` (the string) for an optional argument it decided
    not to use, so that has to be treated as "not provided" rather than sent to the
    API. When resolution genuinely fails, the message names the real cause so the model
    stops guessing and asks the user instead of inventing a value.
    """
    given = normalize_uid(uid)
    if given:
        return given

    cards = client.record_cards(_hoyolab_uid_from_cookies(client))
    genshin = [c for c in cards if str(c.get('game_id')) == '2']

    if len(genshin) == 1:
        resolved = card_uid(genshin[0])
        if resolved:
            return resolved

    if not genshin:
        raise HoyolabError(
            'This HoYoLAB login has no Genshin Impact account attached. '
            'Only Genshin data can be read by these tools.'
        )

    uids = [u for u in (card_uid(c) for c in genshin) if u]
    raise HoyolabError(
        'Several Genshin accounts are attached to this HoYoLAB login, so the uid '
        f'cannot be guessed. Call the tool again with uid set to one of: {", ".join(uids)}'
    )


def _exploration_summary(index: dict) -> dict:
    """Condense exploration data into something an LLM can reason about.

    `exploration_percentage` is returned in TENTHS of a percent, not hundredths: a fully
    explored region reports 1000, and 540 means 54.0%. Dividing by 100 (the obvious
    guess) turned every completed region into "10.0%" and made the account look
    untouched -- the opposite of the truth. The reference wrapper genshin.py divides by
    10 as well, and notes the value can exceed 100% for regions with sub-areas.

    Offerings (statue/reputation levels) are nested inside each region rather than
    returned at the top level, so reading `index["offerings"]` always produced an empty
    list. They are collected per area here, tagged with the area they belong to.
    """
    areas = []
    offerings = []
    for item in index.get('world_explorations') or []:
        if not isinstance(item, dict):
            continue
        name = item.get('name') or 'Unknown area'
        pct = item.get('exploration_percentage')
        explored = round(pct / 10, 1) if isinstance(pct, (int, float)) else None
        area_offerings = []
        for off in item.get('offerings') or []:
            if not isinstance(off, dict):
                continue
            entry = {
                'area': name,
                'name': off.get('name'),
                'level': off.get('level'),
            }
            offerings.append(entry)
            area_offerings.append({'name': entry['name'], 'level': entry['level']})
        areas.append(
            {
                'name': name,
                'explored_percent': explored,
                'complete': explored is not None and explored >= 100,
                'statue_level': item.get('seven_statue_level'),
                'offerings': area_offerings,
            }
        )

    # Rank by incompleteness so "what is not 100%" is answerable without scanning.
    incomplete = [a for a in areas if a['explored_percent'] is not None and a['explored_percent'] < 100]
    incomplete.sort(key=lambda a: a['explored_percent'])
    return {
        'areas': areas,
        'incomplete': incomplete,
        'complete_count': sum(1 for a in areas if a['complete']),
        'total_areas': len(areas),
        'offerings': offerings,
    }


def _duration(seconds: Any) -> Optional[str]:
    """Human-readable duration for an API countdown, or None when there is nothing to say.

    Two measured traps are handled here rather than in each caller:

    * The API sends these counts as STRINGS ("21072"), so `int(value)` is required
      before any arithmetic. Comparing a string with a number raises in Python 3, and
      adding them concatenates or fails depending on the other operand.
    * `"0"` means the resource is already full or nothing is regenerating. It must not
      be rendered as "0 seconds", which reads as "about to tick over". It returns None
      so callers can say "full" instead.

    The unit is SECONDS, and that was verified against live data rather than assumed:
    resin 156/200 needs 44 more at one per 8 minutes (352 minutes), and the API reported
    21072 -- 351.2 minutes. Reading it as minutes would have claimed ~14 days.
    """
    if seconds in (None, ''):
        return None
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return None
    if total <= 0:
        return None

    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        text = f'{days}d {hours}h'
    elif hours:
        text = f'{hours}h {minutes}m'
    elif minutes:
        text = f'{minutes}m'
    else:
        text = f'{secs}s'
    return f'{text} ({total} seconds)'


def _int_or_none(value: Any) -> Optional[int]:
    """Coerce an API counter to int, tolerating the strings it sometimes uses.

    Returns None for anything that is not a number, so callers can distinguish "the API
    did not say" from "the API said zero". Use `_int_or_zero` where a missing component
    must not propagate None into arithmetic.
    """
    if value is None or value == '' or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _int_or_zero(value: Any) -> int:
    """Numeric component of a compound duration, where absent means zero.

    `_int_or_none(...) * 86400` raised `TypeError: unsupported operand type(s) for *:
    'NoneType' and 'int'` whenever the API sent a non-numeric component, which took the
    whole `get_daily_note` answer down over a field nobody asked about. A duration
    component that is absent or unparseable genuinely contributes nothing, so zero is the
    correct value here -- unlike a resin count, where zero would be a lie.
    """
    parsed = _int_or_none(value)
    return parsed if parsed is not None else 0


def _as_dict(value: Any) -> dict:
    """Treat anything that is not a mapping as absent.

    `_check()` in client.py returns `data` as the API sent it, and the API is not
    guaranteed to send an object: a list or null is possible on a schema change or an
    edge-case account. Calling `.get()` on that raised AttributeError and failed the
    entire tool, which is the opposite of this module's stated contract -- missing data
    should surface as an "unavailable" marker, never as an exception.
    """
    return value if isinstance(value, dict) else {}


def _expeditions(raw: Any) -> list[dict]:
    """Per-expedition state, kept only when the API actually returns entries.

    An empty `expeditions` list is normal and not a fault: it means no expedition is
    currently out. The list is left empty rather than filled with placeholders, so a
    model cannot report a finished expedition that does not exist.

    Only `status` and the remaining time are surfaced. The payload carries
    `avatar_side_icon` (an image URL) but no character name, so a name is NOT invented
    here; the icon is passed through untouched for a client that wants to resolve it.
    """
    out = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                'status': item.get('status'),
                'remaining_seconds': _int_or_none(item.get('remained_time')),
                'remaining': _duration(item.get('remained_time')),
                'icon': item.get('avatar_side_icon'),
            }
        )
    return out


def _daily_note_summary(note: dict) -> dict:
    """Shape `dailyNote` into resin/task/coin state without inventing figures.

    Countdowns are returned twice: as raw seconds (machine-usable) and as readable
    text, because a model shown "21072" on its own tends to present it as minutes.
    """
    note = _as_dict(note)

    resin = _int_or_none(note.get('current_resin'))
    resin_max = _int_or_none(note.get('max_resin'))
    resin_seconds = _int_or_none(note.get('resin_recovery_time'))

    # "Full" requires BOTH numbers, and a real cap. An earlier revision also treated a
    # zero countdown as "full", which reported a full bar for a payload that had no
    # current_resin at all -- the exact silent invention this branch is meant to prevent.
    # `max_resin` of 0 is a missing field, not a cap of zero, so it does not count.
    resin_full = (
        resin is not None and resin_max is not None and resin_max > 0 and resin >= resin_max
    )
    if resin_full:
        resin_state = 'full'
    elif resin is None and resin_max is None:
        resin_state = 'unknown'
    elif resin_seconds is None:
        resin_state = 'unknown'
    else:
        resin_state = 'recovering'

    home_coin = _int_or_none(note.get('current_home_coin'))
    home_max = _int_or_none(note.get('max_home_coin'))
    home_seconds = _int_or_none(note.get('home_coin_recovery_time'))
    home_full = (
        home_coin is not None and home_max is not None and home_max > 0 and home_coin >= home_max
    )
    if home_full:
        home_state = 'full'
    elif home_coin is None and home_max is None:
        home_state = 'unknown'
    elif home_seconds is None:
        home_state = 'unknown'
    else:
        home_state = 'accumulating'

    transformer = _as_dict(note.get('transformer'))
    recovery = _as_dict(transformer.get('recovery_time'))
    transformer_seconds = (
        _int_or_zero(recovery.get('Day')) * 86400
        + _int_or_zero(recovery.get('Hour')) * 3600
        + _int_or_zero(recovery.get('Minute')) * 60
        + _int_or_zero(recovery.get('Second'))
    )
    # `reached` is the API's own "ready to use" flag. It is only trustworthy when the
    # transformer was actually obtained; otherwise the answer is "not applicable".
    obtained = transformer.get('obtained')
    reached = recovery.get('reached')
    if obtained is False:
        transformer_ready = False
    elif reached is True:
        transformer_ready = True
    elif reached is False:
        transformer_ready = False
    else:
        transformer_ready = None

    task = _as_dict(note.get('daily_task'))
    week = _as_dict(note.get('week_active_progress'))

    return {
        'resin': {
            'current': resin,
            'max': resin_max,
            'state': resin_state,
            'full_at_seconds': 0 if resin_full else resin_seconds,
            'full_in': None if resin_full else _duration(resin_seconds),
        },
        'realm_currency': {
            'current': home_coin,
            'max': home_max,
            'state': home_state,
            'full_at_seconds': 0 if home_full else home_seconds,
            'full_in': None if home_full else _duration(home_seconds),
        },
        'expeditions': {
            'current': _int_or_none(note.get('current_expedition_num')),
            'max': _int_or_none(note.get('max_expedition_num')),
            'entries': _expeditions(note.get('expeditions')),
        },
        'daily_tasks': {
            'finished': _int_or_none(note.get('finished_task_num')),
            'total': _int_or_none(note.get('total_task_num')),
            'extra_reward_claimed': note.get('is_extra_task_reward_received'),
            # Named `weekly_task_points`, not `attendance_*`: the API calls these
            # `attendance_rewards`, but they are in-game weekly task points (2000 each),
            # entirely unrelated to the HoYoLAB daily check-in that `get_attendance`
            # reports. Sharing the word "attendance" between the two invited a model to
            # conflate them -- observed in a live chat where both were discussed at once.
            # The per-task `task_rewards` entries carry only a status string and no
            # identifying field, so they are deliberately not surfaced: four identical
            # "unfinished" markers read like four distinct rewards.
            'weekly_task_points': [
                {'status': r.get('status'), 'progress': _int_or_none(r.get('progress'))}
                for r in (task.get('attendance_rewards') or [])
                if isinstance(r, dict)
            ],
        },
        'weekly_boss_discount': {
            'remaining': _int_or_none(note.get('remain_resin_discount_num')),
            'limit': _int_or_none(note.get('resin_discount_num_limit')),
        },
        'parametric_transformer': {
            'obtained': obtained,
            'ready': transformer_ready,
            'remaining': None if transformer_ready else _duration(transformer_seconds),
        },
        'weekly_activity': {
            'current': _int_or_none(week.get('progress_current')),
            'total': _int_or_none(week.get('progress_total')),
            'period_current': _int_or_none(week.get('period_progress_current')),
            'period_total': _int_or_none(week.get('period_progress_total')),
        },
    }


def _attendance_summary(info: dict, home: dict, resign: dict) -> dict:
    """Shape the check-in payloads into "did I sign today, and what is today's reward".

    Indexing the reward list needs care. Measured on a live account: `total_sign_day`
    was 28 with `is_sign` false, while that month's reward list had 31 entries. Because
    the count covers days already signed and today is still unsigned, the next reward to
    be claimed is `awards[total_sign_day]` -- index 28, not 27. Off by one here reports
    yesterday's reward as today's.

    Degradation is deliberate: `info` is the only payload that answers the main question
    ("did I sign today?"), so `home` and `resign` are optional. When either is missing
    the corresponding fields become null and `partial` names what could not be read,
    instead of failing the whole tool over the least important call.
    """
    info = _as_dict(info)
    home = _as_dict(home)
    resign = _as_dict(resign)

    missing = []
    if not home:
        missing.append('rewards')
    if not resign:
        missing.append('make_up')

    awards = [a for a in (home.get('awards') or []) if isinstance(a, dict)]
    signed_days = _int_or_none(info.get('total_sign_day'))
    already = bool(info.get('is_sign'))

    # The reward list belongs to the month in `home['month']`, while `info['today']`
    # carries the current date. They disagree on the first day of a new month, when the
    # reward list has not rolled over yet: trusting it would report last month's reward as
    # today's. When the months differ, the reward is reported as unknown rather than
    # guessed, and the mismatch is surfaced.
    month_matches = True
    today = info.get('today')
    home_month = _int_or_none(home.get('month'))
    if isinstance(today, str) and len(today) >= 7 and home_month is not None:
        try:
            today_month = int(today[5:7])
        except ValueError:
            today_month = None
        if today_month is not None and today_month != home_month:
            month_matches = False
            missing.append('reward_month_mismatch')

    today_reward = None
    if month_matches and signed_days is not None and 0 <= signed_days < len(awards):
        award = awards[signed_days]
        today_reward = {'name': award.get('name'), 'count': _int_or_none(award.get('cnt'))}

    claimed_reward = None
    if (
        month_matches
        and already
        and signed_days is not None
        and 0 < signed_days <= len(awards)
    ):
        award = awards[signed_days - 1]
        claimed_reward = {'name': award.get('name'), 'count': _int_or_none(award.get('cnt'))}

    rewards_left = None
    if month_matches and signed_days is not None and awards:
        rewards_left = max(len(awards) - signed_days, 0)

    return {
        'signed_in_today': already,
        'status': 'signed in today' if already else 'not signed in yet today',
        'days_signed_this_month': signed_days,
        'month': home_month,
        'rewards_in_month': (len(awards) or None) if month_matches else None,
        'rewards_left_this_month': rewards_left,
        'date': today,
        'reward_claimed_today': claimed_reward,
        'reward_if_claimed_now': None if already else today_reward,
        'first_time_binding': info.get('first_bind'),
        'auto_check_in_subscribed': info.get('is_sub'),
        'last_day_of_month': info.get('month_last_day'),
        'make_up': {
            'allowed_today': _int_or_none(resign.get('resign_limit_daily')),
            'allowed_this_month': _int_or_none(resign.get('resign_limit_monthly')),
            'used_today': _int_or_none(resign.get('resign_cnt_daily')),
            'used_this_month': _int_or_none(resign.get('resign_cnt_monthly')),
            'missed_days': _int_or_none(resign.get('sign_cnt_missed')),
            'cost_per_day': _int_or_none(resign.get('cost')),
        },
        # Empty when everything was read. A model can use this to say "I could not read
        # the reward list" instead of presenting nulls as fact.
        'partial': missing,
    }


def _prop_name(property_map: dict, prop: dict) -> Optional[str]:
    """Readable stat name for a relic property.

    The API identifies stats by number (`property_type`). `property_map` holds the
    translation, and it distinguishes e.g. type 2 = flat HP from type 3 = HP%, which
    both report the name "HP" on their own. The map's `filter_name` carries the
    distinction, so that is preferred over `name`.
    """
    ptype = prop.get('property_type')
    entry = property_map.get(str(ptype)) or property_map.get(ptype) or {}
    return entry.get('filter_name') or entry.get('name') or f'property_{ptype}'


def _format_stats_block(stats: dict) -> dict:
    """Map the whole `stats` payload into readable keys.

    The API returns 22 top-level fields, two of them nested objects rather than plain
    numbers. An earlier version hand-picked nine of them and dropped the rest, which is
    why Imaginarium Theater and Stygian Onslaught were reported as "not available from
    the API" -- they were present the whole time, as `role_combat` and `hard_challenge`.

    Every field is mapped explicitly rather than copied wholesale, so the tool's output
    stays stable and a newly added API key cannot leak through with a cryptic name.
    """
    role_combat = stats.get('role_combat') or {}
    hard_challenge = stats.get('hard_challenge') or {}

    return {
        # progress
        'achievements': stats.get('achievement_number'),
        'days_active': stats.get('active_day_number'),
        'characters': stats.get('avatar_number'),
        'full_friendship_characters': stats.get('full_fetter_avatar_num'),
        'spiral_abyss': stats.get('spiral_abyss'),
        # Imaginarium Theater: `max_round_id` is the highest act reached this period.
        'imaginarium_theater': {
            'unlocked': role_combat.get('is_unlock'),
            'has_data': role_combat.get('has_data'),
            'highest_act': role_combat.get('max_round_id'),
            'difficulty_id': role_combat.get('difficulty_id'),
            'tarot_finished': role_combat.get('tarot_finished_cnt'),
        },
        # Stygian Onslaught: the API exposes the best record's name and difficulty.
        'stygian_onslaught': {
            'unlocked': hard_challenge.get('is_unlock'),
            'has_data': hard_challenge.get('has_data'),
            'best_record': hard_challenge.get('name'),
            'difficulty': hard_challenge.get('difficulty'),
        },
        # oculi
        'anemoculus': stats.get('anemoculus_number'),
        'geoculus': stats.get('geoculus_number'),
        'electroculus': stats.get('electroculus_number'),
        'dendroculus': stats.get('dendroculus_number'),
        'hydroculus': stats.get('hydroculus_number'),
        'pyroculus': stats.get('pyroculus_number'),
        'cryoculus': stats.get('iceculus_number'),
        'lunoculus': stats.get('moonoculus_number'),
        # world
        'unlocked_waypoints': stats.get('way_point_number'),
        'unlocked_domains': stats.get('domain_number'),
        # chests
        'luxurious_chests': stats.get('luxurious_chest_number'),
        'precious_chests': stats.get('precious_chest_number'),
        'exquisite_chests': stats.get('exquisite_chest_number'),
        'common_chests': stats.get('common_chest_number'),
        'remarkable_chests': stats.get('magic_chest_number'),
    }


def _format_stats(entry: dict, property_map: dict) -> list[dict]:
    """Final character stats (total ATK, CRIT Rate, etc.) with their breakdown.

    `character/detail` returns `selected_properties`, which already contains the
    computed totals the game itself shows: `base` is the character plus weapon, `add`
    is the contribution from artifacts and buffs, `final` is the sum. This is the data a
    "is my build good?" question actually needs.

    It was previously dropped, which sent the model off to scrape a wiki for stat tables
    it did not need. Exposing it keeps the answer derived from the player's own account.
    """
    out = []
    for prop in entry.get('selected_properties') or []:
        if not isinstance(prop, dict):
            continue
        out.append(
            {
                'stat': _prop_name(property_map, prop),
                'base': prop.get('base'),
                'bonus': prop.get('add'),
                'total': prop.get('final'),
            }
        )
    return out


def _format_relic(relic: dict, property_map: dict) -> dict:
    """One artifact in a shape an LLM can reason about."""
    main = relic.get('main_property') or {}
    subs = []
    for sub in relic.get('sub_property_list') or []:
        if not isinstance(sub, dict):
            continue
        subs.append(
            {
                'stat': _prop_name(property_map, sub),
                'value': sub.get('value'),
                # How many rolls landed on this substat; high counts mean the piece is
                # heavily invested rather than merely present.
                'rolls': sub.get('times'),
            }
        )
    set_info = relic.get('set') or {}
    return {
        'name': relic.get('name'),
        'slot': relic.get('pos_name'),
        'rarity': relic.get('rarity'),
        'level': relic.get('level'),
        'set': set_info.get('name'),
        'set_2pc': next(
            (a.get('effect') for a in (set_info.get('affixes') or []) if a.get('activation_number') == 2),
            None,
        ),
        'set_4pc': next(
            (a.get('effect') for a in (set_info.get('affixes') or []) if a.get('activation_number') == 4),
            None,
        ),
        'main_stat': _prop_name(property_map, main),
        'main_value': main.get('value'),
        'substats': subs,
    }


def build_server() -> FastMCP:
    # MCP enables DNS-rebinding protection by default with an EMPTY allow-list, which
    # means only localhost is accepted. A request from Open WebUI carries
    # `Host: hoyolab-mcp:8899` and is rejected with 421 Misdirected Request, which looks
    # like a broken server rather than a policy rejection.
    #
    # Protection stays ON -- it stops a malicious page from driving this server through
    # a browser. The allow-list is just widened to the names this server is actually
    # reached by. Configure with HOYOLAB_MCP_ALLOWED_HOSTS (comma separated) when the
    # deployment uses different names.
    allowed = [
        h.strip()
        for h in (
            os.environ.get(
                'HOYOLAB_MCP_ALLOWED_HOSTS',
                'hoyolab-mcp:8899,hoyolab-mcp,localhost:8899,localhost,127.0.0.1:8899,127.0.0.1',
            )
        ).split(',')
        if h.strip()
    ]
    origins = [
        o.strip()
        for o in (os.environ.get('HOYOLAB_MCP_ALLOWED_ORIGINS', '') or '').split(',')
        if o.strip()
    ]
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed,
        allowed_origins=origins,
    )

    mcp = FastMCP(
        # Deliberately NOT renamed to match the project title. This string is sent to
        # clients at handshake as `serverInfo.name` and nothing here depends on it
        # (Open WebUI reads only `instructions` and uses its own connection id as the
        # tool prefix), so renaming it would be cosmetic — but it would make a rebuilt
        # image differ from already-running deployments for no functional gain.
        name='hoyolab-chronicle',
        instructions=(
            'Read-only access to a Genshin Impact Battle Chronicle. Every tool reads the '
            'account linked by the calling user; there is no shared account. Call '
            'hoyolab_link_status first if you are unsure whether an account is linked. '
            'If a tool reports that no account is linked, it returns a personal link URL '
            '— show that URL to the user and ask them to open it, then retry. '
            'Omit the uid argument when the user has only one Genshin account; the tool '
            'resolves it. Never invent a uid, and never pass the string "None".'
        ),
        stateless_http=True,
        json_response=True,
        transport_security=security,
    )

    @mcp.tool()
    def hoyolab_link_status(ctx: Context) -> dict:
        """Report whether this Open WebUI user has a HoYoLAB account linked."""
        user_id, error = resolve_user_id(_headers_from(ctx))
        if error:
            return {'linked': False, 'error': error}
        status = _store().status(user_id)
        status['user'] = redact(user_id)
        return status

    @mcp.tool()
    def list_game_accounts(ctx: Context) -> dict:
        """List the game accounts (Genshin UIDs) linked to this user's HoYoLAB login."""
        client, _ = _client_for(ctx)
        cards = client.record_cards(_hoyolab_uid_from_cookies(client))
        accounts = []
        for card in cards:
            accounts.append(
                {
                    'game': {1: 'Honkai Impact 3rd', 2: 'Genshin Impact', 6: 'Honkai: Star Rail', 8: 'Zenless Zone Zero'}.get(
                        card.get('game_id'), f"game_id={card.get('game_id')}"
                    ),
                    'uid': card_uid(card),
                    'nickname': card.get('nickname'),
                    'level': card.get('level'),
                    'server': card.get('region'),
                }
            )
        return {'accounts': accounts}

    @mcp.tool()
    def get_genshin_overview(ctx: Context, uid: Optional[str] = None) -> dict:
        """Full account statistics: the same figures the Battle Chronicle page shows.

        `stats` contains, all from this account:
          * progress — achievements, days_active, characters, full_friendship_characters,
            spiral_abyss (highest floor-chamber)
          * imaginarium_theater — highest act this period, difficulty, unlock state
          * stygian_onslaught — best record name and difficulty
          * oculi — anemoculus, geoculus, electroculus, dendroculus, hydroculus,
            pyroculus, cryoculus, lunoculus
          * world — unlocked_waypoints, unlocked_domains
          * chests — luxurious, precious, exquisite, common, remarkable

        Every field is present; nothing here requires a wiki or web lookup. For the
        Imaginarium Theater round-by-round detail use get_imaginarium_theater.

        Args:
            uid: Genshin UID (9 digits). OMIT entirely when the account is unknown.
        """
        client, _ = _client_for(ctx)
        uid = _require_uid(client, uid)
        data = client.index(uid)
        stats = data.get('stats') or {}
        return {
            'uid': uid,
            'server': server_for_uid(uid),
            'nickname': data.get('role', {}).get('nickname'),
            'adventure_rank': data.get('role', {}).get('level'),
            'stats': _format_stats_block(stats),
            'exploration': _exploration_summary(data),
        }

    @mcp.tool()
    def get_character_artifacts(
        ctx: Context,
        character: Optional[str] = None,
        uid: Optional[str] = None,
        limit: int = 10,
    ) -> dict:
        """Everything needed to judge a build: artifacts, substats, and final stats.

        Returns, for each character:
          * `stats` — final totals as the game shows them (ATK, CRIT Rate, CRIT DMG,
            Energy Recharge, Elemental Mastery, ...) with base / bonus / total breakdown
          * `artifacts` — equipped pieces with set, main stat, substats and roll counts

        These numbers come from the player's own account, so do NOT scrape a wiki or
        search the web for character stats, base ATK tables, or artifact set bonuses
        when this tool can answer. Wiki values are generic; these are this account's
        actual numbers.

        Args:
            character: Character name or numeric id, e.g. "Furina" or "10000089".
                Case-insensitive; partial names are matched.
            uid: Genshin UID (9 digits). OMIT entirely when the account is unknown.
            limit: Maximum number of characters to inspect when `character` is omitted
                or matches several.
        """
        client, _ = _client_for(ctx)
        uid = _require_uid(client, uid)

        owned = client.characters(uid)
        if not owned:
            raise HoyolabError('This account has no characters to inspect.')

        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 10

        wanted = (character or '').strip().lower()
        if wanted and wanted.lower() not in _NULLISH:
            matched = [
                c
                for c in owned
                if str(c.get('id')) == wanted or wanted in str(c.get('name', '')).lower()
            ]
            if not matched:
                names = ', '.join(str(c.get('name')) for c in owned[:15])
                raise HoyolabError(
                    f'No character matching "{character}" on this account. '
                    f'Some names that do exist: {names}'
                )
        else:
            matched = owned[: max(1, limit)]

        matched = matched[: max(1, limit)]
        detail = client.character_details(uid, [c['id'] for c in matched])
        property_map = detail['property_map']

        out = []
        for entry in detail['list']:
            if not isinstance(entry, dict):
                continue
            base = entry.get('base') or {}
            relics = [_format_relic(r, property_map) for r in (entry.get('relics') or []) if isinstance(r, dict)]
            # Group by set so a 4-piece bonus is visible at a glance.
            set_counts: dict[str, int] = {}
            for r in relics:
                if r['set']:
                    set_counts[r['set']] = set_counts.get(r['set'], 0) + 1
            weapon = entry.get('weapon') or {}
            out.append(
                {
                    'character': base.get('name'),
                    'level': base.get('level'),
                    'rarity': base.get('rarity'),
                    'element': base.get('element'),
                    'weapon': {
                        'name': weapon.get('name'),
                        'level': weapon.get('level'),
                        'rarity': weapon.get('rarity'),
                        'refinement': weapon.get('affix_level'),
                    },
                    # Totals as the game reports them. base = character + weapon,
                    # bonus = artifacts/buffs, total = base + bonus. This is the answer
                    # to "what is my total ATK / CRIT Rate / CRIT DMG".
                    'stats': _format_stats(entry, property_map),
                    'artifact_count': len(relics),
                    'sets': set_counts,
                    'artifacts': relics,
                }
            )

        return {'uid': uid, 'characters': out}

    @mcp.tool()
    def get_characters(ctx: Context, uid: Optional[str] = None, limit: int = 200) -> dict:
        """List owned Genshin characters with level, rarity, and constellation.

        This is a roster overview. It does NOT include artifacts or substats; call
        get_character_artifacts for those.

        Args:
            uid: Genshin UID (9 digits). OMIT this argument entirely when the account
                is unknown; do not pass null or the word "None".
            limit: Maximum number of characters to return.
        """
        client, _ = _client_for(ctx)
        uid = _require_uid(client, uid)
        raw = client.characters(uid)
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 200
        chars = []
        for item in raw[: max(1, limit)]:
            if not isinstance(item, dict):
                continue
            chars.append(
                {
                    'id': item.get('id'),
                    'name': item.get('name'),
                    'element': item.get('element'),
                    'rarity': item.get('rarity'),
                    'level': item.get('level'),
                    'constellation': item.get('actived_constellation_num'),
                    'friendship': item.get('fetter'),
                    'weapon': (item.get('weapon') or {}).get('name'),
                }
            )
        return {'uid': uid, 'count': len(raw), 'returned': len(chars), 'characters': chars}

    @mcp.tool()
    def get_spiral_abyss(ctx: Context, uid: Optional[str] = None, previous: bool = False) -> dict:
        """Spiral Abyss results: stars, floors, and the characters used.

        Args:
            uid: Genshin UID. Omit when only one Genshin account is linked.
            previous: Return the previous rotation instead of the current one.
        """
        client, _ = _client_for(ctx)
        uid = _require_uid(client, uid)
        data = client.spiral_abyss(uid, previous=previous)
        floors = []
        for floor in data.get('floors') or []:
            if not isinstance(floor, dict):
                continue
            chambers = []
            for ch in floor.get('levels') or []:
                if not isinstance(ch, dict):
                    continue
                chambers.append(
                    {
                        'chamber': ch.get('index'),
                        'stars': ch.get('star'),
                        'battles': [
                            {
                                'characters': [a.get('name') for a in (b.get('avatars') or []) if isinstance(a, dict)],
                                'damage_taken': b.get('damage_taken'),
                            }
                            for b in (ch.get('battles') or [])
                            if isinstance(b, dict)
                        ],
                    }
                )
            floors.append(
                {
                    'floor': floor.get('index'),
                    'stars': floor.get('star'),
                    'max_stars': floor.get('max_star'),
                    'chambers': chambers,
                }
            )
        return {
            'uid': uid,
            'previous_rotation': previous,
            'season': data.get('schedule_id'),
            'total_stars': data.get('total_star'),
            # Deliberately no aggregate maximum. The API reports `total_star` across
            # every floor in the rotation but only returns the floors the player
            # actually attempted, so summing the per-floor maxima undercounts (36 stars
            # against a computed 18). Each floor carries its own accurate max_stars.
            'deepest_floor': data.get('max_floor'),
            'battles': data.get('total_battle_times'),
            'wins': data.get('total_win_times'),
            'floors': floors,
        }

    @mcp.tool()
    def get_imaginarium_theater(ctx: Context, uid: Optional[str] = None, include_roster: bool = False) -> dict:
        """Imaginarium Theater results, current and previous period.

        Returns per-period difficulty, highest act reached, medals earned, coins, and
        optionally the characters used in each round.

        Args:
            uid: Genshin UID (9 digits). OMIT entirely when the account is unknown.
            include_roster: Also return the characters used per round (larger payload).
        """
        client, _ = _client_for(ctx)
        uid = _require_uid(client, uid)
        data = client.imaginarium_theater(uid, need_detail=include_roster)

        periods = []
        for run in data.get('data') or []:
            if not isinstance(run, dict):
                continue
            stat = run.get('stat') or {}
            schedule = run.get('schedule') or {}
            entry = {
                'schedule_id': schedule.get('schedule_id'),
                'difficulty_id': stat.get('difficulty_id'),
                'highest_act': stat.get('max_round_id'),
                'medals': stat.get('medal_num'),
                'coins': stat.get('coin_num'),
                'bonus_characters': stat.get('avatar_bonus_num'),
                'tarot_finished': stat.get('tarot_finished_cnt'),
            }
            if include_roster:
                rounds = []
                for rnd in ((run.get('detail') or {}).get('rounds_data') or []):
                    if not isinstance(rnd, dict):
                        continue
                    rounds.append(
                        {
                            'round': rnd.get('round_id') or rnd.get('index'),
                            'characters': [
                                a.get('name')
                                for a in (rnd.get('avatars') or [])
                                if isinstance(a, dict) and a.get('name')
                            ],
                        }
                    )
                entry['rounds'] = rounds
            periods.append(entry)

        return {
            'uid': uid,
            'unlocked': data.get('is_unlock'),
            'periods': periods,
        }

    @mcp.tool()
    def get_exploration(ctx: Context, uid: Optional[str] = None) -> dict:
        """Exploration progress per region, plus statue/offering levels.

        Returns:
          * `incomplete` — regions below 100%, least explored first. Use this to answer
            "what is not 100% yet"; it is already sorted and filtered.
          * `areas` — every region with `explored_percent` and a `complete` flag
          * `complete_count` / `total_areas` — summary counts
          * `offerings` — statue and reputation levels per region

        Percentages come from the account, not a wiki.

        Args:
            uid: Genshin UID (9 digits). OMIT entirely when the account is unknown.
        """
        client, _ = _client_for(ctx)
        uid = _require_uid(client, uid)
        data = client.index(uid)
        summary = _exploration_summary(data)
        return {'uid': uid, **summary}

    @mcp.tool()
    def get_daily_note(ctx: Context, uid: Optional[str] = None) -> dict:
        """Current resin, realm currency, expeditions and daily task state.

        This is the "Daily Note" the mobile app shows, and it is the only way to get
        resin: the Battle Chronicle overview endpoint does not carry resin, expeditions,
        daily tasks or realm currency at all.

        Returns:
          * `resin` — `current` / `max`, a `state` of `recovering`, `full` or `unknown`,
            and `full_in` as readable text (e.g. "5h 51m (21072 seconds)").
            `full_at_seconds` is the same figure as a number for calculations.
          * `realm_currency` — realm currency (home coin) with the same shape
          * `expeditions` — `current` / `max` and one entry per expedition in progress
          * `daily_tasks` — `finished` / `total` and whether the extra reward is claimed
          * `weekly_boss_discount` — remaining discounted boss claims this week
          * `parametric_transformer` — whether it is ready and time remaining
          * `weekly_activity` — current week's activity progress

        Countdowns are seconds-since-epoch-free durations: report them as durations, not
        as clock times. When `state` is `full`, `full_in` is null and the resource is
        capped.

        Args:
            uid: Genshin UID (9 digits). OMIT entirely when the account is unknown.
        """
        client, _ = _client_for(ctx)
        uid = _require_uid(client, uid)
        note = client.daily_note(uid)
        return {'uid': uid, 'server': server_for_uid(uid), **_daily_note_summary(note)}

    @mcp.tool()
    def get_attendance(ctx: Context) -> dict:
        """HoYoLAB daily check-in state for this account: signed today, and the reward.

        Account-level, not per game UID: the check-in belongs to the HoYoLAB login, so
        there is no `uid` argument.

        Returns:
          * `signed_in_today` — whether today's check-in is already claimed
          * `days_signed_this_month`, `rewards_in_month`, `rewards_left_this_month`
          * `reward_claimed_today` — what was actually claimed today, if anything
          * `reward_if_claimed_now` — what today's check-in would give, if unsigned
          * `make_up` — how many missed days can be recovered, at what cost
          * `partial` — what could not be read; empty when everything was available

        `signed_in_today` comes from the check-in state alone, so it is answered even
        when the reward list or the make-up allowance cannot be fetched. If `partial`
        names something, report that field as unavailable instead of guessing.

        This is read-only: it reports the state and never claims the reward. Telling the
        user is the point; claiming on their behalf is not something this server does.
        """
        client, _ = _client_for(ctx)

        # `info` is mandatory: without it there is no answer at all. The other two are
        # supporting detail, so a failure there degrades the answer instead of discarding
        # it -- the least important call must not take the main question down with it.
        info = client.attendance_info()

        home: dict = {}
        try:
            home = client.attendance_rewards()
        except HoyolabError as exc:
            log.warning('check-in reward list unavailable: %s', exc)

        resign: dict = {}
        try:
            resign = client.attendance_resign()
        except HoyolabError as exc:
            log.warning('check-in make-up allowance unavailable: %s', exc)

        return _attendance_summary(info, home, resign)

    return mcp
