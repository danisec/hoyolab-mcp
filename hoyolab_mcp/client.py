"""Minimal HoYoLAB Genshin Battle Chronicle client.

Written directly against the public web endpoints rather than pulling in a
third-party wrapper. The wrapper libraries (genshin.py and similar) are unofficial and
carry a large dependency surface, and the only part actually needed here is a handful
of GET/POST calls plus the `DS` header. Keeping it local means the request shape is
visible and auditable, and there is no dependency that can silently change behaviour
under us.

MEASURED BEHAVIOUR (verified against the live API)
  * Without a valid cookie the API answers HTTP 200 with
    `{"retcode": 10001, "message": "Please login"}`. Authentication is checked before
    the `DS` signature, so a missing cookie always looks like 10001 regardless of how
    well-formed the request is. Errors therefore have to be read from `retcode`, not
    from the HTTP status.
  * `retcode 10102` means the player disabled their Battle Chronicle, which is a
    privacy setting and not a credential problem. It gets its own message so the user
    is not told to re-link when the real fix is in-game.
"""

from __future__ import annotations

import hashlib
import random
import string
import time
from typing import Any, Optional

import httpx

# Salt for the overseas `DS` header. This is a public constant embedded in the web
# client, not a secret.
DS_SALT = '6s25p5ox5y14umn1p61aqyyvbvvl3lrt'

RECORD_BASE = 'https://sg-public-api.hoyolab.com/event/game_record/genshin/api'
# The account-list endpoint lives on the community API, not the record API. Using the
# record host here returns a 404 page rather than JSON.
CARD_URL = 'https://bbs-api-os.hoyolab.com/game_record/card/wapi/getGameRecordCard'

# Daily check-in ("Hoyolab Daily Check-In") is a different service from the game record
# API, on a different host. Both halves of this were measured, because each wrong guess
# fails with a misleading message rather than a 404:
#   * `/event/luna/*` (the Star Rail and ZZZ variants) on the public host answers
#     `retcode -100, "please open this from inside the game"`, which reads like a
#     permission problem
#   * `sg-hk4e-api` is the Genshin (hk4e) host and `/event/sol/*` is the Genshin path
# The `act_id` below is the Genshin check-in activity. It is a public constant in the
# page URL, not a secret.
SIGN_BASE = 'https://sg-hk4e-api.hoyolab.com/event/sol'
SIGN_ACT_ID = 'e202102251931481'

# Genshin server resolution from the UID prefix.
GENSHIN_SERVERS = {
    'cn_gf01': ('1', '2', '3'),
    'cn_qd01': ('5',),
    'os_usa': ('6',),
    'os_euro': ('7',),
    'os_asia': ('8', '18'),
    'os_cht': ('9',),
}
OVERSEAS_PREFIXES = ('6', '7', '8', '9', '18')

RETCODE_MESSAGES = {
    10001: (
        'HoYoLAB rejected the credential (retcode 10001, "Please login"). '
        'The cookies are missing, expired, or belong to a different account.'
    ),
    -100: 'HoYoLAB rejected the credential (retcode -100). Please re-link your account.',
    1008: 'The HoYoLAB credential is invalid or has expired. Please re-link.',
    10101: (
        'The credential does not match this game account (retcode 10101). '
        'Make sure you linked the HoYoLAB account that owns this UID.'
    ),
    10102: (
        'This player has disabled their Battle Chronicle (retcode 10102). '
        'That is a privacy setting in-game, not a login problem: enable '
        '"Show my Battle Chronicle on my profile" in HoYoLAB settings.'
    ),
    10103: 'The requested game account could not be found (retcode 10103).',
    -1: 'HoYoLAB returned a generic error (retcode -1). Try again shortly.',
    1009: 'The requested data does not exist (retcode 1009).',
    # The check-in service uses its own codes for "not logged in" and "parameter
    # missing", and they differ from the game-record API's 10001. Measured: an
    # unauthenticated `/event/sol/info` answers -100 "Not logged in".
    -100: (
        'HoYoLAB rejected the credential for the daily check-in service (retcode -100, '
        '"Not logged in"). Re-link your account; the stored cookies have expired.'
    ),
    # Measured on `dailyNote`: a valid credential with the wrong `server` value answers
    # 1005 and a message about missing information, not anything that names the
    # parameter. That makes it look like a broken account rather than a bad argument.
    1005: (
        'HoYoLAB rejected the request as incomplete (retcode 1005). For Daily Note this '
        'is what a mismatched server value looks like; the server is derived from the '
        'UID, so check that the uid belongs to this account.'
    ),
    -1005: 'HoYoLAB rejected the request as missing a required parameter (retcode -1005).',
}


class HoyolabError(Exception):
    """An error that should be shown to the user as-is."""


def make_ds() -> str:
    """Build the `DS` header value: `t,r,md5(salt&t&r)`."""
    t = int(time.time())
    r = ''.join(random.choices(string.ascii_letters, k=6))
    h = hashlib.md5(f'salt={DS_SALT}&t={t}&r={r}'.encode()).hexdigest()
    return f'{t},{r},{h}'


def server_for_uid(uid: int | str) -> str:
    """Map a Genshin UID to its `server` parameter."""
    text = str(uid).strip()
    if not text.isdigit():
        raise HoyolabError(f'UID {uid!r} is not numeric.')
    prefix = text[:-8]
    for server, digits in GENSHIN_SERVERS.items():
        if prefix in digits:
            return server
    raise HoyolabError(
        f'UID {uid} does not match a known Genshin server prefix. '
        'Expected a 9-digit UID starting with 1,2,3,5 (China) or 6,7,8,9,18 (global).'
    )


def is_overseas_uid(uid: int | str) -> bool:
    return str(uid).strip()[:-8] in OVERSEAS_PREFIXES


class ChronicleClient:
    """One short-lived client bound to one user's cookies."""

    def __init__(self, cookies: dict[str, str], lang: str = 'en-us', timeout: float = 30.0):
        self._cookies = cookies
        self._lang = lang
        self._timeout = timeout

    def _cookie_header(self) -> str:
        return '; '.join(f'{k}={v}' for k, v in self._cookies.items())

    def _headers(self) -> dict[str, str]:
        return {
            'DS': make_ds(),
            'x-rpc-app_version': '1.5.0',
            'x-rpc-client_type': '5',
            'x-rpc-language': self._lang,
            'Cookie': self._cookie_header(),
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (compatible; open-webui-hoyolab-mcp)',
        }

    def _check(self, payload: dict, context: str) -> dict:
        retcode = payload.get('retcode')
        if retcode == 0:
            data = payload.get('data')
            if data is None:
                raise HoyolabError(f'HoYoLAB returned no data for {context}.')
            return data
        message = RETCODE_MESSAGES.get(
            retcode,
            f'HoYoLAB returned retcode {retcode}: {payload.get("message") or "unknown error"}',
        )
        raise HoyolabError(message)

    def _request(
        self,
        endpoint: str,
        *,
        params: Optional[dict] = None,
        body: Optional[dict] = None,
        url: Optional[str] = None,
    ) -> dict:
        target = url or f'{RECORD_BASE}/{endpoint}'
        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
                if body is not None:
                    resp = client.post(target, params=params, json=body, headers=self._headers())
                else:
                    resp = client.get(target, params=params, headers=self._headers())
        except httpx.TimeoutException as exc:
            raise HoyolabError('HoYoLAB did not respond in time. Try again shortly.') from exc
        except httpx.HTTPError as exc:
            # Deliberately does not include the request headers in the message; they
            # carry the cookie.
            raise HoyolabError(f'Could not reach HoYoLAB ({type(exc).__name__}).') from exc

        if resp.status_code >= 500:
            raise HoyolabError(f'HoYoLAB is having trouble (HTTP {resp.status_code}). Try again later.')
        try:
            payload = resp.json()
        except Exception as exc:
            raise HoyolabError(f'HoYoLAB returned a non-JSON response (HTTP {resp.status_code}).') from exc
        return payload

    # ---- read-only endpoints -------------------------------------------------

    def record_cards(self, hoyolab_uid: int | str) -> list[dict]:
        """The accounts linked to this HoYoLAB login."""
        payload = self._request('', url=CARD_URL, params={'uid': str(hoyolab_uid)})
        data = self._check(payload, 'account list')
        return data.get('list') or []

    def index(self, uid: int | str) -> dict:
        """Overview: stats, exploration, and (optionally) avatars."""
        payload = self._request(
            'index',
            params={'role_id': str(uid), 'server': server_for_uid(uid), 'avatar_list_type': 0},
        )
        return self._check(payload, 'overview')

    def characters(self, uid: int | str) -> list[dict]:
        """Owned characters.

        `character/list` is a POST whose parameters belong in the JSON body, not the
        query string: `role_id` and `server` are read from the body by this endpoint.
        Sending them as query params produces a 10001/1009 style rejection even with a
        valid cookie.
        """
        payload = self._request(
            'character/list',
            body={'role_id': str(uid), 'server': server_for_uid(uid)},
        )
        data = self._check(payload, 'characters')
        return data.get('list') or []

    def character_details(self, uid: int | str, character_ids: list[int]) -> dict:
        """Full detail for specific characters, including equipped artifacts.

        Artifacts are NOT part of `character/list` -- that endpoint returns only name,
        level, rarity, element and weapon. The relic data lives behind
        `character/detail`, which additionally returns a `property_map` that translates
        the numeric `property_type` on each stat into a readable name. Without that map
        the artifacts are a wall of integers.

        Returns {'list': [...], 'property_map': {...}}.
        """
        payload = self._request(
            'character/detail',
            body={
                'role_id': str(uid),
                'server': server_for_uid(uid),
                'character_ids': [int(c) for c in character_ids],
            },
        )
        data = self._check(payload, 'character detail')
        return {'list': data.get('list') or [], 'property_map': data.get('property_map') or {}}

    def imaginarium_theater(self, uid: int | str, need_detail: bool = False) -> dict:
        """Imaginarium Theater runs, including the current and previous period.

        This endpoint carries far more than the summary embedded in `index`: per-period
        difficulty, highest act, medals, coins, and (with `need_detail`) the roster used
        per round. Without it the only figure available was `max_round_id`.
        """
        params = {'role_id': str(uid), 'server': server_for_uid(uid)}
        if need_detail:
            params['need_detail'] = 'true'
        payload = self._request('role_combat', params=params)
        return self._check(payload, 'Imaginarium Theater')

    def spiral_abyss(self, uid: int | str, previous: bool = False) -> dict:
        payload = self._request(
            'spiralAbyss',
            params={
                'role_id': str(uid),
                'server': server_for_uid(uid),
                'schedule_type': '2' if previous else '1',
            },
        )
        return self._check(payload, 'Spiral Abyss')

    def daily_note(self, uid: int | str) -> dict:
        """Real-time resource state: resin, expeditions, daily tasks, home coin.

        This is the endpoint the mobile app's "Daily Note" widget uses. It is NOT part
        of `index`: measured, `index` carries no resin, expedition, daily-task or
        home-coin field at all, which is why a Battle Chronicle-only server cannot
        answer "how much resin do I have".

        `server` is required. Without it the API answers
        `retcode -1, "param server error: value length must be at least 1 runes"`,
        which is a validation complaint rather than a hint that a parameter is missing.
        """
        payload = self._request(
            'dailyNote',
            params={'role_id': str(uid), 'server': server_for_uid(uid)},
        )
        return self._check(payload, 'Daily Note')

    def attendance_info(self) -> dict:
        """This month's check-in state for the calling account.

        Account-level, not per game UID: the credential identifies the HoYoLAB account
        and there is no `role_id` parameter, so nothing here is UID-scoped.
        """
        payload = self._request('info', params={'act_id': SIGN_ACT_ID}, url=f'{SIGN_BASE}/info')
        return self._check(payload, 'daily check-in')

    def attendance_rewards(self) -> dict:
        """The reward list for the current check-in month, plus its month number."""
        payload = self._request(
            'home',
            params={'act_id': SIGN_ACT_ID, 'lang': self._lang},
            url=f'{SIGN_BASE}/home',
        )
        return self._check(payload, 'daily check-in rewards')

    def attendance_resign(self) -> dict:
        """How many missed check-ins can still be bought back, and at what price."""
        payload = self._request(
            'resign_info',
            params={'act_id': SIGN_ACT_ID, 'lang': self._lang},
            url=f'{SIGN_BASE}/resign_info',
        )
        return self._check(payload, 'check-in make-up allowance')
