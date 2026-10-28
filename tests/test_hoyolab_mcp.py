"""Regression tests for the HoYoLAB MCP server.

Focus is on the properties that would be dangerous to get wrong rather than on
coverage for its own sake:

  * one user's cookie can never be read by another user
  * a ciphertext moved to another row fails to decrypt
  * cookie values never appear in logs or error text
  * a malformed or partial credential is rejected instead of stored
  * UID -> server mapping covers every prefix the API documents
  * the DS header has the exact shape the API expects

Run: python3 tests/test_hoyolab_mcp.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hoyolab_mcp.client import (
    ChronicleClient,
    HoyolabError,
    is_overseas_uid,
    make_ds,
    server_for_uid,
)
from hoyolab_mcp.store import (
    API_TOKEN_PREFIX,
    ApiTokenStore,
    CredentialError,
    CredentialStore,
    decode_link_token,
    encode_link_token,
    parse_cookie_string,
    redact,
    validate_cookies,
)
from hoyolab_mcp.tools import resolve_user_id

SECRET = 'test-secret-value-that-is-long-enough'
GOOD_COOKIES = {'ltuid_v2': '123456789', 'ltoken_v2': 'v2_abcdef0123456789', 'ltmid_v2': 'abc123'}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, 'creds.db')
        self.store = CredentialStore(self.db, SECRET)

    def test_roundtrip(self):
        self.store.save('user-a', GOOD_COOKIES)
        self.assertEqual(self.store.load('user-a'), GOOD_COOKIES)

    def test_users_are_isolated(self):
        """The core safety property: no cross-user leakage."""
        self.store.save('user-a', GOOD_COOKIES)
        self.store.save('user-b', {'ltuid_v2': '999', 'ltoken_v2': 'v2_other'})
        self.assertEqual(self.store.load('user-a')['ltoken_v2'], GOOD_COOKIES['ltoken_v2'])
        self.assertEqual(self.store.load('user-b')['ltoken_v2'], 'v2_other')
        self.assertIsNone(self.store.load('user-c'))

    def test_ciphertext_is_bound_to_user(self):
        """A row copied onto another user must not decrypt."""
        self.store.save('user-a', GOOD_COOKIES)
        import sqlite3

        conn = sqlite3.connect(self.db)
        nonce, ct = conn.execute(
            'SELECT nonce, ciphertext FROM credentials WHERE user_id=?', ('user-a',)
        ).fetchone()
        conn.execute(
            'INSERT INTO credentials (user_id, nonce, ciphertext, updated_at) VALUES (?,?,?,0)',
            ('user-b', nonce, ct),
        )
        conn.commit()
        conn.close()
        with self.assertRaises(CredentialError):
            self.store.load('user-b')

    def test_plaintext_never_on_disk(self):
        self.store.save('user-a', GOOD_COOKIES)
        with open(self.db, 'rb') as f:
            blob = f.read()
        # WAL holds the row; check both files for the raw token.
        self.assertNotIn(GOOD_COOKIES['ltoken_v2'].encode(), blob)
        wal = self.db + '-wal'
        if os.path.exists(wal):
            with open(wal, 'rb') as f:
                self.assertNotIn(GOOD_COOKIES['ltoken_v2'].encode(), f.read())

    def test_delete(self):
        self.store.save('user-a', GOOD_COOKIES)
        self.assertTrue(self.store.delete('user-a'))
        self.assertIsNone(self.store.load('user-a'))
        self.assertFalse(self.store.delete('user-a'))

    def test_status_hides_values(self):
        self.store.save('user-a', GOOD_COOKIES)
        status = self.store.status('user-a')
        self.assertTrue(status['linked'])
        self.assertEqual(status['names'], sorted(GOOD_COOKIES))
        self.assertNotIn(GOOD_COOKIES['ltoken_v2'], str(status))

    def test_short_secret_refused(self):
        with self.assertRaises(RuntimeError):
            CredentialStore(self.db, 'short')

    def test_wrong_secret_cannot_decrypt(self):
        self.store.save('user-a', GOOD_COOKIES)
        other = CredentialStore(self.db, 'a-completely-different-secret-value')
        with self.assertRaises(CredentialError):
            other.load('user-a')


class ValidationTests(unittest.TestCase):
    def test_parse_tolerates_devtools_format(self):
        raw = ' ltuid_v2=1 ; ltoken_v2=v2_x ;  ltmid_v2=m ;; '
        self.assertEqual(
            parse_cookie_string(raw), {'ltuid_v2': '1', 'ltoken_v2': 'v2_x', 'ltmid_v2': 'm'}
        )

    def test_unrelated_cookies_dropped(self):
        kept = validate_cookies({'ltuid_v2': '1', 'ltoken_v2': 'v2_x', '_ga': 'GA1.2', 'locale': 'en'})
        self.assertEqual(set(kept), {'ltuid_v2', 'ltoken_v2'})

    def test_no_auth_cookies_rejected(self):
        with self.assertRaises(CredentialError):
            validate_cookies({'_ga': 'x', 'locale': 'en'})

    def test_partial_credential_rejected(self):
        with self.assertRaises(CredentialError):
            validate_cookies({'ltuid_v2': '1'})  # uid without token

    def test_legacy_pair_accepted(self):
        self.assertEqual(set(validate_cookies({'ltuid': '1', 'ltoken': 'x'})), {'ltuid', 'ltoken'})

    def test_redact_keeps_nothing_useful(self):
        self.assertEqual(redact(''), '')
        self.assertEqual(redact('short'), '***')
        out = redact('v2_supersecrettoken')
        self.assertNotIn('supersecret', out)


class ApiTokenStoreTests(unittest.TestCase):
    """Tokens for clients that are not Open WebUI (Claude Code, Codex, opencode)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, 'creds.db')
        self.store = ApiTokenStore(self.db, SECRET)

    def test_issue_and_resolve(self):
        token = self.store.issue_token('user-a', 'claude-code')
        self.assertTrue(token.startswith(API_TOKEN_PREFIX))
        self.assertEqual(self.store.resolve_token(token), 'user-a')

    def test_tokens_are_unique(self):
        a = self.store.issue_token('user-a')
        b = self.store.issue_token('user-a')
        self.assertNotEqual(a, b)
        self.assertEqual(self.store.resolve_token(a), 'user-a')
        self.assertEqual(self.store.resolve_token(b), 'user-a')

    def test_unknown_token_rejected(self):
        self.assertIsNone(self.store.resolve_token('hlt_not-a-real-token'))
        self.assertIsNone(self.store.resolve_token(''))
        self.assertIsNone(self.store.resolve_token(None))

    def test_wrong_prefix_rejected(self):
        """Guards against a raw cookie or an Open WebUI JWT being mistaken for a token."""
        self.assertIsNone(self.store.resolve_token('v2_abcdef0123456789'))

    def test_token_value_never_stored(self):
        """A database dump must not yield working credentials."""
        token = self.store.issue_token('user-a')
        for path in (self.db, self.db + '-wal'):
            if not os.path.exists(path):
                continue
            with open(path, 'rb') as f:
                blob = f.read()
            self.assertNotIn(token.encode(), blob)
            self.assertNotIn(token[len(API_TOKEN_PREFIX) :].encode(), blob)

    def test_list_never_returns_values(self):
        token = self.store.issue_token('user-a', 'laptop')
        listed = self.store.list_tokens('user-a')
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]['label'], 'laptop')
        self.assertNotIn(token, str(listed))

    def test_revoke_one_leaves_others(self):
        a = self.store.issue_token('user-a', 'one')
        b = self.store.issue_token('user-a', 'two')
        token_id = self.store.list_tokens('user-a')[0]['id']
        self.assertTrue(self.store.revoke_token('user-a', token_id))
        resolved = [self.store.resolve_token(a), self.store.resolve_token(b)]
        self.assertEqual(resolved.count(None), 1, 'exactly one token must be revoked')

    def test_revoke_is_scoped_to_user(self):
        """One user cannot revoke another user's token by guessing its id."""
        self.store.issue_token('user-b', 'theirs')
        token_id = self.store.list_tokens('user-b')[0]['id']
        self.assertFalse(self.store.revoke_token('user-a', token_id))
        self.assertEqual(len(self.store.list_tokens('user-b')), 1)

    def test_revoke_all(self):
        self.store.issue_token('user-a')
        self.store.issue_token('user-a')
        self.assertEqual(self.store.revoke_all_tokens('user-a'), 2)
        self.assertEqual(self.store.list_tokens('user-a'), [])

    def test_tokens_do_not_leak_between_users(self):
        a = self.store.issue_token('user-a')
        self.assertEqual(self.store.resolve_token(a), 'user-a')
        self.assertNotEqual(self.store.resolve_token(a), 'user-b')

    def test_cookies_and_tokens_coexist(self):
        self.store.save('user-a', GOOD_COOKIES)
        token = self.store.issue_token('user-a')
        self.assertEqual(self.store.resolve_token(token), 'user-a')
        self.assertEqual(self.store.load('user-a'), GOOD_COOKIES)

    def test_unlink_deletes_only_that_user(self):
        """Deleting a credential must not touch anybody else's."""
        self.store.save('user-a', GOOD_COOKIES)
        self.store.save('user-b', {'ltuid_v2': '999', 'ltoken_v2': 'v2_other'})
        self.assertTrue(self.store.delete('user-a'))
        self.assertIsNone(self.store.load('user-a'))
        self.assertEqual(self.store.load('user-b')['ltoken_v2'], 'v2_other')

    def test_unlink_then_relink_works(self):
        """A user who unlinks can link again without reinitialising anything."""
        self.store.save('user-a', GOOD_COOKIES)
        self.store.delete('user-a')
        self.store.save('user-a', GOOD_COOKIES)
        self.assertEqual(self.store.load('user-a'), GOOD_COOKIES)


class ResolveUserTests(unittest.TestCase):
    """Identity resolution across the three supported sources."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, 'creds.db')
        self.env = mock.patch.dict(
            os.environ,
            {'HOYOLAB_MCP_SECRET': SECRET, 'HOYOLAB_MCP_DB': self.db},
            clear=False,
        )
        self.env.start()
        os.environ.pop('FORWARD_USER_INFO_HEADER_JWT_SECRET', None)
        self.store = ApiTokenStore(self.db, SECRET)

    def tearDown(self):
        self.env.stop()

    def test_bearer_token_resolves(self):
        token = self.store.issue_token('user-a')
        user_id, error = resolve_user_id({'authorization': f'Bearer {token}'})
        self.assertIsNone(error)
        self.assertEqual(user_id, 'user-a')

    def test_bearer_is_case_insensitive(self):
        token = self.store.issue_token('user-a')
        user_id, error = resolve_user_id({'authorization': f'bearer {token}'})
        self.assertIsNone(error)
        self.assertEqual(user_id, 'user-a')

    def test_invalid_bearer_fails_closed(self):
        """A bad token must not fall back to a weaker header."""
        user_id, error = resolve_user_id(
            {'authorization': 'Bearer hlt_bogus', 'x-openwebui-user-id': 'user-a'}
        )
        self.assertIsNone(user_id)
        self.assertIn('not valid', error)

    def test_plain_header_trusted_when_no_jwt_secret(self):
        user_id, error = resolve_user_id({'x-openwebui-user-id': 'user-a'})
        self.assertIsNone(error)
        self.assertEqual(user_id, 'user-a')

    def test_plain_header_ignored_when_jwt_secret_set(self):
        """Regression: the plain header used to be honoured even with a JWT secret
        configured, so anything reaching the port could name itself any user. When a
        secret is set the unsigned header must be ignored entirely."""
        with mock.patch.dict(os.environ, {'FORWARD_USER_INFO_HEADER_JWT_SECRET': 'jwt-secret'}):
            user_id, error = resolve_user_id({'x-openwebui-user-id': 'attacker-chosen'})
            self.assertIsNone(user_id)
            self.assertIsNotNone(error)

    def test_signed_jwt_resolves(self):
        import jwt as pyjwt

        token = pyjwt.encode(
            {'sub': 'user-j', 'iss': 'open-webui', 'exp': int(time.time()) + 300},
            'jwt-secret',
            algorithm='HS256',
        )
        with mock.patch.dict(os.environ, {'FORWARD_USER_INFO_HEADER_JWT_SECRET': 'jwt-secret'}):
            user_id, error = resolve_user_id({'x-openwebui-user-jwt': token})
            self.assertIsNone(error)
            self.assertEqual(user_id, 'user-j')

    def test_bearer_takes_precedence_over_headers(self):
        token = self.store.issue_token('token-user')
        user_id, _ = resolve_user_id(
            {'authorization': f'Bearer {token}', 'x-openwebui-user-id': 'header-user'}
        )
        self.assertEqual(user_id, 'token-user')

    def test_no_identity_explains_both_options(self):
        user_id, error = resolve_user_id({})
        self.assertIsNone(user_id)
        self.assertIn('API token', error)

    def test_rejected_plain_header_explains_why(self):
        """The operator must be told this is policy, not breakage."""
        with mock.patch.dict(os.environ, {'FORWARD_USER_INFO_HEADER_JWT_SECRET': 'jwt-secret'}):
            _, error = resolve_user_id({'x-openwebui-user-id': 'user-a'})
            self.assertIn('ignored', error)
            self.assertIn('API token', error)


class LinkTokenTests(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(decode_link_token(encode_link_token('user-1', SECRET), SECRET), 'user-1')

    def test_no_base64_padding_emitted(self):
        """A trailing '=' is lost or escaped in URLs, which caused a real
        'Malformed link token' report. The token must not need padding at all."""
        self.assertNotIn('=', encode_link_token('user-1', SECRET))

    def test_accepts_common_manglings(self):
        """Each of these was observed or is a realistic copy-paste artifact.

        They are all signature-neutral: the HMAC still has to match, so normalising
        them cannot let an attacker through.
        """
        token = encode_link_token('user-1', SECRET)
        variants = {
            'stripped padding': token.rstrip('='),
            'with padding re-added': token + '=',
            'leading/trailing space': f'  {token}  ',
            'trailing newline': token + '\n',
            'url-encoded equals': token.replace('=', '%3D'),
            'token= prefix': f'token={token}',
            'wrapped in quotes': f'"{token}"',
        }
        for name, value in variants.items():
            with self.subTest(name):
                self.assertEqual(decode_link_token(value, SECRET), 'user-1')

    def test_truncated_token_rejected(self):
        token = encode_link_token('user-1', SECRET)
        with self.assertRaises(CredentialError):
            decode_link_token(token[:-6], SECRET)

    def test_tampered_user_rejected(self):
        token = encode_link_token('user-1', SECRET)
        import base64

        padded = token + '=' * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        forged = raw.replace('user-1', 'user-2')
        bad = base64.urlsafe_b64encode(forged.encode()).decode().rstrip('=')
        with self.assertRaises(CredentialError):
            decode_link_token(bad, SECRET)

    def test_wrong_secret_rejected(self):
        token = encode_link_token('user-1', SECRET)
        with self.assertRaises(CredentialError):
            decode_link_token(token, 'another-secret-value-long-enough')

    def test_expired_rejected(self):
        from unittest import mock
        import time as real_time

        with mock.patch('hoyolab_mcp.store.time.time', return_value=real_time.time() - 4000):
            token = encode_link_token('user-1', SECRET)
        with self.assertRaises(CredentialError):
            decode_link_token(token, SECRET)


class ClientTests(unittest.TestCase):
    def test_uid_to_server_all_prefixes(self):
        cases = {
            '100000001': 'cn_gf01',
            '200000001': 'cn_gf01',
            '300000001': 'cn_gf01',
            '500000001': 'cn_qd01',
            '600000001': 'os_usa',
            '700000001': 'os_euro',
            '800000001': 'os_asia',
            '1800000001': 'os_asia',
            '900000001': 'os_cht',
        }
        for uid, expected in cases.items():
            self.assertEqual(server_for_uid(uid), expected, f'UID {uid}')

    def test_bad_uid_rejected(self):
        with self.assertRaises(HoyolabError):
            server_for_uid('abc')
        with self.assertRaises(HoyolabError):
            server_for_uid('400000001')

    def test_overseas_detection(self):
        self.assertTrue(is_overseas_uid('800000001'))
        self.assertFalse(is_overseas_uid('100000001'))

    def test_ds_shape(self):
        parts = make_ds().split(',')
        self.assertEqual(len(parts), 3)
        self.assertTrue(parts[0].isdigit())
        self.assertEqual(len(parts[1]), 6)
        self.assertEqual(len(parts[2]), 32)  # md5 hex


class RequestShapeTests(unittest.TestCase):
    """Lock in the wire shape of each call.

    These caught two real bugs: `character/list` sends its parameters in the JSON body
    (not the query string), and the account list lives on the community host rather
    than the record host. Both fail in a way that looks like an auth error, so a shape
    regression would be easy to misdiagnose.
    """

    def _capture(self, method_name, **kwargs):
        import httpx
        from unittest import mock

        captured = {}

        class FakeResp:
            status_code = 200

            def json(self):
                return {'retcode': 0, 'data': {'list': []} if method_name == 'characters' else {}}

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def get(self, url, params=None, headers=None):
                captured.update(method='GET', url=url, params=params, headers=headers)
                return FakeResp()

            def post(self, url, params=None, json=None, headers=None):
                captured.update(method='POST', url=url, params=params, body=json, headers=headers)
                return FakeResp()

        with mock.patch.object(httpx, 'Client', FakeClient):
            client = ChronicleClient({'ltuid_v2': '1', 'ltoken_v2': 'x'})
            if method_name == 'record_cards':
                client.record_cards(**kwargs)
            else:
                getattr(client, method_name)('812345678', **kwargs)
        return captured

    def test_index_uses_query_params(self):
        c = self._capture('index')
        self.assertEqual(c['method'], 'GET')
        self.assertEqual(c['params']['role_id'], '812345678')
        self.assertEqual(c['params']['server'], 'os_asia')

    def test_characters_params_go_in_body(self):
        c = self._capture('characters')
        self.assertEqual(c['method'], 'POST')
        self.assertEqual(c['body']['role_id'], '812345678')
        self.assertEqual(c['body']['server'], 'os_asia')
        self.assertFalse(c['params'], 'role_id must not be sent as a query param')

    def test_card_url_is_community_host(self):
        c = self._capture('record_cards', hoyolab_uid='123')
        self.assertIn('bbs-api-os.hoyolab.com', c['url'])
        self.assertIn('getGameRecordCard', c['url'])

    def test_abyss_schedule_type(self):
        c = self._capture('spiral_abyss', previous=True)
        self.assertEqual(c['params']['schedule_type'], '2')
        c = self._capture('spiral_abyss', previous=False)
        self.assertEqual(c['params']['schedule_type'], '1')

    def test_ds_header_present(self):
        c = self._capture('index')
        self.assertIn('DS', c['headers'])
        self.assertEqual(len(c['headers']['DS'].split(',')), 3)

    def test_cookie_header_built_from_stored_cookies(self):
        c = self._capture('index')
        self.assertIn('ltoken_v2=x', c['headers']['Cookie'])


class UidResolutionTests(unittest.TestCase):
    """Both bugs here produced `UID 'None' is not numeric` for a valid account.

    1. the record card names the UID `game_role_id`; reading `game_uid` always gave
       None, so auto-detection never worked
    2. `if uid:` accepts the string "None" (a non-empty string is truthy), so a model
       passing the literal word was treated as a real UID
    """

    def test_card_uid_reads_game_role_id(self):
        from hoyolab_mcp.tools import card_uid

        self.assertEqual(card_uid({'game_role_id': '812345678'}), '812345678')

    def test_card_uid_tolerates_legacy_field(self):
        from hoyolab_mcp.tools import card_uid

        self.assertEqual(card_uid({'game_uid': '812345678'}), '812345678')

    def test_card_uid_missing(self):
        from hoyolab_mcp.tools import card_uid

        self.assertIsNone(card_uid({}))
        self.assertIsNone(card_uid({'game_uid': None, 'game_role_id': ''}))

    def test_normalize_uid_rejects_nullish(self):
        from hoyolab_mcp.tools import normalize_uid

        for value in [None, '', 'None', 'none', 'NULL', 'null', 'undefined', 'N/A', '-', 'nan', 'False', '  None  ']:
            with self.subTest(value=value):
                self.assertIsNone(normalize_uid(value), f'{value!r} must mean "not provided"')

    def test_normalize_uid_keeps_real_values(self):
        from hoyolab_mcp.tools import normalize_uid

        self.assertEqual(normalize_uid('812345678'), '812345678')
        self.assertEqual(normalize_uid(812345678), '812345678')
        self.assertEqual(normalize_uid(' "812345678" '), '812345678')

    def test_default_uid_uses_card_field(self):
        """Regression: this returned None for every account before the fix."""
        from unittest import mock

        from hoyolab_mcp import tools

        fake = mock.Mock()
        fake.record_cards.return_value = [
            {'game_id': 2, 'game_role_id': '812345678', 'nickname': 'x'},
        ]
        fake._cookies = {'ltuid_v2': '1'}
        self.assertEqual(tools._default_uid(fake), '812345678')

    def test_require_uid_ignores_string_none_and_resolves(self):
        """The reported failure: uid='None' must fall through to auto-detection."""
        from unittest import mock

        from hoyolab_mcp import tools

        fake = mock.Mock()
        fake.record_cards.return_value = [{'game_id': 2, 'game_role_id': '812345678'}]
        fake._cookies = {'ltuid_v2': '1'}
        self.assertEqual(tools._require_uid(fake, 'None'), '812345678')

    def test_require_uid_explicit_wins(self):
        from unittest import mock

        from hoyolab_mcp import tools

        fake = mock.Mock()
        self.assertEqual(tools._require_uid(fake, '899999999'), '899999999')

    def test_require_uid_lists_uids_when_ambiguous(self):
        from unittest import mock

        from hoyolab_mcp import tools

        fake = mock.Mock()
        fake.record_cards.return_value = [
            {'game_id': 2, 'game_role_id': '811111111'},
            {'game_id': 2, 'game_role_id': '822222222'},
        ]
        fake._cookies = {'ltuid_v2': '1'}
        with self.assertRaises(HoyolabError) as ctx:
            tools._require_uid(fake, None)
        self.assertIn('811111111', str(ctx.exception))
        self.assertIn('822222222', str(ctx.exception))

    def test_require_uid_no_genshin_account(self):
        from unittest import mock

        from hoyolab_mcp import tools

        fake = mock.Mock()
        fake.record_cards.return_value = [{'game_id': 6, 'game_role_id': '100000001'}]
        fake._cookies = {'ltuid_v2': '1'}
        with self.assertRaises(HoyolabError) as ctx:
            tools._require_uid(fake, None)
        self.assertIn('no Genshin Impact account', str(ctx.exception))


class ResponseShapeTests(unittest.TestCase):
    """Guards against reporting fields the API does not actually return.

    Each case below was a live defect: `max_stars` read a key that does not exist at
    the top level, and `offerings` were looked up at the top level while the API nests
    them inside each region.
    """

    def test_exploration_collects_nested_offerings(self):
        from hoyolab_mcp.tools import _exploration_summary

        index = {
            'world_explorations': [
                {
                    'name': 'Example Region',
                    'exploration_percentage': 540,
                    'seven_statue_level': 3,
                    'offerings': [{'name': 'Example Offering', 'level': 12}],
                }
            ]
        }
        out = _exploration_summary(index)
        # 540 tenths of a percent = 54.0%
        self.assertEqual(out['areas'][0]['explored_percent'], 54.0)
        self.assertEqual(out['areas'][0]['statue_level'], 3)
        self.assertEqual(len(out['offerings']), 1)
        self.assertEqual(out['offerings'][0]['name'], 'Example Offering')
        self.assertEqual(out['offerings'][0]['area'], 'Example Region')

    def test_exploration_handles_missing_fields(self):
        from hoyolab_mcp.tools import _exploration_summary

        out = _exploration_summary({'world_explorations': [{'name': 'X'}]})
        self.assertIsNone(out['areas'][0]['explored_percent'])
        self.assertEqual(out['offerings'], [])

    def test_abyss_does_not_invent_a_total_maximum(self):
        """A derived total maximum would be wrong.

        Live data: total_star 36 but only floors 11-12 returned (18 possible). The API
        counts stars across the whole rotation while returning only attempted floors, so
        any summed denominator contradicts the numerator.
        """
        import inspect

        from hoyolab_mcp import tools

        source = inspect.getsource(tools.build_server)
        abyss = source[source.index('def get_spiral_abyss') : source.index('def get_exploration')]
        self.assertNotIn("'max_stars': sum", abyss)
        self.assertIn("'total_stars'", abyss)
        self.assertIn("'deepest_floor'", abyss)


class ArtifactTests(unittest.TestCase):
    """Artifacts live behind `character/detail`, not `character/list`.

    Measured: `character/list` returns only id/name/level/rarity/element/weapon_type/
    weapon. The relic data is in `character/detail` under `relics`, and the stats are
    numeric `property_type` codes that only become readable via `property_map`.
    """

    PROPERTY_MAP = {
        '2': {'property_type': 2, 'name': 'HP', 'filter_name': 'HP'},
        '3': {'property_type': 3, 'name': 'HP', 'filter_name': 'HP Percentage'},
        '20': {'property_type': 20, 'name': 'CRIT\xa0Rate', 'filter_name': 'CRIT\xa0Rate'},
    }

    RELIC = {
        'name': 'Example Circlet',
        'pos': 1,
        'pos_name': 'Flower of Life',
        'rarity': 5,
        'level': 20,
        'set': {
            'name': 'Example Set',
            'affixes': [
                {'activation_number': 2, 'effect': 'ATK +18%.'},
                {'activation_number': 4, 'effect': 'CRIT Rate +16%.'},
            ],
        },
        'main_property': {'property_type': 2, 'value': '4780', 'times': 0},
        'sub_property_list': [
            {'property_type': 3, 'value': '16.3%', 'times': 2},
            {'property_type': 20, 'value': '5.8%', 'times': 1},
        ],
    }

    def test_relic_parsed_with_readable_stats(self):
        from hoyolab_mcp.tools import _format_relic

        out = _format_relic(self.RELIC, self.PROPERTY_MAP)
        self.assertEqual(out['name'], 'Example Circlet')
        self.assertEqual(out['slot'], 'Flower of Life')
        self.assertEqual(out['set'], 'Example Set')
        self.assertEqual(out['main_stat'], 'HP')
        self.assertEqual(out['main_value'], '4780')
        self.assertEqual(out['set_2pc'], 'ATK +18%.')
        self.assertEqual(out['set_4pc'], 'CRIT Rate +16%.')
        self.assertEqual(len(out['substats']), 2)

    def test_hp_percent_distinguished_from_flat_hp(self):
        """Both report name 'HP'; filter_name is what separates them."""
        from hoyolab_mcp.tools import _format_relic

        out = _format_relic(self.RELIC, self.PROPERTY_MAP)
        stats = {s['stat']: s for s in out['substats']}
        self.assertIn('HP Percentage', stats)
        self.assertNotIn('HP', stats)

    def test_substat_rolls_preserved(self):
        from hoyolab_mcp.tools import _format_relic

        out = _format_relic(self.RELIC, self.PROPERTY_MAP)
        rolls = {s['stat']: s['rolls'] for s in out['substats']}
        self.assertEqual(rolls['HP Percentage'], 2)

    def test_unknown_property_type_does_not_crash(self):
        from hoyolab_mcp.tools import _format_relic

        relic = dict(self.RELIC)
        relic['main_property'] = {'property_type': 999, 'value': '1'}
        out = _format_relic(relic, self.PROPERTY_MAP)
        self.assertEqual(out['main_stat'], 'property_999')

    def test_missing_property_map_still_returns_data(self):
        from hoyolab_mcp.tools import _format_relic

        out = _format_relic(self.RELIC, {})
        self.assertEqual(out['name'], 'Example Circlet')
        self.assertEqual(len(out['substats']), 2)

    def test_character_list_has_no_relics(self):
        """Documents why a separate endpoint is needed."""
        import inspect

        from hoyolab_mcp import client as client_mod

        list_src = inspect.getsource(client_mod.ChronicleClient.characters)
        self.assertNotIn('relic', list_src.lower())
        detail_src = inspect.getsource(client_mod.ChronicleClient.character_details)
        self.assertIn('character/detail', detail_src)
        self.assertIn('property_map', detail_src)


class StatTotalsTests(unittest.TestCase):
    """`selected_properties` carries the computed totals.

    Dropping it made a build-review question unanswerable from the account, so the model
    went off and scraped a wiki. These totals are what the question actually needs.
    """

    PROPERTY_MAP = {
        '2000': {'name': 'Max HP', 'filter_name': 'Max HP'},
        '20': {'name': 'CRIT Rate', 'filter_name': 'CRIT Rate'},
        '2001': {'name': 'ATK', 'filter_name': 'ATK'},
    }

    ENTRY = {
        'selected_properties': [
            {'property_type': 2000, 'base': '13262', 'add': '9007', 'final': '22269'},
            {'property_type': 20, 'base': '70.5%', 'add': '', 'final': '70.5%'},
            {'property_type': 2001, 'base': '864', 'add': '1943', 'final': '2807'},
        ]
    }

    def test_totals_are_extracted(self):
        from hoyolab_mcp.tools import _format_stats

        stats = {s['stat']: s for s in _format_stats(self.ENTRY, self.PROPERTY_MAP)}
        self.assertEqual(stats['ATK']['total'], '2807')
        self.assertEqual(stats['ATK']['base'], '864')
        self.assertEqual(stats['ATK']['bonus'], '1943')
        self.assertEqual(stats['CRIT Rate']['total'], '70.5%')
        self.assertEqual(stats['Max HP']['total'], '22269')

    def test_empty_bonus_is_preserved(self):
        """An empty `add` means no artifact contribution, not a missing value."""
        from hoyolab_mcp.tools import _format_stats

        stats = {s['stat']: s for s in _format_stats(self.ENTRY, self.PROPERTY_MAP)}
        self.assertEqual(stats['CRIT Rate']['bonus'], '')

    def test_missing_selected_properties(self):
        from hoyolab_mcp.tools import _format_stats

        self.assertEqual(_format_stats({}, self.PROPERTY_MAP), [])

    def test_artifacts_tool_exposes_stats(self):
        """The tool output must include totals, not just relics."""
        import inspect

        from hoyolab_mcp import tools

        src = inspect.getsource(tools.build_server)
        section = src[src.index('def get_character_artifacts') : src.index('def get_characters')]
        self.assertIn("'stats': _format_stats", section)
        self.assertIn('do NOT scrape a wiki', section)


class ExplorationScalingTests(unittest.TestCase):
    """`exploration_percentage` is in tenths of a percent, not hundredths.

    Dividing by 100 turned a fully explored region (raw 1000) into "10.0%" and made the
    whole account look unexplored. The live account had 17 of 20 regions at exactly
    1000, so the bug reported "nothing is 100%" when almost everything was.
    """

    def _summary(self, raw_values):
        from hoyolab_mcp.tools import _exploration_summary

        return _exploration_summary(
            {'world_explorations': [{'name': f'A{i}', 'exploration_percentage': v} for i, v in enumerate(raw_values)]}
        )

    def test_raw_1000_is_100_percent(self):
        out = self._summary([1000])
        self.assertEqual(out['areas'][0]['explored_percent'], 100.0)
        self.assertTrue(out['areas'][0]['complete'])

    def test_raw_540_is_54_percent(self):
        """A measured value: raw 540 must read 54.0%, not 5.4%."""
        out = self._summary([540])
        self.assertEqual(out['areas'][0]['explored_percent'], 54.0)

    def test_raw_0_is_zero(self):
        out = self._summary([0])
        self.assertEqual(out['areas'][0]['explored_percent'], 0.0)
        self.assertFalse(out['areas'][0]['complete'])

    def test_over_100_percent_preserved(self):
        """Some regions report above 100 with sub-areas; do not clamp."""
        out = self._summary([1050])
        self.assertEqual(out['areas'][0]['explored_percent'], 105.0)
        self.assertTrue(out['areas'][0]['complete'])

    def test_incomplete_list_sorted_and_filtered(self):
        out = self._summary([1000, 540, 0, 1000, 990])
        pcts = [a['explored_percent'] for a in out['incomplete']]
        self.assertEqual(pcts, [0.0, 54.0, 99.0])
        self.assertEqual(out['complete_count'], 2)
        self.assertEqual(out['total_areas'], 5)

    def test_missing_percentage_not_counted_incomplete(self):
        from hoyolab_mcp.tools import _exploration_summary

        out = _exploration_summary({'world_explorations': [{'name': 'X'}]})
        self.assertIsNone(out['areas'][0]['explored_percent'])
        self.assertFalse(out['areas'][0]['complete'])
        self.assertEqual(out['incomplete'], [])


class StatsCompletenessTests(unittest.TestCase):
    """The `stats` payload has 23 counters; all must be surfaced.

    Hand-picking nine of them caused Imaginarium Theater and Stygian Onslaught to be
    reported as "not available from the API" when they were present all along, as
    `role_combat` and `hard_challenge`.
    """

    LIVE_STATS = {
        'achievement_number': 1335,
        'active_day_number': 619,
        'anemoculus_number': 66,
        'avatar_number': 70,
        'common_chest_number': 3170,
        'dendroculus_number': 271,
        'domain_number': 74,
        'electroculus_number': 181,
        'exquisite_chest_number': 2781,
        'full_fetter_avatar_num': 16,
        'geoculus_number': 131,
        'hard_challenge': {
            'difficulty': 3,
            'name': 'Example Record',
            'has_data': True,
            'is_unlock': True,
        },
        'hydroculus_number': 270,
        'iceculus_number': 139,
        'luxurious_chest_number': 336,
        'magic_chest_number': 392,
        'moonoculus_number': 271,
        'precious_chest_number': 853,
        'pyroculus_number': 271,
        'role_combat': {
            'is_unlock': True,
            'max_round_id': 10,
            'has_data': True,
            'difficulty_id': 4,
            'tarot_finished_cnt': 0,
        },
        'spiral_abyss': '12-3',
        'way_point_number': 840,
    }

    def setUp(self):
        from hoyolab_mcp.tools import _format_stats_block

        self.out = _format_stats_block(self.LIVE_STATS)

    def test_imaginarium_theater_is_present(self):
        """Reported as missing from the API; it lives in `role_combat`."""
        theater = self.out['imaginarium_theater']
        self.assertEqual(theater['highest_act'], 10)
        self.assertEqual(theater['difficulty_id'], 4)
        self.assertTrue(theater['unlocked'])
        self.assertTrue(theater['has_data'])

    def test_stygian_onslaught_is_present(self):
        """Reported as missing; it lives in `hard_challenge`."""
        stygian = self.out['stygian_onslaught']
        self.assertEqual(stygian['best_record'], 'Example Record')
        self.assertEqual(stygian['difficulty'], 3)
        self.assertTrue(stygian['unlocked'])

    def test_all_oculi_present(self):
        for key, expected in {
            'anemoculus': 66,
            'geoculus': 131,
            'electroculus': 181,
            'dendroculus': 271,
            'hydroculus': 270,
            'pyroculus': 271,
            'cryoculus': 139,
            'lunoculus': 271,
        }.items():
            with self.subTest(key):
                self.assertEqual(self.out[key], expected)

    def test_all_chest_tiers_present(self):
        self.assertEqual(self.out['luxurious_chests'], 336)
        self.assertEqual(self.out['precious_chests'], 853)
        self.assertEqual(self.out['exquisite_chests'], 2781)
        self.assertEqual(self.out['common_chests'], 3170)
        self.assertEqual(self.out['remarkable_chests'], 392)

    def test_no_live_field_dropped(self):
        """Every numeric counter in the payload must appear in the output."""
        mapped_values = set()
        for v in self.out.values():
            if isinstance(v, dict):
                mapped_values.update(x for x in v.values() if not isinstance(x, (dict, list)))
            elif not isinstance(v, list):
                mapped_values.add(v)
        for field, value in self.LIVE_STATS.items():
            if isinstance(value, (dict, str)):
                continue
            with self.subTest(field=field):
                self.assertIn(value, mapped_values, f'{field} ({value}) was dropped')

    def test_missing_nested_objects_do_not_crash(self):
        from hoyolab_mcp.tools import _format_stats_block

        out = _format_stats_block({})
        self.assertIsNone(out['imaginarium_theater']['highest_act'])
        self.assertIsNone(out['stygian_onslaught']['best_record'])
        self.assertIsNone(out['anemoculus'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
