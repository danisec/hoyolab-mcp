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


class DurationTests(unittest.TestCase):
    """`resin_recovery_time` is a STRING in SECONDS, and "0" means "nothing pending".

    Both were measured against live data. Resin 156/200 needs 44 more at one per 8
    minutes, which is 352 minutes; the API reported 21072, i.e. 351.2 minutes. Treating
    the value as minutes would have reported roughly 14 days instead of 6 hours, and
    comparing the raw string with a number raises in Python 3.
    """

    def test_seconds_are_read_as_seconds(self):
        from hoyolab_mcp.tools import _duration

        # 21072 s = 5h 51m; the same figure as minutes would be ~14.6 days.
        self.assertEqual(_duration('21072'), '5h 51m (21072 seconds)')
        self.assertEqual(_duration(21072), '5h 51m (21072 seconds)')

    def test_zero_means_nothing_pending_not_zero_seconds(self):
        from hoyolab_mcp.tools import _duration

        for value in ('0', 0, '', None):
            with self.subTest(value=value):
                self.assertIsNone(_duration(value), f'{value!r} must not render as a countdown')

    def test_junk_does_not_raise(self):
        from hoyolab_mcp.tools import _duration

        for value in ('n/a', [], {}, '12.5'):
            with self.subTest(value=value):
                self.assertIsNone(_duration(value), f'{value!r} is not a countdown')

    def test_float_is_truncated_not_rejected(self):
        """The API sends strings, but a float must not crash the tool.

        Truncation is acceptable here: a sub-second remainder on a resin timer is not
        information anyone acts on, and dropping the whole value would lose the answer.
        """
        from hoyolab_mcp.tools import _duration

        self.assertEqual(_duration(3.9), '3s (3 seconds)')

    def test_day_scale_keeps_days(self):
        from hoyolab_mcp.tools import _duration

        self.assertEqual(_duration(2 * 86400 + 3 * 3600), '2d 3h (183600 seconds)')


class DailyNoteShapeTests(unittest.TestCase):
    """Locks in how `dailyNote` is read. Each case is a way to report a wrong number."""

    LIVE = {
        'current_resin': 156,
        'max_resin': 200,
        'resin_recovery_time': '21072',
        'finished_task_num': 4,
        'total_task_num': 4,
        'is_extra_task_reward_received': True,
        'remain_resin_discount_num': 0,
        'resin_discount_num_limit': 3,
        'current_expedition_num': 0,
        'max_expedition_num': 5,
        'expeditions': [],
        'current_home_coin': 300,
        'max_home_coin': 300,
        'home_coin_recovery_time': '0',
        'transformer': {
            'obtained': True,
            'recovery_time': {'Day': 0, 'Hour': 0, 'Minute': 0, 'Second': 0, 'reached': True},
        },
        'daily_task': {'total_num': 4, 'finished_num': 4, 'is_extra_task_reward_received': True},
        'week_active_progress': {'progress_current': 3, 'progress_total': 5},
    }

    def test_live_payload_is_reported_verbatim(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary(self.LIVE)
        self.assertEqual(out['resin']['current'], 156)
        self.assertEqual(out['resin']['max'], 200)
        self.assertEqual(out['resin']['state'], 'recovering')
        self.assertEqual(out['resin']['full_at_seconds'], 21072)
        self.assertEqual(out['resin']['full_in'], '5h 51m (21072 seconds)')
        self.assertEqual(out['realm_currency']['state'], 'full')
        self.assertIsNone(out['realm_currency']['full_in'])
        self.assertEqual(out['expeditions']['current'], 0)
        self.assertEqual(out['expeditions']['entries'], [])
        self.assertEqual(out['daily_tasks']['finished'], 4)
        self.assertEqual(out['weekly_boss_discount']['remaining'], 0)
        self.assertTrue(out['parametric_transformer']['ready'])

    def test_full_resin_reports_full_not_a_countdown(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary({'current_resin': 200, 'max_resin': 200, 'resin_recovery_time': '0'})
        self.assertEqual(out['resin']['state'], 'full')
        self.assertIsNone(out['resin']['full_in'])
        self.assertEqual(out['resin']['full_at_seconds'], 0)

    def test_missing_max_resin_is_not_called_full(self):
        """A missing `max_resin` must not collapse into "full" -- that is a silent lie."""
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary({'current_resin': 40})
        self.assertNotEqual(out['resin']['state'], 'full')
        self.assertEqual(out['resin']['state'], 'unknown')
        self.assertEqual(out['resin']['current'], 40)

    def test_empty_payload_does_not_crash(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary({})
        self.assertIsNone(out['resin']['current'])
        self.assertIsNone(out['resin']['full_in'])
        self.assertEqual(out['expeditions']['entries'], [])

    def test_expedition_without_a_name_does_not_invent_one(self):
        """The payload has `avatar_side_icon` but no character name."""
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary(
            {
                'current_expedition_num': 1,
                'max_expedition_num': 5,
                'expeditions': [
                    {'status': 'Finished', 'remained_time': '0', 'avatar_side_icon': 'https://x/y.png'}
                ],
            }
        )
        entry = out['expeditions']['entries'][0]
        self.assertEqual(entry['status'], 'Finished')
        self.assertNotIn('character', entry)
        self.assertIsNone(entry['remaining'])

    def test_task_rewards_are_not_reported_as_named_rewards(self):
        """`task_rewards` entries carry only a status string, so they are not surfaced."""
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary(
            {'daily_task': {'task_rewards': [{'status': 'TaskRewardStatusUnfinished'}] * 4}}
        )
        self.assertNotIn('task_rewards', out['daily_tasks'])


class AttendanceShapeTests(unittest.TestCase):
    """The reward index is the trap here.

    Measured live: `total_sign_day` 28 with `is_sign` false, and 31 rewards that month.
    The next reward is `awards[28]`, not `awards[27]`; reading the latter reports
    yesterday's reward as today's.
    """

    INFO = {
        'total_sign_day': 28,
        'today': '2026-10-29',
        'is_sign': False,
        'first_bind': False,
        'is_sub': False,
        'month_last_day': False,
    }
    HOME = {
        'month': 10,
        'awards': [{'name': f'Reward {i}', 'cnt': i} for i in range(31)],
    }
    RESIGN = {
        'resign_cnt_daily': 0,
        'resign_cnt_monthly': 0,
        'resign_limit_daily': 1,
        'resign_limit_monthly': 3,
        'sign_cnt_missed': 0,
        'cost': 1,
    }

    def test_next_reward_is_indexed_by_days_already_signed(self):
        from hoyolab_mcp.tools import _attendance_summary

        out = _attendance_summary(self.INFO, self.HOME, self.RESIGN)
        self.assertFalse(out['signed_in_today'])
        self.assertEqual(out['days_signed_this_month'], 28)
        self.assertEqual(out['rewards_in_month'], 31)
        self.assertEqual(out['rewards_left_this_month'], 3)
        # awards[28], not awards[27]
        self.assertEqual(out['reward_if_claimed_now']['name'], 'Reward 28')
        self.assertIsNone(out['reward_claimed_today'])

    def test_after_signing_the_claimed_reward_is_the_previous_index(self):
        from hoyolab_mcp.tools import _attendance_summary

        info = dict(self.INFO, total_sign_day=29, is_sign=True)
        out = _attendance_summary(info, self.HOME, self.RESIGN)
        self.assertTrue(out['signed_in_today'])
        self.assertEqual(out['status'], 'signed in today')
        self.assertEqual(out['reward_claimed_today']['name'], 'Reward 28')
        self.assertIsNone(out['reward_if_claimed_now'])

    def test_make_up_allowance_is_passed_through(self):
        from hoyolab_mcp.tools import _attendance_summary

        out = _attendance_summary(self.INFO, self.HOME, self.RESIGN)
        self.assertEqual(out['make_up']['allowed_today'], 1)
        self.assertEqual(out['make_up']['allowed_this_month'], 3)
        self.assertEqual(out['make_up']['missed_days'], 0)

    def test_missing_award_list_does_not_index_out_of_range(self):
        from hoyolab_mcp.tools import _attendance_summary

        out = _attendance_summary(self.INFO, {}, {})
        self.assertIsNone(out['reward_if_claimed_now'])
        self.assertIsNone(out['rewards_in_month'])
        self.assertIsNone(out['rewards_left_this_month'])

    def test_signed_day_beyond_the_list_is_not_indexed(self):
        from hoyolab_mcp.tools import _attendance_summary

        out = _attendance_summary(dict(self.INFO, total_sign_day=99), self.HOME, self.RESIGN)
        self.assertIsNone(out['reward_if_claimed_now'])
        self.assertEqual(out['rewards_left_this_month'], 0)

    def test_empty_payload_does_not_crash(self):
        from hoyolab_mcp.tools import _attendance_summary

        out = _attendance_summary({}, {}, {})
        self.assertFalse(out['signed_in_today'], 'an absent is_sign is not a signature')
        self.assertEqual(out['status'], 'not signed in yet today')
        self.assertIsNone(out['days_signed_this_month'])
        self.assertIsNone(out['reward_if_claimed_now'])
        self.assertIsNone(out['reward_claimed_today'])


class DailyNoteRequestShapeTests(unittest.TestCase):
    """`dailyNote` needs `server`; omitting it fails with a validation complaint.

    Measured: without `server` the API answers retcode -1, "param server error: value
    length must be at least 1 runes", which does not hint that a parameter is missing.
    The check-in endpoints live on a different host than the record API, and using the
    public host with `/event/luna/*` answers "open this from inside the game" instead of
    a 404, which reads like a permission problem.
    """

    def _capture(self, call):
        import httpx
        from unittest import mock

        captured = {}

        class FakeResp:
            status_code = 200

            def json(self):
                return {'retcode': 0, 'data': {}}

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

        with mock.patch.object(httpx, 'Client', FakeClient):
            client = ChronicleClient({'ltuid_v2': '1', 'ltoken_v2': 'x'})
            call(client)
        return captured

    def test_daily_note_sends_role_id_and_server(self):
        c = self._capture(lambda cl: cl.daily_note('812345678'))
        self.assertEqual(c['method'], 'GET')
        self.assertIn('/dailyNote', c['url'])
        self.assertIn('sg-public-api.hoyolab.com', c['url'])
        self.assertEqual(c['params']['role_id'], '812345678')
        self.assertEqual(c['params']['server'], 'os_asia')

    def test_daily_note_server_comes_from_the_uid(self):
        c = self._capture(lambda cl: cl.daily_note('700000001'))
        self.assertEqual(c['params']['server'], 'os_euro')

    def test_attendance_uses_the_hk4e_host_and_sol_path(self):
        for method, path in (
            ('attendance_info', '/event/sol/info'),
            ('attendance_rewards', '/event/sol/home'),
            ('attendance_resign', '/event/sol/resign_info'),
        ):
            with self.subTest(method=method):
                c = self._capture(lambda cl, m=method: getattr(cl, m)())
                self.assertIn('sg-hk4e-api.hoyolab.com', c['url'], 'the Genshin check-in host')
                self.assertIn(path, c['url'])
                self.assertNotIn('luna', c['url'], 'luna is the Star Rail/ZZZ path')
                self.assertEqual(c['params']['act_id'], 'e202102251931481')

    def test_attendance_is_account_level_not_uid_scoped(self):
        c = self._capture(lambda cl: cl.attendance_info())
        self.assertNotIn('role_id', c['params'])
        self.assertNotIn('server', c['params'])


class ReadOnlyGuaranteeTests(unittest.TestCase):
    """The check-in endpoint has a POST that CLAIMS the reward. This server must not.

    Verified structurally rather than by intent: the tool body is inspected for the
    signing call, and the client is checked to expose no write path for check-in.
    """

    def test_no_check_in_tool_posts_a_sign_request(self):
        """Assert on the HTTP method actually issued, not on words in the source.

        An earlier version asserted `'post' not in source.lower()`, which failed for any
        word containing "post" ("postpone", "post-processing") and proved nothing about
        the request. This drives the client with a fake transport and inspects the method
        and URL of every call the tool makes.
        """
        import asyncio
        import httpx
        from unittest import mock

        from hoyolab_mcp import tools

        calls = []

        class FakeResp:
            status_code = 200

            def json(self):
                return {'retcode': 0, 'data': {'awards': [], 'month': 10}}

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def _record(self, method, url, params=None, **kw):
                calls.append((method, url, params or {}))
                return FakeResp()

            def get(self, url, params=None, headers=None, **kw):
                return self._record('GET', url, params)

            def post(self, url, params=None, json=None, headers=None, **kw):
                return self._record('POST', url, params)

        server = tools.build_server()
        tool = next(t for t in server._tool_manager.list_tools() if t.name == 'get_attendance')  # noqa: SLF001

        with mock.patch.object(httpx, 'Client', FakeClient), mock.patch.object(
            tools, '_client_for', lambda ctx: (tools.ChronicleClient({'ltuid_v2': '1', 'ltoken_v2': 'x'}), 'u')
        ):
            asyncio.run(tool.run({}, None))

        self.assertTrue(calls, 'the tool made no request at all')
        methods = {m for m, _, _ in calls}
        self.assertEqual(methods, {'GET'}, f'check-in tool must only GET, saw {methods}')
        for method, url, params in calls:
            self.assertNotIn('/sign', url, 'the claim endpoint must never be called')
            self.assertIn('/event/sol/', url)
            self.assertEqual(params.get('act_id'), 'e202102251931481')

    def test_client_has_no_attendance_sign_method(self):
        """A write method must not exist to be called by accident."""
        from hoyolab_mcp.client import ChronicleClient

        names = [n for n in dir(ChronicleClient) if not n.startswith('__')]
        self.assertIn('attendance_info', names)
        for forbidden in ('attendance_sign', 'sign', 'claim', 'attendance_claim'):
            self.assertNotIn(forbidden, names)

    def test_attendance_docstring_states_it_is_read_only(self):
        """The tool description tells the model it cannot claim. Prose, but load-bearing.

        A model reads this docstring as the tool description, so a docstring that promised
        a claim action would change behaviour even with read-only code behind it.
        """
        import inspect

        from hoyolab_mcp import tools

        source = inspect.getsource(tools.build_server)
        start = source.index('def get_attendance')
        # Bound the slice at the next tool so this cannot match a later function.
        end = source.find('return mcp', start)
        attendance = source[start:end if end != -1 else len(source)]
        self.assertIn('read-only', attendance.lower())
        self.assertIn('never claims', attendance.lower())


class ToolSignatureTests(unittest.TestCase):
    """Every tool must declare `ctx`, and none may be a write operation.

    A missing `ctx` parameter is invisible to unit tests that call the helpers directly
    -- it only fails at call time, as `name 'ctx' is not defined`, which a model sees as
    a broken tool. This test walks the real server's registered tools instead.
    """

    def _tools(self):
        from hoyolab_mcp.tools import build_server

        server = build_server()
        return server._tool_manager.list_tools()  # noqa: SLF001 - intentional introspection

    def test_every_tool_declares_a_context(self):
        import inspect

        for tool in self._tools():
            with self.subTest(tool=tool.name):
                params = inspect.signature(tool.fn).parameters
                self.assertIn('ctx', params, f'{tool.name} must take ctx: Context')
                annotation = str(params['ctx'].annotation)
                self.assertIn('Context', annotation, f'{tool.name} ctx must be a Context')

    def test_new_tools_are_registered(self):
        names = {t.name for t in self._tools()}
        self.assertIn('get_daily_note', names)
        self.assertIn('get_attendance', names)
        # The two new tools must not have displaced anything.
        self.assertEqual(len(names), 10, sorted(names))

    def test_attendance_takes_no_uid(self):
        """Check-in is account-level; offering a uid would imply per-character data."""
        import inspect

        for tool in self._tools():
            if tool.name == 'get_attendance':
                params = set(inspect.signature(tool.fn).parameters)
                self.assertNotIn('uid', params)
                return
        self.fail('get_attendance not registered')


class MalformedPayloadTests(unittest.TestCase):
    """Payloads the API can send that must degrade, not raise.

    Every case here crashed the tool before it was fixed. `client._check()` returns `data`
    as the API sent it, so a list, a null, or a string is reachable, and `tools.py` states
    its own contract: "Missing keys produce 'unavailable' markers instead of raising."
    """

    def test_daily_note_tolerates_non_dict_payload(self):
        from hoyolab_mcp.tools import _daily_note_summary

        for payload in ([], None, 'x', 0, [1, 2]):
            with self.subTest(payload=payload):
                out = _daily_note_summary(payload)
                self.assertIsNone(out['resin']['current'])
                self.assertEqual(out['expeditions']['entries'], [])

    def test_attendance_tolerates_non_dict_payloads(self):
        from hoyolab_mcp.tools import _attendance_summary

        cases = [
            ([], {}, {}),
            ({}, [], {}),
            ({}, {}, []),
            ({}, {}, None),
            (None, None, None),
        ]
        for info, home, resign in cases:
            with self.subTest(info=info, home=home, resign=resign):
                out = _attendance_summary(info, home, resign)
                self.assertIsNone(out['days_signed_this_month'])
                self.assertIn('rewards', out['partial'])

    def test_transformer_with_non_numeric_components_does_not_crash(self):
        """`_int_or_none(...) * 86400` raised TypeError on a non-numeric component."""
        from hoyolab_mcp.tools import _daily_note_summary

        for bad in ('abc', None, [], {}, ''):
            with self.subTest(component=bad):
                out = _daily_note_summary(
                    {
                        'current_resin': 100,
                        'max_resin': 200,
                        'resin_recovery_time': '48000',
                        'transformer': {
                            'obtained': True,
                            'recovery_time': {'Day': bad, 'Hour': bad, 'reached': False},
                        },
                    }
                )
                # The resin answer must survive a broken transformer field.
                self.assertEqual(out['resin']['current'], 100)
                self.assertEqual(out['resin']['state'], 'recovering')
                self.assertEqual(out['resin']['full_in'], '13h 20m (48000 seconds)')

    def test_transformer_recovery_time_not_a_dict(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary({'transformer': {'recovery_time': 'oops'}})
        self.assertIsNone(out['parametric_transformer']['ready'])
        self.assertIsNone(out['parametric_transformer']['remaining'])

    def test_partial_fields_are_named(self):
        from hoyolab_mcp.tools import _attendance_summary

        full = _attendance_summary(
            {'total_sign_day': 5, 'is_sign': False},
            {'month': 10, 'awards': [{'name': 'R', 'cnt': 1}] * 31},
            {'resign_limit_daily': 1},
        )
        self.assertEqual(full['partial'], [])

        degraded = _attendance_summary({'total_sign_day': 5, 'is_sign': False}, {}, {})
        self.assertIn('rewards', degraded['partial'])
        self.assertIn('make_up', degraded['partial'])


class ResinStateHonestyTests(unittest.TestCase):
    """`state: full` must never be claimed for a payload that has no resin figures.

    An earlier revision wrote `... or resin_seconds == 0`, which reported a full bar for
    `{'resin_recovery_time': '0'}` -- no `current_resin`, no `max_resin` -- while the
    comment directly above claimed that could not happen.
    """

    def test_zero_countdown_without_figures_is_unknown_not_full(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary({'resin_recovery_time': '0'})['resin']
        self.assertEqual(out['state'], 'unknown')
        self.assertIsNone(out['current'])
        self.assertIsNone(out['max'])

    def test_zero_max_is_not_a_full_bar(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary(
            {'current_resin': 0, 'max_resin': 0, 'resin_recovery_time': '0'}
        )['resin']
        self.assertNotEqual(out['state'], 'full')

    def test_genuinely_full_is_still_reported(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary(
            {'current_resin': 200, 'max_resin': 200, 'resin_recovery_time': '0'}
        )['resin']
        self.assertEqual(out['state'], 'full')
        self.assertIsNone(out['full_in'])

    def test_realm_currency_follows_the_same_rule(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary({'home_coin_recovery_time': '0'})['realm_currency']
        self.assertEqual(out['state'], 'unknown')

    def test_transformer_not_obtained_is_not_ready(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary(
            {'transformer': {'obtained': False, 'recovery_time': {'reached': True}}}
        )['parametric_transformer']
        self.assertFalse(out['ready'])


class RewardMonthTests(unittest.TestCase):
    """The reward list belongs to `home.month`; `info.today` is the current date.

    On the first day of a month the two disagree, and trusting the list reports last
    month's reward as today's.
    """

    HOME = {'month': 10, 'awards': [{'name': f'Okt-{i}', 'cnt': 1} for i in range(31)]}

    def test_same_month_reports_the_reward(self):
        from hoyolab_mcp.tools import _attendance_summary

        out = _attendance_summary(
            {'total_sign_day': 5, 'is_sign': False, 'today': '2026-10-06'}, self.HOME, {}
        )
        self.assertEqual(out['reward_if_claimed_now']['name'], 'Okt-5')
        self.assertNotIn('reward_month_mismatch', out['partial'])

    def test_new_month_with_stale_reward_list_reports_nothing(self):
        from hoyolab_mcp.tools import _attendance_summary

        out = _attendance_summary(
            {'total_sign_day': 1, 'is_sign': False, 'today': '2026-11-01'}, self.HOME, {}
        )
        self.assertIsNone(out['reward_if_claimed_now'], 'must not report last month')
        self.assertIsNone(out['rewards_in_month'])
        self.assertIn('reward_month_mismatch', out['partial'])

    def test_mismatch_also_suppresses_claimed_reward(self):
        from hoyolab_mcp.tools import _attendance_summary

        out = _attendance_summary(
            {'total_sign_day': 1, 'is_sign': True, 'today': '2026-11-01'}, self.HOME, {}
        )
        self.assertIsNone(out['reward_claimed_today'])
        self.assertIn('reward_month_mismatch', out['partial'])

    def test_unparseable_date_does_not_break_the_answer(self):
        from hoyolab_mcp.tools import _attendance_summary

        out = _attendance_summary({'total_sign_day': 5, 'today': 'bukan-tanggal'}, self.HOME, {})
        self.assertEqual(out['reward_if_claimed_now']['name'], 'Okt-5')


class FieldNamingTests(unittest.TestCase):
    """`attendance` must not name two different things.

    The API calls in-game weekly task points `attendance_rewards`, while `get_attendance`
    reports the HoYoLAB check-in. A live chat discussed both at once and the model had to
    build its own table to keep them apart.
    """

    def test_weekly_task_points_are_not_called_attendance(self):
        from hoyolab_mcp.tools import _daily_note_summary

        out = _daily_note_summary(
            {'daily_task': {'attendance_rewards': [{'status': 'X', 'progress': 2000}]}}
        )
        self.assertNotIn('attendance_progress', out['daily_tasks'])
        self.assertEqual(out['daily_tasks']['weekly_task_points'][0]['progress'], 2000)


class AttendanceDegradationTests(unittest.TestCase):
    """One failing supporting call must not discard the main answer."""

    def _run(self, info, home, resign):
        import asyncio
        from unittest import mock

        from hoyolab_mcp import tools

        class Stub:
            def attendance_info(self):
                if isinstance(info, Exception):
                    raise info
                return info

            def attendance_rewards(self):
                if isinstance(home, Exception):
                    raise home
                return home

            def attendance_resign(self):
                if isinstance(resign, Exception):
                    raise resign
                return resign

        server = tools.build_server()
        tool = next(t for t in server._tool_manager.list_tools() if t.name == 'get_attendance')  # noqa: SLF001
        with mock.patch.object(tools, '_client_for', lambda ctx: (Stub(), 'u')):
            return asyncio.run(tool.run({}, None))

    GOOD_INFO = {'total_sign_day': 29, 'is_sign': True, 'today': '2026-10-29'}
    GOOD_HOME = {'month': 10, 'awards': [{'name': 'Mora', 'cnt': 5000}] * 31}
    GOOD_RESIGN = {'resign_limit_daily': 1}

    def test_resign_failure_keeps_the_main_answer(self):
        from hoyolab_mcp.client import HoyolabError

        out = self._run(self.GOOD_INFO, self.GOOD_HOME, HoyolabError('resign mati'))
        self.assertTrue(out['signed_in_today'])
        self.assertEqual(out['days_signed_this_month'], 29)
        self.assertEqual(out['reward_claimed_today']['name'], 'Mora')
        self.assertIn('make_up', out['partial'])

    def test_home_failure_keeps_the_main_answer(self):
        from hoyolab_mcp.client import HoyolabError

        out = self._run(self.GOOD_INFO, HoyolabError('home mati'), self.GOOD_RESIGN)
        self.assertTrue(out['signed_in_today'])
        self.assertIsNone(out['reward_claimed_today'])
        self.assertIn('rewards', out['partial'])

    def test_info_failure_still_fails(self):
        """`info` is the only payload that answers the question, so it stays mandatory."""
        from hoyolab_mcp.client import HoyolabError

        with self.assertRaises(Exception) as ctx:
            self._run(HoyolabError('info mati'), self.GOOD_HOME, self.GOOD_RESIGN)
        self.assertIn('info mati', str(ctx.exception))

    def test_all_good_reports_nothing_partial(self):
        out = self._run(self.GOOD_INFO, self.GOOD_HOME, self.GOOD_RESIGN)
        self.assertEqual(out['partial'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
