"""Per-user credential storage for HoYoLAB cookies.

WHY THIS MODULE EXISTS
The Battle Chronicle API does not use OAuth. It authenticates with session cookies
(`ltuid_v2` / `ltoken_v2` / `ltmid_v2`, and the older `ltuid` / `ltoken` pair), which
are equivalent to a logged-in session. Two consequences drive the design here:

  1. A cookie must never be shared between users. If one admin cookie were baked into
     the server, every user granted access to the tools would be reading that one
     person's Genshin account. So credentials are stored per Open WebUI user id and
     are only ever used for a request made by that same user.

  2. A cookie must never be logged. `redact()` is applied to anything that might be
     echoed into a log line or an error message.

Storage is SQLite with AES-GCM encryption at rest, keyed by a secret supplied through
the environment. If that key is absent the server refuses to start rather than falling
back to plaintext: silently storing a login credential unencrypted is worse than being
unavailable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Cookie names that carry authentication. Order matters only for display; the whole
# set is sent so that whichever pair the account actually uses is present.
AUTH_COOKIE_KEYS = (
    'ltuid_v2',
    'ltoken_v2',
    'ltmid_v2',
    'ltuid',
    'ltoken',
    'ltmid',
    'cookie_token_v2',
    'cookie_token',
    'account_id_v2',
    'account_mid_v2',
    'account_id',
    'account_mid',
)

# A minimal viable credential. Different accounts and endpoints accept different
# pairs, so this is a floor, not an exact requirement: any one of these combinations
# is enough to attempt a request, and the API's own retcode tells us if it is not.
_MINIMUM_SETS = (
    {'ltoken_v2', 'ltuid_v2'},
    {'ltoken_v2'},
    {'ltoken', 'ltuid'},
    {'cookie_token_v2', 'account_id_v2'},
    {'cookie_token', 'account_id'},
)

# Retcodes that mean "the credential is gone", as opposed to "the data is private"
# or "that UID does not exist". Distinguishing these is what makes the error message
# actionable instead of just "something failed".
AUTH_RETCODES = {
    10001: 'not logged in',
    -100: 'not logged in',
    1008: 'invalid or expired credential',
    10101: 'credential expired or account mismatch',
}


class CredentialError(Exception):
    """Raised when a stored or supplied credential is unusable."""


def redact(value: str) -> str:
    """Return a value safe to log: keeps a short prefix, drops the rest."""
    if not value:
        return ''
    text = str(value)
    if len(text) <= 8:
        return '***'
    return f'{text[:4]}***{text[-2:]}'


def parse_cookie_string(raw: str) -> dict[str, str]:
    """Parse a `k=v; k=v` cookie header into a dict.

    Tolerates the extra whitespace and trailing semicolons that come from copying
    out of browser devtools, which is how these will realistically be supplied.
    """
    out: dict[str, str] = {}
    for part in (raw or '').split(';'):
        part = part.strip()
        if not part or '=' not in part:
            continue
        name, _, value = part.partition('=')
        name = name.strip()
        value = value.strip()
        if name and value:
            out[name] = value
    return out


def validate_cookies(cookies: dict[str, str]) -> dict[str, str]:
    """Keep only auth cookies and confirm the set could plausibly work.

    Returning the filtered dict rather than the raw one means an accidental paste of
    unrelated cookies (analytics, locale, etc.) does not get persisted.
    """
    kept = {k: v for k, v in cookies.items() if k in AUTH_COOKIE_KEYS}
    if not kept:
        raise CredentialError(
            'No recognised HoYoLAB auth cookies found. Expected at least '
            'ltuid_v2 and ltoken_v2 (or the older ltuid/ltoken).'
        )
    present = set(kept)
    if not any(present >= required for required in _MINIMUM_SETS):
        raise CredentialError(
            'Incomplete credential: need ltoken_v2 together with ltuid_v2 '
            '(or the legacy ltoken/ltuid pair).'
        )
    return kept


class CredentialStore:
    """Encrypted, per-user cookie storage.

    The encryption key is derived from `HOYOLAB_MCP_SECRET`. Changing that secret
    makes previously stored cookies unreadable, which is the intended behaviour for a
    rotation: users re-link rather than silently continuing with a stale key.
    """

    def __init__(self, db_path: str, secret: str):
        if not secret or len(secret) < 16:
            raise RuntimeError(
                'HOYOLAB_MCP_SECRET must be set to at least 16 characters. '
                'Refusing to start: storing login cookies without encryption is unsafe.'
            )
        self._aead = AESGCM(hashlib.sha256(secret.encode()).digest())
        self._db_path = db_path
        self._lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(db_path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA foreign_keys=ON')
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS credentials (
                    user_id    TEXT PRIMARY KEY,
                    nonce      BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )

    def _encrypt(self, user_id: str, payload: dict) -> tuple[bytes, bytes]:
        # The user id is bound as associated data so a ciphertext copied onto another
        # user's row fails to decrypt instead of handing one user another's account.
        nonce = os.urandom(12)
        data = json.dumps(payload, separators=(',', ':')).encode()
        return nonce, self._aead.encrypt(nonce, data, user_id.encode())

    def _decrypt(self, user_id: str, nonce: bytes, ciphertext: bytes) -> dict:
        data = self._aead.decrypt(nonce, ciphertext, user_id.encode())
        return json.loads(data)

    def save(self, user_id: str, cookies: dict[str, str]) -> None:
        """Store cookies for one user, replacing any previous credential."""
        if not user_id:
            raise CredentialError('A user id is required to store credentials.')
        clean = validate_cookies(cookies)
        payload = {'cookies': clean, 'saved_at': int(time.time())}
        nonce, ciphertext = self._encrypt(user_id, payload)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO credentials (user_id, nonce, ciphertext, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    nonce=excluded.nonce,
                    ciphertext=excluded.ciphertext,
                    updated_at=excluded.updated_at
                """,
                (user_id, nonce, ciphertext, int(time.time())),
            )

    def load(self, user_id: str) -> Optional[dict[str, str]]:
        """Return the stored cookie dict for a user, or None if not linked."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                'SELECT nonce, ciphertext FROM credentials WHERE user_id = ?', (user_id,)
            ).fetchone()
        if not row:
            return None
        try:
            return self._decrypt(user_id, row[0], row[1])['cookies']
        except Exception as exc:
            raise CredentialError(
                'Stored credential could not be decrypted. It may have been encrypted '
                'with a different HOYOLAB_MCP_SECRET. Re-link your HoYoLAB account.'
            ) from exc

    def status(self, user_id: str) -> dict:
        """Describe a user's link state without revealing any cookie value."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                'SELECT updated_at FROM credentials WHERE user_id = ?', (user_id,)
            ).fetchone()
        if not row:
            return {'linked': False}
        return {
            'linked': True,
            'updated_at': int(row[0]),
            'names': sorted(self.load(user_id) or {}),
        }

    def delete(self, user_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute('DELETE FROM credentials WHERE user_id = ?', (user_id,))
            return cur.rowcount > 0


# Prefix makes a leaked token recognisable in a log or a paste, the same way `ghp_`
# does for GitHub. It is not a security boundary, only a hint to whoever finds it.
API_TOKEN_PREFIX = 'hlt_'

# Stored as SHA-256 rather than the raw value: a token grants access to an account's
# Battle Chronicle, so a database dump should not hand out working credentials. No
# salt is needed because these are 256-bit random values, not guessable passwords --
# a precomputation attack on a 2^256 space is not a thing.
_TOKEN_HASH_PREFIX = 'sha256:'


def hash_api_token(token: str) -> str:
    return _TOKEN_HASH_PREFIX + hashlib.sha256(token.encode()).hexdigest()


class ApiTokenStore(CredentialStore):
    """Extends the credential store with long-lived tokens for non-Open-WebUI clients.

    WHY THIS EXISTS
    Open WebUI forwards a signed identity header on every tool call, so a browser user
    is identified without any credential of their own. A command-line MCP client
    (Claude Code, Codex, opencode) has no such header and cannot be made to send one
    legitimately. Rather than trust a header the client could invent, such clients get
    a real token that maps to exactly one user id.

    Tokens are stored per user, so the per-user isolation guarantee is unchanged: a
    token resolves to one user id, and that user id's own cookies are the only ones
    ever used.
    """

    def _init_db(self) -> None:
        super()._init_db()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS api_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id    TEXT NOT NULL,
                    label      TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL,
                    last_used  INTEGER
                )
                """
            )
            conn.execute('CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)')

    def issue_token(self, user_id: str, label: str = '') -> str:
        """Mint a token for `user_id` and return it. The raw value is not stored."""
        if not user_id:
            raise CredentialError('A user id is required to issue a token.')
        token = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
        with self._lock, self._connect() as conn:
            conn.execute(
                'INSERT INTO api_tokens (token_hash, user_id, label, created_at) VALUES (?, ?, ?, ?)',
                (hash_api_token(token), user_id, label or '', int(time.time())),
            )
        return token

    def resolve_token(self, token: str) -> Optional[str]:
        """Return the user id a token belongs to, or None if it is unknown."""
        if not token or not token.startswith(API_TOKEN_PREFIX):
            return None
        digest = hash_api_token(token)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                'SELECT user_id FROM api_tokens WHERE token_hash = ?', (digest,)
            ).fetchone()
            if not row:
                return None
            conn.execute('UPDATE api_tokens SET last_used = ? WHERE token_hash = ?', (int(time.time()), digest))
        return str(row[0])

    def list_tokens(self, user_id: str) -> list[dict]:
        """Token metadata for a user. Never includes a token value, which is not stored."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                'SELECT token_hash, label, created_at, last_used FROM api_tokens WHERE user_id = ? '
                'ORDER BY created_at DESC',
                (user_id,),
            ).fetchall()
        return [
            {
                # A short digest prefix is enough to tell two tokens apart when revoking
                # one, and cannot be turned back into a usable token.
                'id': str(r[0])[len(_TOKEN_HASH_PREFIX) :][:12],
                'label': r[1],
                'created_at': int(r[2]),
                'last_used': int(r[3]) if r[3] is not None else None,
            }
            for r in rows
        ]

    def revoke_token(self, user_id: str, token_id: str) -> bool:
        """Revoke one token by its short id, scoped to `user_id` so ids are not a capability."""
        if not token_id:
            return False
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                'SELECT token_hash FROM api_tokens WHERE user_id = ?', (user_id,)
            ).fetchall()
            for (digest,) in rows:
                if str(digest)[len(_TOKEN_HASH_PREFIX) :].startswith(token_id):
                    conn.execute('DELETE FROM api_tokens WHERE token_hash = ?', (digest,))
                    return True
        return False

    def revoke_all_tokens(self, user_id: str) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute('DELETE FROM api_tokens WHERE user_id = ?', (user_id,))
            return cur.rowcount


def encode_link_token(user_id: str, secret: str) -> str:
    """Build a short-lived token that the link page can carry in a URL.

    The link page needs to know which Open WebUI user is linking, but the only thing
    Open WebUI sends on MCP tool calls is a header. Putting a raw user id in a URL
    would let anyone link cookies to anyone else, so the id is signed and time-boxed.

    Base64 padding (`=`) is stripped deliberately. A trailing `=` in a URL query
    string is fragile: it is commonly lost when a URL is copied out of a chat message
    (and some renderers/encoders turn it into `%3D`), which produced a confusing
    "Malformed link token" for a token that was actually intact. Emitting no padding
    at all removes the failure mode instead of tolerating it.
    """
    import hmac

    expiry = int(time.time()) + 900
    body = f'{user_id}:{expiry}'
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()[:32]
    return base64.urlsafe_b64encode(f'{body}:{sig}'.encode()).decode().rstrip('=')


def decode_link_token(token: str, secret: str) -> str:
    """Verify a link token and return the user id it was minted for.

    Tolerates a few real-world manglings rather than rejecting them: surrounding
    whitespace/newlines from copy-paste, a `token=` prefix, quotes, `%3D` escapes, and
    missing base64 padding. These all leave the signature check meaningful, so
    normalising them costs no security -- the HMAC still has to match.
    """
    import hmac

    raw = (token or '').strip().strip('"').strip("'")
    if raw.lower().startswith('token='):
        raw = raw[len('token=') :]
    raw = raw.replace('%3D', '=').replace(' ', '')
    # Re-add padding that may have been stripped, then decode.
    raw += '=' * (-len(raw) % 4)

    try:
        decoded = base64.urlsafe_b64decode(raw.encode()).decode()
        user_id, expiry, sig = decoded.rsplit(':', 2)
    except Exception as exc:
        raise CredentialError(
            'Malformed link token. Open the link again from the tool message rather '
            'than copying part of it.'
        ) from exc

    body = f'{user_id}:{expiry}'
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        raise CredentialError(
            'This link is not valid for your account. Open the link again from the '
            'tool message.'
        )
    if int(expiry) < time.time():
        raise CredentialError('This link has expired. Ask the tool for a new link.')
    return user_id
