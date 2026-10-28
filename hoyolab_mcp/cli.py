"""Command-line administration for accounts and API tokens.

WHY A CLI AND NOT AN HTTP ENDPOINT
Issuing a token is the one operation that must not be reachable over the network: it
converts a user id into a credential. Exposing it as an HTTP route would mean anyone
who could reach the port could mint access for any user, which is exactly the property
the rest of this server works to avoid. So it is a local command that opens the
database directly, run by whoever already has filesystem access to it.

Run it inside the container (or on the host with the same `HOYOLAB_MCP_DB` and
`HOYOLAB_MCP_SECRET`):

    docker exec -it hoyolab-mcp python -m hoyolab_mcp.cli issue-token --user alice

TYPICAL SETUP FOR A COMMAND-LINE MCP CLIENT
Claude Code, Codex and opencode do not send Open WebUI's identity header, so they need
a token of their own. The sequence is:

    # 1. pick a user id for this client, and get a link page URL for it
    docker exec -it hoyolab-mcp python -m hoyolab_mcp.cli link-url --user alice

    # 2. open that URL in a browser and paste the HoYoLAB cookies

    # 3. mint a token and paste it into the client's config
    docker exec -it hoyolab-mcp python -m hoyolab_mcp.cli issue-token --user alice

A user id is just a name; it does not have to be an Open WebUI user id. Two clients
sharing one user id share one HoYoLAB link, which is usually what you want on a single
machine but is worth being deliberate about.
"""

from __future__ import annotations

import argparse
import os
import sys

from .store import ApiTokenStore, CredentialError, encode_link_token


def _store() -> ApiTokenStore:
    secret = os.environ.get('HOYOLAB_MCP_SECRET', '')
    db = os.environ.get('HOYOLAB_MCP_DB', '/data/hoyolab.db')
    return ApiTokenStore(db, secret)


def _require_user(args) -> str:
    user = (getattr(args, 'user', '') or '').strip()
    if not user:
        print('error: --user is required (any stable name, e.g. "alice")', file=sys.stderr)
        raise SystemExit(2)
    return user


def cmd_issue_token(args) -> int:
    user = _require_user(args)
    token = _store().issue_token(user, args.label or '')
    print(token)
    print('', file=sys.stderr)
    print(
        'Store this now -- it is not recoverable, only revocable. Use it as:\n'
        '  Authorization: Bearer <token>',
        file=sys.stderr,
    )
    if not args.quiet:
        print(f'\nuser id: {user}', file=sys.stderr)
    return 0


def cmd_list_tokens(args) -> int:
    user = _require_user(args)
    tokens = _store().list_tokens(user)
    if not tokens:
        print(f'no tokens for user {user}')
        return 0
    print(f'tokens for user {user}:')
    for t in tokens:
        used = 'never' if t['last_used'] is None else t['last_used']
        print(f"  {t['id']}  label={t['label'] or '-'}  created={t['created_at']}  last_used={used}")
    return 0


def cmd_revoke_token(args) -> int:
    user = _require_user(args)
    if _store().revoke_token(user, args.id):
        print(f'revoked {args.id}')
        return 0
    print(f'error: no token with id {args.id} for user {user}', file=sys.stderr)
    return 1


def cmd_revoke_all(args) -> int:
    user = _require_user(args)
    count = _store().revoke_all_tokens(user)
    print(f'revoked {count} token(s) for user {user}')
    return 0


def cmd_link_url(args) -> int:
    user = _require_user(args)
    secret = os.environ.get('HOYOLAB_MCP_SECRET', '')
    if not secret or len(secret) < 16:
        print('error: HOYOLAB_MCP_SECRET must be set (at least 16 chars)', file=sys.stderr)
        return 2
    base = (os.environ.get('HOYOLAB_MCP_PUBLIC_URL', '') or '').rstrip('/')
    if not base:
        print(
            'error: HOYOLAB_MCP_PUBLIC_URL must be set to the URL your BROWSER can reach',
            file=sys.stderr,
        )
        return 2
    print(f'{base}/link?token={encode_link_token(user, secret)}')
    print('\nOpen this in a browser within 15 minutes and paste your HoYoLAB cookies.', file=sys.stderr)
    return 0


def cmd_status(args) -> int:
    user = _require_user(args)
    store = _store()
    try:
        status = store.status(user)
    except CredentialError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    if not status.get('linked'):
        print(f'user {user}: no HoYoLAB account linked')
        print(f'  link it with: python -m hoyolab_mcp.cli link-url --user {user}', file=sys.stderr)
    else:
        print(f"user {user}: linked (cookies: {', '.join(status.get('names') or [])})")
    tokens = store.list_tokens(user)
    print(f'  tokens: {len(tokens)}')
    return 0


def cmd_unlink(args) -> int:
    """Delete a user's stored cookies.

    This is the counterpart to `link-url` and exists for a specific reason: the server
    stores a login credential, so there has to be a way to take it back. Without this,
    the only ways to remove a cookie were to delete the whole database or rotate
    HOYOLAB_MCP_SECRET, which would log out every other user too.

    Tokens are revoked as well unless `--keep-tokens` is given, because a token pointing
    at a user with no cookies can only ever produce a "not linked" error.
    """
    user = _require_user(args)
    store = _store()
    removed = store.delete(user)
    if not removed:
        print(f'user {user}: nothing to unlink (no stored credential)')
    else:
        print(f'user {user}: credential deleted')

    if not args.keep_tokens:
        count = store.revoke_all_tokens(user)
        if count:
            print(f'user {user}: revoked {count} token(s)')

    print(
        '\nThe cookies are gone from this database. To invalidate them at the source as '
        'well, log out of HoYoLAB in the browser that produced them.',
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='python -m hoyolab_mcp.cli',
        description='Manage HoYoLAB MCP accounts and API tokens (local, no network).',
    )
    sub = p.add_subparsers(dest='command', required=True)

    s = sub.add_parser('issue-token', help='mint a token for a user id')
    s.add_argument('--user', required=True, help='stable user id, e.g. "alice"')
    s.add_argument('--label', default='', help='free-form note, e.g. "claude-code on laptop"')
    s.add_argument('--quiet', action='store_true', help='print only the token')
    s.set_defaults(func=cmd_issue_token)

    s = sub.add_parser('list-tokens', help='list token metadata for a user (never values)')
    s.add_argument('--user', required=True)
    s.set_defaults(func=cmd_list_tokens)

    s = sub.add_parser('revoke-token', help='revoke one token by its short id')
    s.add_argument('--user', required=True)
    s.add_argument('--id', required=True, help='short id shown by list-tokens')
    s.set_defaults(func=cmd_revoke_token)

    s = sub.add_parser('revoke-all', help='revoke every token for a user')
    s.add_argument('--user', required=True)
    s.set_defaults(func=cmd_revoke_all)

    s = sub.add_parser('link-url', help='print a 15-minute account-link URL for a user')
    s.add_argument('--user', required=True)
    s.set_defaults(func=cmd_link_url)

    s = sub.add_parser('status', help='show link state and token count for a user')
    s.add_argument('--user', required=True)
    s.set_defaults(func=cmd_status)

    s = sub.add_parser('unlink', help="delete a user's stored HoYoLAB cookies")
    s.add_argument('--user', required=True)
    s.add_argument(
        '--keep-tokens',
        action='store_true',
        help='leave API tokens in place (they will only report "not linked")',
    )
    s.set_defaults(func=cmd_unlink)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CredentialError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    except RuntimeError as exc:
        # Raised by the store when HOYOLAB_MCP_SECRET is missing or too short.
        print(f'error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
