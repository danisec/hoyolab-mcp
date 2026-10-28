#!/usr/bin/env python3
"""End-to-end verification of the HoYoLAB MCP server.

Runs against a live server and checks the properties that matter, in the order a real
failure would show up:

  1. the server is up and speaks MCP
  2. all expected tools are advertised
  3. a call with no identity fails closed with an actionable message
  4. a call with a signed identity resolves to a user and asks them to link
  5. an unlinked user never sees another user's data
  6. the link page accepts a good credential and rejects a bad one
  7. the stored credential is encrypted at rest and absent from the log

Usage:
    python3 verify_e2e.py [--url http://127.0.0.1:8899] [--jwt-secret SECRET] [--db PATH]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import urllib.request

import jwt
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

EXPECTED_TOOLS = {
    'hoyolab_link_status',
    'list_game_accounts',
    'get_genshin_overview',
    'get_characters',
    'get_spiral_abyss',
    'get_exploration',
}

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = '') -> None:
    results.append((ok, name, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f'  ({detail})' if detail else ''))


def make_identity(user_id: str, secret: str) -> dict:
    now = int(time.time())
    token = jwt.encode(
        {
            'sub': user_id,
            'email': 'test@example.invalid',
            'name': 'test',
            'role': 'user',
            'iss': 'open-webui',
            'iat': now,
            'exp': now + 300,
        },
        secret,
        algorithm='HS256',
    )
    return {'X-OpenWebUI-User-Jwt': token}


async def call_tool(url: str, headers: dict | None, tool: str, args: dict) -> str:
    async with streamablehttp_client(url, headers=headers) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(tool, args)
            parts = []
            for c in res.content:
                text = getattr(c, 'text', None)
                if text:
                    parts.append(text)
            return '\n'.join(parts)


async def list_tools(url: str) -> list[str]:
    async with streamablehttp_client(url) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.list_tools()
            return [t.name for t in res.tools]


def http_get(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.read().decode()
    except Exception as exc:
        return 0, str(exc)


def http_post(url: str, form: dict) -> tuple[int, str]:
    import urllib.parse

    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except Exception as exc:
        return 0, str(exc)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default='http://127.0.0.1:8899')
    ap.add_argument('--jwt-secret', default=os.environ.get('FORWARD_USER_INFO_HEADER_JWT_SECRET', ''))
    ap.add_argument('--db', default='')
    ap.add_argument('--log', default='')
    args = ap.parse_args()

    base = args.url.rstrip('/')
    mcp_url = f'{base}/mcp'

    print('=== 1. server health ===')
    status, body = http_get(f'{base}/health')
    check(status == 200 and '"ok"' in body, 'health endpoint responds', f'HTTP {status}')

    print('\n=== 2. MCP tool discovery ===')
    try:
        tools = await list_tools(mcp_url)
        missing = EXPECTED_TOOLS - set(tools)
        check(not missing, 'all expected tools advertised', f'{len(tools)} tools' if not missing else f'missing {missing}')
    except Exception as exc:
        check(False, 'MCP handshake', f'{type(exc).__name__}: {exc}')
        tools = []

    print('\n=== 3. fails closed without identity ===')
    out = await call_tool(mcp_url, None, 'hoyolab_link_status', {})
    check('not forwarding user identity' in out or 'No user identity' in out,
          'no-identity call is refused', out[:90].replace('\n', ' '))

    if not args.jwt_secret:
        print('\n  (skipping identity tests: pass --jwt-secret)')
        return summarise()

    print('\n=== 4. signed identity resolves ===')
    user = 'verify-user-1'
    out = await call_tool(mcp_url, make_identity(user, args.jwt_secret), 'hoyolab_link_status', {})
    try:
        payload = json.loads(out)
        check(payload.get('linked') is False, 'unlinked user reported as not linked')
        check('ltoken' not in out.lower(), 'link status leaks no cookie value')
    except Exception:
        check(False, 'link status is valid JSON', out[:120].replace('\n', ' '))

    out = await call_tool(mcp_url, make_identity(user, args.jwt_secret), 'get_genshin_overview', {})
    check('/link?token=' in out, 'unlinked call returns a link URL')

    print('\n=== 5. users are isolated ===')
    out2 = await call_tool(mcp_url, make_identity('verify-user-2', args.jwt_secret), 'hoyolab_link_status', {})
    check('"linked": false' in out2.replace('\n', ''), 'second user is also unlinked')

    print('\n=== 6. link page ===')
    # Mint a token the same way the server does.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from hoyolab_mcp.store import encode_link_token

    secret = os.environ.get('HOYOLAB_MCP_SECRET', '')
    if not secret:
        print('  (skipping link tests: HOYOLAB_MCP_SECRET not set in this shell)')
        return summarise()

    token = encode_link_token(user, secret)
    status, page = http_get(f'{base}/link?token={token}')
    check(status == 200 and 'Link your HoYoLAB account' in page, 'link form renders')

    status, page = http_post(f'{base}/link', {'token': token, 'cookies': '_ga=GA1.2; locale=en'})
    check('No recognised HoYoLAB auth cookies' in page, 'bad credential rejected')

    good = 'ltuid_v2=123456789; ltoken_v2=v2_verify_secret_token; ltmid_v2=abc123'
    status, page = http_post(f'{base}/link', {'token': token, 'cookies': good})
    check('Account linked' in page, 'good credential accepted')

    out = await call_tool(mcp_url, make_identity(user, args.jwt_secret), 'hoyolab_link_status', {})
    check('"linked": true' in out.replace('\n', ''), 'status now reports linked')
    check('v2_verify_secret_token' not in out, 'status does not echo the token')

    out = await call_tool(mcp_url, make_identity(user, args.jwt_secret), 'get_genshin_overview', {})
    check('retcode 10001' in out or 'retcode' in out,
          'bogus cookie produces an auth error, not a crash', out[:80].replace('\n', ' '))

    print('\n=== 7. credential at rest and in logs ===')
    if args.db and os.path.exists(args.db):
        with open(args.db, 'rb') as f:
            blob = f.read()
        wal = args.db + '-wal'
        if os.path.exists(wal):
            with open(wal, 'rb') as f:
                blob += f.read()
        check(b'v2_verify_secret_token' not in blob, 'no plaintext token in the database')
    if args.log and os.path.exists(args.log):
        with open(args.log, 'r', errors='replace') as f:
            log = f.read()
        check('v2_verify_secret_token' not in log, 'no plaintext token in the log')

    print('\n=== 8. API tokens (command-line clients) ===')
    # The store is opened directly, the same way `python -m hoyolab_mcp.cli` does, so
    # this exercises the real mint path rather than a mock.
    db_path = args.db or os.environ.get('HOYOLAB_MCP_DB', '/data/hoyolab.db')
    try:
        from hoyolab_mcp.store import ApiTokenStore

        token_store = ApiTokenStore(db_path, secret)
        api_token = token_store.issue_token('verify-cli-user', 'e2e')
        check(api_token.startswith('hlt_'), 'token minted with expected prefix')

        bearer = {'Authorization': f'Bearer {api_token}'}
        out = await call_tool(mcp_url, bearer, 'hoyolab_link_status', {})
        try:
            payload = json.loads(out)
            check(payload.get('linked') is False, 'bearer token identifies an unlinked user')
            check('error' not in payload, 'bearer token is accepted as identity')
        except Exception:
            check(False, 'bearer link status is valid JSON', out[:120].replace('\n', ' '))

        out = await call_tool(mcp_url, bearer, 'get_genshin_overview', {})
        check('/link?token=' in out, 'bearer user without cookies gets a link URL')

        # A bogus token must be refused outright, not silently downgraded.
        bad = {'Authorization': 'Bearer hlt_not_a_real_token', 'X-OpenWebUI-User-Id': user}
        out = await call_tool(mcp_url, bad, 'hoyolab_link_status', {})
        check('not valid' in out, 'invalid token is refused even with a spoofed plain header')
        check('"linked": true' not in out.replace('\n', ''), 'spoofed header grants nothing')

        # Revocation must take effect immediately.
        token_id = token_store.list_tokens('verify-cli-user')[0]['id']
        token_store.revoke_token('verify-cli-user', token_id)
        out = await call_tool(mcp_url, bearer, 'hoyolab_link_status', {})
        check('not valid' in out, 'revoked token stops working immediately')

        check(api_token not in str(token_store.list_tokens('verify-cli-user')), 'listing never returns a token value')
    except Exception as exc:
        check(False, 'API token flow', f'{type(exc).__name__}: {exc}')

    print('\n=== 9. unsigned header refused when a JWT secret is configured ===')
    if args.jwt_secret:
        spoof = {'X-OpenWebUI-User-Id': 'verify-user-1'}
        out = await call_tool(mcp_url, spoof, 'hoyolab_link_status', {})
        check('ignored' in out, 'plain header is ignored while a signing secret exists')
        check('"linked": true' not in out.replace('\n', ''), 'unsigned header grants no access')

    return summarise()


def summarise() -> int:
    passed = sum(1 for ok, _, _ in results if ok)
    total = len(results)
    print(f'\n{"=" * 46}\n{passed}/{total} checks passed')
    if passed != total:
        print('FAILED:')
        for ok, name, detail in results:
            if not ok:
                print(f'  - {name}: {detail}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
