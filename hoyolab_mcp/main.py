"""HTTP entrypoint for the HoYoLAB MCP server.

Exposes:
  /mcp    Streamable HTTP MCP transport (what every MCP client connects to)
  /link   A small HTML form where a user pastes their own HoYoLAB cookies
  /health Simple liveness probe

WHY A LINK PAGE AT ALL
The MCP tool calls only carry headers, not a browser session, so the cookie has to be
captured out-of-band. The link page is the capture point. It is deliberately minimal:
it accepts a cookie string, validates it, encrypts it against the user id from a signed
token, and returns nothing about the cookie it stored.

SECURITY NOTES
  * The page never echoes a cookie back, and logs only cookie *names*.
  * The user id comes from a signed, 15-minute token, so a link URL cannot be edited
    to attach a credential to somebody else's account.
  * Responses are marked no-store so the form value is not cached by a proxy.
"""

from __future__ import annotations

import html
import logging
import os

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from .store import (
    ApiTokenStore,
    CredentialError,
    decode_link_token,
    encode_link_token,
    parse_cookie_string,
    redact,
)
from .tools import build_server

log = logging.getLogger('hoyolab_mcp')
logging.basicConfig(level=os.environ.get('HOYOLAB_MCP_LOG_LEVEL', 'INFO'))


def _secret() -> str:
    return os.environ.get('HOYOLAB_MCP_SECRET', '')


def _store() -> ApiTokenStore:
    return ApiTokenStore(os.environ.get('HOYOLAB_MCP_DB', '/data/hoyolab.db'), _secret())


PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Link your HoYoLAB account</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font: 15px/1.5 system-ui, sans-serif; max-width: 44rem; margin: 2.5rem auto; padding: 0 1.25rem; }}
 h1 {{ font-size: 1.35rem; margin-bottom: .25rem; }}
 p.lead {{ opacity: .75; margin-top: 0; }}
 textarea {{ width: 100%; min-height: 7rem; padding: .6rem; font: 13px/1.4 ui-monospace, monospace;
            border: 1px solid #8884; border-radius: .5rem; background: #8881; color: inherit; }}
 button {{ margin-top: .75rem; padding: .55rem 1.1rem; border-radius: .5rem; border: 1px solid #8884;
          background: #2563eb; color: #fff; font-weight: 600; cursor: pointer; }}
 button:hover {{ background: #1d4ed8; }}
 .note {{ border-left: 3px solid #d97706; padding: .6rem .9rem; margin: 1.1rem 0; background: #d9770618;
         border-radius: .35rem; }}
 .ok {{ border-left-color: #16a34a; background: #16a34a18; }}
 .err {{ border-left-color: #dc2626; background: #dc262618; }}
 ol {{ padding-left: 1.3rem; }}
 code {{ background: #8882; padding: .1rem .3rem; border-radius: .25rem; }}
</style>
</head>
<body>
<h1>Link your HoYoLAB account</h1>
<p class="lead">These tools read your own Genshin Battle Chronicle. The cookies are
encrypted and used only for your Open WebUI user.</p>
{banner}
<div class="note">
  <strong>This is a login credential.</strong> The cookies you paste grant access to your
  HoYoLAB session. Do not share them, and do not paste them anywhere you do not trust.
  You can revoke access at any time by logging out of HoYoLAB, which invalidates them.
</div>
<ol>
  <li>Open <a href="https://www.hoyolab.com" target="_blank" rel="noreferrer">hoyolab.com</a> and log in.</li>
  <li>Press <code>F12</code>, open <em>Application &rarr; Cookies &rarr; https://www.hoyolab.com</em>.</li>
  <li>Copy <code>ltuid_v2</code>, <code>ltoken_v2</code> and <code>ltmid_v2</code>.</li>
  <li>Paste them below as <code>ltuid_v2=...; ltoken_v2=...; ltmid_v2=...</code></li>
</ol>
<form method="post" action="/link">
  <input type="hidden" name="token" value="{token}">
  <textarea name="cookies" placeholder="ltuid_v2=123456789; ltoken_v2=v2_...; ltmid_v2=..."
            autocomplete="off" spellcheck="false" required></textarea>
  <button type="submit">Link account</button>
</form>
<p class="lead" style="margin-top:1.5rem">Already linked? Submitting again replaces the stored cookie.</p>
</body>
</html>
"""


def _page(token: str, banner: str = '') -> HTMLResponse:
    return HTMLResponse(
        PAGE_TEMPLATE.format(token=html.escape(token), banner=banner),
        headers={'Cache-Control': 'no-store'},
    )


def _banner(kind: str, message: str) -> str:
    return f'<div class="note {kind}">{html.escape(message)}</div>'


def register_routes(mcp) -> None:
    @mcp.custom_route('/health', methods=['GET'])
    async def health(request: Request) -> JSONResponse:
        # The version is reported here rather than only at startup because the question
        # "which build is actually running?" is asked after the fact, from a different
        # machine, usually while something is misbehaving. It comes from the environment
        # (baked into the image at build time) so it reflects the running artefact, not
        # whatever __version__ says in the source tree.
        version = os.environ.get('HOYOLAB_MCP_VERSION', '')
        payload = {'status': 'ok'}
        if version:
            payload['version'] = version
        try:
            _store()
        except Exception as exc:
            return JSONResponse(
                {'status': 'error', 'detail': str(exc), **({'version': version} if version else {})},
                status_code=503,
            )
        return JSONResponse(payload)

    @mcp.custom_route('/link', methods=['GET', 'POST'])
    async def link(request: Request):
        if request.method == 'GET':
            token = request.query_params.get('token', '')
            if not token:
                return _page('', _banner('err', 'Missing link token. Open the link from the tool message.'))
            try:
                decode_link_token(token, _secret())
            except CredentialError as exc:
                return _page('', _banner('err', str(exc)))
            return _page(token)

        form = await request.form()
        token = str(form.get('token') or '')
        raw = str(form.get('cookies') or '')

        try:
            user_id = decode_link_token(token, _secret())
        except CredentialError as exc:
            return _page('', _banner('err', str(exc)))

        try:
            cookies = parse_cookie_string(raw)
            _store().save(user_id, cookies)
        except CredentialError as exc:
            return _page(token, _banner('err', str(exc)))
        except Exception as exc:
            log.exception('failed to store credential for %s', redact(user_id))
            return _page(token, _banner('err', f'Could not store the credential ({type(exc).__name__}).'))

        # Log names only. Values are never written anywhere.
        log.info('linked HoYoLAB credential for user %s (cookies: %s)', redact(user_id), sorted(cookies))
        return _page(
            '',
            _banner(
                'ok',
                'Account linked. Return to the chat and ask again — the tools will now use '
                'your credential. You can close this page.',
            ),
        )


def create_app():
    mcp = build_server()
    register_routes(mcp)
    return mcp


if __name__ == '__main__':
    app = create_app()
    host = os.environ.get('HOYOLAB_MCP_HOST', '0.0.0.0')
    port = int(os.environ.get('HOYOLAB_MCP_PORT', '8899'))
    log.info('starting HoYoLAB MCP on %s:%s (mcp path /mcp, link path /link)', host, port)
    app.settings.host = host
    app.settings.port = port
    app.run(transport='streamable-http')
