# Contributing

Thanks for taking the time to contribute. This is a small project with a few firm rules,
most of them about not leaking other people's credentials.

## Getting set up

```bash
git clone https://github.com/danisec/hoyolab-mcp.git
cd hoyolab-mcp
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tests/test_hoyolab_mcp.py
```

No HoYoLAB account is needed to run the tests: they use synthetic payloads shaped like
real API responses. Testing against the live API needs your own linked account and is
never required for a pull request.

## What a good change looks like

* **Tests must pass.** `python tests/test_hoyolab_mcp.py` — all of them, not just the
  ones you touched.
* **A bug fix needs a test that fails without it.** Several tests in this repo exist
  precisely because a bug shipped once; the docstring says which.
* **New behaviour needs a test.** The suite is organised around dangerous properties
  (cross-user isolation, credential handling) rather than coverage numbers.
* **Comments explain *why*.** A comment restating the code is noise. A comment recording
  a measured API quirk, or why an obvious approach was rejected, is valuable.
* **No new runtime dependencies** without a reason in the pull request. The small
  dependency surface is deliberate — it is why this project talks to the HTTP API
  directly instead of using a wrapper library.

## Security properties you must not break

These are load-bearing. A change that weakens one of them will be rejected regardless of
what else it improves.

1. **No shared or fallback credential.** Every tool call must resolve to one user id and
   use only that user's cookies. If a fallback existed, one admin linking an account
   would silently serve their data to everyone else.
2. **Cookie values never reach logs or error text.** Use `redact()` for anything that
   might be logged. Log cookie *names*, never values.
3. **An unsigned header must not identify a user once a JWT secret is configured.**
   Otherwise anything able to reach the port can name itself any user.
4. **A bad token fails closed.** It must not fall back to a weaker identity source,
   because that would let a revoked token keep working.
5. **Token issuing stays off the network.** It is a local CLI command on purpose: an HTTP
   route would turn a user id into a credential for anyone who could reach the port.
6. **Ciphertexts stay bound to their user.** The user id is AES-GCM associated data; do
   not drop that binding.

## Code layout

| File | Responsibility |
|---|---|
| `hoyolab_mcp/client.py` | HTTP calls to HoYoLAB, the `DS` header, UID→server mapping |
| `hoyolab_mcp/store.py` | Encrypted per-user credential storage, API tokens, link tokens |
| `hoyolab_mcp/tools.py` | The eight MCP tools, identity resolution, response shaping |
| `hoyolab_mcp/main.py` | HTTP entrypoint: `/mcp`, `/link`, `/health` |
| `hoyolab_mcp/cli.py` | Local administration (tokens, linking, unlinking) |
| `tests/test_hoyolab_mcp.py` | The whole test suite |
| `verify_e2e.py` | Checks a *deployed* server end to end |

## A note on `serverInfo.name`

The MCP server identifies itself as `hoyolab-chronicle` at handshake. This string is
**not** part of the public interface: no supported client keys anything off it. Open WebUI
in particular never reads `serverInfo` — it takes only `instructions` from the handshake
and prefixes tool names with the connection id configured in its admin UI. Renaming it
would therefore be cosmetic, and it is left alone so that a rebuilt image stays
comparable to already-running deployments.

## Reporting a bug

Include:

* What you expected and what happened.
* The `retcode` if the failure came from HoYoLAB (it answers HTTP 200 even when refusing).
* The output of `curl -s http://<host>:8899/health`.
* Your client (Open WebUI, Claude Code, Codex, opencode) and how it authenticates.

**Never paste cookie values, `ltoken_v2`, API tokens, or your `HOYOLAB_MCP_SECRET`** in an
issue. Cookie names alone are enough to diagnose a link problem.

## Licence

By contributing you agree your work is licensed under the MIT licence in
[`LICENSE`](LICENSE). There is no CLA.
