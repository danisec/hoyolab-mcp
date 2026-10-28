# HoYoLAB Genshin Battle Chronicle — MCP server

[![CI](https://img.shields.io/github/actions/workflow/status/danisec/hoyolab-mcp/ci.yml?branch=main&label=tests&style=flat-square)](https://github.com/danisec/hoyolab-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/danisec/hoyolab-mcp?label=release&style=flat-square)](https://github.com/danisec/hoyolab-mcp/releases/latest)
[![Licence](https://img.shields.io/github/license/danisec/hoyolab-mcp?style=flat-square)](https://github.com/danisec/hoyolab-mcp/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-streamable--http-blueviolet?style=flat-square)](https://modelcontextprotocol.io)

Read-only access to a **Genshin Impact** Battle Chronicle, exposed as MCP tools so a
model can answer questions like "what are my Abyss stars this rotation?" or "which
regions am I least finished with?".

Genshin Impact only — Star Rail, ZZZ and Honkai Impact 3rd are named by
`list_game_accounts` but have no tools here.

Works with **Open WebUI**, **Claude Code**, **Codex**, and **opencode**.

```bash
cp .env.example .env
printf 'HOYOLAB_MCP_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env
docker compose up -d --build
curl -s http://localhost:8899/health   # {"status":"ok"}
```

> [!WARNING]
> **Unofficial.** This project is not affiliated with, endorsed by, or supported by
> HoYoverse. It calls the same internal web endpoints the Battle Chronicle page uses.
> Those endpoints are undocumented and can change or be restricted at any time.
>
> **Handle credentials carefully.** Access requires HoYoLAB session cookies, which are
> equivalent to being logged into the account — not a read-only token. Use a secondary
> account if you are unsure, and be aware that using unofficial clients may conflict
> with HoYoverse's Terms of Service. You accept that risk by using this software.

## Contents

- [Why this exists](#why-this-exists)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Authentication: cookies, not OAuth](#authentication-cookies-not-oauth)
- [Tools](#tools)
- [Failure modes are specific](#failure-modes-are-specific)
- [Installation](#installation)
  - [Configuration](#configuration)
- [Connecting a client](#connecting-a-client)
- [Usage](#usage)
- [Upgrading](#upgrading)
- [Removing your data](#removing-your-data)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Limitations](#limitations)
- [Tests](#tests)
- [Contributing](#contributing)
- [Credits and attribution](#credits-and-attribution)
- [Licence](#licence)

## Why this exists

The page at `act.hoyolab.com/app/community-game-records-sea/` is a web app, not an API.
To let a model read that data it has to be turned into tools, which is what this server
does: it calls the same endpoints the page calls and returns condensed JSON.

## Requirements

| | |
|---|---|
| Python | 3.10+ (only for the non-container path) |
| Container | Docker with Compose v2, **or** Podman 4+ with `podman-compose` |
| Client | Any MCP client that speaks **Streamable HTTP** |
| HoYoLAB | A logged-in account with Battle Chronicle visibility enabled |

No HoYoLAB developer account, API key, or OAuth application is needed — and none exists
to be obtained (see [the next section](#authentication-cookies-not-oauth)).

## Quick start

Docker or Podman, both work:

```bash
git clone https://github.com/danisec/hoyolab-mcp.git
cd hoyolab-mcp

cp .env.example .env
printf 'HOYOLAB_MCP_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env

docker compose up -d --build        # or: podman compose up -d
curl -s http://localhost:8899/health
```

Then connect a client — see [Connecting a client](#connecting-a-client). For a
command-line client that is two commands:

```bash
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli link-url --user alice
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli issue-token --user alice
```

## Authentication: cookies, not OAuth

The Battle Chronicle API does **not** use OAuth. It authenticates with HoYoLAB session
cookies (`ltuid_v2` / `ltoken_v2` / `ltmid_v2`, and the legacy `ltuid` / `ltoken`).

Open WebUI's MCP support does speak OAuth 2.1, but that authenticates Open WebUI *to an
MCP server*; it cannot mint a HoYoLAB credential. HoYoverse publishes no OAuth
authorization server for third-party Battle Chronicle access — its standard discovery
endpoints do not exist:

```
account.hoyoverse.com/.well-known/openid-configuration          -> HTTP 403
api-account-os.hoyoverse.com/.well-known/openid-configuration  -> HTTP 404
bbs-api-os.hoyolab.com/.well-known/oauth-authorization-server  -> HTTP 404
```

So cookies are the only mechanism. They are handled as follows.

### Per-user, encrypted, never logged

* Cookies are stored **per user id**, in SQLite, encrypted with AES-GCM. The user id is
  bound as associated data, so a ciphertext copied onto another user's row fails to
  decrypt instead of leaking an account.
* **API tokens** (for command-line clients) are stored as SHA-256 hashes, never in
  plaintext, and each maps to exactly one user id.
* There is **no server-wide fallback credential**. A fallback would mean that as soon
  as one admin linked an account, every other user of the tools would silently read
  that person's Genshin data.
* Values never reach logs or error messages. `redact()` keeps a 4-character prefix; the
  link page logs cookie *names* only.
* The server **fails closed** without `HOYOLAB_MCP_SECRET`: it starts, but every path that
  would touch credentials returns an error instead. `/health` answers `503` with the
  reason, and every tool call fails with the same message. Nothing is ever written
  unencrypted. Compose additionally refuses to start at all (see [Option A —
  Compose](#option-a--compose-recommended)), so the usual path fails earlier and more
  loudly.

### Linking an account

The link page is at `/link`. A user reaches it from the tool message, which includes a
signed, 15-minute token identifying their user id. A raw user id in the URL would let
anyone attach cookies to anyone else's account, so the id is HMAC-signed.

For command-line clients the same URL is printed by
`python -m hoyolab_mcp.cli link-url --user <id>`, so linking does not require a browser
session with Open WebUI.

### Three identity sources, and why unsigned headers are refused

The server resolves the caller in this order:

1. **`Authorization: Bearer <token>`** — a token minted per user id. Used by Claude Code,
   Codex and opencode. Verified against a stored SHA-256 hash; a revoked token stops
   working immediately. A bad token is an error, never a reason to fall back to
   something weaker.
2. **`X-OpenWebUI-User-Jwt`** — the signed HS256 token Open WebUI forwards
   (`iss=open-webui`), verified with the shared secret.
3. **`X-OpenWebUI-User-Id`** — the plain header, honoured **only when no JWT secret is
   configured**.

That last condition is a security boundary, not a convenience. If a JWT secret is
configured, the unsigned header is ignored outright: honouring it would let anything
that can reach the port name itself any user and read that person's Genshin data. The
error message says so explicitly, because otherwise it looks like a broken server.

## Tools

| Tool | Returns |
|---|---|
| `hoyolab_link_status` | Whether this user has linked an account (never the cookie) |
| `list_game_accounts` | Game accounts and UIDs linked to the HoYoLAB login |
| `get_genshin_overview` | All 22 account statistics (see below) + exploration summary |
| `get_characters` | Roster: name, level, rarity, element, constellation |
| `get_character_artifacts` | Equipped artifacts + final stat totals (base/bonus/total) |
| `get_spiral_abyss` | Stars per floor/chamber and the teams used |
| `get_imaginarium_theater` | Per-period act, medals, coins, optional round roster |
| `get_exploration` | Per-region exploration %, incomplete regions, offerings |

All are read-only. Nothing here can modify an account.

### `get_genshin_overview` returns every statistic the page shows

The API's `stats` object carries 22 top-level fields. Two of them are nested objects,
which is easy to miss — they are why Imaginarium Theater and Stygian Onslaught were once
reported as "not available from the API" when they were present all along:

| Page label | API field |
|---|---|
| Imaginarium Theater | `role_combat.max_round_id` (highest act), `difficulty_id` |
| Stygian Onslaught | `hard_challenge.name` (best record), `difficulty` |

Everything else maps one-to-one: achievements, days active, characters, max-friendship
characters, Spiral Abyss, all eight oculi (`iceculus_number` is Cryoculus,
`moonoculus_number` is Lunoculus), waypoints, domains, and all five chest tiers
(`magic_chest_number` is Remarkable Chest).

### Why artifacts need their own tool

`character/list` returns only id, name, level, rarity, element, weapon type and weapon —
**no artifacts at all**. Relic data lives behind `character/detail`, which also returns a
`property_map` that translates numeric `property_type` codes into readable stat names.
Without that map the stats are a wall of integers, so `get_character_artifacts` joins the
two. It also distinguishes flat `HP` (type 2) from `HP Percentage` (type 3), which both
report the name "HP" on their own, and keeps each substat's roll count so an invested
piece is distinguishable from a fresh one.

## Failure modes are specific

HoYoLAB answers HTTP 200 with a `retcode` even when it refuses, so errors are read from
the body, not the status code:

| retcode | Meaning surfaced to the user |
|---|---|
| `10001` | Credential missing, expired, or for another account |
| `10101` | Credential does not match this game UID |
| `10102` | Player disabled their Battle Chronicle — a privacy setting, not a login problem |
| `10103` | Game account not found |

`10102` in particular is called out separately, because telling someone to re-link when
the real fix is an in-game toggle sends them down the wrong path.

## Installation

Three paths: Compose (recommended), plain `docker run`, or a local Python install. A fourth
option covers a long-running Podman host that should supervise the service with systemd
(`deploy.sh`, Option D).

### Option A — Compose (recommended)

Works with **Docker Compose** and **Podman Compose**; the same `compose.yaml` is used by
both.

```bash
git clone https://github.com/danisec/hoyolab-mcp.git
cd hoyolab-mcp

cp .env.example .env
printf 'HOYOLAB_MCP_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env

docker compose up -d --build     # or: podman compose up -d
curl -s http://localhost:8899/health   # {"status":"ok"}
```

Without the `docker` CLI, `podman-compose` works directly:

```bash
podman-compose up -d --build
```

Both were tested against this file: the container reports `healthy`, `/health` answers,
and the MCP handshake returns all 8 tools.

If `HOYOLAB_MCP_SECRET` is missing or empty, Compose refuses to start with a message
naming the variable, so this is caught before a container exists. Run without Compose and
the server itself still refuses to serve: `/health` returns `503` and every tool call
returns an error, rather than writing cookies unencrypted.

Common operations:

```bash
docker compose logs -f              # follow logs
docker compose ps                   # status + health
docker compose down                 # stop, keep the credential database
docker compose down -v              # stop and DELETE the database (all linked accounts)
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli status --user alice
```

With Podman, substitute `podman compose` or `podman-compose` for `docker compose`.

#### What the Compose file sets up

| Concern | Choice | Why |
|---|---|---|
| State | named volume `hoyolab-data` → `/data` | holds the encrypted cookie database; a bind mount would leave it easy to copy or commit, and needs a manual `chown 10001` on rootless Podman |
| Network exposure | `${HOYOLAB_MCP_BIND:-127.0.0.1}:${HOYOLAB_MCP_PORT_HOST:-8899}:8899` | the server has no TLS, so it binds to loopback by default |
| Root filesystem | `read_only: true` + `tmpfs: /tmp` | only `/data` is writable |
| Capabilities | `cap_drop: ALL` | the image already runs as uid 10001 |
| Restart | `unless-stopped` | survives reboot and crashes |

To run a published image instead of building, set `HOYOLAB_MCP_IMAGE` in `.env`:

```bash
HOYOLAB_MCP_IMAGE=ghcr.io/you/hoyolab-mcp:1.0.0
docker compose up -d          # no --build
```

#### If `compose build` fails with a metadata-file error

On a snap-confined Docker, `docker compose build` can fail with:

```
open /tmp/.tmp-compose-build-metadataFile-*.json: no such file or directory
```

That is a BuildKit/snap interaction, not this project — it reproduces with a two-line
`FROM alpine` project. Build with BuildKit disabled, or build the image directly:

```bash
DOCKER_BUILDKIT=0 docker compose up -d --build
# or
docker build -t hoyolab-mcp:latest . && docker compose up -d
```

#### If containers exit with `operation not permitted`

If `security_opt: [no-new-privileges:true]` is added and every container then fails with
`exec ...: operation not permitted` — including `alpine sleep` — the host is blocking it
(e.g. snap-confined Docker). This file therefore leaves that option off; `read_only` and
`cap_drop: ALL` are still applied. Re-enable it on a host that supports it.

### Option B — plain `docker run`

Useful without Compose, or when embedding this in another setup.

```bash
git clone https://github.com/danisec/hoyolab-mcp.git
cd hoyolab-mcp

cp .env.example .env
printf 'HOYOLAB_MCP_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env

docker build -t hoyolab-mcp .
docker run -d --name hoyolab-mcp \
  -p 127.0.0.1:8899:8899 \
  --env-file .env \
  -v hoyolab-data:/data \
  --read-only --tmpfs /tmp --cap-drop ALL \
  hoyolab-mcp
```

`--env-file .env` passes every variable in the file, including `HOYOLAB_MCP_DB` and
`HOYOLAB_MCP_HOST`, which `compose.yaml` sets explicitly.

### Option C — local Python

```bash
git clone https://github.com/danisec/hoyolab-mcp.git
cd hoyolab-mcp
python -m venv .venv && .venv/bin/pip install -r requirements.txt

export HOYOLAB_MCP_SECRET="$(openssl rand -hex 32)"
export HOYOLAB_MCP_DB="$PWD/hoyolab.db"
export HOYOLAB_MCP_PUBLIC_URL="http://localhost:8899"
.venv/bin/python -m hoyolab_mcp.main
```

Requires Python 3.10 or newer (the code uses `X | Y` type syntax and `dict[str, str]`).

### Option D — Podman Quadlet (`deploy.sh`)

For a long-running Podman host, `deploy.sh` installs the server as a **systemd user
service** instead of a Compose container. A Quadlet is turned into a real systemd unit by
`podman-user-generator`, so it starts on boot, restarts on failure, and needs no login
session (given `loginctl enable-linger "$USER"`). Compose has no supervision of its own:
after a reboot, nothing brings the container back.

```bash
git clone https://github.com/danisec/hoyolab-mcp.git
cd hoyolab-mcp

./deploy.sh              # init + build + install, then wait for health
./deploy.sh status       # unit, container, health, and link state
./deploy.sh logs         # follow the service log
./deploy.sh backup       # consistent copy of the credential database
```

Configuration lives in `~/.config/hoyolab-mcp/hoyolab-mcp.env` (mode `600`), outside the
repository, so a `git clean`, a re-clone, or a `compose down -v` cannot destroy the key
that makes already-stored cookies readable. The Quadlet itself is generated from that file
by `./deploy.sh quadlet`, so the published port and bind addresses always match the env
file — there is no second copy to drift out of sync.

Set these before `./deploy.sh init` to control what it writes:

```bash
HOYOLAB_MCP_PORT_HOST=8899                    # host port
HOYOLAB_MCP_BIND=127.0.0.1,100.64.0.5         # publish on loopback AND one more address
HOYOLAB_MCP_OWUI_CONTAINER=open-webui         # container to adopt the JWT secret from
```

`HOYOLAB_MCP_BIND` accepts a comma-separated list. Each address becomes its own
`PublishPort` line, which is narrower than binding `0.0.0.0`: the port stays closed on
every interface not listed. Any non-loopback address is also added to
`HOYOLAB_MCP_ALLOWED_HOSTS` and used as the host in `HOYOLAB_MCP_PUBLIC_URL`, because the
DNS-rebinding check compares the full `Host` header and the link is opened in the user's
browser.

`./deploy.sh init` **adopts** `FORWARD_USER_INFO_HEADER_JWT_SECRET` from the running
Open WebUI container rather than generating one. This matters in both directions: when
this server has the secret, an unsigned `X-OpenWebUI-User-Id` header is rejected outright,
and when it does not, identity falls back to a header anything reaching the port can
spoof. The two processes have to agree on the same value, and a generated value never
would. Re-running `init` is safe: it reports a match and rewrites nothing.

Do **not** also run `podman compose up` for this project. Both would try to own a container
named `hoyolab-mcp` and would fight over the port and the volume.

Verified on a Podman host: the generated Quadlet is accepted by `podman quadlet -dryrun`
(exit 0, no parser errors, the expected `PublishPort` line), and the adopted secret matches
Open WebUI byte for byte. The `status` report was exercised against three cases — this
server's real port, a port belonging to another service, and a closed port — and refuses to
print a foreign HTML page as if it were health output.

Not exercised end to end: `build` and `install` (they need a free port and would restart the
live service). They are the same `podman build` and `systemctl --user restart` steps the
Compose and `docker run` paths already use.

### Configuration

`HOYOLAB_MCP_SECRET` is not optional, at least 16 characters. Without it the server still
starts but refuses to do anything with credentials: `/health` returns `503` and tool calls
return the same explanation, so no cookie is ever written unencrypted. Changing the secret
later makes already-stored cookies unreadable (users simply re-link).

`HOYOLAB_MCP_PUBLIC_URL` is used to build the account-link URL, so it must be reachable
from the **user's browser**, not just from the container. Behind a reverse proxy:

```bash
HOYOLAB_MCP_PUBLIC_URL=https://hoyolab-mcp.example.com
HOYOLAB_MCP_ALLOWED_HOSTS=hoyolab-mcp.example.com,hoyolab-mcp:8899,localhost:8899
```

`HOYOLAB_MCP_ALLOWED_HOSTS` must contain the **exact** `Host` header clients send. A
missing entry is rejected with `421 Misdirected Request`, which looks like a broken
server but is MCP's DNS-rebinding protection doing its job.

Every variable, with its default:

| Variable | Default | Purpose |
|---|---|---|
| `HOYOLAB_MCP_SECRET` | — (**required**) | AES-GCM key for stored cookies; ≥16 chars |
| `FORWARD_USER_INFO_HEADER_JWT_SECRET` | empty | Verify Open WebUI's forwarded identity; must match Open WebUI |
| `HOYOLAB_MCP_PUBLIC_URL` | empty (Compose sets `http://localhost:8899`) | Base URL for the account-link message; must be browser-reachable |
| `HOYOLAB_MCP_ALLOWED_HOSTS` | loopback + container names | Hosts accepted by the DNS-rebinding check |
| `HOYOLAB_MCP_BIND` | `127.0.0.1` | Host interface to publish on; `deploy.sh` accepts a comma-separated list, Compose takes one |
| `HOYOLAB_MCP_PORT_HOST` | `8899` | Host port (Compose only); the container always uses 8899 |
| `HOYOLAB_MCP_IMAGE` | `hoyolab-mcp:latest` | Image to run |
| `HOYOLAB_MCP_VERSION` | `dev` | Reported by `/health`; set at build time |
| `HOYOLAB_MCP_DB` | `/data/hoyolab.db` | Database path inside the container |
| `HOYOLAB_MCP_LOG_LEVEL` | `INFO` | Python log level |

`GET /health` returns `{"status":"ok","version":"..."}`, which is the quickest way to
confirm which build a running container is actually using.

## Connecting a client

There are two kinds of client, and they authenticate differently. This matters more
than it looks: the server never holds a shared credential, so **each client must be
able to say which user it is.**

| Client | How identity reaches the server |
|---|---|
| **Open WebUI** | Open WebUI signs and forwards a per-user header on every tool call |
| **Claude Code / Codex / opencode** | A bearer **API token** you mint for that user |

### Open WebUI

In Open WebUI: **Settings → Admin → Integrations → External Tool Servers → +**,
type **MCP (Streamable HTTP)**, URL `http://<host>:8899/mcp`, auth **None**.

Auth is `None` because identity travels in the forwarded header, not an Authorization
header. Two Open WebUI settings are required:

```bash
ENABLE_FORWARD_USER_INFO_HEADERS=true
FORWARD_USER_INFO_HEADER_JWT_SECRET=<a long random string>   # strongly recommended
```

`FORWARD_USER_INFO_HEADER_JWT_SECRET` must be the **same value** as this server's
`FORWARD_USER_INFO_HEADER_JWT_SECRET`. Without it Open WebUI falls back to an unsigned
`X-OpenWebUI-User-Id` header that anything reaching the port could forge.

There is deliberately **no "Connect" button** in Open WebUI for this server. Open WebUI
only shows one for OAuth-backed MCP servers, and HoYoverse publishes no OAuth
authorization server — so accounts are linked through the `/link` page instead, which
the tool message links to.

### Claude Code, Codex, opencode

These clients do not send Open WebUI's identity header, so they need a token. A token
maps to exactly one user id, and that user id's cookies are the only ones ever used —
the per-user isolation guarantee is unchanged.

#### 1. Choose a user id and link a HoYoLAB account

A "user id" here is just a stable name, not necessarily an Open WebUI user id. Pick one
per person (or per machine):

```bash
# Print a 15-minute link URL, then open it in a browser and paste your cookies
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli link-url --user alice

# Confirm it worked
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli status --user alice
#   user alice: linked (cookies: ltmid_v2, ltoken_v2, ltuid_v2)
```

`docker compose exec` picks the right container by service name, so it keeps working if
the container is renamed. With Podman use `podman compose exec`, or plain
`podman exec hoyolab-mcp ...`.

Without a container at all, drop the prefix and run
`.venv/bin/python -m hoyolab_mcp.cli ...` from the project directory.

#### 2. Mint a token

```bash
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli issue-token \
  --user alice --label "claude-code on laptop"
# hlt_1J2x...   <- shown once, never recoverable
```

Tokens are stored as SHA-256 hashes, so the database cannot be used to recover a working
token. If you lose one, revoke it and mint another.

#### 3. Configure the client

**Claude Code** — one command, or a JSON file:

```bash
claude mcp add --transport http hoyolab http://localhost:8899/mcp \
  --header "Authorization: Bearer hlt_your_token_here"
```

Or in `.mcp.json` (project) / `~/.claude.json` (user):

```json
{
  "mcpServers": {
    "hoyolab": {
      "type": "http",
      "url": "http://localhost:8899/mcp",
      "headers": { "Authorization": "Bearer hlt_your_token_here" }
    }
  }
}
```

The `"type": "http"` field is required — an entry with a `url` but no `type` is read as
a stdio server and skipped.

**Codex** — in `~/.codex/config.toml`:

```toml
[mcp_servers.hoyolab]
url = "http://localhost:8899/mcp"
http_headers = { Authorization = "Bearer hlt_your_token_here" }
```

Codex reads environment variables too, which keeps the token out of the file:

```toml
[mcp_servers.hoyolab]
url = "http://localhost:8899/mcp"
bearer_token_env_var = "HOYOLAB_MCP_TOKEN"
```

```bash
export HOYOLAB_MCP_TOKEN=hlt_your_token_here
```

**opencode** — in `opencode.json` (project) or `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "hoyolab": {
      "type": "remote",
      "url": "http://localhost:8899/mcp",
      "enabled": true,
      "headers": { "Authorization": "Bearer hlt_your_token_here" }
    }
  }
}
```

#### 4. Verify

```bash
# Ask the tool to confirm which account it sees
curl -s http://localhost:8899/mcp \
  -H "Authorization: Bearer hlt_your_token_here" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"hoyolab_link_status","arguments":{}}}'
```

Then in the client itself: *"Use the hoyolab tools to tell me my Spiral Abyss stars."*

### Managing tokens

```bash
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli list-tokens   --user alice
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli revoke-token --user alice --id 54a5448353b4
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli revoke-all   --user alice
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli unlink       --user alice
```

Revoking is immediate — the next tool call with that token is refused. There is no HTTP
route for issuing tokens on purpose: issuing a token turns a user id into a credential,
so it stays a local command requiring filesystem access to the database.

`unlink` deletes the stored cookies and revokes that user's tokens; see
[Removing your data](#removing-your-data).

### What the model sees

The server tells the model its own usage rules through MCP `instructions`, so no client
needs a custom prompt. If a user has not linked an account, every tool returns a message
containing their personal link URL rather than an empty result — the model will surface
it.

## Usage

Once connected, ask in natural language. The model picks the tool.

| Ask | Tool used |
|---|---|
| "Do I have a HoYoLAB account linked?" | `hoyolab_link_status` |
| "Which Genshin accounts do I have?" | `list_game_accounts` |
| "How many achievements and chests do I have?" | `get_genshin_overview` |
| "What are my Spiral Abyss stars this rotation?" | `get_spiral_abyss` |
| "How did I do in Imaginarium Theater?" | `get_imaginarium_theater` |
| "Which regions are least explored?" | `get_exploration` |
| "Show my Furina's artifacts and total CRIT" | `get_character_artifacts` |
| "List my characters by level" | `get_characters` |

`get_character_artifacts` answers build questions from **your own account's numbers**
rather than a wiki, which is why it exists separately from `get_characters`.

## Upgrading

The stored credential database is **forward compatible**: new versions read databases
written by older ones without migration, so upgrading is replacing the image and
restarting.

```bash
# If you run a published image (HOYOLAB_MCP_IMAGE points at a registry):
docker compose pull
docker compose up -d

# If you build locally (the default), pull would fail: the image is not in a registry.
docker compose up -d --build
```

Then confirm what is actually running:

```bash
curl -s http://localhost:8899/health   # {"status":"ok","version":"1.0.0"}
```

`version` comes from the `HOYOLAB_MCP_VERSION` build argument, so it reports the image
you are running rather than whatever the source tree says. If it is missing, the image
was built without it — see [Configuration](#configuration).

Before a major version, back up the volume — it is the only copy of every linked account:

```bash
docker run --rm -v hoyolab-mcp_hoyolab-data:/data -v "$PWD":/backup \
  docker.io/library/alpine:3.20 tar czf /backup/hoyolab-backup.tgz -C /data .
```

The image is named in full (`docker.io/library/alpine:3.20`) rather than as `alpine`,
because Podman refuses a bare short name when no unqualified-search registry is
configured.

To undo an upgrade, run the previous image tag again against the same volume:

```bash
HOYOLAB_MCP_IMAGE=hoyolab-mcp:1.0.0 docker compose up -d
```

Rolling back is safe because the database is only ever extended, never rewritten in a
way older versions cannot read. Restoring the backup above is only needed if a version
wrote something incompatible — which would be a major version, and is called out in the
[changelog](CHANGELOG.md).

**What is stable between versions.** These are treated as public interface, and changing
one would be a breaking change called out in the [changelog](CHANGELOG.md):

| Interface | Value |
|---|---|
| MCP endpoint path | `/mcp` |
| Link page path | `/link` |
| Health path | `/health` |
| Environment variables | `HOYOLAB_MCP_*` (see [Configuration](#configuration)) |
| Container port | `8899` |
| Tool names | the eight names in [Tools](#tools) |
| Database format | readable by later versions |

**If you upgrade an existing install, nothing needs to be re-registered.** The URL, the
auth mode and the tool names above are unchanged, so an Open WebUI connection created
against an earlier build keeps working as-is.

Release notes for each version are in [CHANGELOG.md](CHANGELOG.md).

## Removing your data

Because this server stores a **login credential**, there is an explicit way to take it
back — you do not have to delete the whole database.

```bash
# Delete this user's stored cookies (and their tokens)
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli unlink --user alice

# Keep the tokens, remove only the cookies
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli unlink --user alice --keep-tokens

# Revoke tokens without touching the cookie
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli revoke-all --user alice
```

Removing the credential from this database does **not** invalidate it at HoYoLAB. To do
that, log out of HoYoLAB in the browser the cookies came from — that invalidates the
session for every client, including this one.

To remove everything at once (all users, all tokens):

```bash
docker compose down -v      # -v deletes the named volume holding the database
```

`unlink` is deliberate about scope: it deletes only the named user's row. The database
is shared, so there is no "delete everything" flag that could be run by accident.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `421 Misdirected Request` | MCP's DNS-rebinding protection; the `Host` header is not in the allow-list | Add the exact `host:port` you connect with to `HOYOLAB_MCP_ALLOWED_HOSTS` |
| `No user identity was forwarded` | Client sent no bearer token and Open WebUI is not forwarding headers | Mint a token, or set `ENABLE_FORWARD_USER_INFO_HEADERS=true` in Open WebUI |
| `A plain X-OpenWebUI-User-Id header was sent, but it is ignored` | A JWT secret is configured, so unsigned identity is refused | Send the signed `X-OpenWebUI-User-Jwt`, or use an API token |
| `The API token ... is not valid or has been revoked` | Token typo, or revoked | `issue-token` a new one |
| `required variable HOYOLAB_MCP_SECRET is missing a value` | `.env` not created or key empty | `printf 'HOYOLAB_MCP_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env` |
| `/health` answers `503` with `HOYOLAB_MCP_SECRET must be set to at least 16 characters` | Running outside Compose with no secret, so the server fails closed instead of writing cookies unencrypted | Export a secret of 16+ characters, or use Compose, which refuses to start without one |
| Container is `unhealthy` but `/health` answers | Healthcheck timeout too tight on an emulated host | Raise `healthcheck.timeout` in `compose.yaml` |
| Container exits: `exec ...: operation not permitted` | Host blocks `no-new-privileges` (e.g. snap Docker) | Remove that `security_opt` entry |
| `retcode 10001` | Cookies expired or belong to another account | Re-link via `link-url` |
| `retcode 10102` | Battle Chronicle is disabled in-game | Enable "Show my Battle Chronicle on my profile" in HoYoLAB settings — re-linking will not help |
| `Malformed link token` | The URL was truncated when copied | Run `link-url` again; tokens last 15 minutes |
| Tools report `not linked` right after linking | Different `--user` value than the token was minted for | Check `status --user <id>` for the same id |

Diagnostics:

```bash
docker compose logs -f                       # server logs
docker compose exec hoyolab-mcp python -m hoyolab_mcp.cli status --user alice
curl -s http://localhost:8899/health
```

## Security

What this server does to protect the credentials it holds:

* Cookies are encrypted at rest with AES-GCM; the user id is bound as associated data,
  so a ciphertext moved to another user's row fails to decrypt.
* API tokens are stored as SHA-256 hashes — a database dump yields no usable token.
* Cookie values never reach logs or error text; only names are logged.
* No shared or fallback credential exists, so one user's link can never serve another.
* The container runs as uid 10001 with `read_only` root, `cap_drop: ALL`, and only
  `/data` writable.

What it does **not** do, so you can plan around it:

* It is not a public-internet service. It speaks plain HTTP with no TLS, and a bearer
  token is the only thing protecting the data. Put it behind a TLS-terminating proxy and
  keep the port on loopback unless you have a reason not to.
* It cannot revoke a HoYoLAB session. Only logging out of HoYoLAB does that.
* `HOYOLAB_MCP_SECRET` protects the database, not the host. Anyone with root on the host
  can read the key and decrypt the cookies.

To report a vulnerability, please **do not** open a public issue — use GitHub's private
vulnerability reporting (*Security → Report a vulnerability*). See
[SECURITY.md](SECURITY.md) for scope and what to include.

## Limitations

* **Read-only.** Nothing here can modify a Genshin account.
* **Genshin Impact only.** Honkai: Star Rail, ZZZ and Honkai Impact 3rd are listed by
  `list_game_accounts` but have no tools.
* **Unofficial endpoints.** HoYoverse can change or restrict them without notice; a
  breaking change here would surface as an unexpected `retcode`, not a version warning.
* **Overseas accounts only.** The `DS` salt and endpoints used are the overseas
  (`os_*`) set; mainland China (Miyoushe) is untested.
* **No caching.** Every call hits HoYoLAB, so a chatty model can hit rate limits.

## Tests

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python tests/test_hoyolab_mcp.py
```

Covers cross-user isolation, ciphertext binding, plaintext-on-disk, log redaction,
credential validation, link-token tampering/expiry, API-token issue/resolve/revoke and
hash-only storage, unlinking, identity resolution across all three sources (including
that an unsigned header is refused once a JWT secret exists), UID→server mapping, and
the exact wire shape of each API call (two real bugs were found this way:
`character/list` takes its parameters in the JSON body, and the account list lives on
the community host).

For a live server, `verify_e2e.py` checks the deployed behaviour end to end. It is a
host-side script and is **not** baked into the image, and the container's root filesystem
is read-only, so it cannot simply be copied in. Run it in a throwaway container that
shares the server's volume and can reach it over the network:

```bash
docker run --rm --network host \
  -v hoyolab-mcp_hoyolab-data:/data \
  -v "$PWD":/src:ro \
  -e HOYOLAB_MCP_SECRET="$(grep '^HOYOLAB_MCP_SECRET=' .env | cut -d= -f2-)" \
  -e HOYOLAB_MCP_DB=/data/hoyolab.db \
  -w /src --entrypoint python hoyolab-mcp:latest verify_e2e.py \
  --url http://127.0.0.1:8899
```

Add `--jwt-secret "<Open WebUI's value>"` to include the Open WebUI identity checks.
The token checks need the shared volume, which is why it is mounted rather than pointing
the script at a copy of the database.

## Contributing

Issues and pull requests are welcome. Full guidance is in
[CONTRIBUTING.md](CONTRIBUTING.md); the short version:

* **Keep the tests green** — `python tests/test_hoyolab_mcp.py` must pass. New
  behaviour needs a test; a bug fix needs a test that fails without the fix.
* **Preserve the security properties** listed under [Security](#security). In particular
  do not add a shared credential, do not log cookie values, and do not let an unsigned
  header identify a user once a JWT secret is configured.
* **No new runtime dependencies** without a reason in the PR — the small dependency
  surface is deliberate.
* **Match the surrounding style**: comments explain *why*, not *what*.

There is no CLA. By contributing you agree your work is licensed under the MIT licence
below.

## Credits and attribution

### Prior work this project learned from

**[genshin.py](https://github.com/seriaati/genshin.py)** — MIT, originally by
[sadru](https://github.com/thesadru), now maintained by
[seriaati](https://github.com/seriaati).

This project does **not** depend on or vendor genshin.py; the client here is written
against the HTTP API directly. However, genshin.py was the reference used to work out
parts of the protocol, and three things in this codebase derive from reading it:

1. **The `DS` header algorithm** (`make_ds` in `hoyolab_mcp/client.py`) —
   `md5("salt=…&t=…&r=…")` with a 6-character random component. The algorithm belongs
   to HoYoverse's web client, but this implementation was written after reading
   `genshin/utility/ds.py`.
2. **The UID → server mapping** (`GENSHIN_SERVERS`) — the prefix ranges are HoYoverse
   facts, but the table was transcribed from `genshin/utility/uid.py`.
3. **The `exploration_percentage` divisor** — genshin.py divides by 10, which is what
   revealed that an earlier version of this project dividing by 100 was wrong.

Its MIT licence text is reproduced in `THIRD_PARTY_LICENSES.md`.

**[genshinstats](https://github.com/thesadru/genshinstats)** — the predecessor library
by sadru, superseded by genshin.py. Same lineage for the API knowledge above.

**[UIGF-org/mihoyo-api-collect](https://github.com/UIGF-org/mihoyo-api-collect)** —
community documentation of the HoYoLAB/Miyoushe token and record APIs. Used to confirm
which cookie names carry authentication (`ltuid_v2` / `ltoken_v2` / `ltmid_v2` and the
legacy pair).

### Libraries

| Library | Licence | Used for |
|---|---|---|
| [mcp](https://github.com/modelcontextprotocol/python-sdk) (Anthropic) | MIT | MCP server framework and client (tests) |
| [httpx](https://github.com/encode/httpx) | BSD-3-Clause | HTTP client for HoYoLAB |
| [PyJWT](https://github.com/jpadilla/pyjwt) | MIT | Verifying Open WebUI's forwarded identity token |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause | AES-GCM encryption of stored cookies |
| [uvicorn](https://github.com/encode/uvicorn) / [starlette](https://github.com/encode/starlette) | BSD-3-Clause | ASGI server and routes (via mcp) |

All are permissively licensed; none require attribution in documentation, but they are
listed for transparency. Full texts in `THIRD_PARTY_LICENSES.md`.

### Data and trademarks

Genshin Impact, HoYoLAB and related marks are trademarks of HoYoverse. This project is
unofficial and unaffiliated. Endpoint URLs, property-type codes and game constants are
facts about HoYoverse's own services, reproduced here for interoperability.

### What is original

Everything else: the MCP tool design, per-user encrypted credential store, the
account-linking flow with signed tokens, the Open WebUI integration, response shaping,
and the test suite.

## Licence

MIT — see [`LICENSE`](LICENSE). Third-party licence texts are in
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

Using this software does not grant any rights to Genshin Impact, HoYoLAB, or HoYoverse
services, and this project is not affiliated with them.
