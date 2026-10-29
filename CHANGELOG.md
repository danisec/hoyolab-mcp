# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-10-29

### Added

- `get_daily_note` — current resin, realm currency, expeditions, daily tasks, weekly boss
  discount and Parametric Transformer state. The Battle Chronicle `index` endpoint carries
  none of these, so resin was previously unanswerable. Countdowns are returned as both raw
  seconds and readable text, because the API sends `resin_recovery_time` as a **string of
  seconds** and `"0"` means "already full" — reading it as minutes overstated the refill
  time by roughly 60×.
- `get_attendance` — HoYoLAB daily check-in state: whether today is signed, days signed
  this month, the reward on offer, and the make-up allowance. Read-only: the claim
  endpoint (`POST /event/sol/sign`) is deliberately not implemented, and a test asserts
  no code path reaches it.
- `retcode` messages for `1005` (a mismatched `server` on `dailyNote`), and `-100` /
  `-1005` (the check-in service's own codes, which differ from the record API's `10001`).
- `ToolSignatureTests`: every registered tool must declare `ctx: Context`. A tool without
  it fails only at call time with `name 'ctx' is not defined`, which helper-level tests
  cannot see — this caught exactly that bug in `get_attendance` during development.
- README sections explaining where resin actually lives, why the check-in service is a
  different host, the reward-index off-by-one, and why claiming is left to the user.
- CI workflow (`.github/workflows/ci.yml`): the test suite on Python 3.10, 3.11 and 3.12,
  a container build that is started and health-checked, a check that the container fails
  closed without `HOYOLAB_MCP_SECRET`, Compose file validation, and a tag/`__version__`
  comparison on release tags.
- Issue forms for bug reports and feature requests, plus a contact-links configuration.
- README badges, and a Troubleshooting entry for `/health` answering `503`.
- `deploy.sh` installs the server as a Podman **Quadlet** (a systemd user service), with
  `init`, `build`, `quadlet`, `install`, `status`, `logs` and `backup` subcommands. The
  Quadlet is generated from the env file, so the published port and bind addresses cannot
  drift out of sync with it. Documented in the README as Option D.

### Fixed

- The `HEALTHCHECK` in the `Dockerfile` used a 5-second timeout and a 15-second
  start period, while `compose.yaml` used 10 and 30 seconds. On an emulated host (an arm64
  image on x86_64) starting Python inside the check took about 8 seconds, so the image's
  own healthcheck reported `unhealthy` for a server that was answering normally. Both now
  use 10 seconds and 30 seconds.
- `deploy.sh` did not carry `FORWARD_USER_INFO_HEADER_JWT_SECRET` over to the server, even
  though an earlier revision did. Without it, identity falls back to an unsigned
  `X-OpenWebUI-User-Id` header that anything able to reach the port can spoof; with a
  mismatched value, every tool call fails verification. `init` now adopts the secret from
  the running Open WebUI container and re-running it rewrites nothing.
- `deploy.sh status` aborted mid-report under `set -o pipefail`: `systemctl is-enabled`
  exits non-zero for a unit that is not enabled, which killed the function before it
  printed the container and health lines. It also reported on whatever container happened
  to be running when its env file was missing, and printed a foreign HTML page verbatim
  when another service held the port. It now requires the env file, names the port it is
  checking, and only prints a JSON body.
- `deploy.sh` defaulted the host port to 8912 while `.env.example`, `compose.yaml` and the
  README all use 8899, and left `install` pointing at a Quadlet it never created, so a
  fresh clone could not install at all.

## [1.0.0]

First public release.

### Added

- Streamable-HTTP MCP server exposing eight read-only Genshin Impact Battle Chronicle
  tools: `hoyolab_link_status`, `list_game_accounts`, `get_genshin_overview`,
  `get_characters`, `get_character_artifacts`, `get_spiral_abyss`,
  `get_imaginarium_theater`, `get_exploration`.
- Per-user credential storage: HoYoLAB cookies encrypted with AES-GCM, bound to the user
  id as associated data, in SQLite.
- API tokens for clients that are not Open WebUI (Claude Code, Codex, opencode), stored
  as SHA-256 hashes and revocable individually or in bulk.
- Account linking through a `/link` page guarded by a signed, 15-minute token.
- `python -m hoyolab_mcp.cli` for local administration: `link-url`, `issue-token`,
  `list-tokens`, `revoke-token`, `revoke-all`, `unlink`, `status`.
- `compose.yaml` working with both Docker Compose and Podman Compose, with a read-only
  root filesystem, all capabilities dropped, and the database on a named volume.
- `GET /health` reports `version`, set at build time via the `HOYOLAB_MCP_VERSION` build
  argument, so the running build can be identified from any machine.
- `verify_e2e.py` for checking a deployed server end to end.

### Security

- The unsigned `X-OpenWebUI-User-Id` header is ignored whenever
  `FORWARD_USER_INFO_HEADER_JWT_SECRET` is configured. Previously it was still honoured,
  which would have let anything able to reach the port name itself any user and read that
  user's account.
- A presented API token that does not resolve is rejected outright rather than falling
  back to a weaker identity source, so a revoked token cannot keep working.
- No server-wide fallback credential exists, so one user's link can never serve another's
  request.
- Cookie values are never written to logs or error messages.

### Fixed

- `exploration_percentage` is divided by 10, not 100. The API reports tenths of a
  percent, so dividing by 100 turned every completed region into "10.0%".
- `character/list` parameters are sent in the JSON body, which is what the endpoint
  expects.
- The game account list is read from the community host
  (`bbs-api-os.hoyolab.com/game_record/card/wapi/getGameRecordCard`), where it actually
  lives.
- The record card's game UID field is `game_role_id`; reading `game_uid` yielded `None`
  for every account.
- `uid="None"` (the literal string) is treated as "not provided" instead of being sent
  to the API.
- `offerings` are read per area rather than as one flat list.
- Artifacts are fetched from `character/detail`, since `character/list` returns none.
- All 22 top-level `stats` fields are exposed, including the nested `role_combat`
  (Imaginarium Theater) and `hard_challenge` (Stygian Onslaught) objects that were
  previously reported as unavailable.
- No invented aggregate maximum for Spiral Abyss stars: the API returns only the floors
  actually attempted, so a computed total undercounts.

[Unreleased]: https://github.com/danisec/hoyolab-mcp/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/danisec/hoyolab-mcp/releases/tag/v1.0.0
