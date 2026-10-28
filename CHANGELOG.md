# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
