# Security

## What this software holds

This server stores **HoYoLAB session cookies**, which are equivalent to being logged into
the account — not a read-only token. Anyone who obtains them can act as that user on
HoYoLAB, which is a wider scope than the Genshin data this project reads.

Treat a deployment as a credential store, not a dashboard.

## How credentials are protected

| Property | Implementation |
|---|---|
| Encryption at rest | AES-GCM, key derived from `HOYOLAB_MCP_SECRET` (refused if under 16 chars) |
| Binding to a user | The user id is passed as AES-GCM associated data, so a ciphertext moved to another row fails to decrypt |
| API tokens | Stored as SHA-256 hashes; a database dump yields no usable token |
| Logging | Cookie values never logged; only cookie *names*, via `redact()` |
| Isolation | No shared or fallback credential — every call resolves to exactly one user id |
| Identity | A bad token fails closed rather than falling back to a weaker source |
| Token issuing | Local CLI only; there is deliberately no HTTP route that mints credentials |
| Container | Runs as uid 10001, read-only root filesystem, all capabilities dropped |

## Known limitations

These are accepted trade-offs, not oversights:

* **No TLS.** The server speaks plain HTTP. Publishing it beyond loopback without a
  TLS-terminating reverse proxy exposes bearer tokens and account data on the network.
* **No revocation at the source.** Deleting a stored credential does not invalidate it at
  HoYoLAB; only logging out of HoYoLAB does that.
* **The secret protects the database, not the host.** Anyone with root on the host can
  read `HOYOLAB_MCP_SECRET` and decrypt the stored cookies.
* **No rate limiting.** A client with a valid token can call the tools as fast as it
  likes; HoYoLAB's own limits apply to the upstream calls.
* **Tokens are bearer credentials.** If a token is placed in a client config file, that
  file must be protected (`chmod 600`) — this project cannot protect it for you.
* **Unofficial endpoints.** HoYoverse may change or restrict them, which can break
  behaviour without notice.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use the repository's private vulnerability reporting (GitHub: *Security → Report a
vulnerability*). If that is unavailable, open a minimal issue asking for a private
contact channel, without any details of the flaw.

Include:

* What an attacker gains, and what access they need to start.
* Steps to reproduce, against a throwaway deployment if possible.
* Affected version — `curl -s http://<host>:8899/health` reports it.

You can expect an acknowledgement within a few days. This is a volunteer project, so
please allow reasonable time before disclosing publicly.

## Scope

In scope:

* Cross-user credential access, or any path where one user's cookies serve another's call.
* Bypassing identity checks, including forging the forwarded headers.
* Reading cookie or token values from logs, error messages, the database, or responses.
* Token forgery, or a revoked token continuing to work.

Out of scope:

* Vulnerabilities in HoYoLAB or HoYoverse services themselves.
* Account bans or other consequences of using unofficial clients — see the warning in the
  README.
* Anything requiring root on the host, or physical access.
* Findings from automated scanners reported without a demonstrated impact.
