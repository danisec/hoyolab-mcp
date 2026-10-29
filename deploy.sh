#!/usr/bin/env bash
# HoYoLAB MCP deployment + administration helper for Podman (Quadlet).
#
# Why this exists: an earlier version of this script generated a Quadlet that published
# the port on 0.0.0.0, joined a network that may not exist, and kept its secret in a file
# next to the unit inside the project directory. This version keeps the secret outside the
# repo, binds to loopback by default, adopts Open WebUI's signing secret instead of
# inventing one, and refuses to do anything that would silently lose data.
#
# Why a Quadlet rather than `podman-compose up -d`: compose has no supervision. After a
# reboot, or after a `compose down` run from another shell, nothing brings the service
# back. A Quadlet is turned into a real systemd unit by podman-user-generator, so it
# starts on boot (given `loginctl enable-linger`), restarts on failure, and survives
# reboots without a login session.
#
# Do NOT also run `podman compose up` for this project. Both would try to own a container
# named `hoyolab-mcp` and would fight over the port and the volume.
#
# Usage:
#   ./deploy.sh              init + build + install (the normal path)
#   ./deploy.sh init         create the env file, adopting Open WebUI's JWT secret
#   ./deploy.sh build        build the image locally
#   ./deploy.sh quadlet      (re)write the Quadlet from the env file, without restarting
#   ./deploy.sh install      write the Quadlet, restart the unit, wait for health
#   ./deploy.sh status [uid] show unit, container, health and link state
#   ./deploy.sh logs         follow the service log
#   ./deploy.sh backup       write a consistent copy of the credential database
#
# Everything is configured through $HOME/.config/hoyolab-mcp/hoyolab-mcp.env, mode 0600.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR="$HOME/.config/hoyolab-mcp"
ENV_FILE="$ENV_DIR/hoyolab-mcp.env"
QUADLET_DIR="$HOME/.config/containers/systemd"
QUADLET="$QUADLET_DIR/hoyolab-mcp.container"
UNIT="hoyolab-mcp.service"
CONTAINER="hoyolab-mcp"
VOLUME="hoyolab-mcp_hoyolab-data"
BACKUP_DIR="$HOME/.local/share/hoyolab-mcp/backup"
DEFAULT_PORT=8899
DEFAULT_IMAGE="localhost/hoyolab-mcp:latest"
# The Open WebUI container whose forwarded-identity secret this server must share.
OWUI_CONTAINER="${HOYOLAB_MCP_OWUI_CONTAINER:-open-webui}"

# Single source of truth for the version, read from the package instead of being
# duplicated here. It is baked into the image as HOYOLAB_MCP_VERSION and reported by
# /health, so a stale copy would make a deployed server claim the wrong version.
PACKAGE_VERSION="$(
  sed -n "s/^__version__ = '\([^']*\)'.*/\1/p" "$PROJECT_DIR/hoyolab_mcp/__init__.py" | head -1
)"
[ -n "$PACKAGE_VERSION" ] || { printf 'error: could not read __version__\n' >&2; exit 1; }

log() { printf '%s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

# Read one KEY=value from the env file. Returns empty when the key or file is absent.
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | head -1
}

# Replace (or append) KEY=value in the env file, keeping the inode and mode intact so a
# bind-mounted or hard-linked file keeps working. Written with shell builtins only: a
# value passed through `sed s///` or `awk -v` would have '/' and '&' or backslash escapes
# reinterpreted, which silently corrupts a secret that happens to contain them.
set_env_kv() {
  local key="$1" value="$2" tmp line found=0
  tmp="$(mktemp)"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key"=*) printf '%s=%s\n' "$key" "$value"; found=1 ;;
      *)        printf '%s\n' "$line" ;;
    esac
  done < "$ENV_FILE" > "$tmp"
  [ "$found" -eq 1 ] || printf '%s=%s\n' "$key" "$value" >> "$tmp"
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
}

require_env() {
  [ -f "$ENV_FILE" ] || die "missing $ENV_FILE (run: $0 init)"
  local secret
  secret="$(env_get HOYOLAB_MCP_SECRET)"
  [ -n "$secret" ] || die "HOYOLAB_MCP_SECRET is empty in $ENV_FILE"
  [ "${#secret}" -ge 16 ] || die "HOYOLAB_MCP_SECRET must be at least 16 characters"
}

# The host port the running service is expected on. The env file wins over the shell,
# because the env file is what the Quadlet actually consumes.
host_port() {
  local p
  p="$(env_get HOYOLAB_MCP_PORT_HOST)"
  printf '%s' "${p:-${HOYOLAB_MCP_PORT_HOST:-$DEFAULT_PORT}}"
}

image_ref() {
  local i
  i="$(env_get HOYOLAB_MCP_IMAGE)"
  printf '%s' "${i:-$DEFAULT_IMAGE}"
}

# Publish addresses, comma separated, loopback by default. Each address is a separate
# interface, so "127.0.0.1,100.x.y.z" publishes on both without widening to 0.0.0.0.
bind_addrs() {
  local b
  b="$(env_get HOYOLAB_MCP_BIND)"
  printf '%s' "${b:-127.0.0.1}"
}

# Copy Open WebUI's forwarded-identity secret into our env file.
#
# This is not optional polish: when FORWARD_USER_INFO_HEADER_JWT_SECRET is set on the
# server side, an unsigned X-OpenWebUI-User-Id header is rejected outright (fail closed),
# and when it is NOT set, identity falls back to a header that anything able to reach the
# port can spoof. The two processes must therefore agree on the same value. It is read
# from the running container rather than generated here, because a generated value would
# never match Open WebUI's and every tool call would fail verification.
adopt_forwarded_identity() {
  require_env
  local jwt fwd
  jwt="$(podman exec "$OWUI_CONTAINER" printenv FORWARD_USER_INFO_HEADER_JWT_SECRET 2>/dev/null || true)"
  fwd="$(podman exec "$OWUI_CONTAINER" printenv ENABLE_FORWARD_USER_INFO_HEADERS 2>/dev/null || true)"

  if [ -n "$jwt" ]; then
    if [ "$(env_get FORWARD_USER_INFO_HEADER_JWT_SECRET)" = "$jwt" ]; then
      log "  forwarded-identity secret already matches $OWUI_CONTAINER"
    else
      set_env_kv FORWARD_USER_INFO_HEADER_JWT_SECRET "$jwt"
      log "  adopted FORWARD_USER_INFO_HEADER_JWT_SECRET from $OWUI_CONTAINER"
    fi
  else
    log "  WARNING: $OWUI_CONTAINER has no FORWARD_USER_INFO_HEADER_JWT_SECRET."
    log "           Identity falls back to the unsigned X-OpenWebUI-User-Id header,"
    log "           which anything reaching the port can spoof."
  fi

  # Open WebUI sends no identity at all unless this is on, so every tool call fails closed.
  if [ "$fwd" != "true" ]; then
    log "  WARNING: ENABLE_FORWARD_USER_INFO_HEADERS is not 'true' on $OWUI_CONTAINER."
    log "           Tools will report that no user identity was forwarded."
  fi
}

cmd_init() {
  mkdir -p "$ENV_DIR"
  chmod 700 "$ENV_DIR"
  if [ -f "$ENV_FILE" ]; then
    log "  $ENV_FILE already exists, leaving its values untouched"
    adopt_forwarded_identity
    return
  fi

  local port binds hosts a public_host
  port="${HOYOLAB_MCP_PORT_HOST:-$DEFAULT_PORT}"
  binds="${HOYOLAB_MCP_BIND:-127.0.0.1}"

  # MCP's DNS-rebinding guard compares the FULL Host header, so every name a client may
  # use has to be listed in both "host:port" and bare "host" form. A bind address that is
  # not 127.0.0.1 (a tailnet or LAN address, say) has to be added as well, or requests
  # arriving through it are answered 421 Misdirected Request.
  hosts="hoyolab-mcp:8899,hoyolab-mcp,localhost:${port},localhost,127.0.0.1:${port},127.0.0.1,host.containers.internal:${port}"
  # The link URL is opened in the user's BROWSER, so it has to name an address that
  # browser can reach. Prefer the first non-loopback bind address over "localhost".
  public_host="localhost"
  if [ -n "$binds" ]; then
    local IFS=','
    for a in $binds; do
      [ -z "$a" ] && continue
      case "$a" in
        127.0.0.1|localhost|0.0.0.0) continue ;;
      esac
      hosts="${hosts},${a}:${port},${a}"
      [ "$public_host" = "localhost" ] && public_host="$a"
    done
  fi

  umask 077
  cat > "$ENV_FILE" <<EOF
# Written by deploy.sh. Contains the AES-GCM key that makes stored cookies readable:
# back this file up, and never commit it.
HOYOLAB_MCP_SECRET=$(openssl rand -hex 32)
# Filled in from Open WebUI by "deploy.sh init"; must match its value exactly.
FORWARD_USER_INFO_HEADER_JWT_SECRET=
HOYOLAB_MCP_PUBLIC_URL=http://${public_host}:${port}
HOYOLAB_MCP_BIND=${binds}
HOYOLAB_MCP_PORT_HOST=${port}
HOYOLAB_MCP_ALLOWED_HOSTS=${hosts}
HOYOLAB_MCP_IMAGE=${DEFAULT_IMAGE}
HOYOLAB_MCP_VERSION=${PACKAGE_VERSION}
EOF
  chmod 600 "$ENV_FILE"
  log "  wrote $ENV_FILE (mode 600)"

  adopt_forwarded_identity
}

cmd_build() {
  require_env
  local version platform arch
  version="$(env_get HOYOLAB_MCP_VERSION)"
  version="${version:-dev}"

  # Always state the platform explicitly. Without it, a stale base image for a different
  # architecture already in the local store can be reused, producing an emulated
  # container that is slow and fails its health check. Default to this host's
  # architecture so a native build stays native.
  platform="${HOYOLAB_MCP_PLATFORM:-}"
  if [ -z "$platform" ]; then
    arch="$(podman info --format '{{.Host.Arch}}' 2>/dev/null || true)"
    platform="linux/${arch:-amd64}"
  fi

  log "  building $(image_ref) for $platform from $PROJECT_DIR"
  podman build --platform "$platform" \
    --build-arg HOYOLAB_MCP_VERSION="$version" \
    -t "$(image_ref)" "$PROJECT_DIR" >/dev/null
  log "  image built: $(podman image inspect "$(image_ref)" --format '{{.Architecture}}')"
}

# Write the Quadlet. Kept here rather than as a committed .container file so that the
# bind addresses and port always match the env file that was just read, with no second
# copy to drift out of sync. No host-specific address is baked in.
cmd_quadlet() {
  require_env
  local port binds a
  port="$(host_port)"
  binds="$(bind_addrs)"
  mkdir -p "$QUADLET_DIR"

  {
    cat <<EOF
# Generated by deploy.sh -- do not edit; edit $ENV_FILE instead and re-run
# "deploy.sh quadlet".
[Unit]
Description=HoYoLAB Genshin Battle Chronicle MCP server (Streamable HTTP)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Container]
ContainerName=${CONTAINER}
Image=$(image_ref)

# One file outside the repo, mode 0600: a "git clean", a re-clone, or "compose down -v"
# cannot destroy the key that makes already-stored cookies readable.
EnvironmentFile=%h/.config/hoyolab-mcp/hoyolab-mcp.env

# The image defaults already set these; repeated here so the unit is self-describing.
Environment=HOYOLAB_MCP_HOST=0.0.0.0
Environment=HOYOLAB_MCP_PORT=8899
Environment=HOYOLAB_MCP_DB=/data/hoyolab.db
EOF
    # One line per interface: publishing on a specific address keeps the port off every
    # other interface, which is narrower than 0.0.0.0.
    local IFS=','
    for a in $binds; do
      [ -z "$a" ] && continue
      printf 'PublishPort=%s:%s:8899\n' "$a" "$port"
    done
    unset IFS
    cat <<EOF

# Named volume, not a bind mount: it holds AES-GCM ciphertexts of HoYoLAB session
# cookies, and rootless Podman sets ownership (uid 10001) correctly without a chown.
Volume=${VOLUME}:/data

# Hardening. read-only root, /tmp on tmpfs, only /data writable; all capabilities
# dropped; no-new-privileges blocks setuid escalation inside the container. compose.yaml
# leaves no-new-privileges off because snap-confined Docker rejects it; Podman accepts it.
ReadOnly=true
Tmpfs=/tmp
DropCapability=ALL
NoNewPrivileges=true
User=10001:10001

# timeout 10s / start-period 30s, not 5s/15s: on an emulated host (an arm64 image on
# x86_64) merely starting Python for the check took ~8s here, which made a 5s timeout
# report "unhealthy" for a server that was answering normally.
HealthCmd=python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8899/health',timeout=4).status==200 else 1)"
HealthInterval=30s
HealthTimeout=10s
HealthStartPeriod=30s
HealthRetries=3
HealthOnFailure=kill

[Service]
Restart=always
RestartSec=5
TimeoutStartSec=180

[Install]
WantedBy=default.target
EOF
  } > "$QUADLET"
  chmod 644 "$QUADLET"
  log "  wrote $QUADLET (publishing ${binds//,/, } on port ${port})"
}

cmd_install() {
  require_env
  local port i
  port="$(host_port)"

  cmd_quadlet
  systemctl --user daemon-reload
  systemctl --user restart "$UNIT"

  log "  waiting for health on 127.0.0.1:${port}..."
  for i in $(seq 1 40); do
    if curl -fsS -m 3 "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      log "  health OK"
      break
    fi
    sleep 2
  done

  curl -s -m 5 "http://127.0.0.1:${port}/health" || die "health check did not pass; see: $0 logs"
  log ""
  log "  MCP endpoint : http://127.0.0.1:${port}/mcp"
  log "  Link page    : $(env_get HOYOLAB_MCP_PUBLIC_URL)/link"
}

cmd_status() {
  # Without this the command happily reports on whatever container and port happen to be
  # running, which reads as "my deployment is fine" even when this script's env file is
  # missing or points somewhere else. Say what is being measured instead.
  require_env
  local port user
  port="$(host_port)"
  user="${1:-${HOYOLAB_MCP_USER:-}}"

  log "env file  : $ENV_FILE"
  log "expecting : 127.0.0.1:${port} (from HOYOLAB_MCP_PORT_HOST)"

  if systemctl --user is-active "$UNIT" >/dev/null 2>&1; then
    log "unit      : active"
  else
    log "unit      : INACTIVE"
  fi

  # `systemctl is-enabled` exits non-zero for a unit that is not enabled. Under
  # `set -o pipefail` that non-zero status aborted this function mid-report, so the state
  # is captured first and the exit status handled explicitly.
  local enabled
  if enabled="$(systemctl --user is-enabled "$UNIT" 2>/dev/null)"; then
    log "enabled   : $enabled"
  else
    log "enabled   : ${enabled:-not enabled}"
  fi

  podman inspect "$CONTAINER" --format 'container : {{.State.Status}} (health {{.State.Health.Status}})' 2>/dev/null \
    || log "container : absent"

  # Only a JSON body is printed. Anything else means something other than this server is
  # answering on that port, and dumping a foreign HTML page into the terminal is worse
  # than saying so plainly.
  local body
  if body="$(curl -fsS -m 5 "http://127.0.0.1:${port}/health" 2>/dev/null)"; then
    case "$body" in
      \{*\})
        log "health    : ${body:0:200}"
        ;;
      *)
        log "health    : NOT this server -- 127.0.0.1:${port} answered with non-JSON content."
        log "            Another service is probably on that port; check HOYOLAB_MCP_PORT_HOST."
        ;;
    esac
  else
    log "health    : no response from 127.0.0.1:${port}"
  fi

  if [ -n "$user" ]; then
    podman exec "$CONTAINER" python -m hoyolab_mcp.cli status --user "$user" \
      || log "link state: (could not read link state for $user)"
  else
    log "link state: pass a user id to see it: $0 status <user-id>"
  fi
}

cmd_backup() {
  require_env
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  local out
  out="$BACKUP_DIR/hoyolab-$(date +%Y%m%d-%H%M%S).db"

  # sqlite3's backup API inside the container produces a consistent copy while the server
  # is writing, unlike cp of a live WAL database. The temporary file lives on the /data
  # volume because the container's root filesystem is read-only.
  podman exec "$CONTAINER" python -c "
import sqlite3
src = sqlite3.connect('/data/hoyolab.db')
dst = sqlite3.connect('/data/backup.db')
src.backup(dst)
dst.close()
src.close()
"
  podman cp "$CONTAINER:/data/backup.db" "$out" >/dev/null
  podman exec "$CONTAINER" rm -f /data/backup.db
  chmod 600 "$out"

  # A zero-byte copy is worse than no copy: it looks like a backup until it is needed.
  [ -s "$out" ] || die "backup file is empty: $out"
  log "  backup written: $out ($(wc -c < "$out") bytes)"
}

case "${1:-install}" in
  init)    cmd_init ;;
  build)   cmd_build ;;
  quadlet) cmd_quadlet ;;
  install) cmd_init; cmd_build; cmd_install ;;
  status)  shift; cmd_status "$@" ;;
  logs)    exec journalctl --user -u "$UNIT" -f ;;
  backup)  cmd_backup ;;
  *) die "unknown command: $1 (try: init, build, quadlet, install, status, logs, backup)" ;;
esac
