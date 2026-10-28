#!/usr/bin/env bash
# Enable the Open WebUI settings the HoYoLAB MCP server needs, then register the server.
#
# TWO CHANGES, both required for per-user credential isolation:
#
#   1. ENABLE_FORWARD_USER_INFO_HEADERS=true
#      Without it Open WebUI sends no user identity to tool servers, so the MCP server
#      cannot tell which user is asking. It fails closed rather than guessing, which
#      means every tool call errors. This is the switch that makes per-user cookies
#      possible at all.
#
#   2. FORWARD_USER_INFO_HEADER_JWT_SECRET=<random>
#      With a secret set, Open WebUI sends a signed HS256 JWT instead of a plain
#      X-OpenWebUI-User-Id header. The plain header can be spoofed by anything that can
#      reach the MCP server directly, which would let one user read another's linked
#      HoYoLAB account. The MCP server verifies the signature.
#
# The container is edited in place with a backup, then restarted and health-checked.
# Re-running is safe: values are only inserted when missing.
set -euo pipefail

UNIT="$HOME/.config/containers/systemd/open-webui.container"
BACKUP_DIR="$HOME/backups"
JWT_SECRET_FILE="$HOME/.config/hoyolab-mcp/jwt-secret.txt"

mkdir -p "$BACKUP_DIR" "$(dirname "$JWT_SECRET_FILE")"
chmod 700 "$(dirname "$JWT_SECRET_FILE")"

# Reuse the JWT secret across runs so a redeploy does not invalidate the MCP server's
# copy of it.
if [ -f "$JWT_SECRET_FILE" ]; then
  JWT_SECRET=$(cat "$JWT_SECRET_FILE")
else
  umask 077
  JWT_SECRET=$(openssl rand -hex 32)
  printf '%s' "$JWT_SECRET" > "$JWT_SECRET_FILE"
fi

cp -a "$UNIT" "$BACKUP_DIR/open-webui.container.bak.$(date +%s)"

changed=0
add_env() {
  local key="$1" value="$2"
  if grep -qE "^Environment=$key=" "$UNIT"; then
    if ! grep -qE "^Environment=$key=$value$" "$UNIT"; then
      sed -i "s|^Environment=$key=.*|Environment=$key=$value|" "$UNIT"
      echo "  updated $key"
      changed=1
    else
      echo "  $key already correct"
    fi
  else
    # Insert alongside the other Environment lines so the unit stays readable.
    local last
    last=$(grep -n '^Environment=' "$UNIT" | tail -1 | cut -d: -f1)
    if [ -n "$last" ]; then
      sed -i "${last}a Environment=$key=$value" "$UNIT"
    else
      sed -i "/^\[Container\]/a Environment=$key=$value" "$UNIT"
    fi
    echo "  added $key"
    changed=1
  fi
}

echo "=== configuring $UNIT ==="
add_env ENABLE_FORWARD_USER_INFO_HEADERS true
add_env FORWARD_USER_INFO_HEADER_JWT_SECRET "$JWT_SECRET"

if [ "$changed" -eq 1 ]; then
  systemctl --user daemon-reload
  systemctl --user restart open-webui.service
  echo "  restarted; waiting for health"
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1:3000/health 2>/dev/null || echo 000)
    if [ "$code" = "200" ]; then echo "  health 200"; break; fi
    sleep 2
  done
else
  echo "  no changes needed"
fi

echo
echo "=== verifying forwarded identity is active ==="
podman exec open-webui python -c "
from open_webui.env import ENABLE_FORWARD_USER_INFO_HEADERS, FORWARD_USER_INFO_HEADER_JWT_SECRET
print('  ENABLE_FORWARD_USER_INFO_HEADERS:', ENABLE_FORWARD_USER_INFO_HEADERS)
print('  JWT secret configured:', bool(FORWARD_USER_INFO_HEADER_JWT_SECRET))
" 2>&1 | grep -v '^INFO\|^WARN'

echo
echo "Rollback: cp $BACKUP_DIR/open-webui.container.bak.* $UNIT && systemctl --user daemon-reload && systemctl --user restart open-webui"
