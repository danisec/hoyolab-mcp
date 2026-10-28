#!/usr/bin/env bash
# Deploy the HoYoLAB MCP server as a systemd user service next to Open WebUI.
#
# Idempotent: re-running replaces the container and keeps the existing credential
# database and secrets, so linked accounts survive a redeploy.
set -euo pipefail

IMAGE="${1:-hoyolab-mcp:latest}"
NAME=hoyolab-mcp
UNIT_DIR="$HOME/.config/containers/systemd"
ENV_DIR="$HOME/.config/hoyolab-mcp"
DATA_DIR="$HOME/.local/share/hoyolab-mcp"
# Set this to a URL the user's BROWSER can reach; the tool message builds the link from
# it. Example: https://hoyolab-mcp.example.com
HOST_PORT="${HOYOLAB_MCP_HOST_PORT:-8912}"
PUBLIC_URL="${HOYOLAB_MCP_PUBLIC_URL:-http://localhost:${HOST_PORT}}"

mkdir -p "$UNIT_DIR" "$ENV_DIR" "$DATA_DIR"
chmod 700 "$ENV_DIR"

# The image runs as uid 10001 (non-root). With a :Z bind mount the directory appears
# inside the container owned by root, so the process cannot create its database.
# Set ownership on the host to the same uid/gid the container uses.
if command -v podman >/dev/null 2>&1; then
  podman unshare chown -R 10001:10001 "$DATA_DIR" 2>/dev/null || chmod 777 "$DATA_DIR"
fi

# --- secrets -----------------------------------------------------------------
# Generated once and reused. The JWT secret must equal Open WebUI's
# FORWARD_USER_INFO_HEADER_JWT_SECRET, so it is read from the running container
# when available rather than invented here (a mismatch means every tool call fails
# identity verification).
SECRET_FILE="$ENV_DIR/secret.env"
if [ ! -f "$SECRET_FILE" ]; then
  umask 077
  {
    echo "HOYOLAB_MCP_SECRET=$(openssl rand -hex 32)"
    echo "HOYOLAB_MCP_PUBLIC_URL=$PUBLIC_URL"
  } > "$SECRET_FILE"
fi

# Adopt Open WebUI's forwarded-identity JWT secret if it has one configured.
OWUI_JWT=$(podman exec open-webui printenv FORWARD_USER_INFO_HEADER_JWT_SECRET 2>/dev/null || true)
if [ -n "$OWUI_JWT" ]; then
  if grep -q '^FORWARD_USER_INFO_HEADER_JWT_SECRET=' "$SECRET_FILE"; then
    sed -i "s|^FORWARD_USER_INFO_HEADER_JWT_SECRET=.*|FORWARD_USER_INFO_HEADER_JWT_SECRET=$OWUI_JWT|" "$SECRET_FILE"
  else
    echo "FORWARD_USER_INFO_HEADER_JWT_SECRET=$OWUI_JWT" >> "$SECRET_FILE"
  fi
  echo "  adopted Open WebUI forwarded-identity JWT secret"
else
  echo "  WARNING: Open WebUI has no FORWARD_USER_INFO_HEADER_JWT_SECRET."
  echo "           Identity will fall back to the unsigned X-OpenWebUI-User-Id header."
fi

# Open WebUI must forward identity at all, or every tool call fails closed.
FWD=$(podman exec open-webui printenv ENABLE_FORWARD_USER_INFO_HEADERS 2>/dev/null || echo "")
if [ "$FWD" != "true" ]; then
  echo "  WARNING: ENABLE_FORWARD_USER_INFO_HEADERS is not 'true' on Open WebUI."
  echo "           Tools will report that no user identity was forwarded."
fi

cat > "$UNIT_DIR/hoyolab-mcp.container" <<EOF
[Unit]
Description=HoYoLAB Genshin Battle Chronicle MCP server for Open WebUI
After=network-online.target

[Container]
ContainerName=$NAME
Image=$IMAGE
# Joined to Open WebUI's network so the MCP URL can use the container name
# (http://hoyolab-mcp:8899/mcp) instead of a host address that changes with DHCP.
# Change this if your Open WebUI runs on a differently named podman network.
Network=${HOYOLAB_MCP_NETWORK:-podman}
PublishPort=${HOST_PORT}:8899
Volume=$DATA_DIR:/data:Z
EnvironmentFile=$SECRET_FILE
Environment=HOYOLAB_MCP_HOST=0.0.0.0
Environment=HOYOLAB_MCP_PORT=8899
Environment=HOYOLAB_MCP_DB=/data/hoyolab.db
AutoUpdate=registry
HealthCmd=python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8899/health',timeout=4).status==200 else 1)"
HealthInterval=30s
HealthStartPeriod=15s
HealthRetries=3

[Service]
Restart=always
TimeoutStartSec=180

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user restart "$NAME.service"

echo "  waiting for health..."
for _ in $(seq 1 30); do
  if curl -fsS -m 3 http://127.0.0.1:${HOST_PORT}/health >/dev/null 2>&1; then
    echo "  health OK"
    break
  fi
  sleep 2
done

curl -s -m 5 http://127.0.0.1:${HOST_PORT}/health || echo "  health check did not pass"
echo
echo "MCP endpoint : http://$(hostname -I | awk '{print $1}'):${HOST_PORT}/mcp"
echo "Link page    : ${PUBLIC_URL}/link"
echo
echo "Next steps:"
echo "  Open WebUI  : add the MCP URL above with auth None, then set"
echo "                ENABLE_FORWARD_USER_INFO_HEADERS=true and a shared"
echo "                FORWARD_USER_INFO_HEADER_JWT_SECRET on Open WebUI."
echo "  CLI clients : docker exec -it $NAME python -m hoyolab_mcp.cli link-url --user <id>"
echo "                docker exec -it $NAME python -m hoyolab_mcp.cli issue-token --user <id>"
echo "                then use it as 'Authorization: Bearer <token>'."
