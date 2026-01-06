#!/usr/bin/env bash

# Standalone VPS deploy/update script for the LiteP2P signaling server.
#
# Usage on the VPS:
#   1) Save as: deploy_signaling.sh
#   2) Run:     sudo bash deploy_signaling.sh

set -euo pipefail
IFS=$'\n\t'

echo ">>> LiteP2P signaling: deploy/update"

if [[ "${EUID}" -ne 0 ]]; then
  echo ">>> ERROR: Please run as root (e.g. 'sudo bash deploy_signaling.sh')." >&2
  exit 1
fi

### ---- Config (edit if needed) ----
INSTALL_DIR="/opt/litep2p-signaling"
SERVICE_NAME="litep2p-signaling"
SERVICE_USER="litep2p"
SERVICE_HOME="/var/lib/litep2p"

# Signaling server bind
SIGNALING_HOST="0.0.0.0"
SIGNALING_PORT="8765"
LOG_LEVEL="INFO"

# Optional: install/configure coturn as well
ENABLE_COTURN="0"   # set to 1 to enable
TURN_USER="${TURN_USER:-litep2p}"
TURN_PASS="${TURN_PASS:-TURN_PASSWORD}"   # ← override via env when running
TURN_REALM="${TURN_REALM:-litep2p.org}"

### ---- Helpers ----
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo ">>> ERROR: Missing required command: $1" >&2
    exit 1
  }
}

as_service_user() {
    local cmd="$1"
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$SERVICE_USER" -- env HOME="$SERVICE_HOME" PIP_CACHE_DIR="$SERVICE_HOME/.cache/pip" bash -lc "$cmd"
        return $?
    fi
    env HOME="$SERVICE_HOME" PIP_CACHE_DIR="$SERVICE_HOME/.cache/pip" su -s /bin/bash "$SERVICE_USER" -c "$cmd"
}

require_cmd apt-get

echo ">>> Installing OS dependencies (python3, venv, curl)..."
apt-get update
apt-get install -y python3 python3-venv curl ca-certificates

echo ">>> Ensuring service user '$SERVICE_USER' exists..."
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$SERVICE_HOME" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

echo ">>> Ensuring service home exists: $SERVICE_HOME"
mkdir -p "$SERVICE_HOME/.cache/pip"
chown -R "$SERVICE_USER:$SERVICE_USER" "$SERVICE_HOME"

echo ">>> Preparing install dir: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

echo ">>> Writing requirements.txt"
cat > "$INSTALL_DIR/requirements.txt" <<'REQ'
websockets>=11,<14
REQ

echo ">>> Writing server.py"
cat > "$INSTALL_DIR/server.py" <<'PY'
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import websockets


def _get_log_level() -> int:
    level = os.environ.get("LOG_LEVEL", "INFO").upper().strip()
    return getattr(logging, level, logging.INFO)


logging.basicConfig(
    level=_get_log_level(),
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Store connected peers:
#   {peer_id: {"ws": websocket/connection, "network_id": str | None}}
peers: dict[str, dict[str, Any]] = {}


def _peer_snapshot(exclude_peer_id: str | None = None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for pid, entry in peers.items():
        if exclude_peer_id is not None and pid == exclude_peer_id:
            continue
        peer_obj: dict[str, Any] = {"peer_id": pid}
        network_id = entry.get("network_id")
        if network_id is not None:
            peer_obj["network_id"] = network_id
        items.append(peer_obj)
    # Stable ordering for tests/logging.
    items.sort(key=lambda x: x.get("peer_id") or "")
    return items


async def _safe_send(ws: Any, payload: dict[str, Any]) -> bool:
    try:
        await ws.send(json.dumps(payload))
        return True
    except websockets.exceptions.ConnectionClosed:
        return False


def _extract_path(ws: Any) -> str | None:
    path = getattr(ws, "path", None)
    if path is not None:
        return path

    request = getattr(ws, "request", None)
    return getattr(request, "path", None)


# websockets v11 (legacy) may call handler(websocket, path)
# websockets v12+ calls handler(connection)
async def handler(*args: Any, **kwargs: Any) -> None:
    if not args:
        raise TypeError("handler() missing websocket/connection argument")

    websocket = args[0]
    path = args[1] if len(args) >= 2 else _extract_path(websocket)

    peer_id: str | None = None
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                logging.warning("Received non-JSON message; ignoring")
                continue

            msg_type = data.get("type")

            if msg_type == "REGISTER":
                peer_id = data.get("peer_id")
                if peer_id:
                    network_id = data.get("network_id")
                    # Replace existing connection for the same peer_id.
                    peers[peer_id] = {"ws": websocket, "network_id": network_id}
                    logging.info("Peer registered: %s (path=%s)", peer_id, path)

                    # ACK first.
                    await _safe_send(websocket, {"type": "REGISTER_ACK", "status": "OK"})

                    # Notify existing peers that someone joined.
                    joined_peer: dict[str, Any] = {"peer_id": peer_id}
                    if network_id is not None:
                        joined_peer["network_id"] = network_id
                    joined_payload = {"type": "PEER_JOINED", "peer": joined_peer}
                    for other_id, entry in list(peers.items()):
                        if other_id == peer_id:
                            continue
                        ok = await _safe_send(entry.get("ws"), joined_payload)
                        if not ok:
                            peers.pop(other_id, None)
                else:
                    logging.warning("Register attempt without peer_id")

            elif msg_type == "LIST_PEERS":
                if not peer_id:
                    logging.warning("LIST_PEERS before REGISTER; ignoring")
                    continue
                await _safe_send(websocket, {"type": "PEER_LIST", "peers": _peer_snapshot(exclude_peer_id=peer_id)})

            elif msg_type == "UPDATE":
                # Optional metadata update (e.g., external network_id).
                if not peer_id:
                    logging.warning("UPDATE before REGISTER; ignoring")
                    continue
                entry = peers.get(peer_id)
                if not entry or entry.get("ws") is not websocket:
                    logging.warning("UPDATE from unknown peer_id=%s; ignoring", peer_id)
                    continue
                entry["network_id"] = data.get("network_id")
                logging.info("Peer updated: %s network_id=%s", peer_id, entry.get("network_id"))

                # Broadcast update to other peers so they can refresh a previously-unknown endpoint.
                updated_peer: dict[str, Any] = {"peer_id": peer_id}
                if entry.get("network_id") is not None:
                    updated_peer["network_id"] = entry.get("network_id")
                updated_payload = {"type": "PEER_UPDATED", "peer": updated_peer}
                for other_id, other_entry in list(peers.items()):
                    if other_id == peer_id:
                        continue
                    ok = await _safe_send(other_entry.get("ws"), updated_payload)
                    if not ok:
                        peers.pop(other_id, None)

            elif msg_type == "SIGNAL":
                target_id = data.get("target_peer_id")
                payload = data.get("payload")
                if target_id in peers:
                    target_ws = peers[target_id].get("ws")
                    try:
                        await target_ws.send(
                            json.dumps(
                                {
                                    "type": "SIGNAL",
                                    "source_peer_id": peer_id,
                                    "payload": payload,
                                }
                            )
                        )
                        logging.info("Signal forwarded from %s to %s", peer_id, target_id)
                    except websockets.exceptions.ConnectionClosed:
                        logging.warning("Failed to send to %s, connection closed", target_id)
                        peers.pop(target_id, None)
                else:
                    logging.warning("Target peer %s not found", target_id)

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        logging.exception("Unhandled server error: %s", e)
    finally:
        if peer_id:
            entry = peers.get(peer_id)
            if entry and entry.get("ws") is websocket:
                # Remove first so snapshots don't include the leaver.
                peers.pop(peer_id, None)
                logging.info("Peer disconnected: %s", peer_id)

                left_payload = {"type": "PEER_LEFT", "peer_id": peer_id}
                for other_id, other_entry in list(peers.items()):
                    ok = await _safe_send(other_entry.get("ws"), left_payload)
                    if not ok:
                        peers.pop(other_id, None)


async def main() -> None:
    host = os.environ.get("SIGNALING_HOST", "0.0.0.0")
    port = int(os.environ.get("SIGNALING_PORT", "8765"))

    # Keepalive knobs (useful for CI/soak tests). If unset, websockets defaults apply.
    ping_interval = os.environ.get("SIGNALING_PING_INTERVAL")
    ping_timeout = os.environ.get("SIGNALING_PING_TIMEOUT")
    serve_kwargs: dict[str, Any] = {}
    try:
        if ping_interval is not None:
            serve_kwargs["ping_interval"] = float(ping_interval)
        if ping_timeout is not None:
            serve_kwargs["ping_timeout"] = float(ping_timeout)
    except ValueError:
        logging.warning("Invalid SIGNALING_PING_INTERVAL/SIGNALING_PING_TIMEOUT; using defaults")

    async with websockets.serve(handler, host, port, **serve_kwargs):
        logging.info("Signaling server started on %s:%s", host, port)
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
PY

chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/server.py" "$INSTALL_DIR/requirements.txt"

echo ">>> Ensuring venv exists"
if [[ ! -d "$INSTALL_DIR/venv" ]]; then
    as_service_user "python3 -m venv '$INSTALL_DIR/venv'" || python3 -m venv "$INSTALL_DIR/venv"
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/venv"

echo ">>> Installing/updating python deps"
as_service_user "'$INSTALL_DIR/venv/bin/pip' install --disable-pip-version-check --no-cache-dir --upgrade pip" >/dev/null 2>&1 || true
as_service_user "'$INSTALL_DIR/venv/bin/pip' install --disable-pip-version-check --no-cache-dir -r '$INSTALL_DIR/requirements.txt'"

echo ">>> Installing systemd unit: $SERVICE_NAME"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=LiteP2P Signaling Server
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/server.py
Environment=PYTHONUNBUFFERED=1
Environment=SIGNALING_HOST=${SIGNALING_HOST}
Environment=SIGNALING_PORT=${SIGNALING_PORT}
Environment=LOG_LEVEL=${LOG_LEVEL}
Restart=always
RestartSec=3

# Basic hardening (safe defaults)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
systemctl restart "$SERVICE_NAME"

if [[ "$ENABLE_COTURN" == "1" ]]; then
  echo ">>> Installing coturn"
  apt-get install -y coturn

  echo ">>> Configuring coturn"
  if [[ -f /etc/turnserver.conf && ! -f /etc/turnserver.conf.bak ]]; then
    cp /etc/turnserver.conf /etc/turnserver.conf.bak
  fi

  PUBLIC_IP="$(curl -fsS ifconfig.me || true)"
  if [[ -z "$PUBLIC_IP" ]]; then
    echo ">>> WARNING: Could not detect public IP; external-ip will not be set." >&2
  fi

  cat > /etc/turnserver.conf <<EOF
listening-port=3478
tls-listening-port=5349

fingerprint
lt-cred-mech
user=${TURN_USER}:${TURN_PASS}
realm=${TURN_REALM}

log-file=/var/log/turnserver.log
simple-log

min-port=49152
max-port=65535
EOF

  if [[ -n "$PUBLIC_IP" ]]; then
    echo "external-ip=${PUBLIC_IP}" >> /etc/turnserver.conf
  fi

  sed -i 's/^#\?TURNSERVER_ENABLED=.*/TURNSERVER_ENABLED=1/g' /etc/default/coturn || true
  systemctl restart coturn
fi

echo ">>> Done."
echo ">>> Service status: systemctl status ${SERVICE_NAME} --no-pager"
if [[ "$ENABLE_COTURN" == "1" ]]; then
  echo ">>> Coturn status:  systemctl status coturn --no-pager"
fi
