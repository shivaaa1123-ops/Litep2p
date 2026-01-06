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

                    # ACK first (tests expect this to be the first response).
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
