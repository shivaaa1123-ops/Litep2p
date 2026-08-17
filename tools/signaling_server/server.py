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

# ---------------------------------------------------------------------------
# v0.4 extensions (ask.md §2/§3/§5)
# ---------------------------------------------------------------------------
# Identity directory: alias_hash -> peer_id. Aliases are opaque hashes (e.g.
# SHA-256 of a normalized phone number); the server never sees raw values.
# Persisted across restarts via SIGNALING_STATE_FILE when set.
aliases: dict[str, str] = {}

# Offline mailbox (store-and-forward): target_peer_id -> [message, ...].
# Each message: {"msg_id", "from_peer_id", "payload_b64", "stored_ms"}.
offline_messages: dict[str, list[dict[str, Any]]] = {}

# Last-seen epoch ms per peer (updated on register/disconnect).
last_seen: dict[str, int] = {}

# Presence subscriptions: subscriber_peer_id -> set(peer_id).
presence_subscriptions: dict[str, set[str]] = {}

# Offline queue policy (env-overridable for tests).
OFFLINE_MAX_MESSAGES = int(os.environ.get("SIGNALING_OFFLINE_MAX_MESSAGES", "500"))
OFFLINE_TTL_MS = int(os.environ.get("SIGNALING_OFFLINE_TTL_MS", str(7 * 24 * 3600 * 1000)))
STATE_FILE = os.environ.get("SIGNALING_STATE_FILE", "")


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


def _load_state() -> None:
    """Load persisted alias/last-seen state (best-effort)."""
    if not STATE_FILE or not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
        aliases.update(state.get("aliases", {}))
        last_seen.update({k: int(v) for k, v in state.get("last_seen", {}).items()})
        logging.info("Loaded signaling state: %d aliases", len(aliases))
    except Exception as e:  # noqa: BLE001
        logging.warning("Failed to load signaling state: %s", e)


def _save_state() -> None:
    """Persist alias/last-seen state (best-effort, debounced by caller)."""
    if not STATE_FILE:
        return
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"aliases": aliases, "last_seen": last_seen}, f)
    except Exception as e:  # noqa: BLE001
        logging.warning("Failed to save signaling state: %s", e)


def _prune_offline_messages() -> None:
    """Drop expired / over-capacity offline messages."""
    now = _now_ms()
    for pid in list(offline_messages.keys()):
        msgs = offline_messages[pid]
        msgs[:] = [m for m in msgs if now - m.get("stored_ms", 0) <= OFFLINE_TTL_MS]
        if len(msgs) > OFFLINE_MAX_MESSAGES:
            del msgs[: len(msgs) - OFFLINE_MAX_MESSAGES]
        if not msgs:
            del offline_messages[pid]


def _broadcast_presence(peer_id: str, online: bool) -> None:
    """Notify subscribers that a peer's presence changed."""
    payload = {
        "type": "PRESENCE",
        "peer_id": peer_id,
        "online": online,
        "last_seen_ms": last_seen.get(peer_id, 0),
    }
    for sub_id, watched in list(presence_subscriptions.items()):
        if peer_id not in watched:
            continue
        entry = peers.get(sub_id)
        if not entry:
            continue
        # Fire-and-forget; failures cleaned up on disconnect.
        asyncio.ensure_future(_safe_send(entry.get("ws"), payload))


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
                    last_seen[peer_id] = _now_ms()
                    logging.info("Peer registered: %s (path=%s)", peer_id, path)

                    # ACK first (tests expect this to be the first response).
                    await _safe_send(websocket, {"type": "REGISTER_ACK", "status": "OK"})

                    # v0.4: deliver any offline messages held for this peer.
                    held = offline_messages.pop(peer_id, None)
                    if held:
                        await _safe_send(
                            websocket,
                            {"type": "STORED_MESSAGES", "messages": held},
                        )
                        logging.info("Delivered %d offline messages to %s", len(held), peer_id)

                    # v0.4: notify presence subscribers this peer is online.
                    _broadcast_presence(peer_id, True)

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

            # ------------------------------------------------------------------
            # v0.4 extensions (ask.md §2/§3/§5)
            # ------------------------------------------------------------------
            elif msg_type == "STORE":
                # Offline mailbox: hold a message for an offline target peer.
                if not peer_id:
                    logging.warning("STORE before REGISTER; ignoring")
                    continue
                target_id = data.get("target_peer_id")
                m_id = data.get("msg_id")
                payload_b64 = data.get("payload_b64")
                if not target_id or not m_id:
                    logging.warning("STORE missing target_peer_id/msg_id; ignoring")
                    continue
                _prune_offline_messages()
                if target_id in peers:
                    # Target is online: deliver immediately instead of storing.
                    target_ws = peers[target_id].get("ws")
                    await _safe_send(
                        target_ws,
                        {
                            "type": "STORED_MESSAGES",
                            "messages": [
                                {
                                    "msg_id": m_id,
                                    "from_peer_id": peer_id,
                                    "payload_b64": payload_b64,
                                }
                            ],
                        },
                    )
                    logging.info("STORE: target %s online, delivered directly", target_id)
                else:
                    offline_messages.setdefault(target_id, []).append(
                        {
                            "msg_id": m_id,
                            "from_peer_id": peer_id,
                            "payload_b64": payload_b64,
                            "stored_ms": _now_ms(),
                        }
                    )
                    logging.info("STORE: held message %s for offline peer %s", m_id, target_id)

            elif msg_type == "FETCH":
                # Retrieve any offline messages held for the caller.
                if not peer_id:
                    logging.warning("FETCH before REGISTER; ignoring")
                    continue
                held = offline_messages.pop(peer_id, None)
                if held:
                    await _safe_send(websocket, {"type": "STORED_MESSAGES", "messages": held})
                    logging.info("FETCH: delivered %d messages to %s", len(held), peer_id)

            elif msg_type == "REGISTER_ALIAS":
                # Identity directory: map an opaque alias hash to this peer.
                if not peer_id:
                    logging.warning("REGISTER_ALIAS before REGISTER; ignoring")
                    continue
                alias = data.get("alias")
                if not alias:
                    logging.warning("REGISTER_ALIAS missing alias; ignoring")
                    continue
                aliases[alias] = peer_id
                _save_state()
                logging.info("Alias registered: %s -> %s", alias, peer_id)
                await _safe_send(websocket, {"type": "ALIAS_ACK", "status": "OK", "alias": alias})

            elif msg_type == "LOOKUP":
                # Resolve an alias hash to a peer id (+ presence).
                alias = data.get("alias")
                if not alias:
                    continue
                resolved = aliases.get(alias, "")
                online = bool(resolved) and resolved in peers
                await _safe_send(
                    websocket,
                    {
                        "type": "LOOKUP_RESULT",
                        "alias": alias,
                        "peer_id": resolved,
                        "online": online,
                        "last_seen_ms": last_seen.get(resolved, 0) if resolved else 0,
                    },
                )

            elif msg_type == "INVITE":
                # Nudge a remote peer to connect (signaling push).
                if not peer_id:
                    logging.warning("INVITE before REGISTER; ignoring")
                    continue
                target_id = data.get("target_peer_id")
                if not target_id:
                    continue
                if target_id in peers:
                    target_ws = peers[target_id].get("ws")
                    await _safe_send(
                        target_ws,
                        {"type": "INVITE", "source_peer_id": peer_id},
                    )
                    logging.info("INVITE forwarded from %s to %s", peer_id, target_id)
                else:
                    logging.info("INVITE target %s offline; dropped", target_id)

            elif msg_type == "SUBSCRIBE_PRESENCE":
                # Server-assisted presence subscription.
                if not peer_id:
                    logging.warning("SUBSCRIBE_PRESENCE before REGISTER; ignoring")
                    continue
                watched = data.get("peer_ids") or []
                presence_subscriptions.setdefault(peer_id, set()).update(
                    p for p in watched if isinstance(p, str) and p
                )
                # Immediately report current state for each subscribed peer.
                for p in watched:
                    if not isinstance(p, str) or not p:
                        continue
                    await _safe_send(
                        websocket,
                        {
                            "type": "PRESENCE",
                            "peer_id": p,
                            "online": p in peers,
                            "last_seen_ms": last_seen.get(p, 0),
                        },
                    )

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
                last_seen[peer_id] = _now_ms()
                logging.info("Peer disconnected: %s", peer_id)

                # v0.4: notify presence subscribers this peer went offline.
                _broadcast_presence(peer_id, False)
                presence_subscriptions.pop(peer_id, None)

                left_payload = {"type": "PEER_LEFT", "peer_id": peer_id}
                for other_id, other_entry in list(peers.items()):
                    ok = await _safe_send(other_entry.get("ws"), left_payload)
                    if not ok:
                        peers.pop(other_id, None)


async def main() -> None:
    host = os.environ.get("SIGNALING_HOST", "0.0.0.0")
    port = int(os.environ.get("SIGNALING_PORT", "8765"))

    # v0.4: load persisted alias/last-seen state (identity directory survives restarts).
    _load_state()

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
