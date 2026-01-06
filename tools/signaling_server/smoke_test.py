import asyncio
import argparse
import os
import sys
import time
from pathlib import Path
from typing import Optional

import websockets

# Allow running this file directly without requiring PYTHONPATH.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.signaling_server import server


async def _register(ws: websockets.WebSocketClientProtocol, peer_id: str) -> None:
    await ws.send(f'{{"type":"REGISTER","peer_id":"{peer_id}"}}')
    ack = await asyncio.wait_for(ws.recv(), timeout=2)
    assert '"REGISTER_ACK"' in ack


async def _recv_until(ws: websockets.WebSocketClientProtocol, *, predicate, timeout: float = 3.0) -> str:
    """Receive messages until predicate(message) is True or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    last: Optional[str] = None
    while asyncio.get_event_loop().time() < deadline:
        remaining = max(0.1, deadline - asyncio.get_event_loop().time())
        last = await asyncio.wait_for(ws.recv(), timeout=remaining)
        if predicate(last):
            return last
    raise TimeoutError(f"Timed out waiting for expected message; last={last!r}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="LiteP2P signaling server smoke test")
    parser.add_argument(
        "--url",
        dest="url",
        default=None,
        help='WebSocket URL to test (e.g. "ws://1.2.3.4:8765"). If omitted, uses SIGNALING_URL env; if still omitted, starts a local ephemeral server.',
    )
    args = parser.parse_args()

    uri = args.url or os.environ.get("SIGNALING_URL")

    # Default: local ephemeral server.
    local_server = None
    is_remote_target = bool(uri)
    if not uri:
        server.peers.clear()
        local_server = await websockets.serve(server.handler, "127.0.0.1", 0)
        port = local_server.sockets[0].getsockname()[1]
        uri = f"ws://127.0.0.1:{port}"

    suffix = str(int(time.time()))
    peer_a = f"peer-a-{suffix}"
    peer_b = f"peer-b-{suffix}"

    try:
        async with websockets.connect(uri) as a, websockets.connect(uri) as b:
            await _register(a, peer_a)
            await _register(b, peer_b)

            # Validate UPDATE -> PEER_UPDATED broadcast.
            updated_network_id = "203.0.113.9:45678"
            await b.send(f'{{"type":"UPDATE","network_id":"{updated_network_id}"}}')
            msg = await _recv_until(
                a,
                predicate=lambda m: (
                    '"type": "PEER_UPDATED"' in m
                    or '"type":"PEER_UPDATED"' in m
                )
                and peer_b in m
                and updated_network_id in m,
                timeout=3,
            )
            assert peer_b in msg
            assert updated_network_id in msg

            # Validate peer listing. Server can also send PEER_JOINED to existing peers,
            # so we wait specifically for PEER_LIST.
            await a.send('{"type":"LIST_PEERS"}')
            msg = await _recv_until(a, predicate=lambda m: '"type": "PEER_LIST"' in m or '"type":"PEER_LIST"' in m)
            assert peer_b in msg
            assert updated_network_id in msg

            await b.send('{"type":"LIST_PEERS"}')
            msg = await _recv_until(b, predicate=lambda m: '"type": "PEER_LIST"' in m or '"type":"PEER_LIST"' in m)
            assert peer_a in msg

            await a.send(
                '{"type":"SIGNAL","target_peer_id":"' + peer_b + '","payload":{"hello":"world"}}'
            )
            msg = await _recv_until(b, predicate=lambda m: '"type": "SIGNAL"' in m or '"type":"SIGNAL"' in m, timeout=3)
            assert '"type": "SIGNAL"' in msg or '"type":"SIGNAL"' in msg
            assert peer_a in msg

        where = "remote" if is_remote_target else "local"
        print(f"OK: signaling server smoke test passed ({where}, {uri})")
    finally:
        if local_server is not None:
            local_server.close()
            await local_server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
