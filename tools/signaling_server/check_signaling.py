import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Optional

import websockets


async def _recv_until(ws: websockets.WebSocketClientProtocol, *, predicate, timeout: float = 3.0) -> str:
    deadline = asyncio.get_event_loop().time() + timeout
    last: Optional[str] = None
    while asyncio.get_event_loop().time() < deadline:
        remaining = max(0.1, deadline - asyncio.get_event_loop().time())
        last = await asyncio.wait_for(ws.recv(), timeout=remaining)
        if predicate(last):
            return last
    raise TimeoutError(f"Timed out waiting for expected message; last={last!r}")


def _default_config_path() -> Path:
    # tools/signaling_server/check_signaling.py -> repo root
    return Path(__file__).resolve().parents[2] / "config.json"


def _load_signaling_url(config_path: Path) -> str:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    url = cfg.get("signaling", {}).get("url")
    if not isinstance(url, str) or not url:
        raise ValueError(f"No signaling.url found in {config_path}")
    return url


async def main_async(url: str, timeout: float) -> None:
    suffix = str(int(time.time()))
    peer_id = f"healthcheck-{suffix}"

    async with websockets.connect(url, open_timeout=timeout) as ws:
        await ws.send(f'{{"type":"REGISTER","peer_id":"{peer_id}"}}')
        await _recv_until(ws, predicate=lambda m: "REGISTER_ACK" in m, timeout=timeout)

        await ws.send('{"type":"LIST_PEERS"}')
        await _recv_until(ws, predicate=lambda m: "PEER_LIST" in m, timeout=timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check LiteP2P signaling server liveness")
    parser.add_argument("--url", default=None, help="Override signaling ws:// URL")
    parser.add_argument(
        "--config",
        default=str(_default_config_path()),
        help="Path to config.json (default: repo root config.json)",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout seconds")
    args = parser.parse_args()

    try:
        url = args.url or _load_signaling_url(Path(args.config))
        asyncio.run(main_async(url, args.timeout))
        print(f"OK: signaling reachable ({url})")
        return 0
    except Exception as e:
        print(f"ERROR: signaling check failed: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
