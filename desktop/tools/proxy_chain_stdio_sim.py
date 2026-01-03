#!/usr/bin/env python3
"""Deterministic 3-peer proxy-chain simulation (terminal-friendly).

Spawns three `proxy_stdio` processes and routes their `OUT` frames to each other as `IN` frames:

    A (client)  ->  B (gateway/proxy)  ->  C (final hop)

Assertions:
    - C must observe stream data with sender `peer_b` (not `peer_a`) to confirm hop identity masking.
    - An echo from C must return to A (via B) to confirm bidirectional flow.

Prereq:
    - Build the desktop tool: `desktop/build_mac/bin/proxy_stdio`

Run:
    python3 desktop/tools/proxy_chain_stdio_sim.py
"""
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Proc:
    peer_id: str
    p: subprocess.Popen


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


def hex_encode(b: bytes) -> str:
    return b.hex()


def main() -> int:
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    bin_path = os.path.join(root_dir, "desktop", "build_mac", "bin", "proxy_stdio")

    if not (os.path.isfile(bin_path) and os.access(bin_path, os.X_OK)):
        die(f"proxy_stdio not found/executable at: {bin_path}\nBuild desktop first.", 2)

    # Three peers:
    #   A: client
    #   B: gateway (proxy)
    #   C: final hop (echo + observe)
    peer_a = "peer_a"
    peer_b = "peer_b"
    peer_c = "peer_c"

    # Router: reads OUT lines and delivers them to recipients via IN lines.
    q: queue.Queue[tuple[str, str]] = queue.Queue()  # (from_peer, line)

    def start_peer(peer_id: str, args: list[str]) -> Proc:
        p = subprocess.Popen(
            [bin_path] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert p.stdin is not None
        assert p.stdout is not None

        def reader() -> None:
            for line in p.stdout:
                q.put((peer_id, line.rstrip("\n")))

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        return Proc(peer_id=peer_id, p=p)

    procs: dict[str, Proc] = {}

    # A is a proxy client.
    procs[peer_a] = start_peer(peer_a, ["--role", "client", "--self", peer_a])
    # B is a proxy gateway.
    procs[peer_b] = start_peer(peer_b, ["--role", "gateway", "--self", peer_b])
    # C is a final hop: we disable client/gateway features but enable echo of received stream data.
    procs[peer_c] = start_peer(peer_c, ["--role", "client", "--self", peer_c, "--client", "0", "--gateway", "0", "--echo", "1"])

    def send_line(to_peer: str, line: str) -> None:
        proc = procs[to_peer].p
        if proc.stdin is None:
            die(f"stdin closed for {to_peer}")
        proc.stdin.write(line + "\n")
        proc.stdin.flush()

    # Open stream from A to C via gateway B.
    stream_id = 1
    msg = b"hello-through-proxy"

    send_line(peer_a, f"CMD OPEN_STREAM_ROUTE {peer_b} {stream_id} {peer_c}")
    send_line(peer_a, f"CMD STREAM_DATA {peer_b} {stream_id} {hex_encode(msg)}")

    saw_c_recv_from_b = False
    saw_a_echo = False

    start = time.time()
    timeout_s = 5.0

    try:
        while time.time() - start < timeout_s:
            try:
                from_peer, line = q.get(timeout=0.2)
            except queue.Empty:
                continue

            # Forwarding: OUT <to_peer> <wire_hex>
            if line.startswith("OUT "):
                parts = line.split(" ", 2)
                if len(parts) != 3:
                    continue
                to_peer = parts[1]
                wire_hex = parts[2]
                if to_peer in procs:
                    send_line(to_peer, f"IN {from_peer} {wire_hex}")
                continue

            # Diagnostic line from proxy_stdio
            if line.startswith("RECV_STREAM "):
                # Example:
                # RECV_STREAM from=peer_b stream_id=1 close=0 len=... data_hex=....
                if from_peer == peer_c and "from=peer_b" in line and "close=0" in line:
                    saw_c_recv_from_b = True
                if from_peer == peer_a and "from=peer_b" in line and "data_hex=" + hex_encode(msg) in line:
                    saw_a_echo = True

            # If any peer exits unexpectedly, fail fast.
            for pid, pr in procs.items():
                rc = pr.p.poll()
                if rc is not None and rc != 0:
                    die(f"Peer {pid} exited early with code {rc}. Last line: {line}")

            if saw_c_recv_from_b and saw_a_echo:
                break

    finally:
        # Clean shutdown.
        for pid in [peer_a, peer_b, peer_c]:
            if pid in procs and procs[pid].p.poll() is None:
                try:
                    send_line(pid, "QUIT")
                except Exception:
                    pass

        time.sleep(0.2)
        for pr in procs.values():
            if pr.p.poll() is None:
                pr.p.terminate()
        time.sleep(0.2)
        for pr in procs.values():
            if pr.p.poll() is None:
                pr.p.kill()

    if not saw_c_recv_from_b:
        die("FAIL: Final hop C did not observe stream data from gateway B (peer_b).")

    if not saw_a_echo:
        die("FAIL: Client A did not receive echoed stream data back from gateway B.")

    print("PASS: A -> C via B works; C sees sender as B; echo returns to A.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
