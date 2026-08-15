#!/usr/bin/env python3
"""
End-to-end reliability test for the LiteP2P desktop peer.

Exercises the REAL peer binary end to end:
  - startup with the shared config (incl. security.transport_key)
  - LAN/broadcast discovery
  - auto-connect + Noise handshake to READY
  - application message delivery in BOTH directions (via the plain CLI)
  - peer kill + restart -> discovery re-connect -> messaging resumes
  - optional third peer to verify a small mesh

Usage:
  python3 tools/harness/e2e_messaging_test.py [--peers 2|3] [--config path] [--leave]
  --leave : keep peers running at the end (for a manual demo), else stop them.

Exit status: 0 = all assertions passed, 1 = failed, 2 = broken environment.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

BIN_CANDIDATES = [
    REPO_ROOT / "desktop" / "build_mac" / "bin" / "litep2p_peer_mac",
    REPO_ROOT / "desktop" / "build_linux" / "bin" / "litep2p_peer_linux",
    REPO_ROOT / "desktop" / "build_linux_docker" / "bin" / "litep2p_peer_linux",
]

WORK_ROOT = Path("/tmp") / f"litep2p_e2e_{os.getpid()}"


def log(msg: str) -> None:
    print(f"[e2e] {msg}", flush=True)


def find_binary() -> Path:
    for b in BIN_CANDIDATES:
        if b.is_file() and os.access(b, os.X_OK):
            return b
    return Path("")


class Peer:
    """Wraps a litep2p_peer_* process driven through the plain CLI (--no-tui)."""

    def __init__(self, pid: str, port: int, config_path: Path, workdir: Path):
        self.pid = pid
        self.port = port
        self.config = config_path
        self.workdir = workdir
        self.proc = None
        self.lines = []
        self.lines_lock = threading.Lock()
        self.reader = None

    def start(self) -> bool:
        self.workdir.mkdir(parents=True, exist_ok=True)
        cmd = [
            str(find_binary()),
            "--id", self.pid,
            "--port", str(self.port),
            "--config", str(self.config),
            "--no-tui",
            "--log-level", "info",
        ]
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(self.workdir),
        )
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        return self.proc.poll() is None

    def _read_loop(self):
        try:
            for line in self.proc.stdout:
                with self.lines_lock:
                    self.lines.append(line.rstrip("\n"))
                    if len(self.lines) > 5000:
                        del self.lines[:1000]
        except (ValueError, OSError):
            pass

    def send_cmd(self, cmd: str) -> None:
        if self.proc and self.proc.stdin:
            try:
                self.proc.stdin.write(cmd + "\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

    def text(self) -> str:
        with self.lines_lock:
            return "\n".join(self.lines)

    def wait_for(self, rx: re.Pattern, timeout: float, desc: str = "") -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if rx.search(self.text()):
                if desc:
                    log(f"  OK {self.pid}: {desc}")
                return True
            time.sleep(0.25)
        log(f"  TIMEOUT {self.pid} waiting for /{rx.pattern}/" + (f" ({desc})" if desc else ""))
        return False

    # Helper: wait until the engine logs a delivered application message (either via the
    # CLI "from:" line or the engine's authoritative "Message content: [msg]" line).
    def wait_message(self, msg: str, timeout: float) -> bool:
        rx = re.compile(r"Message content: \[" + re.escape(msg) + r"\]")
        return self.wait_for(rx, timeout, f"received application message '{msg}'")

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        self.proc = None


def dump_tails(peers):
    for p in peers:
        tail = "\n".join(p.text().splitlines()[-15:])
        log(f"----- {p.pid} log tail -----\n{tail}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None, help="config.json for every peer (default: repo config.json)")
    ap.add_argument("--peers", type=int, choices=[2, 3], default=2, help="number of peers to run")
    ap.add_argument("--leave", action="store_true", help="keep peers running at the end")
    ap.add_argument("--timeout", type=float, default=75.0, help="per-stage timeout seconds")
    args = ap.parse_args()

    if not find_binary():
        log("ERROR: desktop peer binary not found. Build it with desktop/build_mac.sh first.")
        return 2

    config = Path(args.config).resolve() if args.config else REPO_ROOT / "config.json"
    if not config.is_file():
        log(f"ERROR: config not found: {config}")
        return 2

    shutil.rmtree(WORK_ROOT, ignore_errors=True)
    WORK_ROOT.mkdir(parents=True, exist_ok=True)

    peers = []
    for idx in range(1, args.peers + 1):
        pid = f"e2e-mesh-{idx}"
        wd = WORK_ROOT / f"peer{idx}"
        wd.mkdir(parents=True, exist_ok=True)
        cfg = wd / "config.json"
        shutil.copy2(config, cfg)
        peers.append(Peer(pid, 31100 + idx, cfg, wd))

    try:
        log(f"binary = {find_binary()}  config = {config}")
        for p in peers:
            ok = p.start()
            log(f"start {p.pid} port={p.port} -> {'ok' if ok else 'FAILED'}")
            if not ok:
                return 1
        time.sleep(6)  # discovery + signaling bootstrap settle

        a, b = peers[0], peers[1]

        # 1) Connect: A <-> B reach READY over the shared-key transport.
        ok = (
            a.wait_for(re.compile(r"READY peer=" + re.escape(b.pid)), args.timeout,
                       f"READY with {b.pid}")
            and b.wait_for(re.compile(r"READY peer=" + re.escape(a.pid)), args.timeout,
                           f"READY with {a.pid}")
        )
        if not ok:
            dump_tails(peers)
            return 1

        # 2) Message A -> B.
        msg1 = f"hello-from-A-{int(time.time())}"
        a.send_cmd(f"send {b.pid} {msg1}")
        if not b.wait_message(msg1, args.timeout):
            dump_tails(peers)
            return 1

        # 3) Message B -> A.
        msg2 = f"hello-from-B-{int(time.time())}"
        b.send_cmd(f"send {a.pid} {msg2}")
        if not a.wait_message(msg2, args.timeout):
            dump_tails(peers)
            return 1
        print("[e2e] bidirectional message delivery verified", flush=True)

        # 4) Crash/restart recovery.
        log(f"crash test: terminating {b.pid}")
        b.stop()
        time.sleep(3)
        b.start()
        time.sleep(6)  # discovery interval is 5s
        if not b.wait_for(re.compile(r"READY peer=" + re.escape(a.pid)), args.timeout,
                          "re-READY after restart"):
            dump_tails(peers)
            return 1
        msg3 = f"post-restart-{int(time.time())}"
        a.send_cmd(f"send {b.pid} {msg3}")
        if not b.wait_message(msg3, args.timeout):
            dump_tails(peers)
            return 1
        log("crash/restart recovery verified (reconnected, message delivered)")

        # 5) Optional third peer mesh.
        if args.peers >= 3:
            c = peers[2]
            ok = (
                c.wait_for(re.compile(r"READY peer=" + re.escape(a.pid)), args.timeout,
                           f"READY with {a.pid}")
                and a.wait_for(re.compile(r"READY peer=" + re.escape(c.pid)), args.timeout,
                               f"A READY with {c.pid}")
                and c.wait_for(re.compile(r"READY peer=" + re.escape(b.pid)), args.timeout,
                               f"C READY with {b.pid}")
            )
            if not ok:
                dump_tails(peers)
                return 1
            msg4 = f"mesh-{int(time.time())}"
            c.send_cmd(f"send {a.pid} {msg4}")
            if not a.wait_message(msg4, args.timeout):
                dump_tails(peers)
                return 1
            log("3-peer mesh verified")

        log("E2E PASS: discovery -> READY -> bidirectional messages -> restart recovery -> mesh")
        if args.leave:
            log("peers left running (--leave):")
            for p in peers:
                log(f"  {p.pid}: pid={p.proc.pid} port={p.port}")
        else:
            for p in peers:
                p.stop()
        return 0
    except KeyboardInterrupt:
        log("interrupted")
        for p in peers:
            p.stop()
        return 1


if __name__ == "__main__":
    sys.exit(main())