#!/usr/bin/env python3

"""Restart/reconnect regression test for LiteP2P desktop peer.

Scenario (matches your report):
  1) Start two peers A and B on the same LAN.
  2) A discovers B, connects, sends a message (B receives it).
  3) Kill A (simulate app close).
  4) Verify B still (incorrectly) may show A as connected for some time.
  5) Restart A with the SAME peer id and SAME port.
  6) A should be able to connect again and send a message to B.

This script drives the desktop peer in "--no-tui" (plain) mode by writing
commands to stdin and parsing stdout.

Usage (macOS, from repo root):
  ./.venv/bin/python tools/restart_reconnect_test.py

Optional:
  ./.venv/bin/python tools/restart_reconnect_test.py --binary ./desktop/build_mac/bin/litep2p_peer_mac
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Optional, Tuple


ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class PeerProc:
    name: str
    proc: subprocess.Popen
    lines: Deque[str]


def find_default_binary() -> Path:
    root = Path(__file__).resolve().parents[1]

    candidates = [
        root / "desktop" / "build_mac" / "bin" / "litep2p_peer_mac",
        root / "desktop" / "build_linux" / "bin" / "litep2p_peer_linux",
        root / "desktop" / "build_linux_docker" / "bin" / "litep2p_peer_linux",
        root / "build" / "litep2p_peer",
    ]

    for c in candidates:
        try:
            if c.exists() and os.access(str(c), os.X_OK):
                return c
        except Exception:
            continue

    raise FileNotFoundError(
        "Could not find a litep2p desktop peer binary. Tried:\n"
        + "\n".join(f"  - {p}" for p in candidates)
    )


def build_lan_safe_config_path(explicit_config: Optional[Path]) -> Tuple[Optional[Path], Optional[Path]]:
    """Return (config_to_use, temp_path_to_delete).

    If the caller passed an explicit config, we respect it.
    Otherwise we generate a temporary config that disables signaling/NAT traversal
    so same-host LAN tests don't attempt public-IP hairpin via signaling.
    """
    if explicit_config is not None:
        return explicit_config, None

    repo_root = Path(__file__).resolve().parents[1]
    repo_config = repo_root / "config.json"
    try:
        data = json.loads(repo_config.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(f"Failed to read/parse repo config.json at {repo_config}: {e}")

    # Force LAN mode.
    data.setdefault("signaling", {})
    data["signaling"]["enabled"] = False
    # NOTE: SessionManager currently attempts to connect regardless of `enabled`.
    # Point it at an invalid local endpoint so broadcast discovery is used.
    data["signaling"]["url"] = "ws://127.0.0.1:1"
    data["signaling"]["reconnect_interval_ms"] = 60000

    data.setdefault("nat_traversal", {})
    data["nat_traversal"]["enabled"] = False
    data["nat_traversal"]["stun_enabled"] = False
    data["nat_traversal"]["turn_enabled"] = False
    data["nat_traversal"]["hole_punching_enabled"] = False

    # Keep discovery enabled.
    data.setdefault("discovery", {})
    data.setdefault("global_discovery", {})
    data["global_discovery"]["enabled"] = False

    # Make disconnect detection faster for this restart scenario.
    data.setdefault("peer_management", {})
    data["peer_management"].setdefault("peer_expiration_timeout_ms", 10000)
    data["peer_management"].setdefault("ping_interval_sec", 2)
    data["peer_management"].setdefault("heartbeat_interval_sec", 2)
    data["peer_management"].setdefault("timer_tick_interval_sec", 1)

    tmp = tempfile.NamedTemporaryFile(prefix="litep2p_lan_", suffix=".json", delete=False)
    tmp_path = Path(tmp.name)
    try:
        tmp.write(json.dumps(data, indent=2).encode("utf-8"))
        tmp.flush()
    finally:
        tmp.close()

    return tmp_path, tmp_path


def start_peer(
    *,
    name: str,
    binary: Path,
    port: int,
    peer_id: str,
    log_level: str,
    config: Optional[Path],
    verbose: bool,
) -> PeerProc:
    cmd = [
        str(binary),
        "--no-tui",
        "--port",
        str(port),
        "--id",
        peer_id,
        "--log-level",
        log_level,
    ]
    if config is not None:
        cmd.extend(["--config", str(config)])

    # Start in its own process group so we can kill the whole group.
    proc = subprocess.Popen(
        cmd,
        cwd=str(Path(__file__).resolve().parents[1]),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        preexec_fn=os.setsid if hasattr(os, "setsid") else None,
    )

    lines: Deque[str] = deque(maxlen=4000)

    def reader() -> None:
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = strip_ansi(raw.rstrip("\n"))
            lines.append(line)
            if verbose:
                sys.stdout.write(f"[{name}] {line}\n")
                sys.stdout.flush()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    return PeerProc(name=name, proc=proc, lines=lines)


def send_cmd(peer: PeerProc, cmd: str) -> None:
    if peer.proc.poll() is not None:
        raise RuntimeError(f"{peer.name} process is not running")
    assert peer.proc.stdin is not None
    peer.proc.stdin.write(cmd + "\n")
    peer.proc.stdin.flush()


def wait_for_line(peer: PeerProc, pattern: re.Pattern, timeout_s: float) -> Optional[str]:
    deadline = time.time() + timeout_s
    # NOTE: Do not start scanning strictly from "now". Some events (like "Connected:")
    # can be logged extremely quickly after we send a command, and we can miss them
    # due to a small race between send_cmd() and entering this function.
    # Scan a small tail window to make the harness robust under fast localhost/VPS runs.
    start_idx = max(0, len(peer.lines) - 400)
    while time.time() < deadline:
        if peer.proc.poll() is not None:
            return None
        # Scan new lines only.
        buf = list(peer.lines)
        for line in buf[start_idx:]:
            if pattern.search(line):
                return line
        start_idx = len(buf)
        time.sleep(0.05)
    return None


def extract_peer_list(peer: PeerProc) -> Tuple[Tuple[str, bool], ...]:
    """Parse the most recent `peers` output block.

    The CLI prints:
      ═══════════ PEERS (full) ═══════════
      Found: N peer(s)
      <peer_id>  [CONNECTED|DISCONNECTED]

    We grab the latest block from the tail buffer.
    """
    tail = list(peer.lines)
    # find last header
    header_idx = -1
    for i in range(len(tail) - 1, -1, -1):
        if "PEERS (full)" in tail[i]:
            header_idx = i
            break
    if header_idx < 0:
        return tuple()

    parsed = []
    for line in tail[header_idx:]:
        if not line.strip():
            continue
        m = re.match(r"^(?P<id>\S+)\s+\[(?P<st>CONNECTED|DISCONNECTED)\]", line.strip())
        if m:
            parsed.append((m.group("id"), m.group("st") == "CONNECTED"))
    return tuple(parsed)


def kill_peer(peer: PeerProc, sig: int, timeout_s: float = 5.0) -> None:
    if peer.proc.poll() is not None:
        return

    try:
        if hasattr(os, "killpg") and peer.proc.pid:
            os.killpg(peer.proc.pid, sig)
        else:
            peer.proc.send_signal(sig)
    except ProcessLookupError:
        return

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if peer.proc.poll() is not None:
            return
        time.sleep(0.05)

    # Escalate.
    try:
        if hasattr(os, "killpg") and peer.proc.pid:
            os.killpg(peer.proc.pid, signal.SIGKILL)
        else:
            peer.proc.kill()
    except Exception:
        pass


def wait_for_discovery(a: PeerProc, b_id: str, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        send_cmd(a, "peers")
        time.sleep(0.2)
        peers = extract_peer_list(a)
        for pid, _conn in peers:
            if pid == b_id:
                return True
        time.sleep(0.8)
    return False


def dump_debug_tail(*peers: PeerProc) -> None:
    """Print a filtered tail of recent logs to help diagnose failures.

    We keep this lightweight so CI/dev runs aren't spammy unless something fails.
    """

    patterns = re.compile(
        r"(" +
        r"Connected:|CONTROL_CONNECT|CONTROL_CONNECT_ACK|CONNECT_ACK|" +
        r"HANDSHAKE|Noise|secure session|Secure session|ENCRYPTED|" +
        r"Failed to decrypt|Queueing message|Queued application message|" +
        r"\[PeerFSM\]|DISCONNECT|TIMEOUT|network_id" +
        r")",
        re.IGNORECASE,
    )

    for p in peers:
        if p is None:
            continue
        buf = list(p.lines)
        hits = [ln for ln in buf if patterns.search(ln)]
        if hits:
            print(f"\n[test][debug] {p.name} recent relevant logs ({len(hits)} line(s)):")
            for ln in hits[-120:]:
                print(f"[{p.name}] {ln}")
        else:
            # Fall back to an unfiltered tail (useful if log formats change).
            raw_tail = buf[-60:]
            if not raw_tail:
                continue
            print(f"\n[test][debug] {p.name} last {len(raw_tail)} log line(s) (unfiltered):")
            for ln in raw_tail:
                print(f"[{p.name}] {ln}")


def main() -> int:
    ap = argparse.ArgumentParser(description="LiteP2P restart/reconnect behavior test")
    ap.add_argument("--binary", type=str, default="", help="Path to desktop peer binary")
    ap.add_argument("--config", type=str, default="", help="Path to config.json (optional)")
    ap.add_argument("--config-a", type=str, default="", help="Config for peer A (overrides --config if set)")
    ap.add_argument("--config-b", type=str, default="", help="Config for peer B (overrides --config if set)")
    ap.add_argument(
        "--use-repo-config",
        action="store_true",
        help="Use the repo's config.json as-is (by default we generate a LAN-safe config for same-host tests)",
    )
    ap.add_argument("--port-a", type=int, default=31001)
    ap.add_argument("--port-b", type=int, default=31002)
    ap.add_argument("--id-a", type=str, default="peerA")
    ap.add_argument("--id-b", type=str, default="peerB")
    ap.add_argument("--log-level", type=str, default="info")
    ap.add_argument("--kill", choices=["term", "kill"], default="kill", help="How to stop A (term=SIGTERM, kill=SIGKILL)")
    ap.add_argument("--timeout", type=float, default=25.0, help="Timeout (seconds) for each phase")
    ap.add_argument("--verbose", action="store_true", help="Stream peer output prefixed with [A]/[B]")
    args = ap.parse_args()

    binary = Path(args.binary).expanduser() if args.binary else find_default_binary()

    # Support per-peer configs to ensure isolated Noise keystores.
    explicit_config = Path(args.config).expanduser() if args.config else None
    if args.use_repo_config and explicit_config is None:
        explicit_config = Path(__file__).resolve().parents[1] / "config.json"

    config_a_path = Path(args.config_a).expanduser() if args.config_a else explicit_config
    config_b_path = Path(args.config_b).expanduser() if args.config_b else explicit_config

    temp_to_delete: Optional[Path] = None
    if config_a_path is None:
        # No explicit config; generate one (shared is okay for generated temp configs).
        config, temp_to_delete = build_lan_safe_config_path(None)
        config_a_path = config
        config_b_path = config

    print(f"[test] binary: {binary}")
    if config_a_path:
        print(f"[test] config_a: {config_a_path}")
    if config_b_path and config_b_path != config_a_path:
        print(f"[test] config_b: {config_b_path}")
    print(f"[test] starting B: id={args.id_b} port={args.port_b}")
    a = None
    a2 = None
    b = None

    try:
        b = start_peer(
            name="B",
            binary=binary,
            port=args.port_b,
            peer_id=args.id_b,
            log_level=args.log_level,
            config=config_b_path,
            verbose=args.verbose,
        )

        # Wait for plain-mode banner
        if not wait_for_line(b, re.compile(r"LiteP2P \(plain mode\)"), timeout_s=8.0):
            raise RuntimeError("B did not start in time")

        print(f"[test] starting A: id={args.id_a} port={args.port_a}")
        a = start_peer(
            name="A",
            binary=binary,
            port=args.port_a,
            peer_id=args.id_a,
            log_level=args.log_level,
            config=config_a_path,
            verbose=args.verbose,
        )

        if not wait_for_line(a, re.compile(r"LiteP2P \(plain mode\)"), timeout_s=8.0):
            raise RuntimeError("A did not start in time")

        print("[test] waiting for A to discover B...")
        if not wait_for_discovery(a, args.id_b, timeout_s=args.timeout):
            raise RuntimeError("A did not discover B in time (check LAN discovery UDP 30000)")

        print("[test] connecting A -> B...")
        send_cmd(a, f"connect {args.id_b}")
        if not wait_for_line(a, re.compile(r"Connected:"), timeout_s=args.timeout):
            raise RuntimeError("A did not report Connected")

        msg1 = f"hello-1 t={now_ms()}"
        print(f"[test] sending first message A -> B: {msg1}")
        send_cmd(a, f"send {args.id_b} {msg1}")
        if not wait_for_line(b, re.compile(re.escape(msg1)), timeout_s=args.timeout):
            raise RuntimeError("B did not receive first message")

        sig = signal.SIGTERM if args.kill == "term" else signal.SIGKILL
        print(f"[test] stopping A via {args.kill.upper()}...")
        kill_peer(a, sig)

        print("[test] checking B peer list after A stop (A may remain CONNECTED until timeout)...")
        send_cmd(b, "peers")
        time.sleep(0.5)
        b_peers = extract_peer_list(b)
        a_state = None
        for pid, connected in b_peers:
            if pid == args.id_a:
                a_state = connected
                break
        print(f"[test] B sees A connected={a_state} (None means not in list)")

        print("[test] restarting A (same id + same port)...")
        a2 = start_peer(
            name="A2",
            binary=binary,
            port=args.port_a,
            peer_id=args.id_a,
            log_level=args.log_level,
            config=config_a_path,
            verbose=args.verbose,
        )

        if not wait_for_line(a2, re.compile(r"LiteP2P \(plain mode\)"), timeout_s=8.0):
            raise RuntimeError("A2 did not start in time")

        print("[test] waiting for A2 to discover B...")
        if not wait_for_discovery(a2, args.id_b, timeout_s=args.timeout):
            raise RuntimeError("A2 did not discover B in time")

        print("[test] trying to connect A2 -> B...")
        send_cmd(a2, f"connect {args.id_b}")
        if not wait_for_line(a2, re.compile(r"Connected:"), timeout_s=args.timeout):
            raise RuntimeError("A2 did not report Connected (this reproduces your issue)")

        msg2 = f"hello-2-after-restart t={now_ms()}"
        print(f"[test] sending second message A2 -> B: {msg2}")
        send_cmd(a2, f"send {args.id_b} {msg2}")
        if not wait_for_line(b, re.compile(re.escape(msg2)), timeout_s=args.timeout):
            raise RuntimeError("B did not receive second message after restart")

        print("[test] OK: restart/reconnect + messaging succeeded")

        # Clean shutdown
        send_cmd(b, "quit")
        kill_peer(b, signal.SIGTERM)
        send_cmd(a2, "quit")
        kill_peer(a2, signal.SIGTERM)
        return 0

    except Exception as e:
        print(f"[test] FAIL: {e}")

        # Dump a small, filtered log tail to make failures actionable.
        try:
            dump_debug_tail(*(p for p in (a, a2, b) if p is not None))
        except Exception:
            pass

        # Best-effort cleanup
        try:
            if a is not None:
                kill_peer(a, signal.SIGTERM)
        except Exception:
            pass
        try:
            if a2 is not None:
                kill_peer(a2, signal.SIGTERM)
        except Exception:
            pass
        try:
            if b is not None:
                kill_peer(b, signal.SIGTERM)
        except Exception:
            pass
        return 2
    finally:
        if temp_to_delete is not None:
            try:
                temp_to_delete.unlink(missing_ok=True)  # py3.8+ supports missing_ok
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
