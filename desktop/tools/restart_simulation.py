#!/usr/bin/env python3

"""Desktop restart/connect/send simulation harness.

This script runs two LiteP2P desktop peers, drives them via stdin commands, restarts one
peer, and verifies that messages are delivered in both directions.

It is intentionally self-contained (std-lib only) so it can run in CI and on developer
machines without extra dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class PeerSpec:
    name: str
    peer_id: str
    port: int


class PeerProcess:
    def __init__(
        self,
        spec: PeerSpec,
        *,
        binary: Path,
        workdir: Path,
        config_path: Path,
        log_level: str,
    ) -> None:
        self.spec = spec
        self.binary = binary
        self.workdir = workdir
        self.config_path = config_path
        self.log_level = log_level

        self._lines: "queue.Queue[str]" = queue.Queue()
        self._all_lines: list[str] = []
        self._reader_thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen[str]] = None
        self._log_file: Optional[object] = None

    @property
    def pid(self) -> int:
        if not self._proc or self._proc.poll() is not None:
            return -1
        return int(self._proc.pid)

    def start(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)

        log_path = self.workdir / f"{self.spec.name}.log"
        self._log_file = open(log_path, "w", encoding="utf-8")

        args = [
            str(self.binary),
            "--port",
            str(self.spec.port),
            "--id",
            self.spec.peer_id,
            "--config",
            str(self.config_path),
            "--log-level",
            self.log_level,
        ]

        self._proc = subprocess.Popen(
            args,
            cwd=str(self.workdir),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        assert self._proc.stdout is not None

        def _reader() -> None:
            try:
                for line in self._proc.stdout:
                    line = line.rstrip("\n")
                    self._all_lines.append(line)
                    try:
                        self._lines.put_nowait(line)
                    except queue.Full:
                        pass
                    try:
                        assert self._log_file is not None
                        self._log_file.write(line + "\n")
                        self._log_file.flush()
                    except Exception:
                        pass
            finally:
                try:
                    if self._log_file is not None:
                        self._log_file.flush()
                except Exception:
                    pass

        self._reader_thread = threading.Thread(target=_reader, daemon=True)
        self._reader_thread.start()

    def send(self, command: str) -> None:
        if not self._proc or self._proc.poll() is not None:
            raise RuntimeError(f"{self.spec.name} is not running")
        assert self._proc.stdin is not None
        self._proc.stdin.write(command + "\n")
        self._proc.stdin.flush()

    def wait_for(self, pattern: str | re.Pattern[str], timeout_s: float) -> str:
        """Wait until a line matches pattern; returns the matching line."""
        if isinstance(pattern, str):
            regex = re.compile(pattern)
        else:
            regex = pattern

        deadline = time.time() + timeout_s
        while time.time() < deadline:
            remaining = max(0.0, deadline - time.time())
            try:
                line = self._lines.get(timeout=min(0.25, remaining))
            except queue.Empty:
                continue
            if regex.search(line):
                return line
        raise TimeoutError(
            f"Timeout waiting for {self.spec.name} to match {regex.pattern}. "
            f"Last 50 lines:\n" + "\n".join(self.tail(50))
        )

    def tail(self, n: int) -> list[str]:
        return self._all_lines[-n:]

    def stop(self, *, graceful: bool, timeout_s: float = 5.0) -> None:
        if not self._proc:
            return

        if self._proc.poll() is not None:
            return

        try:
            if graceful:
                try:
                    self.send("exit")
                except Exception:
                    pass
                try:
                    self._proc.wait(timeout=timeout_s)
                except subprocess.TimeoutExpired:
                    self._proc.terminate()
            else:
                self._proc.terminate()

            try:
                self._proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=timeout_s)
        finally:
            try:
                if self._log_file is not None:
                    self._log_file.flush()
                    self._log_file.close()
            except Exception:
                pass


def _write_peer_config(
    *,
    base_config_path: Path,
    out_config_path: Path,
    listen_port: int,
    protocol: str,
    key_store_path: str,
) -> None:
    base = json.loads(base_config_path.read_text(encoding="utf-8"))

    base.setdefault("network", {})
    base["network"]["default_server_port"] = listen_port

    base.setdefault("communication", {})
    base["communication"]["default_protocol"] = protocol

    proto_key = protocol.lower()
    if proto_key in base["communication"]:
        base["communication"][proto_key]["port"] = listen_port

    base.setdefault("security", {})
    base["security"].setdefault("noise_nk_protocol", {})
    base["security"]["noise_nk_protocol"]["key_store_path"] = key_store_path

    out_config_path.write_text(json.dumps(base, indent=4), encoding="utf-8")


def _require_binary(binary: Path) -> None:
    if not binary.exists():
        raise FileNotFoundError(
            f"Desktop binary not found at {binary}. Build it first (desktop/build_mac.sh on macOS)."
        )
    if not os.access(str(binary), os.X_OK):
        raise PermissionError(f"Desktop binary exists but is not executable: {binary}")


def _get_primary_ipv4() -> str:
    """Best-effort local IPv4 detection.

    We prefer a non-loopback IP so the peer network_id matches what discovery reports
    (and what the TCP stack typically uses for localhost-to-LAN routing on macOS).
    """
    for target in [("8.8.8.8", 80), ("1.1.1.1", 80)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(target)
                ip = s.getsockname()[0]
                if ip and ip != "127.0.0.1":
                    return ip
            finally:
                s.close()
        except Exception:
            continue
    return "127.0.0.1"


def run_once(
    *,
    binary: Path,
    base_config: Path,
    run_dir: Path,
    protocol: str,
    log_level: str,
    restart_graceful: bool,
) -> None:
    a = PeerSpec(name="peer_a", peer_id="peer_a", port=31001)
    b = PeerSpec(name="peer_b", peer_id="peer_b", port=31002)

    ip = _get_primary_ipv4()

    peer_a_dir = run_dir / a.name
    peer_b_dir = run_dir / b.name
    peer_a_dir.mkdir(parents=True, exist_ok=True)
    peer_b_dir.mkdir(parents=True, exist_ok=True)

    _write_peer_config(
        base_config_path=base_config,
        out_config_path=peer_a_dir / "config.json",
        listen_port=a.port,
        protocol=protocol,
        key_store_path="keystore",
    )
    _write_peer_config(
        base_config_path=base_config,
        out_config_path=peer_b_dir / "config.json",
        listen_port=b.port,
        protocol=protocol,
        key_store_path="keystore",
    )

    (peer_a_dir / "keystore").mkdir(exist_ok=True)
    (peer_b_dir / "keystore").mkdir(exist_ok=True)

    proc_a = PeerProcess(a, binary=binary, workdir=peer_a_dir, config_path=peer_a_dir / "config.json", log_level=log_level)
    proc_b = PeerProcess(b, binary=binary, workdir=peer_b_dir, config_path=peer_b_dir / "config.json", log_level=log_level)

    proc_a.start()
    proc_b.start()

    # Ensure both peers are fully started and ready to accept CLI commands.
    proc_a.wait_for(r"\[CLI\] Entering non-interactive mode", timeout_s=10.0)
    proc_b.wait_for(r"\[CLI\] Entering non-interactive mode", timeout_s=10.0)

    try:
        # Manual peer registration (avoid broadcast discovery port conflicts)
        proc_a.send(f"addpeer {b.peer_id} {ip} {b.port}")
        proc_b.send(f"addpeer {a.peer_id} {ip} {a.port}")

        # Initial connect + bidirectional send
        proc_a.send(f"connect {b.peer_id}")
        proc_a.send(f"send {b.peer_id} hello_1_from_a")
        proc_b.wait_for(r"Message received from peer_a: hello_1_from_a", timeout_s=10.0)

        proc_b.send(f"send {a.peer_id} hello_1_from_b")
        proc_a.wait_for(r"Message received from peer_b: hello_1_from_b", timeout_s=10.0)

        # Restart B
        proc_b.stop(graceful=restart_graceful)
        time.sleep(0.25)

        proc_b = PeerProcess(b, binary=binary, workdir=peer_b_dir, config_path=peer_b_dir / "config.json", log_level=log_level)
        proc_b.start()

        proc_b.wait_for(r"\[CLI\] Entering non-interactive mode", timeout_s=10.0)

        # Re-add peers (B lost state; A might still have it but re-adding is harmless)
        proc_a.send(f"addpeer {b.peer_id} {ip} {b.port}")
        proc_b.send(f"addpeer {a.peer_id} {ip} {a.port}")

        # Case: restarted device initiates connection
        proc_b.send(f"connect {a.peer_id}")
        proc_b.send(f"send {a.peer_id} hello_2_from_b")
        proc_a.wait_for(r"Message received from peer_b: hello_2_from_b", timeout_s=10.0)

        # Case: other side initiates connection after restart
        proc_a.send(f"connect {b.peer_id}")
        proc_a.send(f"send {b.peer_id} hello_2_from_a")
        proc_b.wait_for(r"Message received from peer_a: hello_2_from_a", timeout_s=10.0)

    finally:
        try:
            proc_a.stop(graceful=True)
        except Exception:
            pass
        try:
            proc_b.stop(graceful=True)
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="LiteP2P desktop restart simulation")
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "build_mac" / "bin" / "litep2p_peer_mac",
        help="Path to desktop peer binary",
    )
    parser.add_argument(
        "--base-config",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "config.json",
        help="Path to base config.json",
    )
    parser.add_argument(
        "--protocol",
        type=str,
        default="TCP",
        choices=["TCP", "UDP", "QUIC"],
        help="Communication protocol",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="info",
        choices=["debug", "info", "warning", "error", "none"],
        help="Desktop log level",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of runs",
    )
    parser.add_argument(
        "--restart-graceful",
        action="store_true",
        help="Restart peer using CLI exit (default: SIGTERM)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "desktop_sim_runs",
        help="Directory to write run logs",
    )

    args = parser.parse_args()

    _require_binary(args.binary)
    if not args.base_config.exists():
        raise FileNotFoundError(f"Base config not found: {args.base_config}")

    args.out_dir.mkdir(parents=True, exist_ok=True)

    for i in range(1, args.runs + 1):
        run_dir = args.out_dir / time.strftime(f"run_%Y%m%d_%H%M%S_{i:03d}")
        run_dir.mkdir(parents=True, exist_ok=True)
        try:
            run_once(
                binary=args.binary,
                base_config=args.base_config,
                run_dir=run_dir,
                protocol=args.protocol,
                log_level=args.log_level,
                restart_graceful=args.restart_graceful,
            )
            print(f"RUN {i}/{args.runs}: PASS ({run_dir})")
        except Exception as e:
            print(f"RUN {i}/{args.runs}: FAIL ({run_dir})")
            print(str(e))
            return 1

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
