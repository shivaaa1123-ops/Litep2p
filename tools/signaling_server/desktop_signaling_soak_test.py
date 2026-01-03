#!/usr/bin/env python3
"""Soak test: desktop peer stays connected to signaling server.

This launches a local signaling server (tools/signaling_server/server.py) with a
short keepalive ping interval, then launches the desktop peer binary in
headless mode and verifies:
  - the peer registers successfully
  - the server receives at least N keepalive pongs

Usage:
  python3 tools/signaling_server/desktop_signaling_soak_test.py

Optional env vars:
  LITEP2P_DESKTOP_BIN           Path to litep2p desktop binary
  LITEP2P_DESKTOP_CONFIG        Path to config file (must point signaling.url to local server)
    LITEP2P_REMOTE_SIGNALING_URL  Override signaling URL for remote/VPS soak (e.g. ws://64.227.140.251:8765)
  LITEP2P_DESKTOP_PEER_ID       Peer id to register (default: soakPeer)
  LITEP2P_DESKTOP_PORT          Local listen port (default: 31001)
  LITEP2P_SOAK_SECONDS          How long to run (default: 20)
  LITEP2P_REQUIRED_PONGS        Minimum pongs to observe (default: 2)

Exit code:
  0 on success, 1 on failure.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
import json
import selectors
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BIN_CANDIDATES = [
    REPO_ROOT / "desktop" / "build_mac" / "bin" / "litep2p_peer_mac",
    REPO_ROOT / "desktop" / "build_linux" / "bin" / "litep2p_peer_linux",
]
DEFAULT_CONFIG = REPO_ROOT / "tools" / "signaling_server" / "local_config.json"
SERVER_SCRIPT = REPO_ROOT / "tools" / "signaling_server" / "server.py"


class Fail(RuntimeError):
    pass


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return int(v)


def _pick_bin(explicit: Optional[str]) -> Path:
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.exists():
            raise Fail(f"Desktop binary not found: {p}")
        return p

    for c in DEFAULT_BIN_CANDIDATES:
        if c.exists():
            return c

    raise Fail(
        "Could not find a desktop binary. Looked for:\n"
        + "\n".join(f"  - {c}" for c in DEFAULT_BIN_CANDIDATES)
        + "\nBuild it first (e.g. run desktop/build_mac.sh)."
    )


def _must_exist(path: Path, label: str) -> Path:
    if not path.exists():
        raise Fail(f"Missing {label}: {path}")
    return path


def _read_until(proc: subprocess.Popen[str], patterns: list[re.Pattern[str]], deadline: float) -> str:
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if line == "":
            if proc.poll() is not None:
                raise Fail(f"Process exited early: pid={proc.pid}, code={proc.returncode}")
            time.sleep(0.05)
            continue

        s = line.rstrip("\n")
        for p in patterns:
            if p.search(s):
                return s

    raise Fail(f"Timeout waiting for patterns: {[p.pattern for p in patterns]}")


def _read_until_logged(
    proc: subprocess.Popen[str],
    log_file,  # TextIO
    patterns: list[re.Pattern[str]],
    deadline: float,
) -> str:
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if line != "":
            log_file.write(line)
            log_file.flush()
            s = line.rstrip("\n")
            for p in patterns:
                if p.search(s):
                    return s
            continue

        if proc.poll() is not None:
            raise Fail(f"Process exited early: pid={proc.pid}, code={proc.returncode}")
        time.sleep(0.05)

    raise Fail(f"Timeout waiting for patterns: {[p.pattern for p in patterns]}")


def _tail(path: Path, lines: int = 200) -> str:
    if not path.exists():
        return f"(missing log: {path})"
    try:
        data = path.read_text(errors="replace").splitlines()
    except Exception as e:
        return f"(failed to read {path}: {e})"
    return "\n".join(data[-lines:])


def _detect_signaling_url(config_path: Path) -> Optional[str]:
    try:
        cfg = json.loads(config_path.read_text())
        url = (cfg.get("signaling") or {}).get("url")
        if isinstance(url, str) and url.strip():
            return url.strip()
        return None
    except Exception:
        return None


def _monitor_peer_for_disconnect(
    peer: subprocess.Popen[str],
    log_path: Path,
    require_connected_within_s: float,
    total_s: float,
) -> None:
    """Monitor the peer process logs in real time.

    Success criteria:
      - see "Signaling: Connected successfully" within require_connected_within_s
      - do NOT see disconnect indicators before total_s elapses
    """
    assert peer.stdout is not None

    fail_patterns = [
        re.compile(r"SM: Failed to connect to signaling server"),
        re.compile(r"Signaling: Connection failed"),
        re.compile(r"Server closed connection"),
        re.compile(r"Signaling: Receive loop ended"),
    ]
    connected_pat = re.compile(r"Signaling: Connected successfully")

    sel = selectors.DefaultSelector()
    sel.register(peer.stdout, selectors.EVENT_READ)

    connected = False
    t0 = time.monotonic()
    connect_deadline = t0 + float(require_connected_within_s)
    end_deadline = t0 + float(total_s)

    with log_path.open("w", encoding="utf-8") as log:
        while time.monotonic() < end_deadline:
            if peer.poll() is not None:
                raise Fail(f"Peer exited early: pid={peer.pid}, code={peer.returncode}\n{_tail(log_path)}")

            timeout = 0.25
            events = sel.select(timeout=timeout)
            if not events:
                if (not connected) and (time.monotonic() >= connect_deadline):
                    raise Fail(f"Timed out waiting for signaling connect\n{_tail(log_path)}")
                continue

            for key, _mask in events:
                line = key.fileobj.readline()
                if line == "":
                    continue
                log.write(line)
                log.flush()

                if connected_pat.search(line):
                    connected = True

                for pat in fail_patterns:
                    if pat.search(line):
                        raise Fail(f"Detected disconnect/failure: {pat.pattern}\n{_tail(log_path)}")

            if (not connected) and (time.monotonic() >= connect_deadline):
                raise Fail(f"Timed out waiting for signaling connect\n{_tail(log_path)}")


def main() -> int:
    try:
        desktop_bin = _pick_bin(os.environ.get("LITEP2P_DESKTOP_BIN"))
        config_path = Path(os.environ.get("LITEP2P_DESKTOP_CONFIG", str(DEFAULT_CONFIG))).expanduser().resolve()
        remote_url = os.environ.get("LITEP2P_REMOTE_SIGNALING_URL")
        peer_id = os.environ.get("LITEP2P_DESKTOP_PEER_ID", "soakPeer")
        port = _env_int("LITEP2P_DESKTOP_PORT", 31001)
        soak_s = _env_int("LITEP2P_SOAK_SECONDS", 20)
        required_pongs = _env_int("LITEP2P_REQUIRED_PONGS", 2)

        logs_dir = Path(os.environ.get("LITEP2P_SOAK_LOG_DIR", "/tmp")).expanduser().resolve()
        logs_dir.mkdir(parents=True, exist_ok=True)
        server_log_path = logs_dir / "litep2p_signaling_soak_server.log"
        peer_log_path = logs_dir / "litep2p_signaling_soak_peer.log"

        _must_exist(config_path, "config")

        # If an explicit remote URL is provided, force the repo-root config.json by default.
        if remote_url and os.environ.get("LITEP2P_DESKTOP_CONFIG") is None:
            repo_cfg = REPO_ROOT / "config.json"
            if repo_cfg.exists():
                config_path = repo_cfg

        effective_url = (remote_url or "").strip() or (_detect_signaling_url(config_path) or "")
        is_remote = bool(effective_url) and ("127.0.0.1" not in effective_url) and ("localhost" not in effective_url)

        if is_remote:
            # Remote/VPS mode: we can't introspect server PONG logs, so we validate the peer remains connected.
            if peer_log_path.exists():
                peer_log_path.unlink()

            peer = subprocess.Popen(
                [
                    str(desktop_bin),
                    "--config",
                    str(config_path),
                    "--id",
                    peer_id,
                    "--port",
                    str(port),
                    "--log-level",
                    "debug",
                    "--headless",
                    "--no-tui",
                ],
                cwd=str(REPO_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env={
                    **os.environ,
                    "LC_ALL": "C",
                    "LANG": "C",
                },
            )

            try:
                _monitor_peer_for_disconnect(
                    peer,
                    peer_log_path,
                    require_connected_within_s=min(15.0, float(soak_s)),
                    total_s=float(soak_s),
                )
            finally:
                if peer.poll() is None:
                    peer.send_signal(signal.SIGTERM)
                    try:
                        peer.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        peer.kill()

            print(f"OK: peer stayed connected to remote signaling server ({effective_url})")
            return 0

        _must_exist(SERVER_SCRIPT, "signaling server script")

        # Start signaling server with fast keepalives.
        if server_log_path.exists():
            server_log_path.unlink()
        if peer_log_path.exists():
            peer_log_path.unlink()

        server_log = server_log_path.open("w", encoding="utf-8")
        server = subprocess.Popen(
            [sys.executable, str(SERVER_SCRIPT)],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env={
                **os.environ,
                "SIGNALING_HOST": "127.0.0.1",
                "SIGNALING_PORT": "8765",
                "LOG_LEVEL": "DEBUG",
                "SIGNALING_PING_INTERVAL": "5",
                "SIGNALING_PING_TIMEOUT": "5",
            },
        )

        try:
            _read_until_logged(
                server,
                server_log,
                [re.compile(r"Signaling server started on 127\.0\.0\.1:8765")],
                deadline=time.monotonic() + 5.0,
            )

            peer_log = peer_log_path.open("w", encoding="utf-8")
            peer = subprocess.Popen(
                [
                    str(desktop_bin),
                    "--config",
                    str(config_path),
                    "--id",
                    peer_id,
                    "--port",
                    str(port),
                    "--log-level",
                    "debug",
                    "--headless",
                    "--no-tui",
                ],
                cwd=str(REPO_ROOT),
                stdout=peer_log,
                stderr=subprocess.STDOUT,
                text=True,
                env={
                    **os.environ,
                    # Make logs deterministic if any leak through.
                    "LC_ALL": "C",
                    "LANG": "C",
                },
            )

            try:
                # Wait for registration in server log.
                _read_until_logged(
                    server,
                    server_log,
                    [re.compile(rf"Peer registered: {re.escape(peer_id)}\b")],
                    deadline=time.monotonic() + 10.0,
                )

                # Observe pongs.
                # websockets debug logs are like:
                #   > PING '...'
                #   < PONG '...'
                pong_re = re.compile(r"<\s+PONG\b")
                pongs = 0
                deadline = time.monotonic() + float(soak_s)
                assert server.stdout is not None
                while time.monotonic() < deadline and pongs < required_pongs:
                    if peer.poll() is not None:
                        raise Fail(
                            f"Peer exited early: code={peer.returncode}\n"
                            f"--- peer log ---\n{_tail(peer_log_path)}\n"
                            f"--- server log ---\n{_tail(server_log_path)}"
                        )
                    if server.poll() is not None:
                        raise Fail(f"Server exited early: code={server.returncode}\n{_tail(server_log_path)}")

                    line = server.stdout.readline()
                    if line == "":
                        time.sleep(0.05)
                        continue
                    server_log.write(line)
                    server_log.flush()
                    if pong_re.search(line):
                        pongs += 1

                if pongs < required_pongs:
                    raise Fail(
                        f"Only observed {pongs} PONG(s); required {required_pongs}\n"
                        f"--- server log ---\n{_tail(server_log_path)}\n"
                        f"--- peer log ---\n{_tail(peer_log_path)}"
                    )

            finally:
                # Stop peer.
                if peer.poll() is None:
                    peer.send_signal(signal.SIGTERM)
                    try:
                        peer.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        peer.kill()

                try:
                    peer_log.close()
                except Exception:
                    pass

        finally:
            # Stop server.
            if server.poll() is None:
                server.send_signal(signal.SIGTERM)
                try:
                    server.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    server.kill()

            try:
                server_log.close()
            except Exception:
                pass

        print("OK: desktop peer stayed connected and responded to keepalive pings")
        return 0

    except Fail as e:
        print(f"FAIL: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
