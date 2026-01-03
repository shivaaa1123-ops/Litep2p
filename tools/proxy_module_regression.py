#!/usr/bin/env python3

import argparse
import os
import platform
import subprocess
import sys
import time
import json
import selectors
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class CmdResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float


def run_cmd(cmd: list[str], cwd: Path, timeout: Optional[int] = None) -> CmdResult:
    start = time.time()
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        dur = time.time() - start
        return CmdResult(cmd=cmd, returncode=p.returncode, stdout=p.stdout, stderr=p.stderr, duration_s=dur)
    except subprocess.TimeoutExpired as e:
        dur = time.time() - start
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        stderr = (stderr + "\n[TIMEOUT] command exceeded timeout" + (f" ({timeout}s)" if timeout else "") + "\n").lstrip("\n")
        return CmdResult(cmd=cmd, returncode=124, stdout=stdout, stderr=stderr, duration_s=dur)


def _summarize_text(text: str, max_lines: int) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text.rstrip()
    head_len = max(1, max_lines // 2)
    head = lines[:head_len]
    tail = lines[-(max_lines - head_len):]
    omitted = len(lines) - len(head) - len(tail)
    return "\n".join([*head, f"... ({omitted} lines omitted) ...", *tail]).rstrip()


def cmake_configure(source_dir: Path, build_dir: Path, enable_proxy: bool, build_type: str) -> None:
    build_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "cmake",
        "-S",
        str(source_dir),
        "-B",
        str(build_dir),
        f"-DENABLE_PROXY_MODULE={'ON' if enable_proxy else 'OFF'}",
        f"-DCMAKE_BUILD_TYPE={build_type}",
    ]
    r = run_cmd(cmd, cwd=source_dir)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        raise RuntimeError(f"CMake configure failed: {' '.join(cmd)}")


def cmake_build(build_dir: Path, jobs: int) -> None:
    cmd = ["cmake", "--build", str(build_dir)]
    if jobs > 0:
        cmd += ["--parallel", str(jobs)]
    r = run_cmd(cmd, cwd=build_dir)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        raise RuntimeError(f"CMake build failed: {' '.join(cmd)}")


def run_test_exe(exe: Path, timeout_s: int, *, verbose: bool, max_output_lines: int) -> bool:
    if not exe.exists():
        return False
    r = run_cmd([str(exe)], cwd=exe.parent, timeout=timeout_s)
    print(f"[run] {exe} ({r.duration_s:.2f}s)")

    if r.returncode == 0:
        if verbose and r.stdout.strip():
            print(_summarize_text(r.stdout, max_output_lines))
        if verbose and r.stderr.strip():
            print(_summarize_text(r.stderr, max_output_lines), file=sys.stderr)
        return True

    # Failure: always show trimmed output to help debugging, but avoid UI freezes.
    if r.stdout.strip():
        print(_summarize_text(r.stdout, max_output_lines))
    if r.stderr.strip():
        print(_summarize_text(r.stderr, max_output_lines), file=sys.stderr)
    return False


def decode_wire_message(data: bytes) -> tuple[int, bytes]:
    if len(data) < 5:
        raise ValueError(f"wire too short: {len(data)}")
    msg_type = data[0]
    length = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]
    if len(data) < 5 + length:
        raise ValueError(f"wire incomplete: expected {5 + length}, got {len(data)}")
    return msg_type, data[5 : 5 + length]


def decode_stream_data_payload(payload: bytes) -> tuple[int, bytes]:
    if len(payload) < 4:
        raise ValueError("stream payload too short")
    stream_id = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]
    return stream_id, payload[4:]


class ProxyStdioProc:
    def __init__(self, exe: Path, args: list[str]):
        self.exe = exe
        self.args = args
        self.p = subprocess.Popen(
            [str(exe), *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert self.p.stdin and self.p.stdout
        self._sel = selectors.DefaultSelector()
        self._sel.register(self.p.stdout, selectors.EVENT_READ)

    def send_line(self, line: str) -> None:
        assert self.p.stdin
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def read_out(self, timeout_s: float) -> Optional[tuple[str, str]]:
        """Return (to_peer, wire_hex) for the next OUT line, or None on timeout."""
        end = time.time() + timeout_s
        while time.time() < end:
            if self.p.poll() is not None:
                raise RuntimeError(f"proxy_stdio exited early with {self.p.returncode}")

            remaining = max(0.0, end - time.time())
            events = self._sel.select(timeout=remaining)
            if not events:
                continue
            line = self.p.stdout.readline()
            if not line:
                continue
            line = line.strip()
            if not line:
                continue
            if not line.startswith("OUT "):
                continue
            parts = line.split(" ", 2)
            if len(parts) != 3:
                continue
            return parts[1], parts[2]
        return None

    def drain(self) -> None:
        while True:
            got = self.read_out(timeout_s=0.05)
            if got is None:
                return

    def close(self) -> None:
        try:
            self.send_line("QUIT")
        except Exception:
            pass
        try:
            self.p.terminate()
        except Exception:
            pass
        try:
            self.p.wait(timeout=2)
        except Exception:
            try:
                self.p.kill()
            except Exception:
                pass


def run_proxy_stdio_sim(proxy_stdio_exe: Path, timeout_s: float) -> None:
    if not proxy_stdio_exe.exists():
        raise RuntimeError(f"proxy_stdio missing: {proxy_stdio_exe}")

    print("[sim] starting proxy_stdio processes")
    gw = ProxyStdioProc(proxy_stdio_exe, ["--role", "gateway", "--self", "peer_gateway"])
    cl = ProxyStdioProc(proxy_stdio_exe, ["--role", "client", "--self", "peer_client"])

    def expect_out(proc: ProxyStdioProc, who: str, t: float) -> tuple[str, str]:
        got = proc.read_out(timeout_s=t)
        if got is None:
            raise RuntimeError(f"timeout waiting for OUT from {who}")
        return got

    try:
        gw.drain()
        cl.drain()

        # 1) HELLO -> ACCEPT (ok=true)
        print("[sim] step 1/5: HELLO -> ACCEPT")
        cl.send_line("CMD HELLO peer_gateway 1")
        to, wire_hex = expect_out(cl, "client", timeout_s)
        assert to == "peer_gateway"
        gw.send_line(f"IN peer_client {wire_hex}")

        to, resp_hex = expect_out(gw, "gateway", timeout_s)
        assert to == "peer_client"
        msg_type, payload = decode_wire_message(bytes.fromhex(resp_hex))
        assert msg_type == 0x30  # PROXY_CONTROL
        accept = json.loads(payload.decode("utf-8"))
        assert accept.get("type") == "PROXY_ACCEPT"
        assert accept.get("for") == "HELLO"
        assert accept.get("ok") is True
        cl.send_line(f"IN peer_gateway {resp_hex}")

        # 2) OPEN_STREAM -> ACCEPT (ok=true, stream_id)
        print("[sim] step 2/5: OPEN_STREAM -> ACCEPT")
        cl.send_line("CMD OPEN_STREAM peer_gateway 123 TCP example.com 80")
        to, wire_hex = expect_out(cl, "client", timeout_s)
        assert to == "peer_gateway"
        gw.send_line(f"IN peer_client {wire_hex}")

        to, resp_hex = expect_out(gw, "gateway", timeout_s)
        assert to == "peer_client"
        msg_type, payload = decode_wire_message(bytes.fromhex(resp_hex))
        assert msg_type == 0x30  # PROXY_CONTROL
        accept = json.loads(payload.decode("utf-8"))
        assert accept.get("type") == "PROXY_ACCEPT"
        assert accept.get("for") == "OPEN_STREAM"
        assert accept.get("ok") is True
        assert accept.get("stream_id") == 123
        cl.send_line(f"IN peer_gateway {resp_hex}")

        # 3) STREAM_DATA -> echo STREAM_DATA back
        print("[sim] step 3/5: STREAM_DATA echo")
        data = b"hello-over-proxy"
        cl.send_line(f"CMD STREAM_DATA peer_gateway 123 {data.hex()}")
        to, wire_hex = expect_out(cl, "client", timeout_s)
        assert to == "peer_gateway"
        gw.send_line(f"IN peer_client {wire_hex}")

        to, echo_hex = expect_out(gw, "gateway", timeout_s)
        assert to == "peer_client"
        msg_type, payload = decode_wire_message(bytes.fromhex(echo_hex))
        assert msg_type == 0x31  # PROXY_STREAM_DATA
        sid, echoed = decode_stream_data_payload(payload)
        assert sid == 123
        assert echoed == data
        cl.send_line(f"IN peer_gateway {echo_hex}")

        # 4) CLOSE_STREAM then further data should not echo
        print("[sim] step 4/5: CLOSE_STREAM disables echo")
        gw.drain()
        cl.drain()
        cl.send_line("CMD CLOSE_STREAM peer_gateway 123 done")
        to, wire_hex = expect_out(cl, "client", timeout_s)
        assert to == "peer_gateway"
        gw.send_line(f"IN peer_client {wire_hex}")

        cl.send_line(f"CMD STREAM_DATA peer_gateway 123 {b'should-not-echo'.hex()}")
        to, wire_hex = expect_out(cl, "client", timeout_s)
        assert to == "peer_gateway"
        gw.send_line(f"IN peer_client {wire_hex}")

        should_be_none = gw.read_out(timeout_s=0.25)
        if should_be_none is not None:
            raise RuntimeError(f"unexpected gateway output after close: {should_be_none}")

        # 5) Gateway disabled should reject HELLO
        print("[sim] step 5/5: disabled gateway rejects HELLO")
        gw2 = ProxyStdioProc(proxy_stdio_exe, ["--role", "gateway", "--self", "peer_gateway", "--gateway", "0", "--client", "0"])
        try:
            gw2.drain()
            cl.drain()

            cl.send_line("CMD HELLO peer_gateway 1")
            to, wire_hex = expect_out(cl, "client", timeout_s)
            assert to == "peer_gateway"
            gw2.send_line(f"IN peer_client {wire_hex}")

            to, resp_hex = expect_out(gw2, "gateway(disabled)", timeout_s)
            assert to == "peer_client"
            msg_type, payload = decode_wire_message(bytes.fromhex(resp_hex))
            assert msg_type == 0x30
            accept = json.loads(payload.decode("utf-8"))
            assert accept.get("type") == "PROXY_ACCEPT"
            assert accept.get("for") == "HELLO"
            assert accept.get("ok") is False
            assert accept.get("error") == "gateway_disabled"
        finally:
            gw2.close()

    finally:
        cl.close()
        gw.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Build and repeatedly run desktop proxy module regression tests")
    ap.add_argument("--iterations", type=int, default=1, help="How many times to run the full build+test cycle")
    ap.add_argument("--delay", type=float, default=0.0, help="Delay (seconds) between iterations")
    ap.add_argument("--timeout", type=int, default=30, help="Per-test timeout in seconds")
    ap.add_argument("--stdio-timeout", type=float, default=3.0, help="Per-step timeout (seconds) for proxy_stdio simulation")
    ap.add_argument("--skip-stdio-sim", action="store_true", help="Skip the Python-driven proxy_stdio simulation")
    ap.add_argument("--verbose", action="store_true", help="Print test stdout on success (can be noisy)")
    ap.add_argument("--max-output-lines", type=int, default=200, help="Max lines of stdout/stderr to print per test")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1), help="Parallel build jobs")
    ap.add_argument("--build-type", default="Release", help="CMAKE_BUILD_TYPE")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    desktop_src = repo_root / "desktop"

    sys_name = platform.system().lower()
    if sys_name == "darwin":
        plat = "mac"
    elif sys_name == "linux":
        plat = "linux"
    else:
        plat = sys_name

    build_off = desktop_src / f"build_{plat}_proxy_off"
    build_on = desktop_src / f"build_{plat}_proxy_on"

    base_tests = [
        "crypto_test",
        "session_manager_test",
        "file_transfer_test",
        "nat_traversal_test",
    ]

    for i in range(args.iterations):
        print(f"\n=== Iteration {i + 1}/{args.iterations} ===")

        # Build & test with proxy OFF
        print("\n--- Configure/build: ENABLE_PROXY_MODULE=OFF ---")
        cmake_configure(desktop_src, build_off, enable_proxy=False, build_type=args.build_type)
        cmake_build(build_off, jobs=args.jobs)

        bin_off = build_off / "bin"
        failed = False
        for t in base_tests:
            exe = bin_off / t
            ok = run_test_exe(exe, timeout_s=args.timeout, verbose=args.verbose, max_output_lines=args.max_output_lines)
            if not ok:
                print(f"[fail] missing or failing test: {exe}")
                failed = True

        proxy_exe_off = bin_off / "proxy_test"
        if proxy_exe_off.exists():
            print(f"[fail] proxy_test exists with proxy OFF: {proxy_exe_off}")
            failed = True

        proxy_stdio_off = bin_off / "proxy_stdio"
        if proxy_stdio_off.exists():
            print(f"[fail] proxy_stdio exists with proxy OFF: {proxy_stdio_off}")
            failed = True

        if failed:
            return 1

        # Build & test with proxy ON
        print("\n--- Configure/build: ENABLE_PROXY_MODULE=ON ---")
        cmake_configure(desktop_src, build_on, enable_proxy=True, build_type=args.build_type)
        cmake_build(build_on, jobs=args.jobs)

        bin_on = build_on / "bin"
        for t in base_tests:
            exe = bin_on / t
            ok = run_test_exe(exe, timeout_s=args.timeout, verbose=args.verbose, max_output_lines=args.max_output_lines)
            if not ok:
                print(f"[fail] missing or failing test: {exe}")
                failed = True

        proxy_exe_on = bin_on / "proxy_test"
        if not run_test_exe(proxy_exe_on, timeout_s=args.timeout, verbose=args.verbose, max_output_lines=args.max_output_lines):
            print(f"[fail] missing or failing test: {proxy_exe_on}")
            failed = True

        proxy_stdio_on = bin_on / "proxy_stdio"
        if not args.skip_stdio_sim:
            try:
                run_proxy_stdio_sim(proxy_stdio_on, timeout_s=float(args.stdio_timeout))
                print(f"[run] proxy_stdio simulation ({proxy_stdio_on})")
            except Exception as e:
                print(f"[fail] proxy_stdio simulation failed: {e}")
                failed = True

        if failed:
            return 1

        if args.delay > 0 and i + 1 < args.iterations:
            time.sleep(args.delay)

    print("\nAll proxy module regression iterations passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
