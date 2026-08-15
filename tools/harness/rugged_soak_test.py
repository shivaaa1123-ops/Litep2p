#!/usr/bin/env python3
"""
Rugged soak / connectivity test for the LiteP2P engine.

Topology
  - N desktop peers (real litep2p_peer_* binaries, isolated workdirs/keystores,
    shared transport-key config)
  - 1..M Android physical devices driven over adb (engine start/stop/send via
    MainActivity automation intent extras; delivery verified via logcat)

Strict contract
  1. Bring every peer up; require a full READY mesh among active peers.
  2. All-pairs volley: every active ordered pair exchanges a unique message;
     EVERY message must be observed at the receiver.
  3. Random rugged churn between volleys: kill -9 (no restart), restart,
     SIGSTOP blackout / SIGCONT, Android force-stop (crash), relaunch
     (recovery), per-UID network block (network/internet outage) and restore.
  4. After each op: wait for READY re-convergence (bounded, fresh evidence),
     then another strict all-pairs volley.
  5. Report: per-phase results, every lost message, recovery times, verdict.

Note: Android devices attached over wireless adb must NOT have Wi-Fi toggled
(that would drop adb). Engine network outages use per-UID netpolicy instead.
"""

import argparse
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BIN_CANDIDATES = [
    REPO_ROOT / "desktop" / "build_mac" / "bin" / "litep2p_peer_mac",
    REPO_ROOT / "desktop" / "build_linux" / "bin" / "litep2p_peer_linux",
]
APP_PKG = "com.zeengal.litep2p"
APP_ACTIVITY = f"{APP_PKG}/.MainActivity"


def log(msg: str) -> None:
    print(f"[soak {datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def find_binary() -> Path:
    for b in BIN_CANDIDATES:
        if b.is_file() and os.access(b, os.X_OK):
            return b
    return Path("")


def adb(serial: str, *args: str, timeout: float = 20.0) -> str:
    cmd = ["adb", "-s", serial] + list(args)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (out.stdout or "") + (out.stderr or "")
    except subprocess.TimeoutExpired:
        return "<adb timeout>"


def adb_devices() -> list:
    out = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=15).stdout or ""
    serials = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


class DesktopPeer:
    """A real desktop peer process driven through its plain CLI (--no-tui)."""

    def __init__(self, pid: str, port: int, workdir: Path, config: Path, binary: Path):
        self.pid = pid
        self.port = port
        self.workdir = workdir
        self.config = config
        self.binary = str(binary)
        self.proc = None
        self.logf = None
        self.mark = 0        # byte offset of this process's (re)start
        self.phase_off = 0   # byte offset of the current test phase
        self.frozen = False
        self.dead = False

    @property
    def alive(self) -> bool:
        return (not self.dead) and self.proc is not None and self.proc.poll() is None

    def start(self) -> bool:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.logf = open(self.workdir / "out.log", "a")
        self.logf.write(f"\n===== start {datetime.now().isoformat()} =====\n")
        self.logf.flush()
        self.mark = self._size()
        self.proc = subprocess.Popen(
            [self.binary, "--id", self.pid, "--port", str(self.port),
             "--config", str(self.config), "--no-tui", "--log-level", "info"],
            stdin=subprocess.PIPE, stdout=self.logf, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=str(self.workdir),
        )
        self.dead = False
        self.frozen = False
        return self.proc.poll() is None

    def _path(self) -> Path:
        return self.workdir / "out.log"

    def _size(self) -> int:
        try:
            return self._path().stat().st_size
        except OSError:
            return 0

    def _read_from(self, off: int) -> str:
        try:
            with open(self._path(), "rb") as f:
                f.seek(off)
                return f.read().decode(errors="ignore")
        except OSError:
            return ""

    def snapshot_phase(self) -> None:
        self.phase_off = self._size()

    def text_from_phase(self) -> str:
        return self._read_from(self.phase_off)

    def text_full(self) -> str:
        return self._read_from(0)

    def send_msg(self, peer_id: str, msg: str) -> None:
        if not self.alive:
            return
        try:
            self.proc.stdin.write(f"send {peer_id} {msg}\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def kill9(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.proc = None
        self.dead = True
        self.frozen = False

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.kill9()
                return
        self.proc = None
        self.dead = True
        if self.logf:
            try:
                self.logf.close()
            except OSError:
                pass
            self.logf = None

    def freeze(self) -> None:
        if self.alive and not self.frozen:
            os.kill(self.proc.pid, signal.SIGSTOP)
            self.frozen = True

    def unfreeze(self) -> None:
        if self.proc and self.frozen:
            try:
                os.kill(self.proc.pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            self.frozen = False


class AndroidPeer:
    """A physical Android device running the LiteP2P app, driven over adb.

    - Engine start/stop: MainActivity automation extras (onNewIntent also
      applies them while the app is alive).
    - Sends: LITEP2P_SEND_TO_PEER + LITEP2P_SEND_MESSAGE.
    - Delivery evidence: logcat 'LiteP2P_P2P_Hook: Message received from peer
      <src>: <body>' (the hook logs the clean body for LP_APP envelopes too).
    - READY evidence: logcat '[PeerFSM] ... READY peer=<id>'.
    - Network outage: per-UID netpolicy reject (keeps wireless adb alive).
    """

    def __init__(self, serial: str, peer_id: str, rundir: Path):
        self.serial = serial
        self.pid = peer_id
        self.rundir = rundir
        self.lcdir = rundir / f"android_{peer_id}"
        self.lcdir.mkdir(parents=True, exist_ok=True)
        self.logcat_proc = None
        self.logfile = open(self.lcdir / "logcat.txt", "a", encoding="utf-8", errors="ignore")
        self.mark = 0
        self.phase_off = 0
        self.net_blocked = False
        self.engine_up = False
        self.uid = self._detect_uid()

    def _lc_path(self) -> Path:
        return self.lcdir / "logcat.txt"

    def _detect_uid(self) -> str:
        out = adb(self.serial, "shell", f"dumpsys package {APP_PKG}")
        m = re.search(r"appId=(\d+)", out) or re.search(r"userId=(\d+)", out)
        return m.group(1) if m else ""

    def start_logcat(self) -> None:
        adb(self.serial, "logcat", "-c")
        self.logcat_proc = subprocess.Popen(
            ["adb", "-s", self.serial, "logcat", "-v", "threadtime"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, errors="ignore",
        )
        threading.Thread(target=self._read_logcat, daemon=True).start()

    def _read_logcat(self) -> None:
        try:
            for line in self.logcat_proc.stdout:
                self.logfile.write(line)
        except (ValueError, OSError):
            pass

    def _lc_size(self) -> int:
        try:
            return self._lc_path().stat().st_size
        except OSError:
            return 0

    def _lc_read_from(self, off: int) -> str:
        try:
            with open(self._lc_path(), "rb") as f:
                f.seek(off)
                return f.read().decode(errors="ignore")
        except OSError:
            return ""

    def mark_now(self) -> None:
        self.logfile.flush()
        self.mark = self._lc_size()

    def snapshot_phase(self) -> None:
        self.phase_off = self._lc_size()

    def text_from_phase(self) -> str:
        return self._lc_read_from(self.phase_off)

    def text_full(self) -> str:
        return self._lc_read_from(0)

    def wake(self) -> None:
        adb(self.serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
        adb(self.serial, "shell", "wm", "dismiss-keyguard")

    def launch_engine(self) -> None:
        self.wake()
        adb(self.serial, "shell", "am", "start", "-n", APP_ACTIVITY,
            "--ez", "LITEP2P_AUTOSTART", "true",
            "--es", "LITEP2P_PEER_ID", self.pid,
            "--es", "LITEP2P_COMMS_MODE", "UDP")
        self.engine_up = True
        self.mark_now()

    def crash(self) -> None:
        adb(self.serial, "shell", "am", "force-stop", APP_PKG)
        self.engine_up = False
        self.mark_now()

    def send_msg(self, peer_id: str, msg: str) -> None:
        self.wake()
        adb(self.serial, "shell", "am", "start", "-n", APP_ACTIVITY,
            "--es", "LITEP2P_SEND_TO_PEER", peer_id,
            "--es", "LITEP2P_SEND_MESSAGE", msg)

    def connect_to(self, peer_id: str) -> None:
        self.wake()
        adb(self.serial, "shell", "am", "start", "-n", APP_ACTIVITY,
            "--es", "LITEP2P_CONNECT_TO_PEER", peer_id)

    def block_network(self) -> None:
        if self.uid:
            adb(self.serial, "shell", "cmd", "netpolicy",
                "set", "uid-policy", self.uid, "reject")
            self.net_blocked = True

    def unblock_network(self) -> None:
        if self.uid:
            adb(self.serial, "shell", "cmd", "netpolicy",
                "set", "uid-policy", self.uid, "allow")
            self.net_blocked = False

    def stop(self) -> None:
        self.unblock_network()
        if self.logcat_proc:
            try:
                self.logcat_proc.terminate()
            except OSError:
                pass
        try:
            self.logfile.close()
        except OSError:
            pass


class SoakHarness:
    def __init__(self, args):
        self.args = args
        self.rng = random.Random(args.seed)
        self.rundir = (REPO_ROOT / "tools" / "harness" / "runs" /
                       f"rugged_soak_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.rundir.mkdir(parents=True, exist_ok=True)
        self.desktops = []
        self.androids = []
        self.sent = {}          # token -> (phase, src, dst, t_send)
        self.delivered = {}     # token -> latency_ms
        self.phase_results = []
        self.disrupted = set()

    # ---------------- topology ----------------

    def setup(self) -> bool:
        binary = find_binary()
        if not binary:
            log("FATAL: desktop peer binary not found (build desktop/build_mac.sh)")
            return False
        log(f"binary : {binary}")
        log(f"run dir: {self.rundir}")

        cfg_src = REPO_ROOT / "config.json"
        for i in range(1, self.args.desktop + 1):
            wd = self.rundir / f"d{i}"
            wd.mkdir(parents=True, exist_ok=True)
            cfg = wd / "config.json"
            shutil.copy2(cfg_src, cfg)
            self.desktops.append(DesktopPeer(f"soak-d{i}", 35100 + i, wd, cfg, binary))

        for idx, serial in enumerate(self.args.android_serials, start=1):
            self.androids.append(AndroidPeer(serial, f"soak-a{idx}", self.rundir))

        log(f"topology: {len(self.desktops)} desktop + {len(self.androids)} android")
        for a in self.androids:
            log(f"  android {a.pid} on {a.serial} (uid={a.uid or '?'})")
        return True

    def all_peers(self):
        return list(self.desktops) + list(self.androids)

    def snapshot_phase(self) -> None:
        """Snapshot log offsets for fresh-evidence checks (does not touch the
        disrupted set; phases reset it explicitly)."""
        for p in self.all_peers():
            p.snapshot_phase()

    def mark_disrupted(self, *peers) -> None:
        for p in peers:
            self.disrupted.add(p.pid)

    def active_peers(self):
        """Peers expected to communicate right now."""
        d = [p for p in self.desktops if p.alive and not p.frozen]
        a = [p for p in self.androids if p.engine_up and not p.net_blocked]
        return d + a

    # ---------------- READY mesh (strict, fresh evidence) ----------------

    def wait_ready_mesh(self, timeout: float) -> tuple:
        t0 = time.time()
        deadline = t0 + timeout
        peers = self.active_peers()
        while time.time() < deadline:
            missing = []
            for a in peers:
                for b in peers:
                    if a is b:
                        continue
                    touched = (a.pid in self.disrupted) or (b.pid in self.disrupted)
                    text = a.text_from_phase() if touched else a.text_full()
                    if f"READY peer={b.pid}" not in text:
                        missing.append((a.pid, b.pid))
            if not missing:
                return True, [], time.time() - t0
            time.sleep(1.0)
        return False, missing, time.time() - t0

    # ---------------- strict all-pairs volley ----------------

    def volley(self, phase: str) -> dict:
        peers = self.active_peers()
        tokens = []
        n = 0
        for src in peers:
            for dst in peers:
                if src is dst:
                    continue
                n += 1
                token = f"S{phase}-M{n}"
                src.send_msg(dst.pid, token)
                self.sent[token] = (phase, src.pid, dst.pid, time.time())
                tokens.append(token)
        deadline = time.time() + self.args.msg_timeout
        while time.time() < deadline:
            pending = [t for t in tokens if t not in self.delivered]
            if not pending:
                break
            for t in list(pending):
                _, _, dst_id, t0 = self.sent[t]
                dst = next((p for p in self.all_peers() if p.pid == dst_id), None)
                if dst is None:
                    continue
                if t in dst.text_full():
                    self.delivered[t] = (time.time() - t0) * 1000.0
            time.sleep(0.5)
        lost = [t for t in tokens if t not in self.delivered]
        return {"phase": phase, "sent": len(tokens),
                "delivered": len(tokens) - len(lost), "lost": lost}

    # ---------------- rugged churn operations ----------------

    def op_kill9_desktop(self):
        cands = [p for p in self.desktops if p.alive and not p.frozen]
        if not cands:
            return "(skip: no live desktop)"
        victim = self.rng.choice(cands)
        victim.kill9()
        self.mark_disrupted(victim)
        return f"kill -9 desktop {victim.pid} (left dead)"

    def op_restart_desktop(self):
        cands = [p for p in self.desktops if p.dead]
        if not cands:
            return "(skip: no dead desktop)"
        p = self.rng.choice(cands)
        p.start()
        self.mark_disrupted(p)
        return f"restarted desktop {p.pid}"

    def op_freeze_desktop(self):
        cands = [p for p in self.desktops if p.alive and not p.frozen]
        if not cands:
            return "(skip: nothing to freeze)"
        p = self.rng.choice(cands)
        p.freeze()
        self.mark_disrupted(p)
        return f"SIGSTOP desktop {p.pid} (blackout)"

    def op_unfreeze_all(self):
        frozen = [p for p in self.desktops if p.frozen]
        if not frozen:
            return "(skip: nothing frozen)"
        for p in frozen:
            p.unfreeze()
            self.mark_disrupted(p)
        return "SIGCONT " + ", ".join(p.pid for p in frozen) + " (blackout ended)"

    def op_android_crash(self):
        if not self.androids:
            return "(skip: no android)"
        a = self.rng.choice(self.androids)
        a.crash()
        self.mark_disrupted(a)
        return f"force-stop {a.pid} (app crash, left down)"

    def op_android_relaunch(self):
        if not self.androids:
            return "(skip: no android)"
        a = self.rng.choice(self.androids)
        a.launch_engine()
        self.mark_disrupted(a)
        return f"relaunched {a.pid} + engine autostart (crash recovery)"

    def op_android_netblock(self):
        if not self.androids:
            return "(skip: no android)"
        a = self.rng.choice([x for x in self.androids if not x.net_blocked] or self.androids)
        if a.net_blocked:
            return "(skip: already blocked)"
        a.block_network()
        self.mark_disrupted(a)
        return f"netpolicy reject {a.pid} (network/internet outage)"

    def op_android_netrestore(self):
        blocked = [x for x in self.androids if x.net_blocked]
        if not blocked:
            return "(skip: none blocked)"
        for a in blocked:
            a.unblock_network()
            self.mark_disrupted(a)
        return "netpolicy allow " + ", ".join(a.pid for a in blocked) + " (outage ended)"

    # ---------------- phase runner ----------------

    def run_phase(self, idx: int, op_fn) -> None:
        self.disrupted = set()   # fresh evidence scope for this phase
        # Snapshot BEFORE the op: READY lines produced by post-op recovery
        # (including during the settle window) must count as fresh evidence.
        self.snapshot_phase()
        desc = op_fn() if op_fn else "baseline"
        log(f"--- phase {idx}: {desc}")
        time.sleep(self.args.settle)
        ok, missing, elapsed = self.wait_ready_mesh(self.args.ready_timeout)
        if not ok:
            log(f"READY mesh FAILED after {elapsed:.1f}s; missing: {missing[:8]}")
        res = self.volley(str(idx))
        res["op"] = desc
        res["ready_ok"] = ok
        res["ready_secs"] = round(elapsed, 1)
        self.phase_results.append(res)
        lat = [v for v in self.delivered.values()]
        med = sorted(lat)[len(lat)//2] if lat else 0
        log(f"phase {idx} result: ready={'OK' if ok else 'FAIL'} ({elapsed:.1f}s) "
                       f"msgs {res['delivered']}/{res['sent']} lost={len(res['lost'])} "
                       f"(median lat {med:.0f}ms)")
        if res["lost"]:
            for t in res["lost"]:
                _, s, d, _ = self.sent[t]
                log(f"  LOST {t}: {s} -> {d}")

    def bring_all_up(self) -> None:
        for p in self.desktops:
            if not p.alive:
                p.start()
                self.mark_disrupted(p)
        for p in self.desktops:
            if p.frozen:
                p.unfreeze()
                self.mark_disrupted(p)
        for a in self.androids:
            if a.net_blocked:
                a.unblock_network()
                self.mark_disrupted(a)
            if not a.engine_up:
                a.launch_engine()
                self.mark_disrupted(a)

    def write_report(self, verdict: str) -> Path:
        total_sent = len(self.sent)
        total_del = len(self.delivered)
        lines = []
        lines.append("=" * 72)
        lines.append(f"RUGGED SOAK REPORT  {datetime.now().isoformat()}")
        lines.append(f"seed={self.args.seed} desktops={len(self.desktops)} "
                     f"androids={len(self.androids)}")
        lines.append("=" * 72)
        for r in self.phase_results:
            lines.append(f"phase {r['phase']:>3} | ready={'OK ' if r['ready_ok'] else 'FAIL'} "
                         f"{r['ready_secs']:>5.1f}s | msgs {r['delivered']}/{r['sent']} "
                         f"| lost {len(r['lost'])} | {r['op']}")
            for t in r["lost"]:
                _, s, d, _ = self.sent[t]
                lines.append(f"         LOST {t}: {s} -> {d}")
        lines.append("-" * 72)
        lines.append(f"TOTAL messages sent={total_sent} delivered={total_del} "
                     f"lost={total_sent - total_del}")
        lat = sorted(self.delivered.values())
        if lat:
            lines.append(f"latency ms: min={lat[0]:.0f} median={lat[len(lat)//2]:.0f} "
                         f"p95={lat[int(len(lat)*0.95)-1]:.0f} max={lat[-1]:.0f}")
        lines.append(f"VERDICT: {verdict}")
        text = "\n".join(lines)
        path = self.rundir / "report.txt"
        path.write_text(text)
        print(text)
        return path

    # ---------------- main run ----------------

    def pre_cleanup(self) -> None:
        """Kill any leftover soak desktop peers and stop the app so a crashed
        previous run can never poison this one with duplicate peer IDs."""
        try:
            subprocess.run(["pkill", "-9", "-f", "litep2p_peer_mac --id soak-"],
                           capture_output=True, timeout=10)
            subprocess.run(["pkill", "-9", "-f", "litep2p_peer_linux --id soak-"],
                           capture_output=True, timeout=10)
        except Exception:
            pass
        for serial in self.args.android_serials:
            adb(serial, "shell", "am", "force-stop", APP_PKG)
        time.sleep(2)

    def run(self) -> int:
        if not self.setup():
            return 2

        self.pre_cleanup()

        for a in self.androids:
            a.crash()          # clean slate: kill any engine already running
            a.start_logcat()
            a.launch_engine()
        for p in self.desktops:
            p.start()

        log("waiting for baseline READY mesh ...")
        self.snapshot_phase()   # before settle: count READY during settle as fresh
        time.sleep(self.args.settle)
        self.mark_disrupted(*self.all_peers())
        ok, missing, elapsed = self.wait_ready_mesh(self.args.ready_timeout)
        log(f"baseline mesh: {'OK' if ok else 'FAIL'} in {elapsed:.1f}s"
            + (f" missing={missing[:6]}" if not ok else ""))
        res = self.volley("base")
        res["op"] = "baseline"
        res["ready_ok"] = ok
        res["ready_secs"] = round(elapsed, 1)
        self.phase_results.append(res)
        log(f"baseline volley: {res['delivered']}/{res['sent']} delivered, lost={len(res['lost'])}")

        ops = [
            (self.op_kill9_desktop, 3),
            (self.op_restart_desktop, 3),
            (self.op_freeze_desktop, 2),
            (self.op_unfreeze_all, 2),
            (self.op_android_crash, 3),
            (self.op_android_relaunch, 3),
            (self.op_android_netblock, 2),
            (self.op_android_netrestore, 2),
        ]
        fn_weight = [f for f, w in ops for _ in range(w)]

        for i in range(1, self.args.phases + 1):
            fn = self.rng.choice(fn_weight)
            self.run_phase(i, fn)

        log("--- final phase: bring everything back up")
        self.snapshot_phase()   # before bring-up: recovery READY lines count as fresh
        self.bring_all_up()
        time.sleep(self.args.settle)
        ok, missing, elapsed = self.wait_ready_mesh(self.args.ready_timeout)
        log(f"final mesh: {'OK' if ok else 'FAIL'} in {elapsed:.1f}s"
            + (f" missing={missing[:6]}" if not ok else ""))
        res = self.volley("fin")
        res["op"] = "final full recovery"
        res["ready_ok"] = ok
        res["ready_secs"] = round(elapsed, 1)
        self.phase_results.append(res)

        lost = len(self.sent) - len(self.delivered)
        all_ready = all(r["ready_ok"] for r in self.phase_results)
        verdict = ("PASS" if lost == 0 and all_ready
                   else f"FAIL ({lost} messages lost, "
                        f"{sum(1 for r in self.phase_results if not r['ready_ok'])} phase(s) failed READY)")
        path = self.write_report(verdict)

        for p in self.desktops:
            p.stop()
        for a in self.androids:
            a.stop()
        log(f"artifacts: {self.rundir} (report: {path.name})")
        return 0 if verdict == "PASS" else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Rugged LiteP2P connectivity soak")
    ap.add_argument("--desktop", type=int, default=4, help="number of desktop peers")
    ap.add_argument("--android-serials", default=None,
                    help="comma-separated adb serials (default: all attached)")
    ap.add_argument("--phases", type=int, default=7, help="random churn phases")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--settle", type=float, default=10.0, help="post-op settle seconds")
    ap.add_argument("--ready-timeout", type=float, default=75.0)
    ap.add_argument("--msg-timeout", type=float, default=25.0)
    args = ap.parse_args()

    serials = (args.android_serials.split(",") if args.android_serials
               else adb_devices())
    serials = [s.strip() for s in serials if s.strip()]
    args.android_serials = serials

    try:
        return SoakHarness(args).run()
    except KeyboardInterrupt:
        log("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
