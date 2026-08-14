#!/usr/bin/env python3
"""Fail-fast SLA checker for Android handoff harness runs.

Reads the JSON produced by tools/harness/summarize_android_handoff_timings.py
(typically: <run_dir>/timing_summary.md.json) and enforces a strict recovery SLA.

Default SLA:
- For every loop, for every peer:
  - wifi_disable: connected_after_wifi_disable_s must be present and <= SLA
  - wifi_enable:  connected_after_wifi_enable_s must be present and <= SLA
- For every loop, for every phase *where a reconnect is observed* (peer DISCONNECTED or non-zero time-to-CONNECTED):
    - REGISTER_ACK latency after wifi_disable and wifi_enable must be present and <= SLA

This is intentionally strict to surface reliability gaps.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _as_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _load_summary(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise SystemExit(f"ERROR: summary json not found: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"ERROR: failed to parse json {path}: {e}")


def _find_default_summary_json(run_dir: Path) -> Path:
    # Default produced by summarize_android_handoff_timings.py when --out timing_summary.md
    p = run_dir / "timing_summary.md.json"
    if p.exists():
        return p

    # Fallback: any *.md.json under the run dir.
    cands = sorted(run_dir.glob("*.md.json"))
    if cands:
        return cands[0]

    raise SystemExit(
        "ERROR: could not find timing summary json under run dir. Expected timing_summary.md.json"
    )


def check(
    summary: Dict[str, Any],
    sla_s: float,
    require_register_ack: bool,
    require_ready: bool,
) -> Tuple[bool, List[str]]:
    violations: List[str] = []

    peers: List[str] = list(summary.get("peers") or [])
    per_loop: List[Dict[str, Any]] = list(summary.get("per_loop") or [])
    per_case: List[Dict[str, Any]] = list(summary.get("per_case") or [])

    def v(msg: str) -> None:
        violations.append(msg)

    if per_case:
        for row in per_case:
            loop = row.get("loop")
            scenario = row.get("scenario")
            phase = row.get("phase")

            row_peers: Dict[str, Any] = row.get("peers") or {}

            # We only require REGISTER_ACK in a phase when the run actually had to reconnect
            # (i.e., we observed a DISCONNECTED or a non-zero time-to-CONNECTED).
            need_register_ack = False

            for peer in peers:
                pdata = row_peers.get(peer)
                if not isinstance(pdata, dict):
                    v(f"loop={loop} scenario={scenario} phase={phase} peer={peer}: missing peer data")
                    need_register_ack = True
                    continue

                c = _as_float(pdata.get("connected_after_s"))
                if c is None:
                    v(f"loop={loop} scenario={scenario} phase={phase} peer={peer}: missing CONNECTED timing")
                    need_register_ack = True
                else:
                    if c > 0.001:
                        need_register_ack = True
                    if c > sla_s:
                        v(
                            f"loop={loop} scenario={scenario} phase={phase} peer={peer}: CONNECTED {c:.3f}s > SLA {sla_s:.3f}s"
                        )

                if require_ready:
                    r = _as_float(pdata.get("ready_after_s"))
                    if r is None:
                        v(f"loop={loop} scenario={scenario} phase={phase} peer={peer}: missing READY timing")
                    elif r > sla_s:
                        v(
                            f"loop={loop} scenario={scenario} phase={phase} peer={peer}: READY {r:.3f}s > SLA {sla_s:.3f}s"
                        )

                # If we saw an explicit disconnect in a phase window, treat it as a reconnect signal.
                if pdata.get("disconnected_after_s") is not None:
                    need_register_ack = True

                # Extra signal: if a disconnect was observed, ensure DISCONNECTED->reCONNECTED is within SLA too.
                d2r = _as_float(pdata.get("disconnect_to_reconnect_s"))
                if d2r is not None and d2r > sla_s:
                    v(
                        f"loop={loop} scenario={scenario} phase={phase} peer={peer}: DISCONNECTED->reCONNECTED {d2r:.3f}s > SLA {sla_s:.3f}s"
                    )

            if require_register_ack and need_register_ack:
                ra = row.get("register_ack")
                if not ra:
                    v(f"loop={loop} scenario={scenario} phase={phase}: missing REGISTER_ACK")
                else:
                    try:
                        marker_ts = datetime.fromisoformat(str(row.get("start_used") or row.get("start") or row.get("start_cmd")))
                        ack_ts = datetime.fromisoformat(str(ra))
                        dt_s = (ack_ts - marker_ts).total_seconds()
                    except Exception:
                        v(f"loop={loop} scenario={scenario} phase={phase}: cannot parse marker/REGISTER_ACK timestamps")
                    else:
                        if dt_s < 0:
                            dt_s = 0.0
                        if dt_s > sla_s:
                            v(
                                f"loop={loop} scenario={scenario} phase={phase}: REGISTER_ACK {dt_s:.3f}s > SLA {sla_s:.3f}s"
                            )

        return (len(violations) == 0), violations

    for row in per_loop:
        loop = row.get("loop")

        # Peer connected-at-SLA strictness.
        row_peers: Dict[str, Any] = row.get("peers") or {}

        # We only require REGISTER_ACK in a phase when the run actually had to reconnect
        # (i.e., we observed a DISCONNECTED or a non-zero time-to-CONNECTED).
        need_register_ack: Dict[str, bool] = {"wifi_disable": False, "wifi_enable": False}

        for peer in peers:
            pdata = row_peers.get(peer)
            if not isinstance(pdata, dict):
                v(f"loop={loop} peer={peer}: missing peer data")
                continue

            for phase, key in (
                ("wifi_disable", "connected_after_wifi_disable_s"),
                ("wifi_enable", "connected_after_wifi_enable_s"),
            ):
                val = _as_float(pdata.get(key))
                if val is None:
                    v(f"loop={loop} peer={peer} phase={phase}: missing CONNECTED timing")
                    need_register_ack[phase] = True
                    continue
                # If we weren't already CONNECTED at the marker, this is the time to recover.
                # Any non-trivial recovery indicates we should also see signaling recover.
                if val > 0.001:
                    need_register_ack[phase] = True
                if val > sla_s:
                    v(f"loop={loop} peer={peer} phase={phase}: CONNECTED {val:.3f}s > SLA {sla_s:.3f}s")

            if require_ready:
                for phase, key in (
                    ("wifi_disable", "ready_after_wifi_disable_s"),
                    ("wifi_enable", "ready_after_wifi_enable_s"),
                ):
                    r = _as_float(pdata.get(key))
                    if r is None:
                        v(f"loop={loop} peer={peer} phase={phase}: missing READY timing")
                        continue
                    if r > sla_s:
                        v(f"loop={loop} peer={peer} phase={phase}: READY {r:.3f}s > SLA {sla_s:.3f}s")

            # If we saw an explicit disconnect in a phase window, treat it as a reconnect signal.
            if pdata.get("disconnected_after_wifi_disable_s") is not None:
                need_register_ack["wifi_disable"] = True
            if pdata.get("disconnected_after_wifi_enable_s") is not None:
                need_register_ack["wifi_enable"] = True

            # Extra signal: if a disconnect was observed, ensure DISCONNECTED->reCONNECTED is within SLA too.
            for phase, d2r_key in (
                ("wifi_disable", "disconnect_to_reconnect_wifi_disable_s"),
                ("wifi_enable", "disconnect_to_reconnect_wifi_enable_s"),
            ):
                d2r = _as_float(pdata.get(d2r_key))
                if d2r is None:
                    continue
                if d2r > sla_s:
                    v(
                        f"loop={loop} peer={peer} phase={phase}: DISCONNECTED->reCONNECTED {d2r:.3f}s > SLA {sla_s:.3f}s"
                    )

        # REGISTER_ACK strictness (conditional).
        if require_register_ack:
            ra = row.get("register_ack") or {}
            for phase in ("wifi_disable", "wifi_enable"):
                if not need_register_ack.get(phase, False):
                    continue

                if phase not in ra:
                    v(f"loop={loop} phase={phase}: missing REGISTER_ACK")
                    continue

                # Enforce REGISTER_ACK latency within SLA.
                try:
                    marker_key = f"{phase}_cmd" if row.get(f"{phase}_cmd") else phase
                    marker_ts = datetime.fromisoformat(str(row.get(marker_key)))
                    ack_ts = datetime.fromisoformat(str(ra.get(phase)))
                    dt_s = (ack_ts - marker_ts).total_seconds()
                except Exception:
                    v(f"loop={loop} phase={phase}: cannot parse marker/REGISTER_ACK timestamps")
                    continue

                # If the chosen marker was emitted after the ACK (e.g., due to waiting for a
                # "ready" condition), treat negative deltas as 0 for SLA purposes.
                if dt_s < 0:
                    dt_s = 0.0

                if dt_s > sla_s:
                    v(f"loop={loop} phase={phase}: REGISTER_ACK {dt_s:.3f}s > SLA {sla_s:.3f}s")

    return (len(violations) == 0), violations


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, help="Run dir: tools/harness/runs/android_handoff_*.")
    ap.add_argument(
        "--summary-json",
        default="",
        help="Explicit path to summary json (default: <run_dir>/timing_summary.md.json).",
    )
    ap.add_argument("--sla-seconds", type=float, default=8.0, help="SLA threshold in seconds (default: 8).")
    ap.add_argument(
        "--require-ready",
        action="store_true",
        help="Also require PeerFSM READY timing (ready-for-messaging) to be present and <= SLA.",
    )
    ap.add_argument(
        "--no-require-register-ack",
        action="store_true",
        help="Do not require REGISTER_ACK per phase per loop (still checks peer connectivity).",
    )

    args = ap.parse_args()
    run_dir = Path(args.run_dir).expanduser().resolve()
    summary_json = Path(args.summary_json).expanduser().resolve() if args.summary_json else _find_default_summary_json(run_dir)

    summary = _load_summary(summary_json)

    ok, violations = check(
        summary=summary,
        sla_s=float(args.sla_seconds),
        require_register_ack=not bool(args.no_require_register_ack),
        require_ready=bool(args.require_ready),
    )

    if ok:
        print(f"SLA PASS: {run_dir}")
        return

    print(f"SLA FAIL: {run_dir}")
    print(f"summary_json={summary_json}")
    print("Violations:")
    for line in violations:
        print(f"- {line}")

    # Helpful pointers.
    print("\nEvidence:")
    print(f"- android full log: {run_dir / 'android_logcat_threadtime.txt'}")
    print(f"- android high-signal: {run_dir / 'android_logcat_high_signal.txt'}")
    print(f"- counts: {run_dir / 'log_counts.txt'}")
    sys.exit(2)


if __name__ == "__main__":
    main()
