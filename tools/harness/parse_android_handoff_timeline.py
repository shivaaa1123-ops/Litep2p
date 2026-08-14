#!/usr/bin/env python3

"""Parse Android logcat (threadtime) from a handoff run and emit a concise timeline.

Inputs:
  - run directory created by tools/harness/android_wifi_handoff_repro.sh

Outputs (in run dir by default):
  - timeline.md

This is intentionally stdlib-only.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional


_TS_RE = re.compile(r"^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+")


@dataclass(frozen=True)
class Event:
    ts: datetime
    rel_s: float
    kind: str
    detail: str
    line: str


def _parse_ts(line: str) -> Optional[datetime]:
    m = _TS_RE.match(line)
    if not m:
        return None
    try:
        # Year is not present in logcat threadtime; use 1900. Only relative deltas matter.
        return datetime.strptime(m.group(1), "%m-%d %H:%M:%S.%f")
    except Exception:
        return None


def _iter_lines(path: Path) -> Iterable[str]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\n")


def _extract_marker(line: str) -> Optional[str]:
    idx = line.find("MARK:")
    if idx == -1:
        return None
    return line[idx + len("MARK:") :].strip()


def _classify(line: str) -> Optional[tuple[str, str]]:
    marker = _extract_marker(line)
    if marker is not None:
        return ("MARK", marker)

    patterns: list[tuple[str, str]] = [
        ("NET_CHANGE", r"Network change detected"),
        ("NET_INFO", r"Network info update"),
        ("SIGNAL_RECV_END", r"Signaling: Receive loop ended"),
        ("SIGNAL_RECONNECT", r"Signaling reconnect attempt"),
        ("SIGNAL_CONNECTED", r"Signaling: Connected successfully"),
        ("SIGNAL_REGISTER_ACK", r"REGISTER_ACK"),
        ("SIGNAL_PEER_LIST", r"\bPEER_LIST\b"),
        ("CONNECT_SUCCESS", r"CONNECT_SUCCESS"),
        ("CONNECT_FAILED", r"CONNECT_FAILED"),
        ("STUN_START", r"STUN: === Starting NAT Detection"),
    ]

    for kind, pat in patterns:
        if re.search(pat, line):
            # Keep a short detail for readability.
            detail = line
            if len(detail) > 180:
                detail = detail[:177] + "..."
            return (kind, detail)

    return None


def build_timeline(log_path: Path) -> list[Event]:
    events: list[Event] = []

    t0: Optional[datetime] = None
    for line in _iter_lines(log_path):
        ts = _parse_ts(line)
        if ts is None:
            continue

        cls = _classify(line)
        if cls is None:
            continue

        if t0 is None:
            # Prefer the first run_start marker if present; otherwise first event.
            if cls[0] == "MARK" and cls[1].startswith("run_start"):
                t0 = ts
            else:
                # Tentative; may be overwritten when run_start arrives.
                t0 = ts

        # If we later see run_start, reset t0 and recompute existing rel times.
        if cls[0] == "MARK" and cls[1].startswith("run_start") and t0 != ts:
            t0 = ts
            events = [
                Event(e.ts, (e.ts - t0).total_seconds(), e.kind, e.detail, e.line) for e in events
            ]

        rel_s = (ts - t0).total_seconds() if t0 is not None else 0.0
        events.append(Event(ts=ts, rel_s=rel_s, kind=cls[0], detail=cls[1], line=line))

    return events


def render_markdown(events: list[Event]) -> str:
    out: list[str] = []
    out.append("# Android handoff timeline\n")
    out.append("| t (s) | kind | detail |")
    out.append("| ---: | --- | --- |")

    for e in events:
        detail = e.detail.replace("|", "&#124;")
        out.append(f"| {e.rel_s:8.3f} | {e.kind} | {detail} |")

    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse LiteP2P Android handoff logcat into a timeline")
    ap.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Run directory containing android_logcat_threadtime.txt (preferred)",
    )
    ap.add_argument(
        "--logcat",
        type=Path,
        default=None,
        help="Explicit path to android_logcat_threadtime.txt",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output markdown path (default: <run_dir>/timeline.md)",
    )

    args = ap.parse_args()

    log_path: Optional[Path] = args.logcat
    run_dir: Optional[Path] = args.run_dir

    if log_path is None:
        if run_dir is None:
            ap.error("Provide --run-dir or --logcat")
        log_path = (run_dir / "android_logcat_threadtime.txt").resolve()

    log_path = log_path.expanduser().resolve()
    if run_dir is None:
        run_dir = log_path.parent

    if not log_path.exists():
        raise FileNotFoundError(f"Logcat file not found: {log_path}")

    out_path = args.out
    if out_path is None:
        out_path = (run_dir / "timeline.md").resolve()
    else:
        out_path = out_path.expanduser().resolve()

    events = build_timeline(log_path)
    md = render_markdown(events)

    out_path.write_text(md, encoding="utf-8")
    print(str(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
