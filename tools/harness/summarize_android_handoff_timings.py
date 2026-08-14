#!/usr/bin/env python3
"""Summarize reconnection timings from an android handoff harness run.

Parses adb logcat (-v threadtime) output captured by
tools/harness/android_wifi_handoff_repro.sh and computes per-loop latencies from
MARK wifi_disable/wifi_enable to the next peer reaching CONNECTED.

This intentionally avoids needing to understand full session semantics; it keys
off the existing [PeerFSM] transition logs.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


_THREADTIME_TS_RE = re.compile(
    r"^(?P<mon>\d\d)-(?P<day>\d\d) (?P<h>\d\d):(?P<m>\d\d):(?P<s>\d\d)\.(?P<ms>\d\d\d)\s"
)

_MARK_RE = re.compile(r"\bMARK:\s*(?P<msg>.*)$")

# Example:
# 01-09 02:37:11.273 ... I LiteP2P_Native: [NO_SESSION] [PeerFSM] UNKNOWN --(DISCOVERED)--> DISCOVERED peer=desktop-1
# 01-09 02:42:15.479 ... I LiteP2P_Native: [NO_SESSION] [PeerFSM] DISCOVERED --(CONNECT_SUCCESS)--> CONNECTED peer=desktop-2
_PEER_FSM_CONNECTED_RE = re.compile(r"\[PeerFSM\].*?-->\s*CONNECTED\s+peer=(?P<peer>[^\s]+)")
_PEER_FSM_DISCONNECTED_RE = re.compile(r"\[PeerFSM\].*?-->\s*DISCONNECTED\s+peer=(?P<peer>[^\s]+)")
_PEER_FSM_READY_RE = re.compile(r"\[PeerFSM\].*?-->\s*READY\s+peer=(?P<peer>[^\s]+)")

_REGISTER_ACK_RE = re.compile(r"\bREGISTER_ACK\b")

# Signaling reconnect/connect timing (best-effort).
_SIGNAL_RECONNECT_ATTEMPT_RE = re.compile(r"SM:\s*Signaling reconnect attempt", re.IGNORECASE)
_SIGNAL_CONNECTED_RE = re.compile(r"\bSignaling:\s*Connected successfully\b", re.IGNORECASE)

# Best-effort extraction of Android connectivity callback points.
# Log tags/levels vary across devices and builds; keep this broad.
_NETWORK_CALLBACK_RE = re.compile(r"NetworkCallbacks:\s*(?P<what>[^\s]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Marker:
    loop: int
    scenario: Optional[str]
    name: str
    ts: datetime


@dataclass(frozen=True)
class PeerEvent:
    peer: str
    kind: str  # CONNECTED/DISCONNECTED/READY
    ts: datetime
    line: str


@dataclass(frozen=True)
class NetworkCallbackEvent:
    ts: datetime
    kind: str  # AVAILABLE/LOST/CAPS/LP/OTHER


def _infer_year_from_run_dir(run_dir: Path) -> int:
    m = re.search(r"android_handoff_(\d{4})(\d{2})(\d{2})_", run_dir.name)
    if m:
        return int(m.group(1))
    # Fallback: current year (best-effort).
    return datetime.now().year


def _parse_threadtime_ts(line: str, year: int) -> Optional[datetime]:
    m = _THREADTIME_TS_RE.match(line)
    if not m:
        return None
    mon = int(m.group("mon"))
    day = int(m.group("day"))
    h = int(m.group("h"))
    mi = int(m.group("m"))
    s = int(m.group("s"))
    ms = int(m.group("ms"))

    # adb threadtime has no timezone/year. Use local time with an attached tzinfo
    # purely for arithmetic; we don’t rely on absolute wall-clock correctness.
    # (Using local tz would require platform calls; keep it simple and stable.)
    return datetime(year, mon, day, h, mi, s, ms * 1000, tzinfo=timezone.utc)


def _read_log_lines(run_dir: Path) -> List[str]:
    candidates = [
        run_dir / "android_logcat_threadtime.txt",
        run_dir / "android_logcat_dump_threadtime.txt",
    ]
    lines: List[str] = []
    for p in candidates:
        if p.exists():
            try:
                lines.extend(p.read_text(errors="replace").splitlines())
            except Exception:
                # Best-effort: skip unreadable file.
                pass
    return lines


def _parse_markers(lines: Sequence[str], year: int) -> List[Marker]:
    out: List[Marker] = []
    for line in lines:
        ts = _parse_threadtime_ts(line, year)
        if not ts:
            continue
        mm = _MARK_RE.search(line)
        if not mm:
            continue
        msg = mm.group("msg").strip()

        # We care about:
        #   MARK: wifi_disable loop=1
        #   MARK: wifi_enable loop=1
        #   MARK: loop_1_end
        loop: Optional[int] = None

        m_loop_kv = re.search(r"\bloop=(\d+)\b", msg)
        if m_loop_kv:
            loop = int(m_loop_kv.group(1))

        m_loop_marker = re.match(r"loop_(\d+)_(start|end)\b", msg)
        if m_loop_marker:
            loop = int(m_loop_marker.group(1))

        if loop is None:
            continue

        scenario: Optional[str] = None
        m_scenario_kv = re.search(r"\bscenario=([^\s]+)\b", msg)
        if m_scenario_kv:
            scenario = m_scenario_kv.group(1)

        if msg.startswith("wifi_disable_cmd"):
            out.append(Marker(loop=loop, scenario=scenario, name="wifi_disable_cmd", ts=ts))
        elif msg.startswith("wifi_disable_end"):
            out.append(Marker(loop=loop, scenario=scenario, name="wifi_disable_end", ts=ts))
        elif msg.startswith("wifi_disable"):
            out.append(Marker(loop=loop, scenario=scenario, name="wifi_disable", ts=ts))
        elif msg.startswith("wifi_enable_cmd"):
            out.append(Marker(loop=loop, scenario=scenario, name="wifi_enable_cmd", ts=ts))
        elif msg.startswith("wifi_enable"):
            out.append(Marker(loop=loop, scenario=scenario, name="wifi_enable", ts=ts))
        elif msg.startswith("data_disable_cmd"):
            out.append(Marker(loop=loop, scenario=scenario, name="data_disable_cmd", ts=ts))
        elif msg.startswith("data_disable_end"):
            out.append(Marker(loop=loop, scenario=scenario, name="data_disable_end", ts=ts))
        elif msg.startswith("data_disable"):
            out.append(Marker(loop=loop, scenario=scenario, name="data_disable", ts=ts))
        elif msg.startswith("data_enable_cmd"):
            out.append(Marker(loop=loop, scenario=scenario, name="data_enable_cmd", ts=ts))
        elif msg.startswith("data_enable"):
            out.append(Marker(loop=loop, scenario=scenario, name="data_enable", ts=ts))
        elif msg.startswith("no_network_enable_cmd"):
            out.append(Marker(loop=loop, scenario=scenario, name="no_network_enable_cmd", ts=ts))
        elif msg.startswith("no_network_enable"):
            out.append(Marker(loop=loop, scenario=scenario, name="no_network_enable", ts=ts))
        elif msg.startswith("no_network_disable_cmd"):
            out.append(Marker(loop=loop, scenario=scenario, name="no_network_disable_cmd", ts=ts))
        elif msg.startswith("no_network_disable"):
            out.append(Marker(loop=loop, scenario=scenario, name="no_network_disable", ts=ts))
        elif msg.startswith("scenario_start"):
            out.append(Marker(loop=loop, scenario=scenario, name="scenario_start", ts=ts))
        elif msg.startswith("scenario_end"):
            out.append(Marker(loop=loop, scenario=scenario, name="scenario_end", ts=ts))
        elif msg.startswith("scenario_skip"):
            out.append(Marker(loop=loop, scenario=scenario, name="scenario_skip", ts=ts))
        elif re.match(r"loop_\d+_end\b", msg):
            out.append(Marker(loop=loop, scenario=scenario, name="loop_end", ts=ts))

    return out


def _parse_peer_events(lines: Sequence[str], year: int) -> List[PeerEvent]:
    out: List[PeerEvent] = []
    for line in lines:
        ts = _parse_threadtime_ts(line, year)
        if not ts:
            continue

        m = _PEER_FSM_CONNECTED_RE.search(line)
        if m:
            out.append(PeerEvent(peer=m.group("peer"), kind="CONNECTED", ts=ts, line=line))
            continue

        m = _PEER_FSM_READY_RE.search(line)
        if m:
            out.append(PeerEvent(peer=m.group("peer"), kind="READY", ts=ts, line=line))
            continue

        m = _PEER_FSM_DISCONNECTED_RE.search(line)
        if m:
            out.append(PeerEvent(peer=m.group("peer"), kind="DISCONNECTED", ts=ts, line=line))
            continue

    return out


def _parse_register_acks(lines: Sequence[str], year: int) -> List[datetime]:
    out: List[datetime] = []
    for line in lines:
        if not _REGISTER_ACK_RE.search(line):
            continue
        ts = _parse_threadtime_ts(line, year)
        if ts:
            out.append(ts)
    return out


def _parse_signaling_reconnect_attempts(lines: Sequence[str], year: int) -> List[datetime]:
    out: List[datetime] = []
    for line in lines:
        if not _SIGNAL_RECONNECT_ATTEMPT_RE.search(line):
            continue
        ts = _parse_threadtime_ts(line, year)
        if ts:
            out.append(ts)
    return out


def _parse_signaling_connected(lines: Sequence[str], year: int) -> List[datetime]:
    out: List[datetime] = []
    for line in lines:
        if not _SIGNAL_CONNECTED_RE.search(line):
            continue
        ts = _parse_threadtime_ts(line, year)
        if ts:
            out.append(ts)
    return out


def _parse_network_callbacks(lines: Sequence[str], year: int) -> List[NetworkCallbackEvent]:
    out: List[NetworkCallbackEvent] = []
    for line in lines:
        m = _NETWORK_CALLBACK_RE.search(line)
        if not m:
            continue
        ts = _parse_threadtime_ts(line, year)
        if not ts:
            continue

        what = (m.group("what") or "").lower()
        if "available" in what:
            kind = "AVAILABLE"
        elif "lost" in what:
            kind = "LOST"
        elif "capabilit" in what:
            kind = "CAPS"
        elif "linkpropert" in what:
            kind = "LP"
        else:
            kind = "OTHER"

        out.append(NetworkCallbackEvent(ts=ts, kind=kind))
    return out


def _first_ts_in_window(tss: Sequence[datetime], start: datetime, end: datetime) -> Optional[datetime]:
    for ts in tss:
        if start <= ts < end:
            return ts
    return None


def _first_ts_after_in_window(
    tss: Sequence[datetime], after_or_at: datetime, end: datetime
) -> Optional[datetime]:
    for ts in tss:
        if ts < after_or_at:
            continue
        if ts >= end:
            return None
        return ts
    return None


def _last_kind_before(events: Sequence[PeerEvent], ts: datetime) -> Optional[str]:
    """Return the last CONNECTED/DISCONNECTED kind observed strictly before ts."""
    last: Optional[str] = None
    for e in events:
        if e.ts >= ts:
            break
        last = e.kind
    return last


def _first_event_in_window(
    events: Sequence[PeerEvent], kind: str, start: datetime, end: datetime
) -> Optional[PeerEvent]:
    for e in events:
        if e.ts < start:
            continue
        if e.ts >= end:
            return None
        if e.kind == kind:
            return e
    return None


def _first_connected_after(
    events: Sequence[PeerEvent], start: datetime, end: datetime
) -> Optional[PeerEvent]:
    for e in events:
        if e.ts < start:
            continue
        if e.ts >= end:
            return None
        if e.kind == "CONNECTED":
            return e
    return None


def _format_secs(delta: Optional[float]) -> str:
    if delta is None:
        return "—"
    if delta < 0:
        return f"{delta:.3f}s"
    if delta < 10:
        return f"{delta:.3f}s"
    return f"{delta:.1f}s"


def _median(values: Sequence[float]) -> Optional[float]:
    if not values:
        return None
    return float(statistics.median(values))


def summarize(run_dir: Path, peers: Optional[Sequence[str]], out_path: Optional[Path]) -> Dict:
    year = _infer_year_from_run_dir(run_dir)
    lines = _read_log_lines(run_dir)

    markers = sorted(_parse_markers(lines, year), key=lambda m: m.ts)
    peer_events = sorted(_parse_peer_events(lines, year), key=lambda e: e.ts)
    register_acks = sorted(_parse_register_acks(lines, year))
    sig_reconnect_attempts = sorted(_parse_signaling_reconnect_attempts(lines, year))
    sig_connected = sorted(_parse_signaling_connected(lines, year))
    net_callbacks = sorted(_parse_network_callbacks(lines, year), key=lambda e: e.ts)
    net_callback_ts = [e.ts for e in net_callbacks]

    # Infer peers if not provided.
    if peers is None:
        inferred = sorted({e.peer for e in peer_events if e.peer.startswith("desktop-")})
        peers = inferred if inferred else sorted({e.peer for e in peer_events})

    # Build per-loop marker map (scenario-agnostic; last-wins if repeated).
    by_loop: Dict[int, Dict[str, datetime]] = {}
    for m in markers:
        by_loop.setdefault(m.loop, {})[m.name] = m.ts

    # Build per-(loop,scenario) marker map.
    # This enables multiple scenarios per loop without marker collisions.
    by_case: Dict[Tuple[int, str], Dict[str, datetime]] = {}
    for m in markers:
        if m.scenario is None:
            continue
        by_case.setdefault((m.loop, m.scenario), {})[m.name] = m.ts

    loops = sorted(set(by_loop.keys()) | {lp for (lp, _sc) in by_case.keys()})

    # Index peer events.
    events_by_peer: Dict[str, List[PeerEvent]] = {p: [] for p in peers}
    connected_ts_by_peer: Dict[str, List[datetime]] = {p: [] for p in peers}
    ready_ts_by_peer: Dict[str, List[datetime]] = {p: [] for p in peers}
    for e in peer_events:
        if e.peer not in events_by_peer:
            continue
        events_by_peer[e.peer].append(e)
        if e.kind == "CONNECTED":
            connected_ts_by_peer[e.peer].append(e.ts)
        if e.kind == "READY":
            ready_ts_by_peer[e.peer].append(e.ts)

    for p in peers:
        events_by_peer[p].sort(key=lambda ev: ev.ts)
        connected_ts_by_peer[p].sort()
        ready_ts_by_peer[p].sort()

    per_loop_rows = []
    latencies: Dict[str, Dict[str, List[float]]] = {
        "wifi_disable": {p: [] for p in peers},
        "wifi_enable": {p: [] for p in peers},
    }

    ready_latencies: Dict[str, Dict[str, List[float]]] = {
        "wifi_disable": {p: [] for p in peers},
        "wifi_enable": {p: [] for p in peers},
    }

    reconnect_latencies: Dict[str, Dict[str, List[float]]] = {
        "wifi_disable": {p: [] for p in peers},
        "wifi_enable": {p: [] for p in peers},
    }
    disconnect_to_reconnect_latencies: Dict[str, Dict[str, List[float]]] = {
        "wifi_disable": {p: [] for p in peers},
        "wifi_enable": {p: [] for p in peers},
    }
    reg_latencies: Dict[str, List[float]] = {"wifi_disable": [], "wifi_enable": []}
    net_latencies: Dict[str, List[float]] = {"wifi_disable": [], "wifi_enable": []}

    sig_reconnect_latencies: Dict[str, List[float]] = {"wifi_disable": [], "wifi_enable": []}
    sig_connected_latencies: Dict[str, List[float]] = {"wifi_disable": [], "wifi_enable": []}
    sig_connect_to_ack_latencies: Dict[str, List[float]] = {"wifi_disable": [], "wifi_enable": []}

    # Per-phase metrics used by the per-scenario breakdown.
    # Note: `_compute_phase()` is called for wifi_disable/wifi_enable phases too,
    # so these dicts must include those keys (not just the extra phases).
    base_phases = ("wifi_disable", "wifi_enable")
    extra_phases = ("data_disable", "data_enable", "no_network_enable", "no_network_disable")
    all_phases = base_phases + extra_phases

    phase_latencies: Dict[str, Dict[str, List[float]]] = {ph: {p: [] for p in peers} for ph in all_phases}
    phase_ready_latencies: Dict[str, Dict[str, List[float]]] = {ph: {p: [] for p in peers} for ph in all_phases}
    phase_reconnect_latencies: Dict[str, Dict[str, List[float]]] = {ph: {p: [] for p in peers} for ph in all_phases}
    phase_disconnect_to_reconnect_latencies: Dict[str, Dict[str, List[float]]] = {ph: {p: [] for p in peers} for ph in all_phases}
    phase_reg_latencies: Dict[str, List[float]] = {ph: [] for ph in all_phases}
    phase_sig_reconnect_latencies: Dict[str, List[float]] = {ph: [] for ph in all_phases}
    phase_sig_connected_latencies: Dict[str, List[float]] = {ph: [] for ph in all_phases}
    phase_sig_connect_to_ack_latencies: Dict[str, List[float]] = {ph: [] for ph in all_phases}
    phase_net_latencies: Dict[str, List[float]] = {ph: [] for ph in all_phases}

    per_case_rows: List[Dict[str, Any]] = []

    def _phase_end_or_case_end(end_ts: Optional[datetime], case_end: datetime) -> datetime:
        if end_ts is None:
            return case_end
        return end_ts if end_ts <= case_end else case_end

    def _compute_phase(
        *,
        loop: int,
        scenario: str,
        phase: str,
        marker_ts: datetime,
        cmd_ts: Optional[datetime],
        end_ts: datetime,
    ) -> Dict[str, Any]:
        # For ACK/signaling/callback latencies, prefer the *_cmd marker when available.
        start_req = cmd_ts or marker_ts

        row: Dict[str, Any] = {
            "loop": loop,
            "scenario": scenario,
            "phase": phase,
            "start_cmd": cmd_ts.isoformat() if cmd_ts else None,
            "start": marker_ts.isoformat(),
            "start_used": start_req.isoformat(),
            "end": end_ts.isoformat(),
            "peers": {},
            "register_ack": None,
            "signaling": {},
        }

        # Register ACK timings (best-effort).
        reg_ts = _first_ts_in_window(register_acks, start_req, end_ts)
        if reg_ts:
            phase_reg_latencies[phase].append((reg_ts - start_req).total_seconds())
            row["register_ack"] = reg_ts.isoformat()

        # Signaling reconnect/connect timings (best-effort).
        sra = _first_ts_in_window(sig_reconnect_attempts, start_req, end_ts)
        if sra:
            phase_sig_reconnect_latencies[phase].append((sra - start_req).total_seconds())
            row["signaling"]["reconnect_attempt"] = sra.isoformat()

        sc = _first_ts_in_window(sig_connected, start_req, end_ts)
        if sc:
            phase_sig_connected_latencies[phase].append((sc - start_req).total_seconds())
            row["signaling"]["connected"] = sc.isoformat()

        if sc:
            ack_after_sc = _first_ts_after_in_window(register_acks, sc, end_ts)
            if ack_after_sc:
                phase_sig_connect_to_ack_latencies[phase].append((ack_after_sc - sc).total_seconds())
                row["signaling"]["connected_to_register_ack"] = ack_after_sc.isoformat()

        # First NetworkCallbacks event after marker (best-effort).
        cb_ts = _first_ts_in_window(net_callback_ts, start_req, end_ts)
        if cb_ts:
            phase_net_latencies[phase].append((cb_ts - start_req).total_seconds())
            row["network_callbacks"] = cb_ts.isoformat()

        for peer in peers:
            before = _last_kind_before(events_by_peer.get(peer, []), marker_ts)

            c_ts = None
            if before not in ("CONNECTED", "READY"):
                c_ts = _first_ts_in_window(connected_ts_by_peer.get(peer, []), marker_ts, end_ts)
            d_connected = 0.0 if before in ("CONNECTED", "READY") else ((c_ts - marker_ts).total_seconds() if c_ts else None)

            before_ready = _last_kind_before(events_by_peer.get(peer, []), marker_ts)
            r_ts = None
            if before_ready != "READY":
                r_ts = _first_ts_in_window(ready_ts_by_peer.get(peer, []), marker_ts, end_ts)
            d_ready = 0.0 if before_ready == "READY" else ((r_ts - marker_ts).total_seconds() if r_ts else None)

            disc = _first_event_in_window(events_by_peer.get(peer, []), "DISCONNECTED", marker_ts, end_ts)
            rec = _first_connected_after(
                events_by_peer.get(peer, []),
                disc.ts if disc else marker_ts,
                end_ts,
            )
            if disc and rec and rec.ts >= disc.ts:
                phase_reconnect_latencies[phase][peer].append((rec.ts - marker_ts).total_seconds())
                phase_disconnect_to_reconnect_latencies[phase][peer].append((rec.ts - disc.ts).total_seconds())

            if d_connected is not None:
                phase_latencies[phase][peer].append(d_connected)
            if d_ready is not None:
                phase_ready_latencies[phase][peer].append(d_ready)

            row["peers"][peer] = {
                "state_before": before,
                "connected_after_s": d_connected,
                "ready_after_s": d_ready,
                "disconnected_after_s": (disc.ts - marker_ts).total_seconds() if disc else None,
                "reconnected_after_s": (rec.ts - marker_ts).total_seconds() if (disc and rec) else None,
                "disconnect_to_reconnect_s": (rec.ts - disc.ts).total_seconds() if (disc and rec) else None,
            }

        return row

    for idx, loop in enumerate(loops):
        md = by_loop[loop]
        t_disable_cmd = md.get("wifi_disable_cmd")
        t_disable = md.get("wifi_disable")
        t_disable_end = md.get("wifi_disable_end")
        t_enable_cmd = md.get("wifi_enable_cmd")
        t_enable = md.get("wifi_enable")

        t_end = md.get("loop_end")

        # Scenario-aware per-phase rows (wifi/data/no_network). This runs even if a loop
        # doesn't contain wifi markers (e.g., SCENARIOS=data only).
        case_keys = [(lp, sc) for (lp, sc) in by_case.keys() if lp == loop]
        if case_keys:
            # Order scenarios by their scenario_start marker when present (fallback: earliest marker time).
            case_start: Dict[Tuple[int, str], datetime] = {}
            for ck in case_keys:
                cmd = by_case.get(ck, {})
                if "scenario_start" in cmd:
                    case_start[ck] = cmd["scenario_start"]
                elif cmd:
                    case_start[ck] = min(cmd.values())
            ordered = sorted(case_keys, key=lambda ck: case_start.get(ck, datetime.max.replace(tzinfo=timezone.utc)))

            # Pre-compute next scenario start for fallback end windows.
            next_start: Dict[Tuple[int, str], Optional[datetime]] = {}
            for j, ck in enumerate(ordered):
                next_start[ck] = case_start.get(ordered[j + 1]) if j + 1 < len(ordered) else None

            loop_end_ts = md.get("loop_end")

            for ck in ordered:
                _lp, scenario = ck
                cmd = by_case.get(ck, {})
                if not cmd:
                    continue

                sc_start = cmd.get("scenario_start") or case_start.get(ck) or min(cmd.values())
                sc_end = cmd.get("scenario_end") or next_start.get(ck) or loop_end_ts or (sc_start + timedelta(minutes=10))

                # Scenario-specific phases.
                if scenario == "wifi":
                    # wifi_disable window ends at wifi_disable_end (preferred) or wifi_enable or scenario end.
                    if cmd.get("wifi_disable"):
                        p_end = _phase_end_or_case_end(cmd.get("wifi_disable_end") or cmd.get("wifi_enable"), sc_end)
                        per_case_rows.append(
                            _compute_phase(
                                loop=loop,
                                scenario=scenario,
                                phase="wifi_disable",
                                marker_ts=cmd["wifi_disable"],
                                cmd_ts=cmd.get("wifi_disable_cmd"),
                                end_ts=p_end,
                            )
                        )
                    if cmd.get("wifi_enable"):
                        p_end = _phase_end_or_case_end(None, sc_end)
                        per_case_rows.append(
                            _compute_phase(
                                loop=loop,
                                scenario=scenario,
                                phase="wifi_enable",
                                marker_ts=cmd["wifi_enable"],
                                cmd_ts=cmd.get("wifi_enable_cmd"),
                                end_ts=p_end,
                            )
                        )

                elif scenario == "data":
                    if cmd.get("data_disable"):
                        p_end = _phase_end_or_case_end(cmd.get("data_disable_end") or cmd.get("data_enable"), sc_end)
                        per_case_rows.append(
                            _compute_phase(
                                loop=loop,
                                scenario=scenario,
                                phase="data_disable",
                                marker_ts=cmd["data_disable"],
                                cmd_ts=cmd.get("data_disable_cmd"),
                                end_ts=p_end,
                            )
                        )
                    if cmd.get("data_enable"):
                        p_end = _phase_end_or_case_end(None, sc_end)
                        per_case_rows.append(
                            _compute_phase(
                                loop=loop,
                                scenario=scenario,
                                phase="data_enable",
                                marker_ts=cmd["data_enable"],
                                cmd_ts=cmd.get("data_enable_cmd"),
                                end_ts=p_end,
                            )
                        )

                elif scenario in ("no_network", "airplane"):
                    if cmd.get("no_network_enable"):
                        p_end = _phase_end_or_case_end(
                            cmd.get("no_network_disable_cmd") or cmd.get("no_network_disable"),
                            sc_end,
                        )
                        per_case_rows.append(
                            _compute_phase(
                                loop=loop,
                                scenario=scenario,
                                phase="no_network_enable",
                                marker_ts=cmd["no_network_enable"],
                                cmd_ts=cmd.get("no_network_enable_cmd"),
                                end_ts=p_end,
                            )
                        )
                    if cmd.get("no_network_disable"):
                        p_end = _phase_end_or_case_end(None, sc_end)
                        per_case_rows.append(
                            _compute_phase(
                                loop=loop,
                                scenario=scenario,
                                phase="no_network_disable",
                                marker_ts=cmd["no_network_disable"],
                                cmd_ts=cmd.get("no_network_disable_cmd"),
                                end_ts=p_end,
                            )
                        )

                else:
                    # Unknown scenario; ignore.
                    continue

        if not t_disable or not t_enable:
            continue

        # Prefer *_cmd markers as the start of a phase when available.
        # These reflect when we requested the transition, and they avoid missing fast events
        # that can occur before the later "ready" markers (e.g., REGISTER_ACK before wifi_enable).
        t_disable_start = t_disable_cmd or t_disable
        t_enable_start = t_enable_cmd or t_enable

        # Define windows.
        # - wifi_disable phase ends at wifi_disable_end marker when present; otherwise at wifi_enable.
        # - wifi_enable phase ends at loop_end marker (preferred), otherwise at the next loop's
        #   wifi_disable marker, otherwise a generous fallback.
        win_disable_end = t_disable_end or t_enable
        next_loop_disable = None
        if idx + 1 < len(loops):
            next_loop_disable = by_loop.get(loops[idx + 1], {}).get("wifi_disable")
        win_enable_end = t_end or next_loop_disable or (t_enable + timedelta(minutes=10))

        row = {
            "loop": loop,
            "wifi_disable_cmd": t_disable_cmd.isoformat() if t_disable_cmd else None,
            "wifi_disable": t_disable.isoformat(),
            "wifi_disable_end": t_disable_end.isoformat() if t_disable_end else None,
            "wifi_enable_cmd": t_enable_cmd.isoformat() if t_enable_cmd else None,
            "wifi_enable": t_enable.isoformat(),
            "peers": {},
            "register_ack": {},
        }

        row["signaling"] = {"wifi_disable": {}, "wifi_enable": {}}

        # Register ACK timings (best-effort).
        reg_after_disable = _first_ts_in_window(register_acks, t_disable_start, win_disable_end)
        if reg_after_disable:
            reg_latencies["wifi_disable"].append((reg_after_disable - t_disable_start).total_seconds())
            row["register_ack"]["wifi_disable"] = reg_after_disable.isoformat()

        reg_after_enable = _first_ts_in_window(register_acks, t_enable_start, win_enable_end)
        if reg_after_enable:
            reg_latencies["wifi_enable"].append((reg_after_enable - t_enable_start).total_seconds())
            row["register_ack"]["wifi_enable"] = reg_after_enable.isoformat()

        # Signaling reconnect/connect timings (best-effort).
        sra_disable = _first_ts_in_window(sig_reconnect_attempts, t_disable_start, win_disable_end)
        if sra_disable:
            sig_reconnect_latencies["wifi_disable"].append((sra_disable - t_disable_start).total_seconds())
            row["signaling"]["wifi_disable"]["reconnect_attempt"] = sra_disable.isoformat()

        sc_disable = _first_ts_in_window(sig_connected, t_disable_start, win_disable_end)
        if sc_disable:
            sig_connected_latencies["wifi_disable"].append((sc_disable - t_disable_start).total_seconds())
            row["signaling"]["wifi_disable"]["connected"] = sc_disable.isoformat()

        if sc_disable:
            ack_after_sc_disable = _first_ts_after_in_window(register_acks, sc_disable, win_disable_end)
            if ack_after_sc_disable:
                sig_connect_to_ack_latencies["wifi_disable"].append(
                    (ack_after_sc_disable - sc_disable).total_seconds()
                )
                row["signaling"]["wifi_disable"]["connected_to_register_ack"] = ack_after_sc_disable.isoformat()

        sra_enable = _first_ts_in_window(sig_reconnect_attempts, t_enable_start, win_enable_end)
        if sra_enable:
            sig_reconnect_latencies["wifi_enable"].append((sra_enable - t_enable_start).total_seconds())
            row["signaling"]["wifi_enable"]["reconnect_attempt"] = sra_enable.isoformat()

        sc_enable = _first_ts_in_window(sig_connected, t_enable_start, win_enable_end)
        if sc_enable:
            sig_connected_latencies["wifi_enable"].append((sc_enable - t_enable_start).total_seconds())
            row["signaling"]["wifi_enable"]["connected"] = sc_enable.isoformat()

        if sc_enable:
            ack_after_sc_enable = _first_ts_after_in_window(register_acks, sc_enable, win_enable_end)
            if ack_after_sc_enable:
                sig_connect_to_ack_latencies["wifi_enable"].append(
                    (ack_after_sc_enable - sc_enable).total_seconds()
                )
                row["signaling"]["wifi_enable"]["connected_to_register_ack"] = ack_after_sc_enable.isoformat()

        # First NetworkCallbacks event after marker (best-effort).
        cb_after_disable = _first_ts_in_window(net_callback_ts, t_disable_start, win_disable_end)
        if cb_after_disable:
            net_latencies["wifi_disable"].append((cb_after_disable - t_disable_start).total_seconds())
            row.setdefault("network_callbacks", {})["wifi_disable"] = cb_after_disable.isoformat()

        cb_after_enable = _first_ts_in_window(net_callback_ts, t_enable_start, win_enable_end)
        if cb_after_enable:
            net_latencies["wifi_enable"].append((cb_after_enable - t_enable_start).total_seconds())
            row.setdefault("network_callbacks", {})["wifi_enable"] = cb_after_enable.isoformat()

        for peer in peers:
            # If already connected at the marker time, treat as 0s.
            # When Noise is enabled, READY implies the peer is connected and ready for messaging.
            before_disable = _last_kind_before(events_by_peer.get(peer, []), t_disable)
            before_enable = _last_kind_before(events_by_peer.get(peer, []), t_enable)

            c_disable = None
            if before_disable not in ("CONNECTED", "READY"):
                c_disable = _first_ts_in_window(connected_ts_by_peer.get(peer, []), t_disable, win_disable_end)

            c_enable = None
            if before_enable not in ("CONNECTED", "READY"):
                c_enable = _first_ts_in_window(connected_ts_by_peer.get(peer, []), t_enable, win_enable_end)

            d_disable = 0.0 if before_disable in ("CONNECTED", "READY") else ((c_disable - t_disable).total_seconds() if c_disable else None)
            d_enable = 0.0 if before_enable in ("CONNECTED", "READY") else ((c_enable - t_enable).total_seconds() if c_enable else None)

            # READY timing (best-effort): marker -> first READY.
            # With Noise enabled, READY corresponds to "ready for messaging".
            # With Noise disabled, READY may be absent; we still expose this metric.
            before_disable_ready = _last_kind_before(events_by_peer.get(peer, []), t_disable)
            before_enable_ready = _last_kind_before(events_by_peer.get(peer, []), t_enable)

            r_disable_ts = None
            if before_disable_ready != "READY":
                r_disable_ts = _first_ts_in_window(ready_ts_by_peer.get(peer, []), t_disable, win_disable_end)

            r_enable_ts = None
            if before_enable_ready != "READY":
                r_enable_ts = _first_ts_in_window(ready_ts_by_peer.get(peer, []), t_enable, win_enable_end)

            r_disable = 0.0 if before_disable_ready == "READY" else ((r_disable_ts - t_disable).total_seconds() if r_disable_ts else None)
            r_enable = 0.0 if before_enable_ready == "READY" else ((r_enable_ts - t_enable).total_seconds() if r_enable_ts else None)

            # True reconnect timing: marker -> (DISCONNECTED -> CONNECTED).
            # This stays empty when a peer never disconnects during that phase.
            disc_disable = _first_event_in_window(events_by_peer.get(peer, []), "DISCONNECTED", t_disable, win_disable_end)
            rec_disable = _first_connected_after(
                events_by_peer.get(peer, []),
                disc_disable.ts if disc_disable else t_disable,
                win_disable_end,
            )
            if disc_disable and rec_disable and rec_disable.ts >= disc_disable.ts:
                reconnect_latencies["wifi_disable"][peer].append((rec_disable.ts - t_disable).total_seconds())
                disconnect_to_reconnect_latencies["wifi_disable"][peer].append((rec_disable.ts - disc_disable.ts).total_seconds())

            disc_enable = _first_event_in_window(events_by_peer.get(peer, []), "DISCONNECTED", t_enable, win_enable_end)
            rec_enable = _first_connected_after(
                events_by_peer.get(peer, []),
                disc_enable.ts if disc_enable else t_enable,
                win_enable_end,
            )
            if disc_enable and rec_enable and rec_enable.ts >= disc_enable.ts:
                reconnect_latencies["wifi_enable"][peer].append((rec_enable.ts - t_enable).total_seconds())
                disconnect_to_reconnect_latencies["wifi_enable"][peer].append((rec_enable.ts - disc_enable.ts).total_seconds())

            if d_disable is not None:
                latencies["wifi_disable"][peer].append(d_disable)
            if d_enable is not None:
                latencies["wifi_enable"][peer].append(d_enable)

            if r_disable is not None:
                ready_latencies["wifi_disable"][peer].append(r_disable)
            if r_enable is not None:
                ready_latencies["wifi_enable"][peer].append(r_enable)

            row["peers"][peer] = {
                "state_before_wifi_disable": before_disable,
                "state_before_wifi_enable": before_enable,
                "connected_after_wifi_disable_s": d_disable,
                "connected_after_wifi_enable_s": d_enable,
                "ready_after_wifi_disable_s": r_disable,
                "ready_after_wifi_enable_s": r_enable,
                "disconnected_after_wifi_disable_s": (disc_disable.ts - t_disable).total_seconds() if disc_disable else None,
                "reconnected_after_wifi_disable_s": (rec_disable.ts - t_disable).total_seconds() if (disc_disable and rec_disable) else None,
                "disconnect_to_reconnect_wifi_disable_s": (rec_disable.ts - disc_disable.ts).total_seconds() if (disc_disable and rec_disable) else None,
                "disconnected_after_wifi_enable_s": (disc_enable.ts - t_enable).total_seconds() if disc_enable else None,
                "reconnected_after_wifi_enable_s": (rec_enable.ts - t_enable).total_seconds() if (disc_enable and rec_enable) else None,
                "disconnect_to_reconnect_wifi_enable_s": (rec_enable.ts - disc_enable.ts).total_seconds() if (disc_enable and rec_enable) else None,
            }

        per_loop_rows.append(row)

    summary = {
        "run_dir": str(run_dir),
        "year": year,
        "peers": list(peers),
        "loops_detected": loops,
        "per_loop": per_loop_rows,
        "per_case": per_case_rows,
        "stats": {
            "wifi_disable": {},
            "wifi_enable": {},
            "data_disable": {},
            "data_enable": {},
            "no_network_enable": {},
            "no_network_disable": {},
            "ready_for_messaging": {
                "wifi_disable": {},
                "wifi_enable": {},
                "data_disable": {},
                "data_enable": {},
                "no_network_enable": {},
                "no_network_disable": {},
            },
            "reconnect_after_disconnect": {
                "wifi_disable": {},
                "wifi_enable": {},
                "data_disable": {},
                "data_enable": {},
                "no_network_enable": {},
                "no_network_disable": {},
            },
            "disconnect_to_reconnect": {
                "wifi_disable": {},
                "wifi_enable": {},
                "data_disable": {},
                "data_enable": {},
                "no_network_enable": {},
                "no_network_disable": {},
            },
            "register_ack": {
                "wifi_disable": {
                    "count": len(reg_latencies["wifi_disable"]),
                    "min_s": min(reg_latencies["wifi_disable"]) if reg_latencies["wifi_disable"] else None,
                    "median_s": _median(reg_latencies["wifi_disable"]),
                    "max_s": max(reg_latencies["wifi_disable"]) if reg_latencies["wifi_disable"] else None,
                },
                "wifi_enable": {
                    "count": len(reg_latencies["wifi_enable"]),
                    "min_s": min(reg_latencies["wifi_enable"]) if reg_latencies["wifi_enable"] else None,
                    "median_s": _median(reg_latencies["wifi_enable"]),
                    "max_s": max(reg_latencies["wifi_enable"]) if reg_latencies["wifi_enable"] else None,
                },
                "data_disable": {
                    "count": len(phase_reg_latencies["data_disable"]),
                    "min_s": min(phase_reg_latencies["data_disable"]) if phase_reg_latencies["data_disable"] else None,
                    "median_s": _median(phase_reg_latencies["data_disable"]),
                    "max_s": max(phase_reg_latencies["data_disable"]) if phase_reg_latencies["data_disable"] else None,
                },
                "data_enable": {
                    "count": len(phase_reg_latencies["data_enable"]),
                    "min_s": min(phase_reg_latencies["data_enable"]) if phase_reg_latencies["data_enable"] else None,
                    "median_s": _median(phase_reg_latencies["data_enable"]),
                    "max_s": max(phase_reg_latencies["data_enable"]) if phase_reg_latencies["data_enable"] else None,
                },
                "no_network_enable": {
                    "count": len(phase_reg_latencies["no_network_enable"]),
                    "min_s": min(phase_reg_latencies["no_network_enable"]) if phase_reg_latencies["no_network_enable"] else None,
                    "median_s": _median(phase_reg_latencies["no_network_enable"]),
                    "max_s": max(phase_reg_latencies["no_network_enable"]) if phase_reg_latencies["no_network_enable"] else None,
                },
                "no_network_disable": {
                    "count": len(phase_reg_latencies["no_network_disable"]),
                    "min_s": min(phase_reg_latencies["no_network_disable"]) if phase_reg_latencies["no_network_disable"] else None,
                    "median_s": _median(phase_reg_latencies["no_network_disable"]),
                    "max_s": max(phase_reg_latencies["no_network_disable"]) if phase_reg_latencies["no_network_disable"] else None,
                },
            },
            "signaling": {
                "reconnect_attempt": {
                    "wifi_disable": {
                        "count": len(sig_reconnect_latencies["wifi_disable"]),
                        "min_s": min(sig_reconnect_latencies["wifi_disable"]) if sig_reconnect_latencies["wifi_disable"] else None,
                        "median_s": _median(sig_reconnect_latencies["wifi_disable"]),
                        "max_s": max(sig_reconnect_latencies["wifi_disable"]) if sig_reconnect_latencies["wifi_disable"] else None,
                    },
                    "wifi_enable": {
                        "count": len(sig_reconnect_latencies["wifi_enable"]),
                        "min_s": min(sig_reconnect_latencies["wifi_enable"]) if sig_reconnect_latencies["wifi_enable"] else None,
                        "median_s": _median(sig_reconnect_latencies["wifi_enable"]),
                        "max_s": max(sig_reconnect_latencies["wifi_enable"]) if sig_reconnect_latencies["wifi_enable"] else None,
                    },
                    "data_disable": {
                        "count": len(phase_sig_reconnect_latencies["data_disable"]),
                        "min_s": min(phase_sig_reconnect_latencies["data_disable"]) if phase_sig_reconnect_latencies["data_disable"] else None,
                        "median_s": _median(phase_sig_reconnect_latencies["data_disable"]),
                        "max_s": max(phase_sig_reconnect_latencies["data_disable"]) if phase_sig_reconnect_latencies["data_disable"] else None,
                    },
                    "data_enable": {
                        "count": len(phase_sig_reconnect_latencies["data_enable"]),
                        "min_s": min(phase_sig_reconnect_latencies["data_enable"]) if phase_sig_reconnect_latencies["data_enable"] else None,
                        "median_s": _median(phase_sig_reconnect_latencies["data_enable"]),
                        "max_s": max(phase_sig_reconnect_latencies["data_enable"]) if phase_sig_reconnect_latencies["data_enable"] else None,
                    },
                    "no_network_enable": {
                        "count": len(phase_sig_reconnect_latencies["no_network_enable"]),
                        "min_s": min(phase_sig_reconnect_latencies["no_network_enable"]) if phase_sig_reconnect_latencies["no_network_enable"] else None,
                        "median_s": _median(phase_sig_reconnect_latencies["no_network_enable"]),
                        "max_s": max(phase_sig_reconnect_latencies["no_network_enable"]) if phase_sig_reconnect_latencies["no_network_enable"] else None,
                    },
                    "no_network_disable": {
                        "count": len(phase_sig_reconnect_latencies["no_network_disable"]),
                        "min_s": min(phase_sig_reconnect_latencies["no_network_disable"]) if phase_sig_reconnect_latencies["no_network_disable"] else None,
                        "median_s": _median(phase_sig_reconnect_latencies["no_network_disable"]),
                        "max_s": max(phase_sig_reconnect_latencies["no_network_disable"]) if phase_sig_reconnect_latencies["no_network_disable"] else None,
                    },
                },
                "connected": {
                    "wifi_disable": {
                        "count": len(sig_connected_latencies["wifi_disable"]),
                        "min_s": min(sig_connected_latencies["wifi_disable"]) if sig_connected_latencies["wifi_disable"] else None,
                        "median_s": _median(sig_connected_latencies["wifi_disable"]),
                        "max_s": max(sig_connected_latencies["wifi_disable"]) if sig_connected_latencies["wifi_disable"] else None,
                    },
                    "wifi_enable": {
                        "count": len(sig_connected_latencies["wifi_enable"]),
                        "min_s": min(sig_connected_latencies["wifi_enable"]) if sig_connected_latencies["wifi_enable"] else None,
                        "median_s": _median(sig_connected_latencies["wifi_enable"]),
                        "max_s": max(sig_connected_latencies["wifi_enable"]) if sig_connected_latencies["wifi_enable"] else None,
                    },
                    "data_disable": {
                        "count": len(phase_sig_connected_latencies["data_disable"]),
                        "min_s": min(phase_sig_connected_latencies["data_disable"]) if phase_sig_connected_latencies["data_disable"] else None,
                        "median_s": _median(phase_sig_connected_latencies["data_disable"]),
                        "max_s": max(phase_sig_connected_latencies["data_disable"]) if phase_sig_connected_latencies["data_disable"] else None,
                    },
                    "data_enable": {
                        "count": len(phase_sig_connected_latencies["data_enable"]),
                        "min_s": min(phase_sig_connected_latencies["data_enable"]) if phase_sig_connected_latencies["data_enable"] else None,
                        "median_s": _median(phase_sig_connected_latencies["data_enable"]),
                        "max_s": max(phase_sig_connected_latencies["data_enable"]) if phase_sig_connected_latencies["data_enable"] else None,
                    },
                    "no_network_enable": {
                        "count": len(phase_sig_connected_latencies["no_network_enable"]),
                        "min_s": min(phase_sig_connected_latencies["no_network_enable"]) if phase_sig_connected_latencies["no_network_enable"] else None,
                        "median_s": _median(phase_sig_connected_latencies["no_network_enable"]),
                        "max_s": max(phase_sig_connected_latencies["no_network_enable"]) if phase_sig_connected_latencies["no_network_enable"] else None,
                    },
                    "no_network_disable": {
                        "count": len(phase_sig_connected_latencies["no_network_disable"]),
                        "min_s": min(phase_sig_connected_latencies["no_network_disable"]) if phase_sig_connected_latencies["no_network_disable"] else None,
                        "median_s": _median(phase_sig_connected_latencies["no_network_disable"]),
                        "max_s": max(phase_sig_connected_latencies["no_network_disable"]) if phase_sig_connected_latencies["no_network_disable"] else None,
                    },
                },
                "connected_to_register_ack": {
                    "wifi_disable": {
                        "count": len(sig_connect_to_ack_latencies["wifi_disable"]),
                        "min_s": min(sig_connect_to_ack_latencies["wifi_disable"]) if sig_connect_to_ack_latencies["wifi_disable"] else None,
                        "median_s": _median(sig_connect_to_ack_latencies["wifi_disable"]),
                        "max_s": max(sig_connect_to_ack_latencies["wifi_disable"]) if sig_connect_to_ack_latencies["wifi_disable"] else None,
                    },
                    "wifi_enable": {
                        "count": len(sig_connect_to_ack_latencies["wifi_enable"]),
                        "min_s": min(sig_connect_to_ack_latencies["wifi_enable"]) if sig_connect_to_ack_latencies["wifi_enable"] else None,
                        "median_s": _median(sig_connect_to_ack_latencies["wifi_enable"]),
                        "max_s": max(sig_connect_to_ack_latencies["wifi_enable"]) if sig_connect_to_ack_latencies["wifi_enable"] else None,
                    },
                    "data_disable": {
                        "count": len(phase_sig_connect_to_ack_latencies["data_disable"]),
                        "min_s": min(phase_sig_connect_to_ack_latencies["data_disable"]) if phase_sig_connect_to_ack_latencies["data_disable"] else None,
                        "median_s": _median(phase_sig_connect_to_ack_latencies["data_disable"]),
                        "max_s": max(phase_sig_connect_to_ack_latencies["data_disable"]) if phase_sig_connect_to_ack_latencies["data_disable"] else None,
                    },
                    "data_enable": {
                        "count": len(phase_sig_connect_to_ack_latencies["data_enable"]),
                        "min_s": min(phase_sig_connect_to_ack_latencies["data_enable"]) if phase_sig_connect_to_ack_latencies["data_enable"] else None,
                        "median_s": _median(phase_sig_connect_to_ack_latencies["data_enable"]),
                        "max_s": max(phase_sig_connect_to_ack_latencies["data_enable"]) if phase_sig_connect_to_ack_latencies["data_enable"] else None,
                    },
                    "no_network_enable": {
                        "count": len(phase_sig_connect_to_ack_latencies["no_network_enable"]),
                        "min_s": min(phase_sig_connect_to_ack_latencies["no_network_enable"]) if phase_sig_connect_to_ack_latencies["no_network_enable"] else None,
                        "median_s": _median(phase_sig_connect_to_ack_latencies["no_network_enable"]),
                        "max_s": max(phase_sig_connect_to_ack_latencies["no_network_enable"]) if phase_sig_connect_to_ack_latencies["no_network_enable"] else None,
                    },
                    "no_network_disable": {
                        "count": len(phase_sig_connect_to_ack_latencies["no_network_disable"]),
                        "min_s": min(phase_sig_connect_to_ack_latencies["no_network_disable"]) if phase_sig_connect_to_ack_latencies["no_network_disable"] else None,
                        "median_s": _median(phase_sig_connect_to_ack_latencies["no_network_disable"]),
                        "max_s": max(phase_sig_connect_to_ack_latencies["no_network_disable"]) if phase_sig_connect_to_ack_latencies["no_network_disable"] else None,
                    },
                },
            },
            "network_callbacks": {
                "wifi_disable": {
                    "count": len(net_latencies["wifi_disable"]),
                    "min_s": min(net_latencies["wifi_disable"]) if net_latencies["wifi_disable"] else None,
                    "median_s": _median(net_latencies["wifi_disable"]),
                    "max_s": max(net_latencies["wifi_disable"]) if net_latencies["wifi_disable"] else None,
                },
                "wifi_enable": {
                    "count": len(net_latencies["wifi_enable"]),
                    "min_s": min(net_latencies["wifi_enable"]) if net_latencies["wifi_enable"] else None,
                    "median_s": _median(net_latencies["wifi_enable"]),
                    "max_s": max(net_latencies["wifi_enable"]) if net_latencies["wifi_enable"] else None,
                },
                "data_disable": {
                    "count": len(phase_net_latencies["data_disable"]),
                    "min_s": min(phase_net_latencies["data_disable"]) if phase_net_latencies["data_disable"] else None,
                    "median_s": _median(phase_net_latencies["data_disable"]),
                    "max_s": max(phase_net_latencies["data_disable"]) if phase_net_latencies["data_disable"] else None,
                },
                "data_enable": {
                    "count": len(phase_net_latencies["data_enable"]),
                    "min_s": min(phase_net_latencies["data_enable"]) if phase_net_latencies["data_enable"] else None,
                    "median_s": _median(phase_net_latencies["data_enable"]),
                    "max_s": max(phase_net_latencies["data_enable"]) if phase_net_latencies["data_enable"] else None,
                },
                "no_network_enable": {
                    "count": len(phase_net_latencies["no_network_enable"]),
                    "min_s": min(phase_net_latencies["no_network_enable"]) if phase_net_latencies["no_network_enable"] else None,
                    "median_s": _median(phase_net_latencies["no_network_enable"]),
                    "max_s": max(phase_net_latencies["no_network_enable"]) if phase_net_latencies["no_network_enable"] else None,
                },
                "no_network_disable": {
                    "count": len(phase_net_latencies["no_network_disable"]),
                    "min_s": min(phase_net_latencies["no_network_disable"]) if phase_net_latencies["no_network_disable"] else None,
                    "median_s": _median(phase_net_latencies["no_network_disable"]),
                    "max_s": max(phase_net_latencies["no_network_disable"]) if phase_net_latencies["no_network_disable"] else None,
                },
            },
        },
    }

    for direction in ("wifi_disable", "wifi_enable"):
        for peer in peers:
            vals = latencies[direction][peer]
            summary["stats"][direction][peer] = {
                "count": len(vals),
                "min_s": min(vals) if vals else None,
                "median_s": _median(vals),
                "max_s": max(vals) if vals else None,
            }

            rvals_ready = ready_latencies[direction][peer]
            summary["stats"]["ready_for_messaging"][direction][peer] = {
                "count": len(rvals_ready),
                "min_s": min(rvals_ready) if rvals_ready else None,
                "median_s": _median(rvals_ready),
                "max_s": max(rvals_ready) if rvals_ready else None,
            }

            rvals = reconnect_latencies[direction][peer]
            summary["stats"]["reconnect_after_disconnect"][direction][peer] = {
                "count": len(rvals),
                "min_s": min(rvals) if rvals else None,
                "median_s": _median(rvals),
                "max_s": max(rvals) if rvals else None,
            }

            drvals = disconnect_to_reconnect_latencies[direction][peer]
            summary["stats"]["disconnect_to_reconnect"][direction][peer] = {
                "count": len(drvals),
                "min_s": min(drvals) if drvals else None,
                "median_s": _median(drvals),
                "max_s": max(drvals) if drvals else None,
            }

    # Extra phase peer stats (data/no_network).
    for phase in extra_phases:
        for peer in peers:
            vals = phase_latencies[phase][peer]
            summary["stats"][phase][peer] = {
                "count": len(vals),
                "min_s": min(vals) if vals else None,
                "median_s": _median(vals),
                "max_s": max(vals) if vals else None,
            }

            rvals_ready = phase_ready_latencies[phase][peer]
            summary["stats"]["ready_for_messaging"][phase][peer] = {
                "count": len(rvals_ready),
                "min_s": min(rvals_ready) if rvals_ready else None,
                "median_s": _median(rvals_ready),
                "max_s": max(rvals_ready) if rvals_ready else None,
            }

            rvals = phase_reconnect_latencies[phase][peer]
            summary["stats"]["reconnect_after_disconnect"][phase][peer] = {
                "count": len(rvals),
                "min_s": min(rvals) if rvals else None,
                "median_s": _median(rvals),
                "max_s": max(rvals) if rvals else None,
            }

            drvals = phase_disconnect_to_reconnect_latencies[phase][peer]
            summary["stats"]["disconnect_to_reconnect"][phase][peer] = {
                "count": len(drvals),
                "min_s": min(drvals) if drvals else None,
                "median_s": _median(drvals),
                "max_s": max(drvals) if drvals else None,
            }

    # Optional markdown report.
    if out_path:
        out_lines: List[str] = []
        out_lines.append("# Android handoff timing summary\n")
        out_lines.append(f"Run: `{run_dir}`\n")
        out_lines.append(f"Peers: {', '.join(peers) if peers else '(none)'}\n")

        all_phases = (
            "wifi_disable",
            "wifi_enable",
            "data_disable",
            "data_enable",
            "no_network_enable",
            "no_network_disable",
        )

        out_lines.append("## Aggregate stats (time to CONNECTED)\n")
        for direction in all_phases:
            out_lines.append(f"### {direction}\n")
            out_lines.append("| peer | n | min | median | max |\n|---|---:|---:|---:|---:|\n")
            for peer in peers:
                st = summary["stats"][direction][peer]
                out_lines.append(
                    "| {peer} | {n} | {mn} | {med} | {mx} |\n".format(
                        peer=peer,
                        n=st["count"],
                        mn=_format_secs(st["min_s"]),
                        med=_format_secs(st["median_s"]),
                        mx=_format_secs(st["max_s"]),
                    )
                )
            out_lines.append("\n")

        out_lines.append("## Signaling REGISTER_ACK latency (best-effort)\n")
        out_lines.append("| marker | n | min | median | max |\n|---|---:|---:|---:|---:|\n")
        for direction in all_phases:
            st = summary["stats"]["register_ack"][direction]
            out_lines.append(
                "| {dir} | {n} | {mn} | {med} | {mx} |\n".format(
                    dir=direction,
                    n=st["count"],
                    mn=_format_secs(st["min_s"]),
                    med=_format_secs(st["median_s"]),
                    mx=_format_secs(st["max_s"]),
                )
            )
        out_lines.append("\n")

        out_lines.append("## Signaling reconnect/connect timing (best-effort)\n")

        out_lines.append("### MARK → first SM: Signaling reconnect attempt\n")
        out_lines.append("| marker | n | min | median | max |\n|---|---:|---:|---:|---:|\n")
        for direction in all_phases:
            st = summary["stats"]["signaling"]["reconnect_attempt"][direction]
            out_lines.append(
                "| {dir} | {n} | {mn} | {med} | {mx} |\n".format(
                    dir=direction,
                    n=st["count"],
                    mn=_format_secs(st["min_s"]),
                    med=_format_secs(st["median_s"]),
                    mx=_format_secs(st["max_s"]),
                )
            )
        out_lines.append("\n")

        out_lines.append("### MARK → first Signaling: Connected successfully\n")
        out_lines.append("| marker | n | min | median | max |\n|---|---:|---:|---:|---:|\n")
        for direction in all_phases:
            st = summary["stats"]["signaling"]["connected"][direction]
            out_lines.append(
                "| {dir} | {n} | {mn} | {med} | {mx} |\n".format(
                    dir=direction,
                    n=st["count"],
                    mn=_format_secs(st["min_s"]),
                    med=_format_secs(st["median_s"]),
                    mx=_format_secs(st["max_s"]),
                )
            )
        out_lines.append("\n")

        out_lines.append("### Connected → REGISTER_ACK\n")
        out_lines.append("| marker | n | min | median | max |\n|---|---:|---:|---:|---:|\n")
        for direction in all_phases:
            st = summary["stats"]["signaling"]["connected_to_register_ack"][direction]
            out_lines.append(
                "| {dir} | {n} | {mn} | {med} | {mx} |\n".format(
                    dir=direction,
                    n=st["count"],
                    mn=_format_secs(st["min_s"]),
                    med=_format_secs(st["median_s"]),
                    mx=_format_secs(st["max_s"]),
                )
            )
        out_lines.append("\n")

        out_lines.append("## NetworkCallbacks latency (best-effort)\n")
        out_lines.append("| marker | n | min | median | max |\n|---|---:|---:|---:|---:|\n")
        for direction in all_phases:
            st = summary["stats"]["network_callbacks"][direction]
            out_lines.append(
                "| {dir} | {n} | {mn} | {med} | {mx} |\n".format(
                    dir=direction,
                    n=st["count"],
                    mn=_format_secs(st["min_s"]),
                    med=_format_secs(st["median_s"]),
                    mx=_format_secs(st["max_s"]),
                )
            )
        out_lines.append("\n")

        out_lines.append("## Reconnect timing *only when a DISCONNECTED occurs*\n")
        out_lines.append("### marker → reCONNECTED (after first DISCONNECTED in phase)\n")
        for direction in all_phases:
            out_lines.append(f"#### {direction}\n")
            out_lines.append("| peer | n | min | median | max |\n|---|---:|---:|---:|---:|\n")
            for peer in peers:
                st = summary["stats"]["reconnect_after_disconnect"][direction][peer]
                out_lines.append(
                    "| {peer} | {n} | {mn} | {med} | {mx} |\n".format(
                        peer=peer,
                        n=st["count"],
                        mn=_format_secs(st["min_s"]),
                        med=_format_secs(st["median_s"]),
                        mx=_format_secs(st["max_s"]),
                    )
                )
            out_lines.append("\n")

        out_lines.append("### DISCONNECTED → reCONNECTED\n")
        for direction in all_phases:
            out_lines.append(f"#### {direction}\n")
            out_lines.append("| peer | n | min | median | max |\n|---|---:|---:|---:|---:|\n")
            for peer in peers:
                st = summary["stats"]["disconnect_to_reconnect"][direction][peer]
                out_lines.append(
                    "| {peer} | {n} | {mn} | {med} | {mx} |\n".format(
                        peer=peer,
                        n=st["count"],
                        mn=_format_secs(st["min_s"]),
                        med=_format_secs(st["median_s"]),
                        mx=_format_secs(st["max_s"]),
                    )
                )
            out_lines.append("\n")

        out_lines.append("## Per-loop breakdown\n")
        out_lines.append("Each cell is time from MARK to first `[PeerFSM] ... --> CONNECTED` within that phase window.\n\n")

        header = "| loop | phase | " + " | ".join(peers) + " |\n"
        sep = "|---:|---|" + "|".join(["---:" for _ in peers]) + "|\n"
        out_lines.append(header)
        out_lines.append(sep)

        for row in per_loop_rows:
            loop = row["loop"]
            for direction in ("wifi_disable", "wifi_enable"):
                vals = []
                for peer in peers:
                    key = "connected_after_wifi_disable_s" if direction == "wifi_disable" else "connected_after_wifi_enable_s"
                    vals.append(_format_secs(row["peers"][peer][key]))
                out_lines.append(f"| {loop} | {direction} | " + " | ".join(vals) + " |\n")

        if per_case_rows:
            out_lines.append("\n## Per-scenario breakdown (all phases)\n")
            out_lines.append("Each cell is time from phase MARK to first `[PeerFSM] ... --> CONNECTED` within that phase window.\n\n")
            header = "| loop | scenario | phase | " + " | ".join(peers) + " |\n"
            sep = "|---:|---|---|" + "|".join(["---:" for _ in peers]) + "|\n"
            out_lines.append(header)
            out_lines.append(sep)

            for row in sorted(per_case_rows, key=lambda r: (int(r.get("loop") or 0), str(r.get("scenario") or ""), str(r.get("phase") or ""))):
                loop = row.get("loop")
                scenario = row.get("scenario")
                phase = row.get("phase")
                vals = []
                for peer in peers:
                    vals.append(_format_secs(((row.get("peers") or {}).get(peer) or {}).get("connected_after_s")))
                out_lines.append(f"| {loop} | {scenario} | {phase} | " + " | ".join(vals) + " |\n")

        out_path.write_text("".join(out_lines))

        # Also drop a machine-readable json alongside.
        json_path = out_path.with_suffix(out_path.suffix + ".json")
        json_path.write_text(json.dumps(summary, indent=2, sort_keys=True))

    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, help="Run directory under tools/harness/runs/android_handoff_*.")
    ap.add_argument(
        "--peers",
        default="",
        help="Comma-separated peer ids to track (default: infer from logs; prefer desktop-*).",
    )
    ap.add_argument("--out", default="", help="Write a markdown summary to this path.")

    args = ap.parse_args()
    run_dir = Path(args.run_dir).expanduser().resolve()

    peers = [p.strip() for p in args.peers.split(",") if p.strip()] or None
    out_path = Path(args.out).expanduser().resolve() if args.out else None

    summary = summarize(run_dir=run_dir, peers=peers, out_path=out_path)

    if out_path:
        print(str(out_path))
    else:
        print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
