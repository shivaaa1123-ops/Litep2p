import re
from pathlib import Path

import pytest

from tools.harness.summarize_android_handoff_timings import summarize


def _tt(ts: str, pid: int, tid: int, level: str, tag: str, msg: str) -> str:
    """Create an adb logcat -v threadtime line.

    ts: 'MM-DD HH:MM:SS.mmm'
    """
    assert re.match(r"^\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d$", ts)
    return f"{ts} {pid:5d} {tid:5d} {level} {tag}: {msg}"


def test_signaling_reconnect_and_connect_metrics(tmp_path: Path) -> None:
    run_dir = tmp_path / "android_handoff_20260109_000000"
    run_dir.mkdir(parents=True)

    log_path = run_dir / "android_logcat_threadtime.txt"

    pid = 12345
    tid = 12346

    lines = [
        _tt("01-09 00:00:00.000", pid, tid, "I", "LITEP2P_TEST", "MARK: wifi_disable_cmd loop=1"),
        _tt("01-09 00:00:00.500", pid, tid, "I", "LITEP2P_TEST", "MARK: wifi_disable loop=1"),
        _tt(
            "01-09 00:00:01.000",
            pid,
            tid,
            "I",
            "LiteP2P_Native",
            "[NO_SESSION] SM: Signaling reconnect attempt #2 to: ws://example:8765",
        ),
        _tt(
            "01-09 00:00:02.500",
            pid,
            tid,
            "I",
            "LiteP2P_Native",
            "[NO_SESSION] Signaling: Connected successfully",
        ),
        _tt(
            "01-09 00:00:03.000",
            pid,
            tid,
            "I",
            "LiteP2P_Native",
            "[NO_SESSION] SM: Signaling message received: {\"type\": \"REGISTER_ACK\", \"status\": \"OK\"}",
        ),
        _tt("01-09 00:00:10.000", pid, tid, "I", "LITEP2P_TEST", "MARK: wifi_disable_end loop=1"),
        _tt("01-09 00:00:11.500", pid, tid, "I", "LITEP2P_TEST", "MARK: wifi_enable_cmd loop=1"),
        _tt("01-09 00:00:12.000", pid, tid, "I", "LITEP2P_TEST", "MARK: wifi_enable loop=1 iface=wlan0"),
        _tt(
            "01-09 00:00:12.200",
            pid,
            tid,
            "I",
            "LiteP2P_Native",
            "[NO_SESSION] SM: Signaling reconnect attempt #3 to: ws://example:8765",
        ),
        _tt(
            "01-09 00:00:12.400",
            pid,
            tid,
            "I",
            "LiteP2P_Native",
            "[NO_SESSION] Signaling: Connected successfully",
        ),
        _tt(
            "01-09 00:00:13.000",
            pid,
            tid,
            "I",
            "LiteP2P_Native",
            "[NO_SESSION] SM: Signaling message received: {\"type\": \"REGISTER_ACK\", \"status\": \"OK\"}",
        ),
        _tt("01-09 00:00:30.000", pid, tid, "I", "LITEP2P_TEST", "MARK: loop_1_end"),
    ]

    log_path.write_text("\n".join(lines) + "\n")

    summary = summarize(run_dir=run_dir, peers=["desktop-1"], out_path=None)

    s = summary["stats"]["signaling"]

    assert s["reconnect_attempt"]["wifi_disable"]["count"] == 1
    assert s["connected"]["wifi_disable"]["count"] == 1
    assert s["connected_to_register_ack"]["wifi_disable"]["count"] == 1

    assert s["reconnect_attempt"]["wifi_disable"]["median_s"] == pytest.approx(1.0)
    assert s["connected"]["wifi_disable"]["median_s"] == pytest.approx(2.5)
    assert s["connected_to_register_ack"]["wifi_disable"]["median_s"] == pytest.approx(0.5)

    # wifi_enable metrics are measured from wifi_enable_cmd when present.
    assert s["reconnect_attempt"]["wifi_enable"]["median_s"] == pytest.approx(0.7)
    assert s["connected"]["wifi_enable"]["median_s"] == pytest.approx(0.9)
    assert s["connected_to_register_ack"]["wifi_enable"]["median_s"] == pytest.approx(0.6)

    assert summary["per_loop"][0]["loop"] == 1
    assert "signaling" in summary["per_loop"][0]
    assert "reconnect_attempt" in summary["per_loop"][0]["signaling"]["wifi_disable"]
    assert "connected" in summary["per_loop"][0]["signaling"]["wifi_disable"]
