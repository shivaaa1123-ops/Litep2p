from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module_from_path(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses (and some typing helpers) expect the defining module to be present
    # in sys.modules during class creation.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


def test_summarizer_writes_json_for_wifi_phases(tmp_path: Path) -> None:
    # Arrange: create a fake run dir that matches the year-inference regex.
    run_dir = tmp_path / "android_handoff_20260101_000000"
    run_dir.mkdir(parents=True)

    log = run_dir / "android_logcat_threadtime.txt"
    log.write_text(
        "\n".join(
            [
                "01-01 00:00:00.000  1000  1000 I LITEP2P_TEST: MARK: run_start",
                "01-01 00:00:01.000  1000  1000 I LITEP2P_TEST: MARK: wifi_disable_cmd loop=1 scenario=wifi",
                "01-01 00:00:01.100  1000  1000 I LITEP2P_TEST: MARK: wifi_disable loop=1 scenario=wifi",
                "01-01 00:00:02.000  1000  1000 I LiteP2P_Native: [NO_SESSION] SM: Signaling message received: {\"type\": \"REGISTER_ACK\", \"status\": \"OK\"}",
                "01-01 00:00:02.500  1000  1000 I LiteP2P_Native: [NO_SESSION] [PeerFSM] DISCOVERED --(CONNECT_SUCCESS)--> CONNECTED peer=desktop-1",
                "01-01 00:00:05.000  1000  1000 I LITEP2P_TEST: MARK: wifi_enable_cmd loop=1 scenario=wifi",
                "01-01 00:00:05.200  1000  1000 I LITEP2P_TEST: MARK: wifi_enable loop=1 scenario=wifi",
                "01-01 00:00:06.000  1000  1000 I LiteP2P_Native: [NO_SESSION] SM: Signaling message received: {\"type\": \"REGISTER_ACK\", \"status\": \"OK\"}",
                "01-01 00:00:06.500  1000  1000 I LiteP2P_Native: [NO_SESSION] [PeerFSM] DISCOVERED --(CONNECT_SUCCESS)--> CONNECTED peer=desktop-1",
                "01-01 00:00:10.000  1000  1000 I LITEP2P_TEST: MARK: loop_1_end",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # Act
    mod_path = Path(__file__).resolve().parents[1] / "tools" / "harness" / "summarize_android_handoff_timings.py"
    mod = _load_module_from_path(mod_path)

    out_md = run_dir / "timing_summary.md"
    summary = mod.summarize(run_dir=run_dir, peers=None, out_path=out_md)

    # Assert
    assert out_md.exists(), "expected timing summary markdown to be written"
    assert out_md.with_suffix(out_md.suffix + ".json").exists(), "expected timing summary JSON to be written"
    assert summary.get("peers") == ["desktop-1"]
    assert summary.get("loops_detected") == [1]
