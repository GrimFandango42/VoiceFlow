"""VF-10 review finding 3: latency must include injection, not processing only.

The field-log evidence first quoted `total_ms` (processing only, 388/775/2310 ms)
as the user-visible delay. `inject_ms` is logged separately and is not part of
`total_ms`; release-through-injection is their sum (583.7/1034.5/2503.3 ms).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("vf_log_latency", REPO / "scripts" / "dev" / "log_latency.py")
ll = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
sys.modules["vf_log_latency"] = ll
_spec.loader.exec_module(ll)


def _timing(total: float, inject: float, warmup: float = 0.0) -> str:
    return (
        f"2026-09-01 10:00:00,000 INFO voiceflow transcription_timing total_ms={total:.1f} path=primary "
        f"model_id=x device=cuda compute=float16 retry_used=False compaction_ms=0.0 guard_ms=0.1 "
        f"asr_ms={total - 10:.1f} retry_ms=0.0 post_ms=5.0 safe2_ms=1.0 heavy2_ms=0.0 second_pass=safe "
        f"delta_chars=0 inject_ms={inject:.1f} raw_dur=3.00 compacted_dur=3.00 reduction=0.0 "
        f"retry_strategy=none retry_chunks=0 idle_resume=False idle_resume_force_primary=False "
        f"warmup_ms={warmup:.1f}\n"
    )


def test_release_through_injection_adds_inject_to_processing():
    lines = [_timing(400.0, 200.0), _timing(300.0, 190.0), _timing(1000.0, 180.0)]
    s = ll.summarize(ll.parse(lines))
    assert s["processing_only_ms"]["median"] == 400.0
    assert s["inject_ms"]["median"] == 190.0
    assert s["release_through_injection_ms"]["median"] == 600.0
    assert s["release_through_injection_ms"]["max"] == 1180.0
    # The headline figure must never be the processing-only one.
    assert s["release_through_injection_ms"]["median"] > s["processing_only_ms"]["median"]


def test_only_timing_lines_and_numeric_fields_are_read():
    secret = "transcribed text that must never be parsed total_ms=99999 inject_ms=99999"
    lines = [
        f"2026-09-01 INFO voiceflow final_text {secret}\n",
        _timing(500.0, 100.0),
        "2026-09-01 INFO voiceflow second_pass_cleanup safe_ms=1.0 heavy_ms=0.0\n",
    ]
    records = ll.parse(lines)
    assert len(records) == 1
    assert set(records[0]) <= set(ll.FIELDS)
    assert records[0]["total_ms"] == 500.0


def test_nearest_rank_percentile_is_an_observed_sample():
    values = [float(v) for v in range(1, 58)]  # 57 samples like the field log
    assert ll.percentile(values, 50) == 29.0
    assert ll.percentile(values, 90) == 52.0  # ceil(0.9 * 57) = 52nd
    assert ll.percentile(values, 100) == 57.0
    assert ll.percentile([7.0], 90) == 7.0


def test_cli_runs_on_a_log_file(tmp_path, capsys):
    log = tmp_path / "voiceflow.log"
    log.write_text(_timing(388.0, 192.5) + _timing(2310.0, 193.3), encoding="utf-8")
    assert ll.main([str(log)]) == 0
    out = capsys.readouterr().out
    assert "release_through_injection_ms" in out
    assert "2503.3" in out
