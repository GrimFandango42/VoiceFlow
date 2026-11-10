"""VF-17 item 2: full-fidelity, local-only, bounded tuning log."""

from __future__ import annotations

import json
import time
from pathlib import Path

from voiceflow.ai import tuning_log as tuning_log_module
from voiceflow.ai.tuning_log import TuningLog


def _log(tmp_path: Path, **kw) -> TuningLog:
    return TuningLog(tmp_path / "tuning_log.jsonl", **kw)


def test_stores_untruncated_text_up_to_cap(tmp_path: Path) -> None:
    log = _log(tmp_path)
    long_text = "word " * 1200  # 6000 chars: the old audit log cut this at 200
    log.append_utterance(raw_text=long_text, final_text=long_text.upper())

    (rec,) = log.load_utterances()
    assert rec["raw_text"] == long_text
    assert rec["final_text"] == long_text.upper()
    assert rec["truncated"] is False


def test_caps_at_8000_chars_and_flags_truncation(tmp_path: Path) -> None:
    log = _log(tmp_path)
    log.append_utterance(raw_text="a" * 9000, final_text="b" * 10)
    (rec,) = log.load_utterances()
    assert len(rec["raw_text"]) == 8000
    assert rec["truncated"] is True


def test_records_the_full_triple_and_metadata(tmp_path: Path) -> None:
    log = _log(tmp_path)
    uid = log.append_utterance(
        raw_text="so i think we should meet thursday",
        final_text="So I think we should meet thursday",
        reconstructed_text="So, I think we should meet Thursday.",
        reconstruction={"status": "accepted", "latency_ms": 812},
        metadata={"model_tier": "balanced", "audio_duration": 3.1, "retry_used": False},
    )
    log.append_user_edit(uid, "So I think we should meet Thursday.")

    (rec,) = log.load_utterances()
    assert rec["reconstructed_text"].endswith("Thursday.")
    assert rec["reconstruction"]["status"] == "accepted"
    assert rec["metadata"]["model_tier"] == "balanced"
    assert rec["edited_text"] == "So I think we should meet Thursday."


def test_late_reconstruction_verdict_merges_into_the_utterance(tmp_path: Path) -> None:
    log = _log(tmp_path)
    uid = log.append_utterance(raw_text="a b c", final_text="a b c", reconstruction={"status": "pending"})
    log.append_reconstruction(uid, reconstructed_text="A, B, C.", reconstruction={"status": "rejected", "reason": "word_ratio"})

    (rec,) = log.load_utterances()
    assert rec["reconstruction"] == {"status": "rejected", "reason": "word_ratio"}
    assert rec["reconstructed_text"] == "A, B, C."


def test_rotates_at_entry_limit_and_keeps_two_generations(tmp_path: Path) -> None:
    log = _log(tmp_path, max_entries=10)
    for i in range(35):
        log.append_utterance(raw_text=f"utt {i}", final_text=f"utt {i}")

    active = [json.loads(l) for l in (tmp_path / "tuning_log.jsonl").read_text().splitlines()]
    prev = [json.loads(l) for l in (tmp_path / "tuning_log.prev.jsonl").read_text().splitlines()]
    assert len(active) <= 10 and len(prev) == 10
    assert not list(tmp_path.glob("tuning_log.*.*.jsonl"))  # bounded: no unbounded archive pile
    # Nothing is reordered, and the newest entry is always in the active file.
    assert active[-1]["raw_text"] == "utt 34"


def test_rotates_when_oldest_entry_is_older_than_max_age(tmp_path: Path) -> None:
    path = tmp_path / "tuning_log.jsonl"
    old = {"v": 1, "kind": "utterance", "id": "old", "ts": time.time() - 40 * 86400, "raw_text": "old", "final_text": "old"}
    path.write_text(json.dumps(old) + "\n", encoding="utf-8")

    log = TuningLog(path, max_age_days=30)
    log.append_utterance(raw_text="new", final_text="new")

    assert [r["raw_text"] for r in log.load_utterances()] == ["old", "new"]
    active = [json.loads(l)["raw_text"] for l in path.read_text().splitlines()]
    assert active == ["new"]  # the 40-day-old entry moved to the previous generation


def test_disabled_writes_nothing(tmp_path: Path) -> None:
    log = _log(tmp_path, enabled=False)
    assert log.append_utterance(raw_text="x", final_text="x") == ""
    assert not (tmp_path / "tuning_log.jsonl").exists()


def test_survives_unwritable_path(tmp_path: Path) -> None:
    blocker = tmp_path / "file_not_dir"
    blocker.write_text("x")
    log = TuningLog(blocker / "sub" / "tuning_log.jsonl")
    log.append_utterance(raw_text="x", final_text="x")  # must not raise


def test_module_is_local_only() -> None:
    """VF-03: the tuning corpus never leaves the machine. No network client may be imported."""
    source = Path(tuning_log_module.__file__).read_text(encoding="utf-8")
    for needle in ("urllib", "requests", "http.client", "socket", "httpx", "aiohttp", "smtplib"):
        assert needle not in source, f"tuning_log must stay local-only; found {needle!r}"


def test_cloud_client_does_not_read_the_tuning_log() -> None:
    from voiceflow.ai import learning_clients

    assert "tuning_log" not in Path(learning_clients.__file__).read_text(encoding="utf-8")


class _InlineExecutor:
    def submit(self, fn, *a, **k):
        fn(*a, **k)


def _stub_app(tmp_path: Path):
    import logging
    from collections import deque
    from types import SimpleNamespace

    from voiceflow.ui.cli_enhanced import EnhancedApp

    app = SimpleNamespace(
        tuning_log=TuningLog(tmp_path / "tuning_log.jsonl"),
        _recent_utterance_ids=deque(maxlen=50),
        postprocess_executor=_InlineExecutor(),
        adaptive_learning=None,
        _log=logging.getLogger("t"),
    )
    app._record_tuning = lambda *a, **k: EnhancedApp._record_tuning(app, *a, **k)
    app.handle_manual_correction_feedback = lambda *a, **k: EnhancedApp.handle_manual_correction_feedback(app, *a, **k)
    return app


def test_app_hook_writes_full_text_and_links_user_edit(tmp_path: Path, monkeypatch) -> None:
    app = _stub_app(tmp_path)
    long_raw = "so we ship on friday " * 40  # ~840 chars, well past the old 200-char cut
    uid = app._record_tuning(long_raw, "So we ship on Friday.", dict(model_tier="balanced"))
    assert uid

    monkeypatch.setattr("voiceflow.ui.cli_enhanced.append_jsonl_bounded", lambda *a, **k: None)
    app.handle_manual_correction_feedback("So we ship on Friday.", "So we ship on Thursday.", dict(local_ts="x"))

    (rec,) = app.tuning_log.load_utterances()
    assert rec["raw_text"] == long_raw and len(rec["raw_text"]) > 200
    assert rec["edited_text"] == "So we ship on Thursday."
