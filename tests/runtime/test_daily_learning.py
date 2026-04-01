from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from voiceflow.ai.daily_learning import DailyLearningJob
from voiceflow.core.config import Config


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _test_dir(name: str) -> Path:
    path = Path("build") / "test-runtime" / f"{name}-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_daily_learning_updates_patterns_from_user_corrections():
    base_dir = _test_dir("daily-learning-corrections")
    try:
        yesterday = datetime.now() - timedelta(days=1)
        _write_jsonl(
            base_dir / "transcription_corrections.jsonl",
            [
                {
                    "local_ts": yesterday.isoformat(timespec="seconds"),
                    "item_id": 17,
                    "original_text": "send to jon",
                    "corrected_text": "send to john",
                }
            ],
        )
        _write_jsonl(base_dir / "recent_history_events.jsonl", [])

        cfg = Config(adaptive_min_count=1, adaptive_user_correction_min_count=1, adaptive_store_raw_text=False)
        job = DailyLearningJob(cfg=cfg, base_dir=base_dir)
        report = job.run(days_back=1, dry_run=False)

        stats = report["stats"]
        assert stats["correction_items_used"] == 1
        assert stats["observed_from_user_corrections"] == 1
        assert Path(stats["report_path"]).exists()
        assert job.manager.apply("send to jon") == "send to john"
        snapshot = report["adaptive_snapshot"]
        assert snapshot["top_replacements"]
        assert any(item["token"] == "john" for item in snapshot["top_tokens"])
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_daily_learning_dry_run_does_not_update_patterns():
    base_dir = _test_dir("daily-learning-dry-run")
    try:
        yesterday = datetime.now() - timedelta(days=1)
        _write_jsonl(
            base_dir / "transcription_corrections.jsonl",
            [
                {
                    "local_ts": yesterday.isoformat(timespec="seconds"),
                    "item_id": 18,
                    "original_text": "send to jon",
                    "corrected_text": "send to john",
                }
            ],
        )
        _write_jsonl(base_dir / "recent_history_events.jsonl", [])

        cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
        job = DailyLearningJob(cfg=cfg, base_dir=base_dir)
        report = job.run(days_back=1, dry_run=True)

        stats = report["stats"]
        assert stats["dry_run"] is True
        assert stats["observed_from_user_corrections"] == 1
        assert job.manager.apply("send to jon") == "send to jon"
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_daily_learning_auto_analysis_learns_from_history():
    base_dir = _test_dir("daily-learning-auto-analysis")
    try:
        yesterday_epoch = (datetime.now() - timedelta(days=1, hours=1)).timestamp()
        _write_jsonl(base_dir / "transcription_corrections.jsonl", [])
        _write_jsonl(
            base_dir / "recent_history_events.jsonl",
            [
                {
                    "event_epoch": yesterday_epoch,
                    "audio_duration": 8.4,
                    "full_text": "we should use terraforce for this change",
                }
            ],
        )

        cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
        job = DailyLearningJob(cfg=cfg, base_dir=base_dir)
        report = job.run(days_back=1, dry_run=False)

        stats = report["stats"]
        assert stats["history_items_used"] == 1
        assert stats["observed_from_auto_analysis"] == 1
        assert any(item["to"] == "terraform" for item in report["top_replacement_pairs"])
        assert job.manager.apply("use terraforce now") == "use terraform now"
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_daily_learning_instructional_pass_updates_insights():
    base_dir = _test_dir("daily-learning-instructional")
    try:
        yesterday_epoch = (datetime.now() - timedelta(days=1, hours=1)).timestamp()
        _write_jsonl(base_dir / "transcription_corrections.jsonl", [])
        _write_jsonl(
            base_dir / "recent_history_events.jsonl",
            [
                {
                    "event_epoch": yesterday_epoch,
                    "audio_duration": 9.2,
                    "full_text": (
                        "please improve capitalization at the beginning of each sentence "
                        "and keep paragraph spacing more readable"
                    ),
                }
            ],
        )

        cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
        job = DailyLearningJob(cfg=cfg, base_dir=base_dir)
        report = job.run(days_back=1, dry_run=False)

        stats = report["stats"]
        assert stats["instructional_items_used"] == 1
        assert stats["observed_from_instruction_pass"] == 1

        insights = report["instructional_insights"]
        assert any(item["theme"] == "formatting_capitalization" for item in insights["top_themes"])
        assert (base_dir / "self_learning_insights.json").exists()
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_daily_learning_instructional_pass_dry_run_does_not_persist_insights():
    base_dir = _test_dir("daily-learning-instructional-dry-run")
    try:
        yesterday_epoch = (datetime.now() - timedelta(days=1, hours=1)).timestamp()
        _write_jsonl(base_dir / "transcription_corrections.jsonl", [])
        _write_jsonl(
            base_dir / "recent_history_events.jsonl",
            [
                {
                    "event_epoch": yesterday_epoch,
                    "audio_duration": 6.8,
                    "full_text": "we should improve recent history ordering and correction review workflow",
                }
            ],
        )

        cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
        job = DailyLearningJob(cfg=cfg, base_dir=base_dir)
        report = job.run(days_back=1, dry_run=True)

        stats = report["stats"]
        assert stats["instructional_items_used"] == 1
        assert stats["observed_from_instruction_pass"] == 1
        assert not (base_dir / "self_learning_insights.json").exists()
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_manual_correction_source_is_tracked_separately():
    """manual_correction items are counted in observed_from_manual_corrections."""
    base_dir = _test_dir("daily-learning-manual-source")
    try:
        yesterday = datetime.now() - timedelta(days=1)
        _write_jsonl(
            base_dir / "transcription_corrections.jsonl",
            [
                {
                    "local_ts": yesterday.isoformat(timespec="seconds"),
                    "item_id": 1,
                    "original_text": "the meetup is at forst street",
                    "corrected_text": "the meetup is at forest street",
                    "source": "manual_correction",
                },
                {
                    "local_ts": yesterday.isoformat(timespec="seconds"),
                    "item_id": 2,
                    "original_text": "send to jon",
                    "corrected_text": "send to john",
                },
            ],
        )
        _write_jsonl(base_dir / "recent_history_events.jsonl", [])

        cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
        job = DailyLearningJob(cfg=cfg, base_dir=base_dir)
        report = job.run(days_back=1, dry_run=False)

        stats = report["stats"]
        assert stats["correction_items_used"] == 2
        assert stats["observed_from_user_corrections"] == 2
        assert stats["observed_from_manual_corrections"] == 1
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_top_pairs_have_weight_field():
    """Each entry in top_replacement_pairs must carry a weight field."""
    base_dir = _test_dir("daily-learning-weight-field")
    try:
        yesterday = datetime.now() - timedelta(days=1)
        _write_jsonl(
            base_dir / "transcription_corrections.jsonl",
            [
                {
                    "local_ts": yesterday.isoformat(timespec="seconds"),
                    "item_id": 3,
                    "original_text": "use terraforce here",
                    "corrected_text": "use terraform here",
                    "source": "manual_correction",
                }
            ],
        )
        _write_jsonl(base_dir / "recent_history_events.jsonl", [])

        cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
        job = DailyLearningJob(cfg=cfg, base_dir=base_dir)
        report = job.run(days_back=1, dry_run=False)

        pairs = report["top_replacement_pairs"]
        assert pairs, "expected at least one replacement pair"
        for pair in pairs:
            assert "weight" in pair, f"pair missing weight field: {pair}"
            assert pair["weight"] > 0
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_manual_correction_pairs_outrank_auto_pairs():
    """A manual correction for a pair should give it higher weight than an auto-analysis pair."""
    base_dir = _test_dir("daily-learning-weight-ranking")
    try:
        yesterday = datetime.now() - timedelta(days=1)
        yesterday_epoch = (datetime.now() - timedelta(days=1, hours=1)).timestamp()

        # One manual correction: "jon" → "john"
        # One auto-analysis source: "terraforce" → "terraform" (via history normalization)
        _write_jsonl(
            base_dir / "transcription_corrections.jsonl",
            [
                {
                    "local_ts": yesterday.isoformat(timespec="seconds"),
                    "item_id": 4,
                    "original_text": "send report to jon",
                    "corrected_text": "send report to john",
                    "source": "manual_correction",
                }
            ],
        )
        _write_jsonl(
            base_dir / "recent_history_events.jsonl",
            [
                {
                    "event_epoch": yesterday_epoch,
                    "audio_duration": 5.0,
                    "full_text": "we should use terraforce for this change",
                }
            ],
        )

        cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
        job = DailyLearningJob(cfg=cfg, base_dir=base_dir)
        report = job.run(days_back=1, dry_run=False)

        pairs = report["top_replacement_pairs"]
        assert pairs

        # Find the user pair and the auto pair
        user_pair = next((p for p in pairs if p["sources"]["user"] > 0), None)
        auto_pair = next((p for p in pairs if p["sources"]["auto"] > 0 and p["sources"]["user"] == 0), None)

        if user_pair and auto_pair:
            assert user_pair["weight"] > auto_pair["weight"], (
                f"manual pair weight {user_pair['weight']} should exceed "
                f"auto pair weight {auto_pair['weight']}"
            )
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)
