from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from voiceflow.ai.daily_learning import DailyLearningJob
from voiceflow.core.config import Config


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_daily_learning_updates_patterns_from_user_corrections(tmp_path):
    yesterday = datetime.now() - timedelta(days=1)
    _write_jsonl(
        tmp_path / "transcription_corrections.jsonl",
        [
            {
                "local_ts": yesterday.isoformat(timespec="seconds"),
                "item_id": 17,
                "original_text": "send to jon",
                "corrected_text": "send to john",
            }
        ],
    )
    _write_jsonl(tmp_path / "recent_history_events.jsonl", [])

    cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
    job = DailyLearningJob(cfg=cfg, base_dir=tmp_path)
    report = job.run(days_back=1, dry_run=False)

    stats = report["stats"]
    assert stats["correction_items_used"] == 1
    assert stats["observed_from_user_corrections"] == 1
    assert Path(stats["report_path"]).exists()
    assert job.manager.apply("send to jon") == "send to john"


def test_daily_learning_dry_run_does_not_update_patterns(tmp_path):
    yesterday = datetime.now() - timedelta(days=1)
    _write_jsonl(
        tmp_path / "transcription_corrections.jsonl",
        [
            {
                "local_ts": yesterday.isoformat(timespec="seconds"),
                "item_id": 18,
                "original_text": "send to jon",
                "corrected_text": "send to john",
            }
        ],
    )
    _write_jsonl(tmp_path / "recent_history_events.jsonl", [])

    cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
    job = DailyLearningJob(cfg=cfg, base_dir=tmp_path)
    report = job.run(days_back=1, dry_run=True)

    stats = report["stats"]
    assert stats["dry_run"] is True
    assert stats["observed_from_user_corrections"] == 1
    assert job.manager.apply("send to jon") == "send to jon"


def test_daily_learning_auto_analysis_learns_from_history(tmp_path):
    yesterday_epoch = (datetime.now() - timedelta(days=1, hours=1)).timestamp()
    _write_jsonl(tmp_path / "transcription_corrections.jsonl", [])
    _write_jsonl(
        tmp_path / "recent_history_events.jsonl",
        [
            {
                "event_epoch": yesterday_epoch,
                "audio_duration": 8.4,
                "full_text": "we should use terraforce for this change",
            }
        ],
    )

    cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
    job = DailyLearningJob(cfg=cfg, base_dir=tmp_path)
    report = job.run(days_back=1, dry_run=False)

    stats = report["stats"]
    assert stats["history_items_used"] == 1
    assert stats["observed_from_auto_analysis"] == 1
    assert any(item["to"] == "terraform" for item in report["top_replacement_pairs"])
    assert job.manager.apply("use terraforce now") == "use terraform now"


def test_daily_learning_instructional_pass_updates_insights(tmp_path):
    yesterday_epoch = (datetime.now() - timedelta(days=1, hours=1)).timestamp()
    _write_jsonl(tmp_path / "transcription_corrections.jsonl", [])
    _write_jsonl(
        tmp_path / "recent_history_events.jsonl",
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
    job = DailyLearningJob(cfg=cfg, base_dir=tmp_path)
    report = job.run(days_back=1, dry_run=False)

    stats = report["stats"]
    assert stats["instructional_items_used"] == 1
    assert stats["observed_from_instruction_pass"] == 1

    insights = report["instructional_insights"]
    assert any(item["theme"] == "formatting_capitalization" for item in insights["top_themes"])
    assert (tmp_path / "self_learning_insights.json").exists()


def test_daily_learning_instructional_pass_dry_run_does_not_persist_insights(tmp_path):
    yesterday_epoch = (datetime.now() - timedelta(days=1, hours=1)).timestamp()
    _write_jsonl(tmp_path / "transcription_corrections.jsonl", [])
    _write_jsonl(
        tmp_path / "recent_history_events.jsonl",
        [
            {
                "event_epoch": yesterday_epoch,
                "audio_duration": 6.8,
                "full_text": "we should improve recent history ordering and correction review workflow",
            }
        ],
    )

    cfg = Config(adaptive_min_count=1, adaptive_store_raw_text=False)
    job = DailyLearningJob(cfg=cfg, base_dir=tmp_path)
    report = job.run(days_back=1, dry_run=True)

    stats = report["stats"]
    assert stats["instructional_items_used"] == 1
    assert stats["observed_from_instruction_pass"] == 1
    assert not (tmp_path / "self_learning_insights.json").exists()
