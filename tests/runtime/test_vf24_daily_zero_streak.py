"""VF-24 item 5: the nightly report counts corrections; seven empty days leave one note."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta

from voiceflow.ai import daily_learning
from voiceflow.ai.daily_learning import DailyLearningJob
from voiceflow.core.config import Config

update = DailyLearningJob._update_correction_input
D0 = date(2026, 11, 1)


def _days(state: dict, counts: list[int], start: date = D0) -> None:
    for i, n in enumerate(counts):
        update(state, start + timedelta(days=i), n)


def test_seven_consecutive_zero_days_write_the_note_once() -> None:
    state: dict = {}
    _days(state, [0] * 6)
    assert state["correction_input"]["zero_streak_days"] == 6
    assert state["correction_input"]["note"] == ""
    assert update(state, D0 + timedelta(days=6), 0) is True
    block = state["correction_input"]
    assert block["zero_streak_days"] == 7
    assert "no correction input" in block["note"]
    note = block["note"]
    update(state, D0 + timedelta(days=7), 0)  # an eighth empty day
    assert state["correction_input"]["note"] == note  # one line, not a second one
    assert state["correction_input"]["zero_streak_days"] == 8


def test_a_day_with_corrections_clears_it() -> None:
    state: dict = {}
    _days(state, [0] * 7)
    update(state, D0 + timedelta(days=7), 2)
    block = state["correction_input"]
    assert block["zero_streak_days"] == 0
    assert block["note"] == ""
    assert block["last_nonzero_date"] == (D0 + timedelta(days=7)).isoformat()


def test_same_or_older_date_counts_once() -> None:
    state: dict = {}
    _days(state, [0, 0, 0])
    snapshot = json.dumps(state, sort_keys=True)
    assert update(state, D0 + timedelta(days=2), 0) is False  # the catch-up run, same day
    assert update(state, D0, 0) is False                      # an older date
    assert json.dumps(state, sort_keys=True) == snapshot


def test_a_gap_restarts_the_count() -> None:
    state: dict = {}
    _days(state, [0] * 5)
    update(state, D0 + timedelta(days=9), 0)  # three days were never processed
    assert state["correction_input"]["zero_streak_days"] == 1


def _job(tmp_path) -> DailyLearningJob:
    return DailyLearningJob(Config(adaptive_ai_analysis_enabled=False), base_dir=tmp_path)


def test_report_and_insights_carry_the_block(tmp_path) -> None:
    yesterday = (datetime.now() - timedelta(days=1)).date()
    state = {"correction_input": {"zero_streak_days": 6, "last_counted_date": (yesterday - timedelta(days=1)).isoformat(),
                                  "last_nonzero_date": "", "note": "", "last_items": 0}}
    (tmp_path / "self_learning_insights.json").write_text(json.dumps(state), encoding="utf-8")
    report = _job(tmp_path).run(days_back=1)
    assert report["stats"]["correction_items_total"] == 0
    assert report["correction_input"]["zero_streak_days"] == 7
    saved = json.loads((tmp_path / "self_learning_insights.json").read_text(encoding="utf-8"))
    assert "no correction input" in saved["correction_input"]["note"]
    # The note is a single line in the file.
    lines = [ln for ln in (tmp_path / "self_learning_insights.json").read_text(encoding="utf-8").splitlines()
             if "no correction input" in ln]
    assert len(lines) == 1


def test_dry_run_does_not_touch_the_insights_file(tmp_path) -> None:
    path = tmp_path / "self_learning_insights.json"
    report = _job(tmp_path).run(days_back=1, dry_run=True)
    assert not path.exists()
    assert report["dry_run"] is True


def test_stdout_prints_the_note(tmp_path, monkeypatch, capsys) -> None:
    fake = {"target_date": "2026-11-26", "dry_run": False, "stats": {"report_path": "r.json"},
            "correction_input": {"note": daily_learning.ZERO_CORRECTION_NOTE}, "top_replacement_pairs": []}
    monkeypatch.setattr(daily_learning, "run_daily_learning_job", lambda **_k: fake)
    daily_learning.main([])
    assert "no correction input for 7 days" in capsys.readouterr().out
