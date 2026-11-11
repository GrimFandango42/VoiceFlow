"""A dictation that pastes nothing must still leave a record: why, and any text."""

from __future__ import annotations

import pytest

from voiceflow.core.history import (
    STATUS_FAILED,
    TranscriptHistory,
    copy_text,
    failure_summary,
    menu_label,
)


def test_failure_is_recorded_with_reason_and_survives_a_restart(tmp_path):
    path = tmp_path / "h.json"
    history = TranscriptHistory(path)
    history.add_failure("silent", detail="peak level 0.0001", audio_seconds=4.2)
    reloaded = TranscriptHistory(path).recent()
    assert len(reloaded) == 1
    entry = reloaded[0]
    assert entry["status"] == STATUS_FAILED and entry["reason"] == "silent"
    assert "Only silence was recorded" in failure_summary(entry)
    assert "4.2s" in failure_summary(entry) and "peak level" in failure_summary(entry)


def test_filtered_text_is_kept_and_is_what_copy_returns(tmp_path):
    history = TranscriptHistory(tmp_path / "h.json")
    entry_id = history.add_failure("filtered", detail="lone_filler", text="Thank you.", audio_seconds=2.0)
    entry = history.get(entry_id)
    assert copy_text(entry) == "Thank you."
    assert menu_label(entry).endswith("[discarded] Thank you.")


def test_copy_of_a_textless_failure_is_the_explanation(tmp_path):
    history = TranscriptHistory(tmp_path / "h.json")
    entry = history.get(history.add_failure("timeout", detail="gave up after 45s", audio_seconds=30.0))
    assert copy_text(entry).startswith("VoiceFlow did not transcribe this: Transcription timed out")
    assert "[failed]" in menu_label(entry)


def test_repaste_skips_failures_without_text(tmp_path):
    history = TranscriptHistory(tmp_path / "h.json")
    history.add("the real dictation")
    history.add_failure("empty", audio_seconds=3.0)
    assert history.last()["text"] == "the real dictation"


def test_successful_entries_are_unchanged(tmp_path):
    history = TranscriptHistory(tmp_path / "h.json")
    entry = history.get(history.add("hello world"))
    assert copy_text(entry) == "hello world"
    assert "[failed]" not in menu_label(entry)


def test_panel_filter_and_summary_know_about_failures():
    vi = pytest.importorskip("voiceflow.ui.visual_indicators")
    rows = [
        {"outcome": "ok", "source_kind": "live"},
        {"outcome": "failed", "source_kind": "live", "failure_reason": "silent"},
    ]
    cls = vi.BottomScreenIndicator
    assert cls._filter_history_rows(rows, "failed") == [rows[1]]
    assert "1 failed" in cls._describe_history_rows(rows, "all")
    assert ("failed", "Failed") in vi._HISTORY_FILTER_OPTIONS


def test_caption_tail_shows_the_newest_words_on_a_word_boundary():
    vi = pytest.importorskip("voiceflow.ui.visual_indicators")
    text = " ".join(f"word{n}" for n in range(1, 60))
    tail = vi.caption_tail(text, 60)
    assert len(tail) <= 60
    assert tail.endswith("word59") and tail.startswith("…word")
    assert vi.caption_tail("short caption", 60) == "short caption"
