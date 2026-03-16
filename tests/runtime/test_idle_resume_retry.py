from __future__ import annotations

from types import SimpleNamespace

from voiceflow.ui.cli_enhanced import EnhancedApp


class _DummyApp:
    _evaluate_compaction_retry_signal = EnhancedApp._evaluate_compaction_retry_signal

    def __init__(self) -> None:
        self.cfg = SimpleNamespace(
            pause_compaction_retry_min_reduction_pct=38.0,
            pause_compaction_retry_max_words=8,
            pause_compaction_retry_min_words_per_second=1.15,
            pause_compaction_retry_min_chars_per_second=5.0,
            idle_resume_retry_on_compaction=True,
            idle_resume_retry_min_reduction_pct=55.0,
            idle_resume_retry_min_raw_audio_seconds=12.0,
        )


def test_idle_resume_heavy_compaction_triggers_retry_even_when_general_sparse_check_misses() -> None:
    app = _DummyApp()

    result = app._evaluate_compaction_retry_signal(
        raw_audio_duration=61.92,
        compaction_reduction_pct=66.5,
        initial_words=65,
        initial_chars=341,
        idle_resume_active=True,
    )

    assert result["retry_due_to_sparse"] is False
    assert result["idle_resume_retry_due_to_compaction"] is True
    assert result["retry_triggered"] is True
    assert "idle_resume_compaction" in result["reasons"]


def test_non_idle_heavy_compaction_still_uses_general_sparse_rules() -> None:
    app = _DummyApp()

    result = app._evaluate_compaction_retry_signal(
        raw_audio_duration=61.92,
        compaction_reduction_pct=66.5,
        initial_words=65,
        initial_chars=341,
        idle_resume_active=False,
    )

    assert result["retry_due_to_sparse"] is False
    assert result["idle_resume_retry_due_to_compaction"] is False
    assert result["retry_triggered"] is False
    assert result["reasons"] == []


def test_general_sparse_compaction_retry_behavior_still_applies() -> None:
    app = _DummyApp()

    result = app._evaluate_compaction_retry_signal(
        raw_audio_duration=18.0,
        compaction_reduction_pct=52.0,
        initial_words=5,
        initial_chars=24,
        idle_resume_active=False,
    )

    assert result["retry_due_to_short"] is True
    assert result["retry_due_to_sparse"] is True
    assert result["retry_triggered"] is True
    assert "short_output" in result["reasons"]
    assert "sparse_output" in result["reasons"]
