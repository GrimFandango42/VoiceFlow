from __future__ import annotations

import json
from datetime import datetime

from voiceflow.ui import visual_indicators as visual_mod
from voiceflow.ui.visual_indicators import (
    BottomScreenIndicator,
    _build_ui_palette,
    _emit_correction_feedback_learning,
)


def test_normalize_history_seed_rows_keeps_live_and_correction_sources():
    history_lines = [
        json.dumps(
            {
                "event_epoch": 101.0,
                "audio_duration": 1.8,
                "processing_time": 0.06,
                "full_text": "live transcript",
                "retry_used": True,
            },
            ensure_ascii=True,
        )
    ]
    correction_lines = [
        json.dumps(
            {
                "local_ts": datetime.fromtimestamp(102.0).isoformat(timespec="seconds"),
                "audio_duration": 1.8,
                "processing_time": 0.06,
                "original_text": "live transcript",
                "corrected_text": "corrected transcript",
            },
            ensure_ascii=True,
        )
    ]

    rows = BottomScreenIndicator._normalize_history_seed_rows(
        history_lines,
        correction_lines,
        session_started_at=100.0,
    )

    assert len(rows) == 2
    rows_by_source = {row["source_kind"]: row for row in rows}
    assert rows_by_source["live"]["retry_used"] is True
    assert rows_by_source["live"]["full_text"] == "live transcript"
    assert rows_by_source["correction"]["retry_used"] is False
    assert rows_by_source["correction"]["full_text"] == "corrected transcript"


def test_filter_history_rows_supports_all_views():
    rows = [
        {"source_kind": "live", "retry_used": False, "full_text": "first"},
        {"source_kind": "live", "retry_used": True, "full_text": "second"},
        {"source_kind": "correction", "retry_used": False, "full_text": "third"},
    ]

    assert len(BottomScreenIndicator._filter_history_rows(rows, "all")) == 3
    assert len(BottomScreenIndicator._filter_history_rows(rows, "live")) == 2
    assert len(BottomScreenIndicator._filter_history_rows(rows, "corrections")) == 1
    retry_rows = BottomScreenIndicator._filter_history_rows(rows, "retries")
    assert len(retry_rows) == 1
    assert retry_rows[0]["full_text"] == "second"


def test_describe_history_rows_reports_counts_for_current_view():
    rows = [
        {"source_kind": "live", "retry_used": False},
        {"source_kind": "live", "retry_used": True},
        {"source_kind": "correction", "retry_used": False},
    ]

    all_summary = BottomScreenIndicator._describe_history_rows(rows, "all")
    correction_summary = BottomScreenIndicator._describe_history_rows(rows, "corrections")
    retry_summary = BottomScreenIndicator._describe_history_rows(rows, "retries")

    assert "2 live" in all_summary
    assert "1 correction" in all_summary
    assert correction_summary == "Showing 1 saved correction."
    assert retry_summary == "Showing 1 retry-backed capture."


def test_build_ui_palette_respects_theme_mode():
    scheme = {
        "accent_color": "#0078D4",
        "success_color": "#107C10",
        "warning_color": "#FF8C00",
    }

    dark_palette = _build_ui_palette(scheme, "dark_mode")
    light_palette = _build_ui_palette(scheme, "light_mode")

    assert dark_palette["panel_bg"] == "#10161D"
    assert light_palette["panel_bg"] == "#F3F6FA"
    assert dark_palette["accent"] != light_palette["accent"]
    assert dark_palette["badge_correction_bg"] != light_palette["badge_correction_bg"]


def test_manual_correction_feedback_handler_dispatches_learning_signal():
    calls = []
    visual_mod.set_correction_feedback_handler(
        lambda original, corrected, metadata: calls.append((original, corrected, dict(metadata)))
    )
    try:
        _emit_correction_feedback_learning(
            "send to jon",
            "send to john",
            {"item_id": 7, "source": "manual_correction"},
        )
    finally:
        visual_mod.set_correction_feedback_handler(None)

    assert calls == [
        (
            "send to jon",
            "send to john",
            {"item_id": 7, "source": "manual_correction"},
        )
    ]
