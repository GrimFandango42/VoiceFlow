"""VF-11 overlay: build date instead of version/detail text, live recording timer.

Nithin: replace the version string ("3.2.1") and the other detail text with the build's
last-updated date (from the bundle stamp) and a live elapsed counter while recording -
seconds, switching to m:ss after 60 s.
"""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from voiceflow.ui import visual_indicators as vi
from voiceflow.ui.visual_indicators import BottomScreenIndicator, TranscriptionStatus, format_elapsed
from voiceflow.utils import build_info as bi


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (0, "0s"),
        (0.9, "0s"),      # truncates: never ahead of the clock
        (1, "1s"),
        (7.4, "7s"),
        (59, "59s"),
        (59.99, "59s"),
        (60, "1:00"),     # switches to m:ss at 60 s
        (65, "1:05"),
        (118.6, "1:58"),  # the length of Nithin's test dictation
        (600, "10:00"),
        (3661, "61:01"),
        (-3, "0s"),
        (float("nan"), "0s"),
        (None, "0s"),
    ],
)
def test_format_elapsed(seconds, text) -> None:
    assert format_elapsed(seconds) == text


# --- build date -----------------------------------------------------------------------

def test_updated_label_shows_only_the_build_date() -> None:
    info = bi.BuildInfo(version="3.2.1", commit="39e2e22", built_at="11-02 23:14", source="stamp")
    label = info.updated_label()
    assert label == "Updated 11-02 23:14"
    assert "3.2.1" not in label and "39e2e22" not in label


def test_updated_label_is_empty_when_the_date_is_unknown() -> None:
    assert bi.BuildInfo(version="3.2.1", commit="x", built_at="unknown", source="mtime").updated_label() == ""


def test_module_updated_label_reads_the_bundle_stamp(monkeypatch) -> None:
    stamp = SimpleNamespace(VERSION="3.2.1", COMMIT="abc1234", BUILT_AT="11-03 09:05", DIRTY=False)
    monkeypatch.setattr(bi, "_from_stamp", lambda: bi.BuildInfo("3.2.1", "abc1234", stamp.BUILT_AT, "stamp"))
    assert bi.updated_label() == "Updated 11-03 09:05"


def test_overlay_no_longer_references_the_version_label() -> None:
    assert not hasattr(vi, "build_short_label")
    assert hasattr(vi, "build_updated_label")


# --- dock text ------------------------------------------------------------------------

class _Var:
    def __init__(self) -> None:
        self.value = None

    def set(self, value) -> None:
        self.value = value


def test_dock_shows_status_word_only() -> None:
    dummy = SimpleNamespace(
        dock_var=_Var(),
        dock_enabled=True,
        current_status=TranscriptionStatus.IDLE,
    )
    BottomScreenIndicator._refresh_dock_text(dummy)
    assert dummy.dock_var.value == "Ready"

    BottomScreenIndicator._refresh_dock_text(dummy, status=TranscriptionStatus.LISTENING)
    assert dummy.dock_var.value == "Listening"

    BottomScreenIndicator._refresh_dock_text(
        dummy,
        status=TranscriptionStatus.COMPLETE,
        last_item={"audio_duration": 3.2, "processing_time": 0.4},
    )
    assert "|" not in dummy.dock_var.value and "Last" not in dummy.dock_var.value


# --- the ticking counter (no Tk) ----------------------------------------------------------

class _FakeWindow:
    """Records `after` callbacks so the test can fire them by hand."""

    def __init__(self) -> None:
        self.pending: dict[int, object] = {}
        self._next = 1
        self.cancelled: list[int] = []

    def after(self, ms, fn):
        ident = self._next
        self._next += 1
        self.pending[ident] = fn
        return ident

    def after_cancel(self, ident) -> None:
        self.cancelled.append(ident)
        self.pending.pop(ident, None)

    def fire_all(self) -> None:
        for ident, fn in list(self.pending.items()):
            self.pending.pop(ident, None)
            fn()


def _indicator(started_ago: float) -> SimpleNamespace:
    ind = SimpleNamespace(
        window=_FakeWindow(),
        elapsed_var=_Var(),
        _listening_started_at=time.monotonic() - started_ago,
    )
    ind._start_elapsed_timer = lambda: BottomScreenIndicator._start_elapsed_timer(ind)
    ind._stop_elapsed_timer = lambda clear=True: BottomScreenIndicator._stop_elapsed_timer(ind, clear)
    return ind


def test_timer_starts_at_zero_and_counts_with_the_clock() -> None:
    ind = _indicator(started_ago=0.0)
    ind._start_elapsed_timer()
    assert ind.elapsed_var.value == "0s"
    assert len(ind.window.pending) == 1  # re-armed for the next tick


def test_timer_shows_minutes_after_sixty_seconds() -> None:
    ind = _indicator(started_ago=65.0)
    ind._start_elapsed_timer()
    assert ind.elapsed_var.value == "1:05"


def test_timer_keeps_ticking_until_stopped_then_clears() -> None:
    ind = _indicator(started_ago=12.0)
    ind._start_elapsed_timer()
    assert ind.elapsed_var.value == "12s"

    ind._listening_started_at = time.monotonic() - 13.0  # clock moves on; the next tick shows it
    ind.window.fire_all()
    # started is captured when the timer starts, so the displayed value follows real time:
    assert ind.elapsed_var.value in {"12s", "13s"}
    assert len(ind.window.pending) == 1

    ind._stop_elapsed_timer()
    assert ind.elapsed_var.value == ""
    assert not ind.window.pending
    ind.window.fire_all()  # a stale callback firing late must be a no-op
    assert ind.elapsed_var.value == ""


def test_restarting_the_timer_does_not_leave_two_loops_running() -> None:
    ind = _indicator(started_ago=1.0)
    ind._start_elapsed_timer()
    ind._start_elapsed_timer()
    assert len(ind.window.pending) == 1
    assert ind.window.cancelled, "the first loop must be cancelled"


def test_timer_survives_a_destroyed_window() -> None:
    ind = _indicator(started_ago=1.0)
    ind.window = None
    ind._start_elapsed_timer()   # must not raise
    ind._stop_elapsed_timer()    # must not raise
