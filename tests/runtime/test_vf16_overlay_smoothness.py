"""VF-16: smoother overlay animation + recording-duration counter in the dock (bottom bar).

Nithin: make the animation smoother and blend better with the desktop; put a compact
duration counter in the bottom bar next to status / build date / Hide / History.
"""
from __future__ import annotations

import inspect
import time
from types import SimpleNamespace

from voiceflow.ui import visual_indicators as vi
from voiceflow.ui.visual_indicators import BottomScreenIndicator, TranscriptionStatus


class _Var:
    def __init__(self, value=None) -> None:
        self.value = value

    def set(self, value) -> None:
        self.value = value


class _FakeWindow:
    def __init__(self) -> None:
        self.pending: dict[int, object] = {}
        self.intervals: list[int] = []
        self._next = 1

    def after(self, ms, fn):
        ident = self._next
        self._next += 1
        self.pending[ident] = fn
        self.intervals.append(ms)
        return ident

    def after_cancel(self, ident) -> None:
        self.pending.pop(ident, None)


# --- dock counter -----------------------------------------------------------------------

def _indicator(started_ago: float, dock_enabled: bool = True) -> SimpleNamespace:
    ind = SimpleNamespace(
        window=_FakeWindow(),
        elapsed_var=_Var(""),
        dock_elapsed_var=_Var(""),
        dock_enabled=dock_enabled,
        _listening_started_at=time.monotonic() - started_ago,
    )
    ind._start_elapsed_timer = lambda: BottomScreenIndicator._start_elapsed_timer(ind)
    ind._stop_elapsed_timer = lambda clear=True: BottomScreenIndicator._stop_elapsed_timer(ind, clear)
    return ind


def test_dock_counts_while_recording_and_overlay_stays_empty() -> None:
    ind = _indicator(started_ago=12.0)
    ind._start_elapsed_timer()
    assert ind.dock_elapsed_var.value == "12s"
    assert ind.elapsed_var.value == "", "no second counter stacked above the dock"


def test_dock_holds_the_final_duration_after_recording_stops() -> None:
    ind = _indicator(started_ago=118.6)
    ind._start_elapsed_timer()
    ind._stop_elapsed_timer()
    assert ind.dock_elapsed_var.value == "1:58"
    assert not ind.window.pending


def test_overlay_shows_the_counter_when_the_dock_is_hidden() -> None:
    ind = _indicator(started_ago=7.0, dock_enabled=False)
    ind._start_elapsed_timer()
    assert ind.elapsed_var.value == "7s"


def test_stop_without_start_leaves_dock_untouched() -> None:
    ind = _indicator(started_ago=0.0)
    ind.dock_elapsed_var.value = "0:42"
    ind._stop_elapsed_timer()
    assert ind.dock_elapsed_var.value == "0:42"


# --- single animation clock ---------------------------------------------------------------

def _wave_dummy(status):
    calls: list[str] = []
    dummy = SimpleNamespace(
        window=_FakeWindow(),
        wave_canvas=object(),
        current_status=status,
        _WAVE_MODES=BottomScreenIndicator._WAVE_MODES,
        _animate_waveform=lambda mode="listening": calls.append(mode),
        _resolve_animation_interval=lambda s: 31,
        _idle_wave_job=None,
    )
    dummy._idle_wave_tick = lambda: BottomScreenIndicator._idle_wave_tick(dummy)
    return dummy, calls


def test_wave_clock_follows_status_with_one_step_per_frame() -> None:
    dummy, calls = _wave_dummy(TranscriptionStatus.LISTENING)
    dummy._idle_wave_tick()
    assert calls == ["listening"]
    assert dummy.window.intervals == [31]

    dummy.current_status = TranscriptionStatus.IDLE
    dummy._idle_wave_tick()
    assert calls == ["listening", "idle"]
    assert dummy.window.intervals[-1] == 35


def test_status_icon_loop_no_longer_drives_the_waveform() -> None:
    src = inspect.getsource(BottomScreenIndicator._animate_status_icon)
    assert "_animate_waveform" not in src
    assert "_animate_waveform" not in inspect.getsource(BottomScreenIndicator._set_icon_idle)


def test_glow_is_not_stippled() -> None:
    # gray50 stipple renders as a checkerboard over the desktop through the colour key.
    assert 'stipple="gray50"' not in inspect.getsource(vi)


# --- hi-res timer is balanced ------------------------------------------------------------

def test_hires_timer_begin_end_are_balanced(monkeypatch) -> None:
    log: list[str] = []

    class _Winmm:
        def timeBeginPeriod(self, ms):
            log.append(f"begin{ms}")

        def timeEndPeriod(self, ms):
            log.append(f"end{ms}")

    import ctypes

    monkeypatch.setattr(vi.sys, "platform", "win32")
    monkeypatch.setattr(ctypes, "WinDLL", lambda name: _Winmm(), raising=False)
    ind = SimpleNamespace()
    for on in (True, True, False, False, True, False):
        BottomScreenIndicator._set_hires_timer(ind, on)
    assert log == ["begin1", "end1", "begin1", "end1"]
