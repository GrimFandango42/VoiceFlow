"""VF-11: the idle-resume warm-up runs when the hotkey goes down, not on the release path.

Field evidence (VF-10 log analysis, 57 dictations): 11 first-after-20-min-idle
dictations each paid 329-439 ms of warm-up between release and text.
"""
from __future__ import annotations

import logging
import threading
import time
from types import SimpleNamespace

import numpy as np

from voiceflow.ui.cli_enhanced import EnhancedApp

WARMUP_COST_S = 0.3


class _FakeAsr:
    """Stands in for the cold ASR engine: a decode costs WARMUP_COST_S."""

    def __init__(self) -> None:
        self.calls = 0
        self.lock = threading.Lock()

    def transcribe(self, audio):
        with self.lock:
            self.calls += 1
        time.sleep(WARMUP_COST_S)
        return "x"


class _App:
    _idle_gap_seconds = EnhancedApp._idle_gap_seconds
    _maybe_prewarm_on_press = EnhancedApp._maybe_prewarm_on_press
    _await_idle_prewarm = EnhancedApp._await_idle_prewarm
    _run_idle_resume_warmup = EnhancedApp._run_idle_resume_warmup
    _make_warmup_speech_audio = staticmethod(EnhancedApp._make_warmup_speech_audio)

    def __init__(self, idle_gap_s: float, *, ready: bool = True, **cfg_overrides) -> None:
        cfg = dict(
            idle_resume_guard_enabled=True,
            idle_resume_warmup_enabled=True,
            idle_resume_threshold_seconds=1200.0,
            idle_resume_warmup_audio_seconds=0.5,
            sample_rate=16000,
        )
        cfg.update(cfg_overrides)
        self.cfg = SimpleNamespace(**cfg)
        self.asr = _FakeAsr()
        self.asr_fast = None
        self._fast_model_ready = False
        self._ready = ready
        self._log = logging.getLogger("test")
        self._idle_resume_warmup_lock = threading.Lock()
        self._idle_resume_last_warmup_at = 0.0
        self._idle_prewarm_thread = None
        self._last_transcription_completed_at = time.time() - idle_gap_s

    def is_model_ready(self) -> bool:
        return self._ready

    def release_path_warmup_ms(self) -> float:
        """What _perform_transcription does at release (idle-resume branch), timed."""
        started = time.perf_counter()
        self._await_idle_prewarm()
        self._run_idle_resume_warmup()
        return (time.perf_counter() - started) * 1000.0


def test_without_prewarm_the_release_path_pays_the_full_warmup() -> None:
    app = _App(idle_gap_s=25 * 60)
    cost_ms = app.release_path_warmup_ms()
    assert cost_ms >= WARMUP_COST_S * 1000 * 0.9
    assert app.asr.calls == 1


def test_prewarm_on_press_removes_the_warmup_from_the_release_path() -> None:
    app = _App(idle_gap_s=25 * 60)

    assert app._maybe_prewarm_on_press() is True  # hotkey goes down
    time.sleep(WARMUP_COST_S + 0.15)              # the user speaks for a moment

    cost_ms = app.release_path_warmup_ms()        # hotkey released

    assert cost_ms < 50, f"release path still waited {cost_ms:.0f} ms"
    assert app.asr.calls == 1, "warm-up must run once, not once at press and again at release"


def test_release_path_waits_only_for_the_unfinished_remainder() -> None:
    app = _App(idle_gap_s=25 * 60)
    assert app._maybe_prewarm_on_press() is True
    time.sleep(0.1)  # a very short hold: warm-up still has ~0.2 s to go

    cost_ms = app.release_path_warmup_ms()

    assert 100 <= cost_ms <= WARMUP_COST_S * 1000 + 150
    assert app.asr.calls == 1


def test_no_prewarm_when_recently_active() -> None:
    app = _App(idle_gap_s=60)
    assert app._maybe_prewarm_on_press() is False
    assert app.asr.calls == 0


def test_no_prewarm_before_the_first_transcription() -> None:
    app = _App(idle_gap_s=0)
    app._last_transcription_completed_at = 0.0
    assert app._maybe_prewarm_on_press() is False


def test_no_prewarm_while_the_model_is_still_loading() -> None:
    app = _App(idle_gap_s=25 * 60, ready=False)
    assert app._maybe_prewarm_on_press() is False


def test_prewarm_respects_the_warmup_switch() -> None:
    app = _App(idle_gap_s=25 * 60, idle_resume_warmup_enabled=False)
    assert app._maybe_prewarm_on_press() is False


def test_a_second_press_does_not_start_a_second_prewarm() -> None:
    app = _App(idle_gap_s=25 * 60)
    assert app._maybe_prewarm_on_press() is True
    assert app._maybe_prewarm_on_press() is False
    time.sleep(WARMUP_COST_S + 0.15)
    assert app.asr.calls == 1


def test_warmup_audio_is_speech_like_not_silence() -> None:
    audio = EnhancedApp._make_warmup_speech_audio(16000, 0.5)
    assert audio.dtype == np.float32 and float(np.abs(audio).max()) > 0.05
