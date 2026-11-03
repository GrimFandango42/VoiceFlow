"""The last word of an utterance must survive the hotkey release.

`start()` prepends 800 ms of pre-buffer so the beginning is never clipped.
Nothing protected the end: `stop()` set `_recording = False` before stopping the
stream, and the callback only appends while that flag is True, so every frame the
driver had captured but not yet delivered was discarded. Reported from real use
as "the last words in the last sentence tend to get cut off".
"""

from __future__ import annotations

import threading
import time

from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
from voiceflow.core.config import Config


class _Recorder:
    """Minimal stand-in exposing only what the drain touches."""

    def __init__(self, cfg):
        self.cfg = cfg
        self._callback_count = 0

    _drain_pending_audio = EnhancedAudioRecorder._drain_pending_audio


class _Ticking(_Recorder):
    """A recorder whose audio thread is still delivering blocks."""

    def __init__(self, cfg, *, blocks, interval=0.01):
        super().__init__(cfg)
        self._blocks = blocks
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        for _ in range(self._blocks):
            if self._stop.wait(self._interval):
                return
            self._callback_count += 1

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=1.0)


class TestDrainTiming:
    def test_quiet_stream_returns_fast(self):
        cfg = Config(stop_drain_seconds=0.5)
        r = _Recorder(cfg)
        start = time.perf_counter()
        r._drain_pending_audio()
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, "a silent stream must not wait out the full cap"

    def test_drain_is_bounded_by_the_cap(self):
        cfg = Config(stop_drain_seconds=0.15)
        with _Ticking(cfg, blocks=100_000, interval=0.001) as r:
            start = time.perf_counter()
            r._drain_pending_audio()
            elapsed = time.perf_counter() - start
        assert elapsed < 1.0, "a stream that never goes quiet must still be capped"

    def test_it_waits_while_audio_is_still_arriving(self):
        cfg = Config(stop_drain_seconds=0.4)
        quiet = _Recorder(cfg)

        t0 = time.perf_counter()
        quiet._drain_pending_audio()
        quiet_elapsed = time.perf_counter() - t0

        with _Ticking(cfg, blocks=20, interval=0.01) as busy:
            t1 = time.perf_counter()
            busy._drain_pending_audio()
            busy_elapsed = time.perf_counter() - t1

        assert busy_elapsed > quiet_elapsed, (
            "a stream still delivering audio must be waited on longer than a silent one"
        )


class TestConfiguration:
    def test_zero_disables_the_drain(self):
        r = _Recorder(Config(stop_drain_seconds=0.0))
        start = time.perf_counter()
        r._drain_pending_audio()
        assert time.perf_counter() - start < 0.02

    def test_negative_is_treated_as_disabled(self):
        r = _Recorder(Config(stop_drain_seconds=-1.0))
        start = time.perf_counter()
        r._drain_pending_audio()
        assert time.perf_counter() - start < 0.02

    def test_garbage_cap_falls_back_instead_of_raising(self):
        cfg = Config()
        cfg.stop_drain_seconds = "not a number"
        r = _Recorder(cfg)
        r._drain_pending_audio()  # must not raise

    def test_garbage_blocksize_falls_back_instead_of_raising(self):
        cfg = Config(stop_drain_seconds=0.05)
        cfg.blocksize = 0
        r = _Recorder(cfg)
        r._drain_pending_audio()  # ZeroDivisionError guard

    def test_default_is_a_sane_quarter_second(self):
        # Long enough to cover several 32 ms blocks plus driver latency,
        # short enough not to feel like lag on top of a ~0.75s transcribe.
        assert 0.1 <= Config().stop_drain_seconds <= 0.5


class TestOrdering:
    def test_stop_drains_before_clearing_the_recording_flag(self):
        # The ordering IS the fix. If _recording is cleared first the callback
        # stops appending and the drain protects nothing.
        import inspect

        src = inspect.getsource(EnhancedAudioRecorder.stop)
        drain_at = src.index("_drain_pending_audio()")
        flag_at = src.index("self._recording = False")
        assert drain_at < flag_at, "drain must run before _recording is cleared"
