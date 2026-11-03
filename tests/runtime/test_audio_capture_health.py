"""VF-10: the capture callback must never block, and long holds are not hangs.

Field log (Aug-Sep 2026): 20 `input overflow` warnings logged from inside the
PortAudio callbacks, and 2 `Hang detected: Operation 'recording'` on 158 s and
261 s dictations that then transcribed fine in under 3 s.
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager

import numpy as np
import pytest

from voiceflow.core import audio_enhanced as audio_mod
from voiceflow.core.audio_enhanced import BoundedRingBuffer, EnhancedAudioRecorder, _block_to_mono
from voiceflow.core.config import Config
from voiceflow.utils.idle_aware_monitor import IdleAwareMonitor, ProcessState

SR = 16000
BLOCK = 512


class _Overflow:
    """Truthy stand-in for sounddevice.CallbackFlags with input_overflow set."""

    input_overflow = True

    def __bool__(self) -> bool:
        return True


class _OtherStatus:
    input_overflow = False

    def __bool__(self) -> bool:
        return True


def _recorder(**overrides) -> EnhancedAudioRecorder:
    cfg = Config(stop_drain_seconds=0.0, **overrides)
    return EnhancedAudioRecorder(cfg)


def _feed(rec: EnhancedAudioRecorder, blocks) -> None:
    """Drive the recording callback faster than real time.

    When the queue is half full, wait for the worker (back-pressure a real
    32 ms device clock gives for free); the point of these tests is ordering
    and memory, not saturation, which has its own test.
    """
    half = rec._capture.max_blocks // 2
    for b in blocks:
        rec._callback(b, len(b), None, None)
        if rec._capture.depth() >= half:
            assert rec._capture.flush(audio_mod.CHANNEL_RECORDING, 5.0)
    assert rec._capture.dropped[audio_mod.CHANNEL_RECORDING] == 0


@contextmanager
def _stalled_reader(buf: BoundedRingBuffer, seconds: float):
    """A reader thread that holds the ring lock for `seconds` (like a slow
    streaming-preview read), yielded once it actually holds it."""
    holding = threading.Event()

    def _hold():
        with buf.lock:
            holding.set()
            time.sleep(seconds)

    t = threading.Thread(target=_hold, daemon=True)
    t.start()
    assert holding.wait(2.0)
    try:
        yield t
    finally:
        t.join(timeout=seconds + 2.0)


class _FakeStream:
    def __init__(self, *a, **k):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def close(self):
        pass


def _ramp_blocks(seconds: float):
    """Yield (frames, 1) blocks whose values encode their absolute sample index."""
    total = int(seconds * SR)
    for start in range(0, total, BLOCK):
        n = min(BLOCK, total - start)
        idx = np.arange(start, start + n, dtype=np.float64)
        # Values stay within [-1, 1] and are unique per sample within 3 minutes.
        yield ((idx / (SR * 200.0)).astype(np.float32)).reshape(n, 1)


class TestCallbackNeverBlocks:
    def test_status_is_counted_not_logged_on_the_audio_thread(self, caplog):
        rec = _recorder()
        rec._recording = True
        block = np.zeros((BLOCK, 1), dtype=np.float32)
        with caplog.at_level(logging.DEBUG):
            for _ in range(50):
                rec._callback(block, BLOCK, None, _Overflow())
                rec._continuous_recording = True
                rec._continuous_callback(block, BLOCK, None, _Overflow())
            rec._callback(block, BLOCK, None, _OtherStatus())
        audio_records = [r for r in caplog.records if r.name == audio_mod.logger.name]
        assert audio_records == [], "nothing may be logged from inside a PortAudio callback"
        health = rec.get_audio_health()
        assert health["overflow_recording"] == 50
        assert health["overflow_continuous"] == 50
        assert health["status_other"] == 1

    def test_callback_does_not_run_the_logging_validation_guard(self, monkeypatch):
        def _boom(*_a, **_k):  # pragma: no cover - must not be called
            raise AssertionError("audio_validation_guard called on the audio thread")

        monkeypatch.setattr(audio_mod, "audio_validation_guard", _boom)
        rec = _recorder()
        rec._recording = True
        rec._callback(np.ones((BLOCK, 1), dtype=np.float32) * 0.1, BLOCK, None, None)
        assert rec._callback_count == 1
        assert rec._callback_error_count == 0

    def test_fast_producer_keeps_every_sample_in_order(self):
        """A synthetic producer hammering the callback from its own thread while
        a reader polls the ring (like the streaming feed) loses nothing."""
        rec = _recorder()
        rec._recording = True
        blocks = list(_ramp_blocks(20.0))
        stop = threading.Event()
        reads = {"n": 0}

        def _reader():
            last = 0
            while not stop.is_set():
                _, last = rec._ring_buffer.get_samples_since(last)
                rec._ring_buffer.get_latest_samples(4096)
                reads["n"] += 1
                time.sleep(0.001)  # like the real 180 ms feed loop, just faster

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        t0 = time.perf_counter()
        for i, b in enumerate(blocks):
            rec._callback(b, len(b), None, None)
            if i % 8 == 7:
                time.sleep(0.002)  # 8 blocks = 256 ms of audio per ~2 ms: >50x real time
        elapsed = time.perf_counter() - t0
        stop.set()
        reader.join(timeout=2.0)

        audio = rec.stop()
        expected = np.concatenate([b[:, 0] for b in blocks])
        assert audio.shape == expected.shape
        np.testing.assert_array_equal(audio, expected)
        assert reads["n"] > 0
        health = rec.get_audio_health()
        assert health["queue_dropped_recording"] == 0
        assert health["capture_worker_alive"] is True
        # 625 blocks = 20 s of audio; real time allows 20 s. Loose bound: the
        # point is per-block cost far below the 32 ms block period.
        assert elapsed < 5.0, f"callbacks too slow: {elapsed:.2f}s for 20s of audio"

    def test_callback_returns_promptly_while_a_reader_holds_the_ring_lock(self):
        """Review finding (fa5ff26): the callback took the ring lock, so a
        reader holding it blocked the audio thread for >100 ms. Now the worker
        waits on the lock, the callback does not."""
        rec = _recorder()
        rec._recording = True
        blocks = list(_ramp_blocks(0.32))  # 10 blocks
        durations = []
        with _stalled_reader(rec._ring_buffer, 0.5) as holder:
            for b in blocks:
                t0 = time.perf_counter()
                rec._callback(b, len(b), None, None)
                durations.append(time.perf_counter() - t0)
            # The lock really was held for the whole burst, and the worker is
            # stuck behind it (it holds one block; the rest are queued).
            assert holder.is_alive()
            assert rec._capture.depth() >= len(blocks) - 1
        assert max(durations) < 0.010, f"callback blocked {max(durations) * 1000:.1f} ms behind a reader"
        audio = rec.stop()
        np.testing.assert_array_equal(audio, np.concatenate([b[:, 0] for b in blocks]))

    def test_queue_saturation_drops_and_counts_without_blocking(self, caplog):
        rec = _recorder(audio_queue_max_seconds=0.5)  # 16 blocks
        cap = rec._capture.max_blocks
        assert cap == 16
        rec._recording = True
        blocks = list(_ramp_blocks(40 * BLOCK / SR))
        durations = []
        with _stalled_reader(rec._ring_buffer, 0.4):
            for b in blocks:
                t0 = time.perf_counter()
                rec._callback(b, len(b), None, None)
                durations.append(time.perf_counter() - t0)
        assert max(durations) < 0.010
        health = rec.get_audio_health()
        dropped = health["queue_dropped_recording"]
        # The worker holds at most one block while blocked on the lock.
        assert len(blocks) - cap - 1 <= dropped <= len(blocks) - cap
        assert health["queue_high_water"] == cap
        assert rec._callback_count == len(blocks), "activity is counted even for dropped blocks"
        with caplog.at_level(logging.WARNING):
            audio = rec.stop()
        assert audio.size == (len(blocks) - dropped) * BLOCK
        assert any("audio_queue_saturated" in r.getMessage() for r in caplog.records)

    def test_stop_drains_the_queue_before_returning(self):
        """Blocks still queued at key release (worker stalled) are waited for,
        so the tail of the utterance is not cut off."""
        rec = _recorder()
        rec._recording = True
        blocks = list(_ramp_blocks(0.64))
        with _stalled_reader(rec._ring_buffer, 0.2):
            for b in blocks:
                rec._callback(b, len(b), None, None)
            # stop() runs while the reader still holds the lock; its bounded
            # flush waits for the worker once the lock is released.
            audio = rec.stop()
        np.testing.assert_array_equal(audio, np.concatenate([b[:, 0] for b in blocks]))

    def test_blocks_from_a_previous_recording_do_not_leak_into_the_next(self):
        rec = _recorder()
        rec._recording = True
        stale = list(_ramp_blocks(0.32))
        with _stalled_reader(rec._ring_buffer, 0.2):
            for b in stale:
                rec._callback(b, len(b), None, None)
            # What start() does for the next recording. It waits for the lock,
            # racing the worker (which already holds one stale block): either
            # order must leave the new recording empty.
            rec._begin_generation()
        assert rec.flush_capture(2.0)
        assert rec._ring_buffer.get_data().size == 0
        # And blocks of the new generation are accepted.
        fresh = np.full((BLOCK, 1), 0.5, dtype=np.float32)
        rec._callback(fresh, BLOCK, None, None)
        assert rec.flush_capture(2.0)
        assert rec._ring_buffer.get_data().size == BLOCK

    def test_dead_worker_falls_back_to_draining_on_stop(self):
        rec = _recorder()
        rec._capture.close()
        assert not rec._capture.worker_alive()
        rec._recording = True
        blocks = list(_ramp_blocks(0.32))
        for b in blocks:
            rec._callback(b, len(b), None, None)
        assert rec.get_audio_health()["capture_worker_alive"] is False
        audio = rec.stop()
        np.testing.assert_array_equal(audio, np.concatenate([b[:, 0] for b in blocks]))

    def test_start_restarts_a_dead_worker_and_includes_pre_roll(self, monkeypatch):
        monkeypatch.setattr(audio_mod.sd, "InputStream", _FakeStream)
        rec = _recorder()
        rec._capture.close()
        rec._continuous_recording = True
        pre = np.full((BLOCK, 1), 0.25, dtype=np.float32)
        for _ in range(12):  # 384 ms of pre-roll, queued but not yet applied
            rec._continuous_callback(pre, BLOCK, None, None)
        rec.start()
        try:
            assert rec._capture.worker_alive()
            assert rec._ring_buffer.get_data().size == 12 * BLOCK
        finally:
            rec._recording = False
            rec.close()

    def test_non_finite_samples_are_zeroed_not_dropped(self):
        block = np.array([[0.1], [np.nan], [np.inf], [-np.inf]], dtype=np.float32)
        out = _block_to_mono(block)
        assert out.shape == (4,)
        assert np.isfinite(out).all()
        assert out[0] == pytest.approx(0.1)
        assert out[1] == 0.0

    def test_stereo_is_downmixed(self):
        block = np.array([[0.2, 0.4], [0.0, -0.2]], dtype=np.float32)
        np.testing.assert_allclose(_block_to_mono(block), [0.3, -0.1], rtol=1e-6)

    def test_overflow_during_recording_is_reported_once_at_stop(self, caplog):
        rec = _recorder()
        rec.start_continuous = lambda: None  # no real device in tests
        rec._continuous_recording = True
        rec._overflow_at_start = rec._overflow_count
        rec._continuous_overflow_at_start = rec._continuous_overflow_count
        rec._recording = True
        block = np.zeros((BLOCK, 1), dtype=np.float32)
        rec._callback(block, BLOCK, None, _Overflow())
        rec._callback(block, BLOCK, None, _Overflow())
        with caplog.at_level(logging.WARNING):
            rec.stop()
        msgs = [r.getMessage() for r in caplog.records if "audio_input_overflow" in r.getMessage()]
        assert msgs == ["audio_input_overflow recording=2 continuous=0 duration=0.06"]


class TestStreamLatency:
    @pytest.mark.parametrize(
        "raw, expected",
        [("high", "high"), ("LOW", "low"), ("0.08", 0.08), (0.12, 0.12), ("junk", "high"), (5.0, "high"), (0, "high")],
    )
    def test_latency_setting_is_validated(self, raw, expected):
        rec = _recorder()
        rec.cfg.audio_input_latency = raw
        assert rec._stream_latency() == expected

    def test_default_is_high(self):
        assert Config().audio_input_latency == "high"


class TestThreeMinuteRecording:
    def test_three_minutes_fit_with_constant_memory(self):
        rec = _recorder()
        cap_bytes = rec._ring_buffer.buffer.nbytes
        rec._recording = True
        blocks = list(_ramp_blocks(180.0))
        _feed(rec, blocks)
        assert rec.flush_capture(5.0)
        assert rec._ring_buffer.buffer.nbytes == cap_bytes, "ring must not grow"
        assert rec.get_current_duration() == pytest.approx(180.0, abs=BLOCK / SR)
        audio = rec.stop()
        expected = np.concatenate([b[:, 0] for b in blocks])
        np.testing.assert_array_equal(audio, expected)
        assert rec.get_audio_health()["ring_wraps"] == 0

    def test_hold_past_capacity_keeps_latest_and_says_so(self, caplog):
        rec = _recorder(max_recording_seconds=60.0)
        rec._recording = True
        blocks = list(_ramp_blocks(70.0))
        _feed(rec, blocks)
        with caplog.at_level(logging.WARNING):
            audio = rec.stop()
        expected = np.concatenate([b[:, 0] for b in blocks])[-60 * SR:]
        np.testing.assert_array_equal(audio, expected)
        assert any("recording_ring_wrapped" in r.getMessage() for r in caplog.records)
        assert rec.get_audio_health()["ring_wraps"] == 1

    def test_capacity_setting_is_bounded(self):
        assert _recorder(max_recording_seconds=1.0)._max_duration == 300.0
        assert _recorder(max_recording_seconds=99999.0)._max_duration == 300.0
        assert _recorder(max_recording_seconds=120.0)._max_duration == 120.0


class _Clock:
    def __init__(self, start: float = 1_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr("voiceflow.utils.idle_aware_monitor.time.time", c)
    return c


class TestWatchdogDuringLongDictation:
    def _monitor(self, probe=None) -> IdleAwareMonitor:
        return IdleAwareMonitor(
            operation_timeout=120.0,
            check_interval=10.0,
            recording_timeout=1800.0,
            recording_stall_seconds=15.0,
            activity_probe=probe,
        )

    def test_three_minute_hold_with_audio_flowing_is_healthy(self, clock):
        count = {"n": 0}
        mon = self._monitor(lambda: count["n"])
        mon.set_state(ProcessState.RECORDING)
        for _ in range(18):  # 18 checks x 10 s = 180 s
            clock.now += 10.0
            count["n"] += 312  # ~10 s of 32 ms blocks
            assert mon.get_health().is_healthy, "a 3-minute dictation is not a hang"

    def test_stalled_stream_is_still_detected(self, clock):
        count = {"n": 0}
        mon = self._monitor(lambda: count["n"])
        mon.set_state(ProcessState.RECORDING)
        for _ in range(13):  # 130 s with audio flowing
            clock.now += 10.0
            count["n"] += 312
            assert mon.get_health().is_healthy
        # Stream stops delivering blocks while the key is still held.
        clock.now += 10.0
        assert mon.get_health().is_healthy  # 10 s quiet < 15 s stall window
        clock.now += 10.0
        assert not mon.get_health().is_healthy

    def test_stuck_key_hits_the_hard_ceiling(self, clock):
        count = {"n": 0}
        mon = self._monitor(lambda: count["n"])
        mon.set_state(ProcessState.RECORDING)
        clock.now += 1801.0
        count["n"] += 1
        assert not mon.get_health().is_healthy

    def test_without_probe_long_hold_is_not_flagged_below_ceiling(self, clock):
        mon = self._monitor(None)
        mon.set_state(ProcessState.RECORDING)
        clock.now += 300.0
        assert mon.get_health().is_healthy

    def test_processing_timeout_is_unchanged(self, clock):
        mon = self._monitor(lambda: 0)
        mon.set_state(ProcessState.PROCESSING)
        clock.now += 121.0
        assert not mon.get_health().is_healthy

    def test_probe_errors_do_not_raise_or_flag(self, clock):
        def _bad():
            raise RuntimeError("recorder gone")

        mon = self._monitor(_bad)
        mon.set_state(ProcessState.RECORDING)
        clock.now += 200.0
        assert mon.get_health().is_healthy

    def test_new_recording_resets_stall_tracking(self, clock):
        count = {"n": 500}
        mon = self._monitor(lambda: count["n"])
        mon.set_state(ProcessState.RECORDING)
        clock.now += 130.0
        assert mon.get_health().is_healthy
        mon.set_state(ProcessState.IDLE)
        count["n"] = 0  # recorder resets its counter per recording
        mon.set_state(ProcessState.RECORDING)
        clock.now += 125.0
        count["n"] = 3900
        assert mon.get_health().is_healthy


def test_ring_buffer_append_still_validates_for_external_callers():
    buf = BoundedRingBuffer(1.0, SR)
    buf.append(np.array([0.1, 0.2], dtype=np.float32))
    np.testing.assert_allclose(buf.get_data(), [0.1, 0.2])
