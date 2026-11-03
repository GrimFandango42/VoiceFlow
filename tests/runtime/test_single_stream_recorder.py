"""VF-11: one always-on microphone stream shared by pre-roll and recording.

Nithin's 118.6 s test still logged 2 audio_input_overflow (recording=2). Candidate causes
were the stream latency/blocksize and the second concurrent stream (a stream opened and
closed on the hotkey path next to the always-on pre-buffer stream). With a single stream
there is no second stream and nothing to open when the key goes down.
"""
from __future__ import annotations

import logging

import numpy as np
import pytest

from voiceflow.core import audio_enhanced as audio_mod
from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
from voiceflow.core.config import Config

SR = 16000
BLOCK = 512


class _Overflow:
    input_overflow = True

    def __bool__(self) -> bool:
        return True


class _Streams:
    """Counts sd.InputStream constructions; each fake stream records start/stop/close."""

    def __init__(self) -> None:
        self.created: list["_Stream"] = []

    def __call__(self, *args, **kwargs):
        stream = _Stream(kwargs)
        self.created.append(stream)
        return stream


class _Stream:
    def __init__(self, kwargs) -> None:
        self.kwargs = kwargs
        self.started = self.stopped = self.closed = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def close(self):
        self.closed = True


def _ramp(seconds: float):
    total = int(seconds * SR)
    out = []
    for start in range(0, total, BLOCK):
        n = min(BLOCK, total - start)
        idx = np.arange(start, start + n, dtype=np.float64)
        out.append((idx / (SR * 200.0)).astype(np.float32).reshape(n, 1))
    return out


@pytest.fixture()
def streams(monkeypatch):
    fake = _Streams()
    monkeypatch.setattr(audio_mod.sd, "InputStream", fake)
    return fake


def _rec(**kw) -> EnhancedAudioRecorder:
    return EnhancedAudioRecorder(Config(stop_drain_seconds=0.0, **kw))


def _feed(rec: EnhancedAudioRecorder, blocks) -> None:
    for b in blocks:
        rec._continuous_callback(b, len(b), None, None)
    assert rec._capture.flush(audio_mod.CHANNEL_CONTINUOUS, 5.0)


def test_default_is_single_stream() -> None:
    assert Config().audio_single_stream is True


def test_recording_opens_no_second_stream(streams) -> None:
    rec = _rec()
    rec.start_continuous()
    assert len(streams.created) == 1

    rec.start()
    rec.stop()
    rec.start()
    rec.stop()

    assert len(streams.created) == 1, "start()/stop() must not open or close a microphone stream"
    shared = streams.created[0]
    assert shared.started and not shared.stopped and not shared.closed
    rec.close()


def test_start_brings_up_the_shared_stream_if_it_is_not_running(streams) -> None:
    rec = _rec()
    rec.start()
    assert len(streams.created) == 1
    rec.stop()
    rec.close()


def test_two_stream_mode_still_opens_a_recording_stream(streams) -> None:
    rec = _rec(audio_single_stream=False)
    rec.start_continuous()
    rec.start()
    assert len(streams.created) == 2
    rec.stop()
    assert streams.created[1].stopped and streams.created[1].closed
    rec.close()


def test_pre_roll_and_live_audio_join_without_gap_or_duplicate(streams) -> None:
    rec = _rec()
    rec.start_continuous()
    blocks = _ramp(2.0)
    before, after = blocks[:32], blocks[32:]
    _feed(rec, before)

    rec.start()
    _feed(rec, after)
    audio = rec.stop()

    full = np.concatenate([b[:, 0] for b in blocks])
    pre_roll = int(0.8 * SR)
    start_idx = sum(len(b) for b in before) - pre_roll
    np.testing.assert_array_equal(audio, full[start_idx:])
    rec.close()


def test_audio_offered_but_not_yet_applied_at_start_is_not_lost_or_doubled(streams) -> None:
    """Blocks queued when the key goes down land after the pre-roll, once."""
    rec = _rec()
    rec.start_continuous()
    rec._capture.close()  # worker stopped: everything below stays queued until start()/stop() drain it
    blocks = _ramp(1.5)
    for b in blocks:
        rec._continuous_callback(b, len(b), None, None)

    rec.start()
    audio = rec.stop()

    # 1.5 s offered = exactly the pre-roll buffer's capacity; the newest 0.8 s is handed over.
    full = np.concatenate([b[:, 0] for b in blocks])
    np.testing.assert_array_equal(audio, full[-int(0.8 * SR):])
    rec.close()


def test_hand_over_is_gapless_while_blocks_arrive_concurrently(streams) -> None:
    """A producer thread feeds blocks continuously while start()/stop() flip the routing."""
    import threading
    import time

    rec = _rec()
    rec.start_continuous()
    stop_feeding = threading.Event()
    blocks = _ramp(3.0 * 60)  # long enough that the producer never runs out

    def producer() -> None:
        for b in blocks:
            if stop_feeding.is_set():
                return
            rec._continuous_callback(b, len(b), None, None)
            time.sleep(0.0005)

    t = threading.Thread(target=producer, daemon=True)
    t.start()
    try:
        for _ in range(5):
            time.sleep(0.15)
            rec.start()
            time.sleep(0.2)
            audio = rec.stop()
            assert audio.size > int(0.8 * SR)
            idx = np.rint(audio.astype(np.float64) * SR * 200.0).astype(np.int64)
            steps = np.diff(idx)
            bad = int(np.argmax(steps != 1))
            assert np.all(steps == 1), "gap or duplicate at sample " + str(bad)
    finally:
        stop_feeding.set()
        t.join(timeout=2.0)
    assert rec._capture.dropped[audio_mod.CHANNEL_CONTINUOUS] == 0
    rec.close()


def test_next_recording_does_not_start_with_the_previous_utterances_tail(streams) -> None:
    rec = _rec()
    rec.start_continuous()
    _feed(rec, _ramp(1.0))
    rec.start()
    _feed(rec, [np.full((BLOCK, 1), 0.9, dtype=np.float32)] * 20)  # loud utterance
    first = rec.stop()
    assert float(np.max(first)) == pytest.approx(0.9)

    rec.start()  # immediately again: nothing has been heard since stop
    second = rec.stop()
    assert second.size == 0 or float(np.max(second)) < 0.9
    rec.close()


def test_overflow_while_recording_is_attributed_to_the_recording_and_explained(streams, caplog) -> None:
    rec = _rec()
    rec.start_continuous()
    _feed(rec, _ramp(0.5))
    rec.start()

    block = np.zeros((BLOCK, 1), dtype=np.float32)
    rec._continuous_callback(block, BLOCK, None, _Overflow())
    rec._continuous_callback(block, BLOCK, None, _Overflow())
    with caplog.at_level(logging.INFO):
        rec.stop()

    messages = [r.getMessage() for r in caplog.records]
    summary = [m for m in messages if m.startswith("audio_input_overflow ")]
    assert len(summary) == 1 and "recording=2 continuous=0" in summary[0]
    detail = [m for m in messages if m.startswith("audio_overflow_detail ")]
    assert len(detail) == 1
    assert "single_stream=True" in detail[0] and "at_s=[" in detail[0] and "max_callback_gap_ms=" in detail[0]
    rec.close()


def test_overflow_between_recordings_is_not_charged_to_the_recording(streams, caplog) -> None:
    rec = _rec()
    rec.start_continuous()
    block = np.zeros((BLOCK, 1), dtype=np.float32)
    rec._continuous_callback(block, BLOCK, None, _Overflow())  # idle: pre-roll stream only
    rec.start()
    with caplog.at_level(logging.WARNING):
        rec.stop()
    assert not [r for r in caplog.records if r.getMessage().startswith("audio_input_overflow")]
    assert rec.get_audio_health()["overflow_continuous"] == 1
    rec.close()


def test_callback_count_advances_while_recording_for_the_stop_drain(streams) -> None:
    rec = _rec()
    rec.start_continuous()
    rec.start()
    before = rec._callback_count
    _feed(rec, _ramp(0.1))
    assert rec._callback_count > before
    rec.stop()
    rec.close()
