from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pytest

from voiceflow.core.asr_engine import ASREngine, TranscriptionResult
from voiceflow.core.audio_enhanced import BoundedRingBuffer

SAMPLE_RATE = 16000


def _tone(seconds: float, sample_rate: int = SAMPLE_RATE) -> np.ndarray:
    samples = int(seconds * sample_rate)
    t = np.linspace(0.0, seconds, samples, endpoint=False, dtype=np.float32)
    return (0.1 * np.sin(2.0 * np.pi * 220.0 * t)).astype(np.float32)


@dataclass
class _FakeBackend:
    speed_factor: float = 4.0

    def load(self) -> None:
        return None

    def is_loaded(self) -> bool:
        return True

    def cleanup(self) -> None:
        return None

    def transcribe(self, audio: np.ndarray, **kwargs) -> TranscriptionResult:
        duration = float(len(audio) / SAMPLE_RATE)
        processing_time = duration / max(self.speed_factor, 0.01)
        return TranscriptionResult(
            text=f"mock transcript ({duration:.1f}s)",
            language="en",
            duration=duration,
            processing_time=processing_time,
        )


def test_bounded_ring_buffer_keeps_latest_audio_only() -> None:
    buffer = BoundedRingBuffer(max_duration_seconds=10.0, sample_rate=SAMPLE_RATE)
    chunk = _tone(4.0)

    buffer.append(chunk)
    buffer.append(chunk)
    buffer.append(chunk)  # 12s total written into 10s ring

    data = buffer.get_data()
    assert len(data) == 10 * SAMPLE_RATE
    assert np.abs(np.mean(data)) < 0.01


@pytest.mark.parametrize(
    "label,duration_seconds,min_speed_factor",
    [
        ("short", 1.2, 3.0),
        ("medium", 12.0, 3.0),
        ("long", 90.0, 3.0),
    ],
)
def test_transcription_profiles_short_medium_long(
    label: str,
    duration_seconds: float,
    min_speed_factor: float,
) -> None:
    engine = ASREngine(device="cpu", compute_type="int8")
    engine._backend = _FakeBackend(speed_factor=4.0)  # replace heavy model backend

    result = engine.transcribe(_tone(duration_seconds))

    assert label in {"short", "medium", "long"}
    assert result.text
    assert result.duration == pytest.approx(duration_seconds, rel=0.02, abs=0.05)
    assert result.processing_time > 0.0
    assert (result.duration / result.processing_time) >= min_speed_factor


def test_transcription_stats_across_mixed_lengths() -> None:
    engine = ASREngine(device="cpu", compute_type="int8")
    engine._backend = _FakeBackend(speed_factor=4.0)

    for seconds in (1.0, 15.0, 75.0):
        result = engine.transcribe(_tone(seconds))
        assert result.text

    stats = engine.get_stats()
    assert stats["transcription_count"] == 3
    assert stats["total_audio_duration"] == pytest.approx(91.0, rel=0.02)
    assert stats["avg_speed"] >= 3.0
