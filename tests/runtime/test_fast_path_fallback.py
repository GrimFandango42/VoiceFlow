from __future__ import annotations

import logging
from types import SimpleNamespace

import numpy as np

from voiceflow.ui.cli_enhanced import EnhancedApp


class _FakeASR:
    def __init__(self, text: str, model_id: str):
        self.text = text
        self.calls = 0
        self.model_config = SimpleNamespace(
            name=model_id,
            model_id=model_id,
            device="cpu",
            compute_type="int8",
        )

    def transcribe(self, audio: np.ndarray) -> str:
        self.calls += 1
        return self.text


class _DummyApp:
    _should_retry_blank_fast_path = EnhancedApp._should_retry_blank_fast_path
    _transcribe_with_fast_path_fallback = EnhancedApp._transcribe_with_fast_path_fallback

    def __init__(self, primary_text: str, fast_text: str):
        self.cfg = SimpleNamespace(min_rms_amplitude=5e-4)
        self.asr = _FakeASR(primary_text, "primary-model")
        self.asr_fast = _FakeASR(fast_text, "fast-model")
        self._log = logging.getLogger("voiceflow.tests.fast_path_fallback")


def test_blank_fast_path_retries_on_primary_for_speech_like_audio() -> None:
    app = _DummyApp(primary_text="hello world", fast_text="")
    audio = np.ones(16000, dtype=np.float32) * 0.05

    text, final_asr, retry_used, retry_path, decode_ms, retry_ms = app._transcribe_with_fast_path_fallback(
        app.asr_fast,
        "fast",
        audio,
        audio_duration=1.0,
        raw_audio_duration=1.0,
        is_non_speech=False,
        non_speech_reason="speech_like",
        non_speech_metrics={
            "peak": 0.08,
            "rms": 0.01,
            "voiced_ratio": 0.34,
            "longest_voiced_seconds": 0.42,
            "speech_hint": 1.0,
        },
    )

    assert text == "hello world"
    assert final_asr is app.asr
    assert retry_used is True
    assert retry_path == "fast-empty-primary-retry"
    assert decode_ms >= 0.0
    assert retry_ms >= 0.0
    assert app.asr_fast.calls == 1
    assert app.asr.calls == 1


def test_blank_fast_path_retries_even_when_metrics_are_weak() -> None:
    app = _DummyApp(primary_text="fallback text", fast_text="")
    audio = np.zeros(16000, dtype=np.float32)

    text, final_asr, retry_used, retry_path, decode_ms, retry_ms = app._transcribe_with_fast_path_fallback(
        app.asr_fast,
        "fast",
        audio,
        audio_duration=1.0,
        raw_audio_duration=1.0,
        is_non_speech=False,
        non_speech_reason="unknown",
        non_speech_metrics={
            "peak": 0.0,
            "rms": 0.0,
            "voiced_ratio": 0.0,
            "longest_voiced_seconds": 0.0,
            "speech_hint": 0.0,
        },
    )

    assert text == "fallback text"
    assert final_asr is app.asr
    assert retry_used is True
    assert retry_path == "fast-empty-primary-retry"
    assert decode_ms >= 0.0
    assert retry_ms >= 0.0
    assert app.asr_fast.calls == 1
    assert app.asr.calls == 1


def test_blank_fast_path_does_not_retry_for_non_speech_audio() -> None:
    app = _DummyApp(primary_text="should not be used", fast_text="")
    audio = np.zeros(16000, dtype=np.float32)

    text, final_asr, retry_used, retry_path, decode_ms, retry_ms = app._transcribe_with_fast_path_fallback(
        app.asr_fast,
        "fast",
        audio,
        audio_duration=1.0,
        raw_audio_duration=1.0,
        is_non_speech=True,
        non_speech_reason="likely_non_speech_burst",
        non_speech_metrics={
            "peak": 0.0,
            "rms": 0.0,
            "voiced_ratio": 0.0,
            "longest_voiced_seconds": 0.0,
            "speech_hint": 0.0,
        },
    )

    assert text == ""
    assert final_asr is app.asr_fast
    assert retry_used is False
    assert retry_path == "none"
    assert decode_ms >= 0.0
    assert retry_ms == 0.0
    assert app.asr_fast.calls == 1
    assert app.asr.calls == 0
