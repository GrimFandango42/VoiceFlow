"""VF-24: engine-side decisions for a short dictation (tail lift gate, repetition guards, right-context pad)."""

from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

from voiceflow.core import asr_engine
from voiceflow.core.asr_engine import (
    ASREngine,
    FasterWhisperBackend,
    MODEL_CONFIGS,
    TranscriptionResult,
    should_lift_tail,
    short_clip_repetition_guards,
)
from voiceflow.core.config import Config
from voiceflow.core.segmenter import decode_audio, pad_right_context

SR = 16000


def _voiced(seconds: float, amp: float, f0: float = 140.0) -> np.ndarray:
    t = np.arange(int(seconds * SR)) / SR
    sig = sum(np.sin(2 * np.pi * f0 * k * t) / k for k in (1, 2, 3, 4))
    env = np.minimum(1.0, np.minimum(t, seconds - t) / 0.01)
    return (amp * sig * env / 2.0).astype(np.float32)


def _noise(seconds: float, sigma: float, rng: np.random.Generator) -> np.ndarray:
    return (rng.standard_normal(int(seconds * SR)) * sigma).astype(np.float32)


def _fading_clip(head_seconds: float) -> np.ndarray:
    """A loud phrase of ``head_seconds`` and a soft last word ~20 dB down: exactly what the tail lift acts on."""
    rng = np.random.default_rng(24)
    floor = 0.0004
    return np.concatenate([
        _noise(1.5, floor, rng),  # enough room tone that the clip's own noise floor is measurable
        _voiced(head_seconds, 0.25) + _noise(head_seconds, floor, rng),
        _noise(0.08, floor, rng),
        _voiced(0.5, 0.02, f0=190.0) + _noise(0.5, floor, rng),
        _noise(0.35, floor, rng),
    ]).astype(np.float32)


class _Spy:
    def __init__(self) -> None:
        self.audio = None

    def load(self) -> None:  # pragma: no cover - interface
        pass

    def is_loaded(self) -> bool:
        return True

    def cleanup(self) -> None:  # pragma: no cover - interface
        pass

    def transcribe(self, audio, **kwargs) -> TranscriptionResult:
        self.audio = audio
        return TranscriptionResult(text="x", language="en", duration=len(audio) / SR, processing_time=0.01)


def _engine(**attrs) -> tuple[ASREngine, _Spy]:
    engine = ASREngine(device="cpu", compute_type="int8")
    spy = _Spy()
    engine._backend = spy
    for key, value in attrs.items():
        setattr(engine, key, value)
    return engine, spy


# --- the tail lift decision ---------------------------------------------------------------------------

@pytest.mark.parametrize("seconds,expected", [(0.5, False), (3.4, False), (5.99, False), (6.0, True), (14.0, True)])
def test_should_lift_tail_by_clip_length(seconds: float, expected: bool) -> None:
    assert should_lift_tail(seconds) is expected


def test_should_lift_tail_switch_off_always_allows() -> None:
    assert should_lift_tail(1.0, skip_short=False) is True


def test_config_defaults_skip_the_lift_for_short_clips_and_guard_them() -> None:
    cfg = Config()
    assert cfg.asr_tail_lift_skip_short is True
    assert cfg.asr_tail_lift_min_clip_seconds == 6.0
    assert cfg.asr_short_clip_guards is True
    assert cfg.repeat_collapse_enabled is True
    assert cfg.repeat_collapse_max_seconds == 8.0
    assert cfg.asr_tail_lift_db == 9.0  # VF-17 stays on for longer dictations


def test_short_clip_reaches_the_backend_unlevelled_and_a_long_one_is_lifted() -> None:
    short = _fading_clip(2.0)  # ~3.3 s
    long = _fading_clip(7.0)   # ~8.3 s
    engine, spy = _engine(tail_lift_db=9.0, tail_lift_skip_short=True, tail_lift_min_clip_seconds=6.0)

    engine.transcribe(short)
    assert np.array_equal(spy.audio, short)

    engine.transcribe(long)
    assert not np.array_equal(spy.audio, long), "a long clip's faded tail is still levelled"
    n = len(long)
    assert np.array_equal(spy.audio[: n - 3 * SR], long[: n - 3 * SR])  # head untouched


def test_with_the_skip_switched_off_a_short_clip_is_lifted_as_before() -> None:
    short = _fading_clip(2.0)
    engine, spy = _engine(tail_lift_db=9.0, tail_lift_skip_short=False)
    engine.transcribe(short)
    assert not np.array_equal(spy.audio, short)


def test_a_bare_engine_keeps_the_old_behaviour() -> None:
    """Only ModernWhisperASR (built from a Config) turns the skip on; a bare ASREngine is unchanged."""
    short = _fading_clip(2.0)
    engine, spy = _engine(tail_lift_db=9.0)
    engine.transcribe(short)
    assert not np.array_equal(spy.audio, short)


# --- the pad -------------------------------------------------------------------------------------------

def test_no_extra_tail_pad_by_default_and_the_final_decode_adds_room_tone() -> None:
    """VF-17 measured the engine-side pad as no help; ``decode_audio`` already appends 0.4 s of room tone."""
    assert Config().asr_tail_pad_ms == 0
    clip = _fading_clip(2.0)
    engine, spy = _engine()
    decode_audio(engine, clip, Config())
    assert len(spy.audio) == len(clip) + int(0.4 * SR)
    assert np.array_equal(spy.audio[: len(clip)], clip)
    padded = pad_right_context(clip, SR, 0.4)
    tone = padded[len(clip):]
    assert 0 < float(np.sqrt(np.mean(tone ** 2))) < 0.01  # room tone, not digital silence and not speech


# --- the decode guards ----------------------------------------------------------------------------------

def test_guards_exist_only_for_short_clips() -> None:
    for seconds in (0.0, -1.0, 8.0, 8.5, 60.0):
        assert short_clip_repetition_guards(seconds) == {}
    guards = short_clip_repetition_guards(3.4)
    assert guards["no_repeat_ngram_size"] >= 3
    assert guards["compression_ratio_threshold"] < 2.4
    assert len(guards["temperature"]) >= 2 and guards["temperature"][0] == 0.0
    assert short_clip_repetition_guards(3.4, max_seconds=3.0) == {}


class _Seg:
    def __init__(self, text: str) -> None:
        self.text, self.start, self.end = text, 0.0, 1.0
        self.avg_logprob, self.no_speech_prob = -0.2, 0.01


def _backend(model, *, guards: bool, seconds: float = 8.0) -> FasterWhisperBackend:
    cfg = next(iter(MODEL_CONFIGS.values()))
    cfg = SimpleNamespace(**{**cfg.__dict__})
    cfg.short_clip_guards = guards
    cfg.short_clip_seconds = seconds
    cfg.vad_filter = False
    cfg.hotwords = ""
    backend = FasterWhisperBackend(cfg)
    backend._model = model
    return backend


class _AnyKwargsModel:
    def __init__(self) -> None:
        self.kwargs = {}

    def transcribe(self, audio, **kwargs):
        self.kwargs = kwargs
        return iter([_Seg("ok")]), SimpleNamespace(language="en")


def test_backend_passes_the_guards_to_a_short_final_decode() -> None:
    model = _AnyKwargsModel()
    _backend(model, guards=True).transcribe(np.zeros(int(3.4 * SR), np.float32))
    assert model.kwargs["no_repeat_ngram_size"] == 4
    assert model.kwargs["compression_ratio_threshold"] == 1.8
    assert model.kwargs["temperature"][0] == 0.0 and len(model.kwargs["temperature"]) == 3
    assert model.kwargs["condition_on_previous_text"] is False  # nothing else about the decode moved


def test_backend_leaves_long_clips_the_preview_path_and_a_disabled_switch_alone() -> None:
    model = _AnyKwargsModel()
    backend = _backend(model, guards=True)
    backend.transcribe(np.zeros(int(12.0 * SR), np.float32))
    assert "no_repeat_ngram_size" not in model.kwargs and model.kwargs["temperature"] == 0.0

    backend.transcribe(np.zeros(int(3.4 * SR), np.float32), beam_size_override=2, vad_filter_override=False)
    assert "no_repeat_ngram_size" not in model.kwargs  # live-caption partials are not the final pass

    off = _backend(model, guards=False)
    off.transcribe(np.zeros(int(3.4 * SR), np.float32))
    assert "no_repeat_ngram_size" not in model.kwargs and model.kwargs["temperature"] == 0.0


def test_backend_drops_a_guard_the_installed_faster_whisper_does_not_take() -> None:
    class _OldModel:
        seen: dict = {}

        def transcribe(self, audio, language=None, beam_size=1, best_of=1, temperature=0.0,
                       compression_ratio_threshold=2.4, condition_on_previous_text=False,
                       without_timestamps=True, vad_filter=False, initial_prompt=None):
            type(self).seen = {"temperature": temperature, "ratio": compression_ratio_threshold}
            return iter([_Seg("ok")]), SimpleNamespace(language="en")

    result = _backend(_OldModel(), guards=True).transcribe(np.zeros(int(3.4 * SR), np.float32))
    assert result.text == "ok"  # no TypeError for the missing no_repeat_ngram_size
    assert _OldModel.seen["ratio"] == 1.8


def test_helper_is_exported_for_the_probe() -> None:
    assert asr_engine.short_clip_repetition_guards is short_clip_repetition_guards
