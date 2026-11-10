"""VF-17 item 1: the last word of a dictation must survive.

The recorder-side drain was fixed in VF-10. What remained deterministic and
reproducible on the base commit was in ``EnhancedApp._compact_pauses``: its
"blip" filter (speech runs shorter than 120 ms are zeroed) is meant for clicks
in the middle of a pause, but it also deleted a short, soft, unstressed final
word ("...end of the", "...is good", "...and that") that follows a pause,
because such a word is both quieter than the dynamic threshold and shorter than
the blip window.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import numpy as np
import pytest

from voiceflow.core.asr_engine import ASREngine, TranscriptionResult
from voiceflow.core.config import Config
from voiceflow.ui.cli_enhanced import EnhancedApp

SR = 16000


def _voiced(seconds: float, amp: float, f0: float = 140.0) -> np.ndarray:
    t = np.arange(int(seconds * SR)) / SR
    sig = sum(np.sin(2 * np.pi * f0 * k * t) / k for k in (1, 2, 3, 4))
    env = np.minimum(1.0, np.minimum(t, seconds - t) / 0.01)  # 10 ms edges
    return (amp * sig * env / 2.0).astype(np.float32)


def _word(seconds: float, amp: float, rng: np.random.Generator) -> np.ndarray:
    """A short unstressed word, modelled as an enveloped noise burst.

    Deliberately not periodic: a harmonic stand-in correlates ~1.0 with every
    other voiced stretch, which would make the survival check meaningless.
    """
    n = int(seconds * SR)
    t = np.arange(n) / SR
    env = np.minimum(1.0, np.minimum(t, seconds - t) / 0.01)
    return (amp * rng.standard_normal(n) * env).astype(np.float32)


def _noise(seconds: float, sigma: float, rng: np.random.Generator) -> np.ndarray:
    return (rng.standard_normal(int(seconds * SR)) * sigma).astype(np.float32)


def _long_dictation_with_soft_last_word(last_word_ms: int = 90, last_word_amp: float = 0.012):
    """~14 s clip: two loud phrases, a 6 s pause, then one short soft word.

    (Compaction refuses to run when it would remove >82% of the clip, so the
    fixture needs enough speech for the pause removal to be accepted.)

    Returns (audio, last_word_start_sample, last_word_end_sample); the word
    itself is ``audio[start:end]``.
    """
    rng = np.random.default_rng(17)
    sigma = 0.0004
    parts = [_noise(0.5, sigma, rng), _voiced(3.0, 0.25) + _noise(3.0, sigma, rng)]
    parts.append(_noise(1.0, sigma, rng))
    parts.append(_voiced(3.0, 0.22, f0=170.0) + _noise(3.0, sigma, rng))
    parts.append(_noise(6.0, sigma, rng))
    start = sum(len(p) for p in parts)
    word = _word(last_word_ms / 1000.0, last_word_amp, rng) + _noise(last_word_ms / 1000.0, sigma, rng)
    parts.append(word)
    end = start + len(word)
    parts.append(_noise(0.8, sigma, rng))  # key-release hangover
    return np.concatenate(parts).astype(np.float32), start, end


def _app(**overrides):
    cfg = Config()
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return SimpleNamespace(cfg=cfg)


def _contains(compacted: np.ndarray, template: np.ndarray, min_corr: float = 0.9) -> bool:
    """True when ``template`` appears (normalised cross-correlation) in ``compacted``.

    Compaction copies samples verbatim, so a surviving word correlates ~1.0.
    """
    n = len(template)
    if len(compacted) < n:
        return False
    size = 1 << int(np.ceil(np.log2(len(compacted) + n)))
    corr = np.fft.irfft(np.fft.rfft(compacted, size) * np.conj(np.fft.rfft(template, size)), size)[: len(compacted) - n + 1]
    csum = np.concatenate(([0.0], np.cumsum(compacted.astype(np.float64) ** 2)))
    window = np.sqrt(np.maximum(csum[n:] - csum[:-n], 1e-12))
    norm = window * float(np.sqrt(np.sum(template.astype(np.float64) ** 2)))
    return bool(np.max(corr / norm) >= min_corr)


def test_soft_short_final_word_survives_compaction() -> None:
    audio, a, b = _long_dictation_with_soft_last_word()
    compacted = EnhancedApp._compact_pauses(_app(), audio)

    assert len(compacted) < len(audio) * 0.75, "fixture must actually compact the 6 s pause"
    assert _contains(compacted, audio[a:b]), "final word was cut by pause compaction"


def test_legacy_behaviour_drops_the_final_word() -> None:
    """Documents the base-commit defect: tail protection off == old code path."""
    audio, a, b = _long_dictation_with_soft_last_word()
    compacted = EnhancedApp._compact_pauses(_app(pause_compaction_tail_protect_ms=0), audio)

    assert len(compacted) < len(audio) * 0.75
    assert not _contains(compacted, audio[a:b]), (
        "expected the legacy blip filter to remove the soft final word; if this "
        "starts passing, the fixture no longer reproduces the defect"
    )


@pytest.mark.parametrize("word_ms,amp", [(60, 0.012), (90, 0.010), (110, 0.015), (140, 0.008)])
def test_tail_retention_across_short_words(word_ms: int, amp: float) -> None:
    audio, a, b = _long_dictation_with_soft_last_word(word_ms, amp)
    compacted = EnhancedApp._compact_pauses(_app(), audio)
    assert _contains(compacted, audio[a:b])


def test_tail_protection_does_not_undo_pause_compaction() -> None:
    audio, _, _ = _long_dictation_with_soft_last_word()
    compacted = EnhancedApp._compact_pauses(_app(), audio)
    # 6 s of dead air must still go; we only keep the last 1.5 s of context.
    assert len(compacted) < 9.5 * SR


def test_quiet_noise_only_tail_is_not_treated_as_speech() -> None:
    rng = np.random.default_rng(3)
    audio = np.concatenate([
        _noise(0.5, 0.0004, rng),
        _voiced(3.0, 0.25),
        _noise(1.0, 0.0004, rng),
        _voiced(3.0, 0.22, f0=170.0),
        _noise(6.0, 0.0004, rng),
    ])
    compacted = EnhancedApp._compact_pauses(_app(), audio)
    # Only ~1.5 s of tail context + the phrases; not the whole 6 s pause.
    assert len(compacted) < 9.5 * SR


@dataclass
class _RecordingBackend:
    seen_len: int = 0

    def load(self) -> None:
        pass

    def is_loaded(self) -> bool:
        return True

    def cleanup(self) -> None:
        pass

    def transcribe(self, audio, **kwargs) -> TranscriptionResult:
        self.seen_len = len(audio)
        return TranscriptionResult(text="x", language="en", duration=len(audio) / SR, processing_time=0.01)


def test_asr_tail_pad_is_applied_when_configured_and_hidden_from_duration() -> None:
    engine = ASREngine(device="cpu", compute_type="int8")
    backend = _RecordingBackend()
    engine._backend = backend
    audio = _voiced(1.0, 0.1)

    engine.transcribe(audio)
    assert backend.seen_len == len(audio)  # default: no pad

    engine.tail_pad_ms = 400
    result = engine.transcribe(audio)
    assert backend.seen_len == len(audio) + int(0.4 * SR)
    assert result.duration == pytest.approx(1.0, abs=0.01)  # stats see real audio length


class _Seg:
    def __init__(self, text: str, start: float, end: float) -> None:
        self.text, self.start, self.end = text, start, end
        self.avg_logprob, self.no_speech_prob = -0.2, 0.01


def test_final_segment_is_consumed_not_left_in_the_generator() -> None:
    """The decode generator is lazy; a missed iteration would drop the last segment."""
    from voiceflow.core.asr_engine import FasterWhisperBackend, ModelConfig

    class _Model:
        def transcribe(self, audio, **kwargs):
            def gen():
                yield _Seg("we will finish", 0.0, 1.0)
                yield _Seg("the end of the", 1.0, 2.0)

            return gen(), SimpleNamespace(language="en")

    cfg = next(iter(__import__("voiceflow.core.asr_engine", fromlist=["MODEL_CONFIGS"]).MODEL_CONFIGS.values()))
    backend = FasterWhisperBackend(cfg)
    backend._model = _Model()
    result = backend.transcribe(np.zeros(SR * 2, dtype=np.float32))
    assert result.text.endswith("the end of the")
    assert len(result.segments) == 2
