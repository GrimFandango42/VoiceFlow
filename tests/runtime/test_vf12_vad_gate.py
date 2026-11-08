"""VF-12 review finding 1: silence/noise must not become text, even when Whisper is confident.

Reproduced by the reviewer: 30 s of stationary noise decoded to "I think. Thank you." with
``no_speech_prob`` about 0.04, and the artifact classifier cannot catch it (4 words, and "i think
thank you" is not a known phrase). The gate is therefore text-independent: Silero VAD (bundled
with faster-whisper, offline) says whether there was speech at all, and nothing is decoded when
there was not. Spoken "Thank you." must survive.

Tests marked ``real_vad`` run the real Silero model on synthetic noise; they skip (not fail) only
if faster-whisper's VAD cannot load in the test interpreter.
"""
from __future__ import annotations

import wave
from pathlib import Path

import numpy as np
import pytest

import vf12_synth as syn
from voiceflow.core import segmenter as seg_mod
from voiceflow.core.config import Config
from voiceflow.core.segmenter import decode_for_duration, transcribe_segmented, vad_speech_regions

SR = 16000
CLIPS = Path(__file__).resolve().parents[2] / "build" / "vf12-real" / "clips"


class _Hallucinator:
    """What the reviewer observed: confident filler with a LOW no-speech probability."""

    def __init__(self, text="I think. Thank you.", no_speech=0.0377):
        self.text, self.last_no_speech_prob = text, no_speech
        self.calls: list[float] = []

    def transcribe(self, audio):
        self.calls.append(len(audio) / SR)
        return self.text


def _noise(seconds: float, std: float, seed: int) -> np.ndarray:
    return (np.random.default_rng(seed).standard_normal(int(seconds * SR)) * std).astype(np.float32)


def _real_vad_or_skip(audio):
    if vad_speech_regions(audio, SR, Config()) is None:
        pytest.skip("faster-whisper Silero VAD not loadable in this interpreter")


# ------------------------------------------------------------------ real Silero on noise

@pytest.mark.parametrize("std", [0.002, 0.01, 0.03])
def test_stationary_noise_with_low_no_speech_prob_yields_nothing_and_is_not_decoded(std):
    audio = _noise(30.0, std, seed=int(std * 1e4))
    _real_vad_or_skip(audio)
    eng = _Hallucinator()
    result = transcribe_segmented(eng, audio, Config())
    assert result.text == ""
    assert result.fallback_reason == "no_speech_vad"
    assert eng.calls == [], "audio VAD calls speechless must never reach the decoder"
    assert decode_for_duration(_Hallucinator(), audio, Config()) == ""


def test_digital_silence_and_room_tone_are_not_decoded_either():
    for audio in (np.zeros(30 * SR, dtype=np.float32), _noise(30.0, 1e-4, seed=3)):
        _real_vad_or_skip(audio)
        eng = _Hallucinator(no_speech=0.9)
        assert decode_for_duration(eng, audio, Config()) == ""
        assert eng.calls == []


def test_gate_can_be_switched_off_and_then_old_behaviour_applies():
    audio = _noise(30.0, 0.01, seed=5)
    eng = _Hallucinator()
    result = transcribe_segmented(eng, audio, Config(silence_vad_gate_enabled=False))
    assert result.fallback_reason == "no_speech_found"
    assert result.text == "I think. Thank you.", "documented degrade path: trusts the decoder as before"
    assert len(eng.calls) == 1


# ------------------------------------------------------------------ VAD says there IS speech

def _patch_vad(monkeypatch, regions):
    monkeypatch.setattr(seg_mod, "vad_speech_regions", lambda audio, sample_rate, cfg=None: regions)


def test_a_spoken_thank_you_in_a_long_noisy_recording_is_kept_and_only_that_part_is_decoded(monkeypatch):
    audio = _noise(30.0, 0.01, seed=8)
    _patch_vad(monkeypatch, [(12 * SR, int(12.8 * SR))])
    eng = _Hallucinator(text="Thank you.", no_speech=0.04)
    result = transcribe_segmented(eng, audio, Config())
    assert result.text == "Thank you."
    assert result.fallback_reason in {"no_speech_found", "too_little_speech"}
    assert len(eng.calls) == 1 and eng.calls[0] < 3.0, "must decode the speech region, not 30 s of noise"


def test_artifact_in_a_piece_with_almost_no_vad_speech_is_suppressed(monkeypatch):
    built = syn.build([[1, 2], [3, 4]], [6.0], tail_s=0.5)
    n = len(built.audio)
    # VAD only credits a 0.1 s sliver inside each piece: below the 0.25 s needed to trust a lone filler.
    _patch_vad(monkeypatch, [(int(0.5 * SR), int(0.6 * SR)), (n - 2 * SR, n - 2 * SR + int(0.1 * SR))])

    class _Says(syn.OracleEngine):
        def transcribe(self, audio):
            super().transcribe(audio)
            self.last_no_speech_prob = 0.04
            return "Thank you."

    result = transcribe_segmented(_Says(), built.audio, Config())
    assert result.text == ""
    assert {p.suppressed for p in result.pieces} <= {"silence_artifact_non_speech_guard", "vad_no_speech"}


def test_piece_with_no_vad_speech_is_skipped_without_decoding(monkeypatch):
    built = syn.build([[1, 2], [3, 4]], [6.0], tail_s=0.5)
    n = len(built.audio)
    # VAD credits only the SECOND phrase (the last ~2.5 s of the recording).
    _patch_vad(monkeypatch, [(n - int(2.5 * SR), n - int(0.5 * SR))])
    eng = syn.OracleEngine()
    result = transcribe_segmented(eng, built.audio, Config())
    assert len(eng.calls) == 1, "the piece VAD never heard must not reach the decoder"
    assert result.suppressed_count == 1
    assert [p.suppressed for p in result.pieces][0] == "vad_no_speech"


def test_real_sentence_after_a_noise_burst_is_not_lost(monkeypatch):
    built = syn.build([[1, 2], [3, 4]], [6.0], tail_s=0.5)
    n = len(built.audio)
    _patch_vad(monkeypatch, [(0, n)])        # VAD hears speech everywhere: nothing may be skipped
    result = transcribe_segmented(syn.OracleEngine(), built.audio, Config())
    assert result.text.replace("\n\n", " ").split() == ["w1", "w2", "w3", "w4"]


# ------------------------------------------------------------------ VAD unavailable

def test_vad_unavailable_falls_back_to_the_previous_classifier_path_without_crashing(monkeypatch):
    _patch_vad(monkeypatch, None)
    silence = np.zeros(30 * SR, dtype=np.float32)

    class _Silent(_Hallucinator):
        pass

    eng = _Silent(text="Thank you.", no_speech=0.93)
    result = transcribe_segmented(eng, silence, Config())
    assert result.text == "", "no_speech_prob evidence still suppresses a lone artifact"
    assert result.fallback_reason == "no_speech_found"
    assert len(eng.calls) == 1


def test_vad_import_failure_degrades_and_warns_once(monkeypatch, caplog):
    import builtins

    real_import = builtins.__import__

    def _no_vad(name, *a, **k):
        if name.startswith("faster_whisper.vad"):
            raise ImportError("simulated: onnxruntime missing")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _no_vad)
    monkeypatch.setattr(seg_mod, "_vad_warned", False)
    audio = _noise(2.0, 0.01, seed=1)
    with caplog.at_level("WARNING"):
        assert vad_speech_regions(audio, SR, Config()) is None
        assert vad_speech_regions(audio, SR, Config()) is None
    assert sum("silence_vad_unavailable" in r.message for r in caplog.records) == 1


def test_non_16k_audio_is_not_sent_to_silero():
    assert vad_speech_regions(np.zeros(8000, dtype=np.float32), 8000, Config()) is None


# ------------------------------------------------------------------ real speech (SAPI clips, if generated)

def _load(clip: str) -> np.ndarray:
    with wave.open(str(CLIPS / f"{clip}.wav"), "rb") as w:
        rate = w.getframerate()
        x = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2").astype(np.float32) / 32768.0
    if rate != SR:
        x = np.interp(np.arange(int(len(x) * SR / rate)) * (rate / SR), np.arange(len(x)), x).astype(np.float32)
    return x


@pytest.mark.skipif(not (CLIPS / "t01.wav").exists(), reason="run scripts/vf12_make_tts_clips.py first")
def test_real_spoken_thank_you_survives_in_30s_of_noise_and_the_noise_alone_does_not():
    noise = _noise(30.0, 0.01, seed=21)
    _real_vad_or_skip(noise)
    clip = _load("t01")
    spoken = noise.copy()
    spoken[12 * SR:12 * SR + len(clip)] += clip

    eng = _Hallucinator(text="Thank you.", no_speech=0.04)
    assert decode_for_duration(eng, spoken, Config()) == "Thank you.", "genuinely spoken words must be kept"
    assert len(eng.calls) == 1

    eng2 = _Hallucinator(text="Thank you.", no_speech=0.04)
    assert decode_for_duration(eng2, noise, Config()) == ""
    assert eng2.calls == []
