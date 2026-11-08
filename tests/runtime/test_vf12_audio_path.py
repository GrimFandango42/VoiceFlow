"""VF-12 items 1 + the end-of-utterance priority: what the audio path hands the decoder.

Measured with the synthetic oracle in ``vf12_synth`` -- word-loss in the audio path,
not acoustic WER (no model or real speech is available to the suite).
"""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import numpy as np
import pytest

import vf12_synth as syn
from voiceflow.core import audio_enhanced as audio_mod
from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
from voiceflow.core.config import Config
from voiceflow.core.segmenter import (
    decode_for_duration,
    find_speech_regions,
    pad_right_context,
    plan_segments,
    room_tone,
    transcribe_segmented,
)
from voiceflow.ui.cli_enhanced import EnhancedApp

SR = syn.SR


class _Compactor:
    _compact_pauses = EnhancedApp._compact_pauses

    def __init__(self, cfg):
        self.cfg = cfg


# ----------------------------------------------------------------- item 1: long dictation


def _long_dictation(seed: int = 3):
    rng = np.random.default_rng(seed)
    phrases, gaps = [], []
    wid = 0
    total = 0.0
    while total < 200.0:                         # > 3 minutes of recording
        n = int(rng.integers(3, 9))
        phrase = list(range(wid, wid + n))
        wid += n
        phrases.append(phrase)
        total += n * (syn.WORD_S + syn.WORD_GAP_S)
        if len(phrases) > 1:
            gap = float(rng.uniform(5.0, 20.0))  # thinking pauses
            gaps.append(gap)
            total += gap
    return syn.build(phrases, gaps, tail_s=0.5), phrases, gaps


def test_three_minute_dictation_with_long_pauses_loses_no_words():
    built, phrases, gaps = _long_dictation()
    assert len(built.audio) / SR > 180.0
    eng = syn.OracleEngine()
    cfg = Config()

    text = decode_for_duration(eng, built.audio, cfg)

    expected = [f"w{w}" for w in built.words]
    assert text.replace("\n\n", " ").split() == expected, "dropped, clipped or invented words"
    assert "Thank you" not in text


def test_silence_never_reaches_the_decoder_in_a_long_dictation():
    built, _, _ = _long_dictation()
    eng = syn.OracleEngine()
    decode_for_duration(eng, built.audio, Config())
    assert eng.calls, "no decode calls"
    # Every piece handed to the model is mostly speech, not a 5-20 s silence.
    assert min(v for _, v in eng.calls) > 0.15
    assert max(d for d, _ in eng.calls) <= Config().segment_max_seconds + 2.0


def test_long_pauses_become_paragraph_breaks():
    built, phrases, gaps = _long_dictation()
    text = decode_for_duration(syn.OracleEngine(), built.audio, Config())
    assert text.count("\n\n") == len(gaps)           # every 5-20 s pause is >= 2.5 s


def test_short_pauses_stay_in_the_same_paragraph():
    built = syn.build([[1, 2, 3], [4, 5], [6, 7, 8]], [1.0, 1.5], lead_s=0.3, tail_s=0.5)
    text = transcribe_segmented(syn.OracleEngine(), built.audio, Config()).text
    assert "\n\n" not in text
    assert text.split() == [f"w{i}" for i in range(1, 9)]


def test_hallucinated_filler_on_a_silent_piece_is_dropped_and_recorded():
    class _Hallucinating(syn.OracleEngine):
        def transcribe(self, audio):
            out = super().transcribe(audio)
            if len(self.calls) == 1:               # first piece: the model invents a sign-off
                self.last_no_speech_prob = 0.95
                return "Thank you."
            return out

    built = syn.build([[1, 2], [3, 4]], [6.0], tail_s=0.5)
    result = transcribe_segmented(_Hallucinating(), built.audio, Config())
    assert result.suppressed_count == 1
    assert "Thank you" not in result.text
    assert result.text.split() == ["w3", "w4"]


def test_a_real_thank_you_survives_when_speech_was_detected():
    class _Says(syn.OracleEngine):
        def transcribe(self, audio):
            super().transcribe(audio)
            self.last_no_speech_prob = 0.05
            return "Thank you."

    built = syn.build([[1, 2]], [], tail_s=0.5)
    assert transcribe_segmented(_Says(), built.audio, Config()).text == "Thank you."


def test_continuous_speech_longer_than_the_cap_is_cut_not_dropped():
    phrase = list(range(0, 90))                        # ~42 s with no pause
    built = syn.build([phrase], [], tail_s=0.5)
    plans = plan_segments(built.audio, SR, max_segment_seconds=25.0)
    assert len(plans) >= 2
    assert plans[0].start <= int(0.1 * SR) and plans[-1].end >= len(built.audio) - SR
    covered = sum(p.end - p.start for p in plans)
    assert covered >= len(built.audio) - SR          # nothing in the middle is skipped


def test_segments_are_contiguous_around_speech_and_never_overlap():
    built, _, _ = _long_dictation()
    plans = plan_segments(built.audio, SR)
    for a, b in zip(plans, plans[1:]):
        assert a.end <= b.start
    assert all(p.end > p.start for p in plans)


def test_detector_finding_no_speech_falls_back_to_a_whole_recording_decode():
    # Constant loud hum, no speech-like dynamics: nothing should be silently discarded.
    class _Echo(syn.OracleEngine):
        def transcribe(self, audio):
            self.calls.append((len(audio) / SR, 1.0))
            self.last_no_speech_prob = 0.0
            return "whole recording decoded"

    quiet_speaker = syn.noise(30.0, 9) * 0.0 + 1e-6
    eng = _Echo()
    result = transcribe_segmented(eng, quiet_speaker, Config(min_rms_amplitude=0.5))
    assert result.fallback_reason in {"no_speech_found", "too_little_speech"}
    assert result.text == "whole recording decoded"
    assert len(eng.calls) == 1 and eng.calls[0][0] > 30.0


def test_too_little_detected_speech_also_falls_back():
    built = syn.build([[1, 2]], [], lead_s=0.4, tail_s=40.0)      # 1 s of speech in 41 s
    class _Echo(syn.OracleEngine):
        def transcribe(self, audio):
            super().transcribe(audio)
            return "w1 w2"
    result = transcribe_segmented(_Echo(), built.audio, Config(segment_min_speech_fraction=0.2))
    assert result.fallback_reason == "too_little_speech"
    assert result.text == "w1 w2"


def test_normal_long_dictation_does_not_trigger_the_fallback():
    built, _, _ = _long_dictation()
    assert transcribe_segmented(syn.OracleEngine(), built.audio, Config()).fallback_reason == ""


def test_short_recordings_use_a_single_padded_decode():
    built = syn.build([[1, 2, 3]], [], tail_s=0.0)
    eng = syn.OracleEngine()
    text = decode_for_duration(eng, built.audio, Config())
    assert text == "w1 w2 w3"
    assert len(eng.calls) == 1
    assert eng.calls[0][0] > len(built.audio) / SR + 0.3   # right context was added


def test_find_speech_regions_ignores_clicks_and_merges_breaths():
    audio = syn.noise(3.0, 5)
    audio[8000:8400] += 0.4                            # 25 ms click
    word = syn._burst(3)
    audio[16000:16000 + len(word)] += word
    audio[16000 + len(word) + 1600:16000 + 2 * len(word) + 1600] += word    # 100 ms breath gap
    regions = find_speech_regions(audio, SR)
    assert len(regions) == 1


def test_room_tone_is_deterministic_and_not_digital_silence():
    a = room_tone(syn.noise(1.0, 1), SR, 0.4)
    b = room_tone(syn.noise(1.0, 1), SR, 0.4)
    np.testing.assert_array_equal(a, b)
    assert len(a) == int(0.4 * SR) and float(np.std(a)) > 0.0
    assert float(np.std(a)) < 0.02
    assert len(pad_right_context(np.zeros(0, dtype=np.float32), SR, 0.4)) == 0


# ------------------------------------------------------- end-of-utterance priority


class _Streams:
    def __call__(self, *a, **kw):
        return SimpleNamespace(start=lambda: None, stop=lambda: None, close=lambda: None)


def _tail_seconds_captured(drain_seconds: float, monkeypatch) -> float:
    """Press, speak, release; the mic keeps delivering real-time blocks. How much of
    the audio that arrives AFTER release makes it into the result?"""
    monkeypatch.setattr(audio_mod.sd, "InputStream", _Streams())
    rec = EnhancedAudioRecorder(Config(stop_drain_seconds=drain_seconds))
    rec.start_continuous()
    block = np.full((512, 1), 0.1, dtype=np.float32)
    for _ in range(40):
        rec._continuous_callback(block, 512, None, None)
    rec.start()
    for _ in range(40):
        rec._continuous_callback(block, 512, None, None)
    rec._capture.flush(audio_mod.CHANNEL_CONTINUOUS, 2.0)

    done = threading.Event()
    marker = np.full((512, 1), 0.5, dtype=np.float32)   # distinguishable post-release audio

    def mic():
        while not done.is_set():
            rec._continuous_callback(marker, 512, None, None)
            time.sleep(0.032)

    t = threading.Thread(target=mic, daemon=True)
    t.start()
    audio = rec.stop()
    done.set()
    t.join(timeout=1.0)
    rec.close()
    post = int(np.sum(np.isclose(audio, 0.5)))
    assert np.isclose(audio[:100], 0.1).all()   # the pre-recorded part is intact
    return post / SR


def test_recorder_keeps_listening_after_key_up(monkeypatch):
    captured = _tail_seconds_captured(Config().stop_drain_seconds, monkeypatch)
    assert captured >= 0.2, f"only {captured:.2f}s captured after release"


RELEASE_CONFIRM_S = 0.12   # hotkeys_enhanced: continuous key-up needed before a release counts


def default_tail_seconds(cfg: Config) -> float:
    """Mic time after key-up at default settings: release confirm + PTT tail buffer + stop drain."""
    return RELEASE_CONFIRM_S + cfg.ptt_tail_buffer_seconds + cfg.stop_drain_seconds


def test_post_key_up_capture_budget_meets_the_order():
    # VF-12 asked for >= 300-500 ms of capture after key-up. The listener + recorder already
    # deliver about 0.7 s; the order's first suspect (tail cut) is covered by existing code.
    assert default_tail_seconds(Config()) >= 0.5


def test_vf12_defaults():
    cfg = Config()
    assert cfg.decode_right_context_seconds >= 0.3
    assert cfg.pause_compaction_keep_silence_ms >= 200
    assert cfg.pause_compaction_tail_keep_ms >= 400
    assert cfg.latency_boost_tiny_max_audio_seconds <= 1.5


def _endings():
    """Utterance endings: questions and short final words, 8-12 s so compaction applies."""
    out = []
    for n_phrases, final_len in [(3, 1), (3, 3), (4, 2), (4, 4), (5, 1)]:
        phrases = [list(range(10 * i, 10 * i + 4)) for i in range(n_phrases - 1)]
        phrases.append(list(range(90, 90 + final_len)))
        out.append(syn.build(phrases, [1.0] * (n_phrases - 1), lead_s=0.3, tail_s=1.2))
    return out


OLD = dict(decode_right_context_seconds=0.0, pause_compaction_keep_silence_ms=80,
           pause_compaction_tail_keep_ms=0, segmented_transcription_enabled=False)
EARLY_MS = [0, 100, 200, 300, 400]   # how long before the word ends the key came up


def _end_errors(cfg_kwargs, release_early_ms, tail_s=None) -> tuple[int, int]:
    errors = total = 0
    for built in _endings():
        end = built.word_spans[-1][1]
        for early in release_early_ms:
            cfg = Config(**cfg_kwargs)
            tail = default_tail_seconds(cfg) if tail_s is None else tail_s
            release_idx = end - int(early / 1000.0 * SR)
            recorded = built.audio[: release_idx + int(tail * SR)]
            audio = _Compactor(cfg)._compact_pauses(recorded)
            toks = decode_for_duration(syn.OracleEngine(), audio, cfg).split()
            total += 1
            if not toks or toks[-1] != f"w{built.words[-1]}":
                errors += 1
    return errors, total


def test_end_of_utterance_word_loss_vs_tail_window(capsys):
    grid = {t: _end_errors({}, EARLY_MS, tail_s=t) for t in (0.0, 0.25, default_tail_seconds(Config()))}
    old_err, n = _end_errors(OLD, EARLY_MS)
    new_err, _ = _end_errors({}, EARLY_MS)
    with capsys.disabled():
        print("\n[VF-12] end-of-utterance word loss, synthetic audio path (final word cut when the "
              "key comes up 0-400 ms early):")
        for t, (e, total) in grid.items():
            print(f"        tail window {t:.2f}s after key-up -> {e}/{total} endings clipped")
        print(f"        default pipeline, old compaction/padding settings: {old_err}/{n}; new: {new_err}/{n}")
    assert grid[default_tail_seconds(Config())][0] == 0      # shipped defaults lose nothing
    assert grid[0.0][0] > 0                                  # and the fixture can see a clipped ending
    assert new_err == 0 and old_err == 0                     # no regression from compaction/padding changes


# --- review VF-12-review-codex-20261107-190306, finding 3 ---------------------------------

def test_pure_silence_fallback_does_not_emit_a_hallucinated_thank_you():
    class _Hallucinating(syn.OracleEngine):
        def transcribe(self, audio):
            self.calls.append((len(audio) / SR, 1.0))
            self.last_no_speech_prob = 0.93          # what Whisper reports for silence
            return "Thank you."

    silence = np.zeros(30 * SR, dtype=np.float32)
    result = transcribe_segmented(_Hallucinating(), silence, Config())
    assert result.fallback_reason == "no_speech_found"
    assert result.text == ""
    assert decode_for_duration(_Hallucinating(), silence, Config()) == ""


def test_room_tone_only_fallback_does_not_emit_a_hallucinated_thank_you():
    class _Hallucinating(syn.OracleEngine):
        def transcribe(self, audio):
            self.last_no_speech_prob = 0.9
            return "Thank you."

    tone = (syn.noise(30.0, 3) * 1e-4).astype(np.float32)
    assert decode_for_duration(_Hallucinating(), tone, Config()) == ""


def test_fallback_keeps_a_real_thank_you_when_the_decoder_heard_speech():
    class _Says(syn.OracleEngine):
        def transcribe(self, audio):
            self.last_no_speech_prob = 0.05
            return "Thank you."

    built = syn.build([[1, 2]], [], lead_s=0.4, tail_s=40.0)
    result = transcribe_segmented(_Says(), built.audio, Config(segment_min_speech_fraction=0.2))
    assert result.fallback_reason == "too_little_speech"
    assert result.text == "Thank you."
