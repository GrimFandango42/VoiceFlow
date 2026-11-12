"""VF-21: long dictations come out as paragraphs; an empty trigger pastes nothing.

Synthetic audio only (see ``vf12_synth``): no model, no microphone. The "decoder" returns
scripted sentences so the tests measure where breaks go, not word accuracy.
"""
from __future__ import annotations

import logging
import time
from types import SimpleNamespace

import pytest

import vf12_synth as syn
from voiceflow.core import segmenter as seg_mod
from voiceflow.core.config import Config
from voiceflow.core.history import TranscriptHistory, copy_text, failure_summary, menu_label
from voiceflow.core.segmenter import (
    count_sentences,
    decode_for_duration,
    find_speech_regions,
    last_dropped_text,
    last_empty_reason,
)
from voiceflow.core.silence_artifacts import classify
from voiceflow.core.textproc import auto_paragraphs
from voiceflow.ui.cli_enhanced import EnhancedApp

SR = syn.SR


class ScriptedEngine:
    """Returns the next scripted text per decode call."""

    def __init__(self, texts):
        self.texts = list(texts)
        self.calls = 0
        self.last_no_speech_prob = 0.05

    def transcribe(self, audio):
        text = self.texts[min(self.calls, len(self.texts) - 1)]
        self.calls += 1
        return text


def _phrase(n_words, start=0):
    return list(range(start, start + n_words))


def three_minute_fixture():
    """8 topic groups of five phrases (1 s breaths between phrases), 4 s pauses between groups."""
    phrases, gaps = [], []
    for g in range(8):
        for p in range(5):
            phrases.append(_phrase(7, start=g))
            gaps.append(4.0 if (p == 0 and g > 0) else 1.0)
    built = syn.build(phrases, gaps[1:])
    texts = [f"Topic {g + 1} starts here. It has a second sentence." for g in range(8)]
    return built.audio, texts


def _decode(audio, texts, cfg=None, vad="energy"):
    cfg = cfg or Config()
    engine = ScriptedEngine(texts)
    if vad == "energy":
        seg_mod_vad = lambda a, sr, cfg=None: None  # noqa: E731 -- no VAD evidence: energy gaps only
    else:
        seg_mod_vad = lambda a, sr, cfg=None: find_speech_regions(a, sr)  # noqa: E731 -- a VAD timeline
    orig = seg_mod.vad_speech_regions
    seg_mod.vad_speech_regions = seg_mod_vad
    try:
        return decode_for_duration(engine, audio, cfg, logging.getLogger("test")), engine
    finally:
        seg_mod.vad_speech_regions = orig


# ---------------------------------------------------------------- paragraphs


@pytest.mark.parametrize("vad", ["energy", "vad"])
def test_three_minute_dictation_breaks_at_its_long_pauses(vad):
    audio, texts = three_minute_fixture()
    assert len(audio) / SR > 170
    text, engine = _decode(audio, texts, vad=vad)
    paragraphs = text.split("\n\n")
    assert len(paragraphs) >= 2
    assert engine.calls == len(texts)
    # Breaks fall exactly at the 4 s pauses (between topic groups), not at the 1 s breaths.
    assert [p.split(" ")[0:2] for p in paragraphs] == [["Topic", str(g + 1)] for g in range(8)]
    assert " ".join(text.split()) == " ".join(" ".join(texts).split()), "words never change"


def test_two_sentence_dictation_never_gets_a_paragraph_break():
    # 27 s: long enough to be decoded pause by pause, with a 6 s pause in the middle.
    built = syn.build([_phrase(22), _phrase(22, 3)], [6.0])
    assert len(built.audio) / SR > 20
    text, _ = _decode(built.audio, ["First sentence here.", "Second sentence here."])
    assert "\n" not in text
    assert text.startswith("First sentence here.") and text.endswith("Second sentence here.")


def test_a_short_dictation_with_one_long_pause_stays_one_block():
    audio, texts = three_minute_fixture()
    text, _ = _decode(audio[: int(40 * SR)], ["One thought.", "Another thought."])
    assert "\n" not in text


def test_paragraphing_can_be_turned_off():
    audio, texts = three_minute_fixture()
    text, _ = _decode(audio, texts, cfg=Config(auto_paragraphs_enabled=False))
    assert "\n" not in text
    assert text.count("Topic") == 8


def test_auto_paragraphs_default_is_on():
    assert Config().auto_paragraphs_enabled is True
    assert Config().paragraph_min_sentences == 3


def test_count_sentences():
    assert count_sentences("") == 0
    assert count_sentences("One. Two! Three?") == 3
    assert count_sentences("no punctuation at all") == 1


def test_spoken_next_point_is_a_topic_shift():
    text = (
        "We reviewed the budget and it looks fine for the quarter overall. The vendors all confirmed their numbers "
        "last week. Nothing else is outstanding on that front for now, which is good news for everyone involved. "
        "Next point is the hiring plan for the team in the autumn. We need two engineers and a designer. "
        "The recruiter has a shortlist ready for us to review together before the end of the month."
    )
    shaped = auto_paragraphs(text)
    assert "\n\nNext point is the hiring plan" in shaped
    assert shaped.split() == text.split()


def test_list_formatting_is_untouched_by_paragraphing():
    listed = "Here is what I need:\n1. Speed.\n2. Accuracy.\n3. Quiet.\n\nThat is all."
    assert auto_paragraphs(listed) == listed


def test_formatting_time_per_dictation_is_under_5_ms():
    audio, texts = three_minute_fixture()
    text, _ = _decode(audio, texts)
    long_block = " ".join(texts * 3)
    assert count_sentences(long_block) >= 40
    runs = []
    for _ in range(20):
        t0 = time.perf_counter()
        auto_paragraphs(long_block)
        auto_paragraphs(text)
        count_sentences(text)
        classify(text, no_speech_prob=0.1)
        runs.append((time.perf_counter() - t0) * 1000.0)
    assert min(runs) < 5.0, runs


# ---------------------------------------------------------------- empty trigger


HALLUCINATIONS = [
    "Thank you.",
    "Thanks for watching!",
    "Thank you for watching.",
    "you",
    "Okay.",
    "Okay. Okay. Okay.",
    "Bye.",
    "Thank you. Thank you.",
    "Hmm.",
    "Please subscribe.",
    ".",
    "...",
]


def test_silence_pastes_nothing_and_decodes_nothing(monkeypatch):
    monkeypatch.setattr(seg_mod, "vad_speech_regions", lambda a, sr, cfg=None: [])
    for seconds in (3, 30):
        engine = ScriptedEngine(["Thank you."])
        audio = syn.noise(seconds, seed=4)
        assert decode_for_duration(engine, audio, Config()) == ""
        assert engine.calls == 0
        assert last_empty_reason() == "no_speech"


@pytest.mark.parametrize("phrase", HALLUCINATIONS)
def test_known_silence_hallucinations_over_a_sliver_of_speech_paste_nothing(monkeypatch, phrase):
    # VAD heard 0.3 s (a click, a breath); the decoder's own no-speech probability is low.
    monkeypatch.setattr(seg_mod, "vad_speech_regions", lambda a, sr, cfg=None: [(SR, SR + int(0.3 * SR))])
    engine = ScriptedEngine([phrase])
    assert decode_for_duration(engine, syn.noise(5, seed=5), Config()) == ""
    assert last_empty_reason() == "no_speech"
    if phrase.strip(" .") != "":
        assert last_dropped_text() == phrase.strip(), "what was thrown away stays recoverable"


def test_hallucinations_in_a_long_recording_with_no_speech_paste_nothing(monkeypatch):
    monkeypatch.setattr(seg_mod, "vad_speech_regions", lambda a, sr, cfg=None: None)
    for phrase in HALLUCINATIONS:
        engine = ScriptedEngine([phrase])
        # Energy detector fooled by loud room tone: whole recording decoded once, then classified.
        engine.last_no_speech_prob = 0.95
        assert decode_for_duration(engine, syn.noise(30, seed=6), Config()) == ""


def test_real_short_dictation_is_not_suppressed(monkeypatch):
    monkeypatch.setattr(seg_mod, "vad_speech_regions", lambda a, sr, cfg=None: [(SR, SR + int(2.0 * SR))])
    for said in ("Thank you.", "Thank you for sending the report.", "Okay, send it."):
        assert decode_for_duration(ScriptedEngine([said]), syn.noise(5, seed=7), Config()) == said
        assert last_empty_reason() == ""


def test_empty_attempt_is_recorded_in_history_and_stays_off_the_error_toast(tmp_path):
    history = TranscriptHistory(tmp_path / "h.json")
    app = SimpleNamespace(
        _log=logging.getLogger("test"),
        history=history,
        injector=SimpleNamespace(get_target_context=lambda: {"process_name": "notepad.exe"}),
        visual_indicators_enabled=False,
        _FAILURE_MIN_AUDIO_SECONDS=EnhancedApp._FAILURE_MIN_AUDIO_SECONDS,
        _QUIET_FAILURES=EnhancedApp._QUIET_FAILURES,
        _QUIET_FAILURE_MIN_AUDIO_SECONDS=EnhancedApp._QUIET_FAILURE_MIN_AUDIO_SECONDS,
    )
    EnhancedApp._history_fail(app, "no_speech", detail='dropped "Thank you."', audio_seconds=1.8)
    entries = history.recent()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["status"] == "failed" and entry["reason"] == "no_speech"
    assert "No speech was detected" in failure_summary(entry)
    assert 'dropped "Thank you."' in failure_summary(entry)
    assert copy_text(entry).startswith("VoiceFlow did not transcribe this")
    assert "No speech was detected" in menu_label(entry)
    # A stray tap (under a second) is logged but not an attempt worth listing.
    EnhancedApp._history_fail(app, "no_speech", audio_seconds=0.4)
    assert len(history.recent()) == 1
    assert history.last() is None, "re-paste never pastes an empty attempt"


# ------------------------------------------------- review round 1 (VF-21-review-claude-20261111-174446)


def _plans_with_cough(second_speech_start_s):
    """Speech 0-10 s, a cough 10.5-11.5 s (VAD hears nothing), then speech again."""
    from voiceflow.core.segmenter import SegmentPlan

    def s(x):
        return int(x * SR)

    plans = [
        SegmentPlan(start=0, end=s(10.2), gap_before_s=0.0),
        SegmentPlan(start=s(10.5), end=s(11.5), gap_before_s=1.0),  # energy-only blip
        SegmentPlan(start=s(second_speech_start_s - 0.2), end=s(20.0), gap_before_s=1.1),
    ]
    regions = [(0, s(10.0)), (s(second_speech_start_s), s(19.0))]
    return plans, regions, s(20.0)


def _run_plans(plans, regions, n_samples):
    import numpy as np

    # The cough piece is never decoded (VAD heard nothing), so only two replies are consumed.
    engine = ScriptedEngine(["First sentence. Second sentence.", "Third sentence."])
    result = seg_mod._decode_plans(
        engine, np.zeros(n_samples, dtype=np.float32), plans, Config(), logging.getLogger("test"),
        vad_regions=regions, min_vad_s=0.5,
    )
    return result.text


def test_a_cough_between_two_short_pauses_is_not_counted_twice():
    # Real silence is 2.1 s (< 2.5 s). The old code added the cough's energy gap (1.0 s) to the
    # next VAD gap (2.1 s, which already spans it) and broke the paragraph at 3.1 s.
    plans, regions, n = _plans_with_cough(12.1)
    text = _run_plans(plans, regions, n)
    assert "\n" not in text
    assert text.startswith("First sentence.") and text.endswith("Third sentence.")


def test_a_cough_does_not_hide_a_genuinely_long_pause():
    plans, regions, n = _plans_with_cough(13.5)  # 3.5 s of real silence
    assert _run_plans(plans, regions, n).split("\n\n")[-1] == "Third sentence."


def test_non_latin_transcripts_are_not_treated_as_empty():
    assert classify("नमस्ते दुनिया") == (False, "")
    assert classify("你好，世界。") == (False, "")
    assert classify("...") == (True, "empty")
    assert classify(" ,-— ") == (True, "empty")
