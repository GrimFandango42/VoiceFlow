"""Blank in, blank out — and words the user actually said always survive.

Regression tests for the silence-hallucination filter. The bug these exist to
prevent: the original patterns were built with `'thank you' * 2`, which is
"thank youthank you" with no space. Nothing ever matched, so every filter in
the list was dead code that looked like working protection.
"""

from __future__ import annotations

import pytest

from voiceflow.core.silence_artifacts import (
    DEFAULT_NO_SPEECH_THRESHOLD,
    REPEAT_HALLUCINATIONS,
    classify,
    is_repeat_hallucination,
    is_silence_artifact,
    longest_run,
    normalize,
    tokenize,
)

SILENT = 0.95   # decoder is sure there was no speech
SPOKEN = 0.02   # decoder is sure there was


class TestTheOriginalBug:
    def test_repeat_patterns_contain_spaces(self):
        # `'okay' * 3` would produce "okayokayokay". If this ever regresses,
        # every repeat filter silently stops matching.
        for pattern in REPEAT_HALLUCINATIONS:
            assert " " in pattern, (
                f"{pattern!r} has no spaces - string-multiplication bug is back"
            )

    def test_spaceless_concatenation_is_not_what_we_match(self):
        assert "thank youthank you" not in REPEAT_HALLUCINATIONS


class TestBlankInBlankOut:
    @pytest.mark.parametrize("text", ["", "   ", "\n", "\t "])
    def test_empty_stays_empty(self, text):
        suppress, reason = classify(text)
        assert suppress and reason == "empty"

    @pytest.mark.parametrize(
        "text",
        [
            "Thank you.",
            "thank you",
            "THANK YOU!",
            " Thank you ",
            "you",
            "Bye.",
            "Thanks for watching",
        ],
    )
    def test_silence_artifacts_suppressed_when_decoder_heard_nothing(self, text):
        suppress, reason = classify(text, no_speech_prob=SILENT)
        assert suppress, f"{text!r} should be suppressed on silent audio"
        assert reason == "silence_artifact_no_speech_prob"

    def test_non_speech_guard_alone_is_enough(self):
        suppress, reason = classify(
            "Thank you.", no_speech_prob=0.0, non_speech_suspected=True
        )
        assert suppress and reason == "silence_artifact_non_speech_guard"


class TestRealSpeechSurvives:
    def test_deliberate_thank_you_is_kept(self):
        # The whole point of gating on no_speech_prob. If someone dictates
        # "Thank you." we must not eat it.
        suppress, reason = classify("Thank you.", no_speech_prob=SPOKEN)
        assert not suppress
        assert reason == "silence_artifact_but_speech_detected"

    @pytest.mark.parametrize(
        "text",
        [
            "Thank you for the report, I'll review it tonight.",
            "Thanks for watching the deployment logs while I was out.",
            "You should check the Caddyfile first.",
            "Okay, so the next step is the migration runner.",
            "Bye week planning for the fantasy league.",
        ],
    )
    def test_longer_sentences_containing_artifact_words_survive(self, text):
        # Substring matching would destroy all of these.
        for prob in (SILENT, SPOKEN):
            suppress, _ = classify(text, no_speech_prob=prob)
            assert not suppress, f"{text!r} suppressed at no_speech_prob={prob}"

    def test_short_real_words_survive(self):
        for text in ("No.", "Yes", "Stop"):
            suppress, _ = classify(text, no_speech_prob=SPOKEN)
            assert not suppress


class TestRepeatLoops:
    @pytest.mark.parametrize(
        "text",
        [
            "okay okay okay",
            "Okay okay okay, that's it.",
            "thank you thank you",
            "you you you you",
            "bye bye bye",
        ],
    )
    def test_loops_suppressed_regardless_of_speech_evidence(self, text):
        # A loop is never legitimate dictation, so it does not need the
        # no_speech_prob gate.
        suppress, reason = classify(text, no_speech_prob=SPOKEN)
        assert suppress and reason == "repeat_hallucination"

    def test_single_okay_is_not_a_loop(self):
        assert not is_repeat_hallucination("okay")
        assert not is_repeat_hallucination("okay, moving on")


class TestThreshold:
    def test_boundary_is_inclusive(self):
        suppress, _ = classify("thank you", no_speech_prob=DEFAULT_NO_SPEECH_THRESHOLD)
        assert suppress

    def test_just_below_boundary_keeps_text(self):
        suppress, _ = classify(
            "thank you", no_speech_prob=DEFAULT_NO_SPEECH_THRESHOLD - 0.01
        )
        assert not suppress

    def test_threshold_is_overridable(self):
        suppress, _ = classify(
            "thank you", no_speech_prob=0.3, no_speech_threshold=0.25
        )
        assert suppress


class TestNormalize:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("  Thank  you.  ", "thank you"),
            ("THANK YOU!!!", "thank you"),
            ("...you...", "you"),
            ("", ""),
        ],
    )
    def test_normalize(self, raw, expected):
        assert normalize(raw) == expected

    def test_is_silence_artifact_is_exact_not_substring(self):
        assert is_silence_artifact("Thank you.")
        assert not is_silence_artifact("Thank you for everything")


class TestNoneAndGarbageInput:
    def test_none_no_speech_prob_defaults_safely(self):
        suppress, _ = classify("thank you", no_speech_prob=None)
        assert not suppress  # no evidence of silence -> keep the words


class TestPunctuatedLoops:
    """Whisper writes loops as "Okay. Okay. Okay." far more often than
    "okay okay okay". A substring test misses every one of them."""

    @pytest.mark.parametrize(
        "text",
        [
            "Okay. Okay. Okay.",
            "Okay, okay, okay.",
            "okay. okay. okay. okay. okay.",
            "Okay! Okay! Okay!",
            "Okay okay okay okay okay.",
            "okay okay",
            "Okay. Okay.",
        ],
    )
    def test_punctuation_separated_repeats_are_caught(self, text):
        suppress, reason = classify(text, no_speech_prob=SPOKEN)
        assert suppress, f"{text!r} not caught"
        assert reason == "repeat_hallucination"

    def test_the_substring_approach_would_have_missed_these(self):
        # Documents exactly why tokenize() exists.
        assert "okay okay okay" not in "okay. okay. okay."


class TestRepetitionInRealSpeech:
    """Emphatic repetition is not a decoder loop. Suppressing it would eat
    words the user said, which is worse than the bug being fixed."""

    @pytest.mark.parametrize(
        "text",
        [
            "No no no, use the other branch.",
            "Okay, so the next step is the migration runner.",
            "Yeah, that works.",
            "So we should ship it.",
            "Thank you for the report.",
            "Wait wait wait, back up a second.",
        ],
    )
    def test_repetition_surrounded_by_content_survives(self, text):
        for prob in (SILENT, SPOKEN):
            suppress, reason = classify(text, no_speech_prob=prob)
            assert not suppress, f"{text!r} eaten at no_speech_prob={prob} ({reason})"

    def test_dominance_is_what_separates_them(self):
        # Same word, same run length. Only the surrounding content differs.
        assert is_repeat_hallucination("okay okay okay")
        assert not is_repeat_hallucination("okay okay okay, let me think about it")

    def test_non_filler_repetition_needs_a_longer_run(self):
        # "no" was deliberately dropped from FILLER_TOKENS: people say it
        # three times in a row and mean it. It only trips the generic rule.
        assert not is_repeat_hallucination("no no no")
        assert is_repeat_hallucination("no no no no")


class TestObservedInProduction:
    """Exact strings from this user's own transcription history, all on
    0.9-2.6s of audio where nothing was actually said."""

    @pytest.mark.parametrize("text", ["Okay.", "So.", "Thank you."])
    def test_real_silence_artifacts_suppressed(self, text):
        suppress, _ = classify(text, no_speech_prob=SILENT)
        assert suppress


class TestTokenizeAndRun:
    def test_tokenize_drops_all_punctuation(self):
        assert tokenize("Okay. Okay, okay!") == ["okay", "okay", "okay"]

    def test_tokenize_empty(self):
        assert tokenize("") == []
        assert tokenize("...") == []

    @pytest.mark.parametrize(
        "tokens,expected",
        [
            (["a", "a", "a", "b"], ("a", 3)),
            (["a", "b", "b"], ("b", 2)),
            ([], ("", 0)),
            (["solo"], ("solo", 1)),
            (["a", "b", "a", "b"], ("a", 1)),
        ],
    )
    def test_longest_run(self, tokens, expected):
        assert longest_run(tokens) == expected
