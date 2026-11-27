"""VF-24: a short dictation must come out once, not three or four times.

Covers the last-line guard in post-processing (``core/repeat_guard``).
"""

from __future__ import annotations

import pytest

from voiceflow.core.repeat_guard import DEFAULT_MAX_AUDIO_SECONDS, collapse_adjacent_repeats

SENTENCE = "Here's an example."


@pytest.mark.parametrize("copies", [2, 3, 4])
def test_adjacent_repeats_collapse_to_one(copies: int) -> None:
    text = " ".join([SENTENCE] * copies)
    out, removed = collapse_adjacent_repeats(text, 3.4)
    assert out == SENTENCE
    assert removed == copies - 1


def test_repeats_match_after_case_and_punctuation_are_normalised() -> None:
    out, removed = collapse_adjacent_repeats("Here's an example. here's an example! HERE'S AN EXAMPLE", 3.0)
    assert out == "Here's an example."
    assert removed == 2


def test_curly_apostrophe_counts_as_the_same_word() -> None:
    out, removed = collapse_adjacent_repeats("Here’s an example. Here's an example.", 3.0)
    assert removed == 1
    assert out == "Here’s an example."


def test_repeat_inside_a_longer_text_collapses_only_the_run() -> None:
    out, removed = collapse_adjacent_repeats("Okay. Send it today. Send it today. Thanks.", 4.0)
    assert out == "Okay. Send it today. Thanks."
    assert removed == 1


def test_loop_without_sentence_marks_collapses() -> None:
    out, removed = collapse_adjacent_repeats("Here's an example here's an example here's an example.", 3.5)
    assert out == "Here's an example."
    assert removed == 2


def test_loop_cut_off_mid_copy_collapses_with_its_tail() -> None:
    out, removed = collapse_adjacent_repeats("Let me check. Let me check. Let me", 3.0)
    assert out == "Let me check."
    assert removed == 2
    out, removed = collapse_adjacent_repeats("Let me check let me check let me", 3.0)
    assert out == "Let me check"
    assert removed == 2


def test_deliberate_double_one_word_answer_stays() -> None:
    """"No. No." in under a second of audio is two words said twice on purpose."""
    for text in ("No. No.", "No. No. No.", "Yes. Yes.", "ha ha ha ha"):
        out, removed = collapse_adjacent_repeats(text, 0.9)
        assert (out, removed) == (text, 0), text


def test_non_adjacent_repeats_stay() -> None:
    text = "Here's an example. Something else. Here's an example."
    assert collapse_adjacent_repeats(text, 4.0) == (text, 0)


def test_different_sentences_stay() -> None:
    text = "Here's an example. Here's another example."
    assert collapse_adjacent_repeats(text, 4.0) == (text, 0)


@pytest.mark.parametrize("seconds", [DEFAULT_MAX_AUDIO_SECONDS, 8.5, 30.0, 120.0])
def test_long_clips_are_untouched(seconds: float) -> None:
    text = " ".join([SENTENCE] * 3)
    assert collapse_adjacent_repeats(text, seconds) == (text, 0)


@pytest.mark.parametrize("seconds", [0, 0.0, -1.0, None, "n/a"])
def test_unknown_length_is_untouched(seconds) -> None:
    text = " ".join([SENTENCE] * 3)
    assert collapse_adjacent_repeats(text, seconds) == (text, 0)


def test_just_under_the_limit_is_guarded() -> None:
    text = " ".join([SENTENCE] * 2)
    assert collapse_adjacent_repeats(text, DEFAULT_MAX_AUDIO_SECONDS - 0.01) == (SENTENCE, 1)


def test_empty_and_plain_text_pass_through() -> None:
    assert collapse_adjacent_repeats("", 3.0) == ("", 0)
    assert collapse_adjacent_repeats("   ", 3.0) == ("   ", 0)
    assert collapse_adjacent_repeats("Thank you.", 1.2) == ("Thank you.", 0)


def test_a_question_repeated_keeps_its_question_mark() -> None:
    out, removed = collapse_adjacent_repeats("Can you open the file? Can you open the file?", 3.5)
    assert (out, removed) == ("Can you open the file?", 1)


def test_unchanged_text_is_returned_verbatim() -> None:
    text = "  Line one.\n\nLine two.  "
    assert collapse_adjacent_repeats(text, 3.0) == (text, 0)
