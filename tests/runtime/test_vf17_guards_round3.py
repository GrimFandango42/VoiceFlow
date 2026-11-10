"""VF-17 review round 3 (reviewed b031340): guard holes found by independent probing.

1. A close spelling is not a licence to swap one thing for another (cat -> car).
2. Raw-ASR tokens are compared as multisets; spoken numbers and sentence-initial names count.
"""

from __future__ import annotations

import pytest

from voiceflow.ai.reconstruction import check_candidate, numeric_values

VOCAB = ["Claude Code", "PyInstaller", "faster-whisper", "Ollama", "VoiceFlow"]


def ok(pre: str, cand: str, **kw) -> None:
    result = check_candidate(pre, cand, vocab_terms=kw.pop("vocab_terms", VOCAB), **kw)
    assert result.ok, f"expected accept, got {result.reason}: {result.detail}"


def bad(pre: str, cand: str, reason: str, **kw) -> None:
    result = check_candidate(pre, cand, vocab_terms=kw.pop("vocab_terms", VOCAB), **kw)
    assert not result.ok, f"expected reject({reason}) but accepted: {cand!r}"
    assert result.reason == reason, f"rejected for {result.reason} ({result.detail}), wanted {reason}"


# --- finding 1 --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "pre,cand",
    [
        ("the cat is here and we should feed it soon", "The car is here and we should feed it soon."),
        ("please move the bat to the shed before dinner", "Please move the bar to the shed before dinner."),
        ("we heard the plan and then he left the room early", "We heard the plan and then she left the room early."),
        ("i think we can ship it on friday if the tests pass", "I think we cant ship it on friday if the tests pass."),
    ],
)
def test_semantic_swaps_that_are_a_letter_or_two_apart_are_rejected(pre: str, cand: str) -> None:
    result = check_candidate(pre, cand, vocab_terms=VOCAB)
    assert not result.ok, f"accepted a meaning change: {cand!r}"
    assert result.reason in {"unsourced_replacement", "rewritten", "inflection_changed"}, result


def test_cat_to_car_is_reported_as_an_unsourced_replacement() -> None:
    bad("the cat is here and we should feed it soon", "The car is here and we should feed it soon.", "unsourced_replacement")


def test_content_word_may_become_a_term_the_speaker_already_used_in_the_same_dictation() -> None:
    ok("we run it on kubernetes tonight and then cubernetes restarts the pods by itself",
       "We run it on kubernetes tonight, and then kubernetes restarts the pods by itself.")


def test_content_word_may_become_a_vocabulary_term_but_only_that() -> None:
    ok("we run all llama on the cpu tonight", "We run ollama on the cpu tonight.", vocab_terms=["ollama"])
    bad("we run all llama on the cpu tonight", "We run ollama on the cpu tonight.", "unsourced_replacement", vocab_terms=["Claude Code"])


def test_contractions_and_homophones_remain_allowed_function_word_respellings() -> None:
    ok("i think that is what we should do about the budget soon", "I think that's what we should do about the budget soon.")
    ok("i left their keys over there on the table after the meeting",
       "I left there keys over there on the table after the meeting.")


# --- finding 2 --------------------------------------------------------------------------------------------------

def _lost(raw: str, pre: str, cand: str) -> str:
    result = check_candidate(pre, cand, raw_text=raw, vocab_terms=VOCAB)
    assert not result.ok, f"accepted although something from the raw text was lost: {cand!r}"
    return result.reason + ":" + result.detail


def test_a_sentence_initial_name_cannot_be_dropped_or_respelled() -> None:
    raw = "Alice sent the notes to the team after lunch today"
    assert "raw_token_lost:alice" in _lost(raw, raw, "Alicia sent the notes to the team after lunch today.").lower()
    assert "raw_token_lost:alice" in _lost(raw, raw, "Sent the notes to the team after lunch today.").lower()
    ok(raw, "Alice sent the notes to the team after lunch today.", raw_text=raw)
    # a capitalised function word that merely opens the sentence is not a name
    plain = "The notes went to the team after lunch today"
    ok(plain, "The notes went to the team after lunch today.", raw_text=plain)


def test_the_pre_text_sentence_initial_name_is_protected_without_a_raw_text() -> None:
    pre = "Alice sent the notes to the team after lunch today"
    bad(pre, "Alicia sent the notes to the team after lunch today.", "proper_noun_lost")


def test_a_sentence_initial_word_folded_into_a_vocabulary_term_is_still_a_valid_repair() -> None:
    raw = "Pie installer is slow on the build server today"
    ok(raw, "PyInstaller is slow on the build server today.", raw_text=raw)


def test_a_spelled_number_in_the_raw_text_cannot_vanish() -> None:
    raw = "the shuttle leaves at nine and the lunch is catered on site"
    pre = "the shuttle leaves at and the lunch is catered on site"  # text processing lost it
    assert _lost(raw, pre, "The shuttle leaves at, and the lunch is catered on site.").startswith("raw_token_lost:9")
    # ...but its digit form is the same number
    ok("the shuttle leaves at 9 and the lunch is catered on site",
       "The shuttle leaves at 9, and the lunch is catered on site.", raw_text=raw)


def test_a_compound_spelled_number_is_compared_by_value() -> None:
    raw = "we have forty two seats on the bus for the trip"
    ok("we have 42 seats on the bus for the trip", "We have 42 seats on the bus for the trip.", raw_text=raw)
    assert _lost(raw, "we have seats on the bus for the trip", "We have seats on the bus for the trip.").startswith("raw_token_lost:42")


def test_one_of_two_occurrences_of_a_number_cannot_vanish() -> None:
    raw = "move 7 boxes to room 7 before noon today please"
    pre = "move 7 boxes to room before noon today please"
    assert _lost(raw, pre, "Move 7 boxes to room before noon today, please.").startswith("raw_token_lost:7")
    ok(raw, "Move 7 boxes to room 7 before noon today, please.", raw_text=raw)


def test_a_protected_token_that_occurs_twice_must_keep_both_occurrences() -> None:
    raw = "open main.py then compare it with main.py on the other branch"
    pre = "open main.py then compare it with on the other branch"
    assert _lost(raw, pre, "Open main.py, then compare it with on the other branch.").startswith("raw_token_lost:main.py")


@pytest.mark.parametrize(
    "text,expected",
    [
        ("nine", {"9": 1}),
        ("forty two", {"42": 1}),
        ("forty-two", {"42": 1}),
        ("42", {"42": 1}),
        ("two thousand twenty six", {"2026": 1}),
        ("one hundred and five", {"105": 1}),
        ("ten thirty", {"10": 1, "30": 1}),
        ("1,250 and 7%", {"1250": 1, "7": 1}),
        ("the one that got away", {}),
        ("seven or seven", {"7": 2}),
        ("the first half", {"first": 1, "half": 1}),
        ("see v3.2.1 and main.py on 9", {"9": 1}),
    ],
)
def test_numeric_values_normalise_spoken_and_typed_numbers(text: str, expected: dict) -> None:
    assert dict(numeric_values(text)) == expected
