"""VF-17 review round 5 (reviewed a12e69e): reconstruction could still invent meaning.

A vocabulary term may only REPLACE a word that was actually transcribed and is a close spelling/phonetic match; it is
never inserted on its own. A sentence-initial word is protected from being lost, but its position-only capital does not
make it a name that licenses a later replacement. The reviewer's three probes are pinned verbatim.
"""

from __future__ import annotations

import pytest

from voiceflow.ai.reconstruction import check_candidate

VOCAB = ["Claude Code", "PyInstaller", "faster-whisper", "Ollama", "VoiceFlow"]


def _reject(pre: str, cand: str, *, vocab_terms=VOCAB, raw_text: str = ""):
    result = check_candidate(pre, cand, raw_text=raw_text, vocab_terms=vocab_terms)
    assert not result.ok, f"accepted a meaning change: {pre!r} -> {cand!r}"
    return result


# --- the reviewer's probes, verbatim ------------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["", "Car is ready. The cat is red."])
def test_probe_car_is_ready_cat_does_not_become_car(raw: str) -> None:
    result = _reject("Car is ready. The cat is red.", "Car is ready. The car is red.", raw_text=raw)
    assert result.reason == "unsourced_replacement", result


@pytest.mark.parametrize("cand", ["Ship the build today. the ship is broken.", "Ship the build today. The ship is broken."])
def test_probe_ship_the_build_chip_does_not_become_ship(cand: str) -> None:
    result = _reject("Ship the build today. The chip is broken.", cand, raw_text="Ship the build today. The chip is broken.")
    assert result.reason == "unsourced_replacement", result


@pytest.mark.parametrize("vocab", [["Claude"], VOCAB + ["Claude"]])
def test_probe_vocabulary_term_is_never_inserted(vocab) -> None:
    result = _reject("we will send it today", "We will send it to Claude today.", vocab_terms=vocab, raw_text="we will send it today")
    assert result.reason == "vocab_inserted", result


# --- variants of the same holes -----------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "pre,cand",
    [
        ("we will send it today", "We will send it today Claude."),          # appended at the tail
        ("we will send it today", "Claude we will send it today."),          # prepended
        ("we will send it today", "We will send it to Ollama today."),       # any vocabulary term
        ("we will send it today", "We will send Claude it today."),
    ],
)
def test_no_vocabulary_term_can_be_inserted_anywhere(pre: str, cand: str) -> None:
    _reject(pre, cand, vocab_terms=["Claude", "Ollama"])


def test_a_replacement_cannot_smuggle_in_an_extra_word() -> None:
    # "cloud" -> "to Claude" is spelling-close as a joined string; it is still an insertion of "to Claude".
    result = _reject("we will push the cloud build today", "We will push the to Claude build today.", vocab_terms=["Claude"])
    assert result.reason in {"vocab_inserted", "novel_content"}, result


def test_a_sentence_initial_content_word_never_licenses_a_later_replacement() -> None:
    _reject("Bat is in the shed. The bar is open late.", "Bat is in the shed. The bat is open late.")


# --- legitimate repairs that must still pass ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "pre,cand,vocab",
    [
        ("we run all llama on the cpu tonight", "We run ollama on the cpu tonight.", ["ollama"]),
        ("we will send it to clawed today", "We will send it to Claude today.", ["Claude"]),
        ("the pie installer build is slow today", "The PyInstaller build is slow today.", VOCAB),
        ("we tested the build we shipped the build on friday", "We tested the build and we shipped the build on friday.", VOCAB),
    ],
)
def test_vocabulary_replacement_of_a_spoken_source_is_still_accepted(pre: str, cand: str, vocab) -> None:
    result = check_candidate(pre, cand, vocab_terms=vocab)
    assert result.ok, f"{result.reason}: {result.detail}"


def test_a_sentence_initial_name_is_still_protected_from_loss() -> None:
    pre = "Alice sent the notes. The team read them after lunch"
    result = _reject(pre, "Alicia sent the notes. The team read them after lunch.", raw_text=pre)
    assert result.reason in {"raw_token_lost", "proper_noun_lost"}, result


def test_a_mid_sentence_name_is_still_a_replacement_source() -> None:
    result = check_candidate(
        "we run it on Kubernetes tonight and then cubernetes restarts the pods by itself",
        "We run it on Kubernetes tonight, and then Kubernetes restarts the pods by itself.",
        vocab_terms=VOCAB,
    )
    assert result.ok, f"{result.reason}: {result.detail}"
