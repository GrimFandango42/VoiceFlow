"""VF-17 review round 4 (reviewed 41b5a56).

1. Guards must not permit meaning changes (negation, modality, certainty, frequency, causality; cat -> car via an ordinary word).
2. An async reconstruction's outcome is always logged, even when the paste fell back to the clipboard.
(3. the bundle verifier's DLL-check timeout lives in test_verify_bundle.py.)
"""

from __future__ import annotations

import re
import threading
from pathlib import Path

import pytest

from voiceflow.ai.reconstruction import INSERTABLE, ReconstructionOutcome, check_candidate
from voiceflow.ai.reconstruction_runtime import ReconstructionCoordinator
from voiceflow.core.config import Config

VOCAB = ["Claude Code", "PyInstaller", "faster-whisper", "Ollama", "VoiceFlow"]
PRE = "so i think we need twelve licenses and maya should send the budget to the team"
GOOD = "So I think we need twelve licenses, and maya should send the budget to the team."


def _reject(pre: str, cand: str, **kw):
    result = check_candidate(pre, cand, vocab_terms=kw.pop("vocab_terms", VOCAB), **kw)
    assert not result.ok, f"accepted a meaning change: {cand!r}"
    return result


# --- finding 1: insertions ---------------------------------------------------------------------------------------

def test_inserting_not_flips_polarity_and_is_rejected() -> None:
    _reject("I will ship today", "I will not ship today")


@pytest.mark.parametrize(
    "word", ["maybe", "always", "because", "should", "never", "definitely", "probably", "might", "must", "also", "not"]
)
def test_inserting_polarity_certainty_frequency_causality_or_modality_words_is_rejected(word: str) -> None:
    pre = "we will ship the release candidate on friday"
    result = _reject(pre, f"We will {word} ship the release candidate on friday.")
    assert result.reason in {"novel_content", "meaning_word_inserted"}, result


@pytest.mark.parametrize("word", ["maybe", "always", "because", "should"])
def test_the_four_reviewer_probes_with_the_exact_sentence(word: str) -> None:
    _reject("I will ship today", f"I will {word} ship today")


def test_a_vocabulary_entry_does_not_license_a_meaning_word() -> None:
    result = _reject("I will ship today", "I will not ship today", vocab_terms=["not", "Ollama"])
    assert result.reason == "meaning_word_inserted", result


def test_a_filler_cannot_be_turned_into_a_meaning_word() -> None:
    _reject("we will um ship the release on friday for sure", "We will not ship the release on friday for sure.")


def test_insertable_set_is_only_the_neutral_connectors() -> None:
    assert INSERTABLE == {"and", "to", "of"}


@pytest.mark.parametrize(
    "pre,cand",
    [
        ("we tested the build we shipped the build on friday", "We tested the build and we shipped the build on friday."),
        ("we really need go over the numbers before the meeting", "We really need to go over the numbers before the meeting."),
        ("there was a lot the work left after the demo", "There was a lot of the work left after the demo."),
    ],
)
def test_neutral_connector_repairs_are_still_accepted(pre: str, cand: str) -> None:
    result = check_candidate(pre, cand, vocab_terms=VOCAB)
    assert result.ok, f"{result.reason}: {result.detail}"


# --- finding 1: replacements -------------------------------------------------------------------------------------

def test_cat_to_car_via_an_ordinary_earlier_word_is_rejected() -> None:
    result = _reject("The cat and car are here. The cat is red.", "The cat and car are here. The car is red.")
    assert result.reason == "unsourced_replacement", result


def test_an_ordinary_word_elsewhere_in_the_utterance_is_not_a_replacement_source() -> None:
    result = _reject(
        "we met the bat and the bar owner then the bat flew off",
        "We met the bat and the bar owner, then the bar flew off.",
    )
    assert result.reason == "unsourced_replacement", result


def test_replacement_to_a_vocabulary_term_is_still_allowed() -> None:
    result = check_candidate("we run all llama on the cpu tonight", "We run ollama on the cpu tonight.", vocab_terms=["ollama"])
    assert result.ok, result


def test_replacement_to_a_name_used_earlier_is_still_allowed() -> None:
    result = check_candidate(
        "we run it on Kubernetes tonight and then cubernetes restarts the pods by itself",
        "We run it on Kubernetes tonight, and then Kubernetes restarts the pods by itself.",
        vocab_terms=VOCAB,
    )
    assert result.ok, f"{result.reason}: {result.detail}"


def test_replacement_to_a_code_token_used_earlier_is_still_allowed() -> None:
    result = check_candidate(
        "set the flag in max_retries then raise max retrys before the run",
        "Set the flag in max_retries, then raise max retries before the run.",
        vocab_terms=VOCAB,
    )
    assert result.ok, f"{result.reason}: {result.detail}"


# --- finding 2: async outcome is always recorded -----------------------------------------------------------------

class _FakeReconstructor:
    def __init__(self, outcome: ReconstructionOutcome | None = None) -> None:
        self.outcome = outcome

    def should_run(self, pre_text, *, code_mode=False, destination_profile=""):
        return True, ""

    def reconstruct(self, pre_text, raw_text="", *, context=(), timeout_s=None):
        return self.outcome or ReconstructionOutcome("accepted", text=GOOD, latency_ms=1.0)


def _coord(outcome: ReconstructionOutcome | None = None) -> ReconstructionCoordinator:
    cfg = Config()
    cfg.reconstruction_mode = "async"
    return ReconstructionCoordinator(cfg, _FakeReconstructor(outcome))  # type: ignore[arg-type]


def test_not_replaceable_paste_still_reports_the_outcome_but_offers_no_swap() -> None:
    """Focus drift -> clipboard fallback: nothing in the target window to swap, but the log must still close out."""
    coord = _coord()
    job = coord.begin(PRE)
    seen: list = []
    done = threading.Event()
    coord.attach_async(job, utterance_id="u", pasted_text=PRE, replaceable=False,
                       on_done=lambda outcome, usable: (seen.append((outcome.status, usable)), done.set()))
    assert done.wait(3)
    assert seen == [("accepted", False)]
    assert coord.take_pending() is None


@pytest.mark.parametrize("status,reason", [("rejected", "number_changed"), ("timeout", "llm_error"), ("failed", "llm_error")])
def test_rejection_and_timeout_are_reported_when_not_replaceable(status: str, reason: str) -> None:
    coord = _coord(ReconstructionOutcome(status, text="x", reason=reason))
    job = coord.begin(PRE)
    seen: list = []
    done = threading.Event()
    coord.attach_async(job, utterance_id="u", pasted_text=PRE, replaceable=False,
                       on_done=lambda outcome, usable: (seen.append((outcome.status, outcome.reason, usable)), done.set()))
    assert done.wait(3)
    assert seen == [(status, reason, False)]


def test_replaceable_default_is_unchanged() -> None:
    coord = _coord()
    job = coord.begin(PRE)
    done = threading.Event()
    coord.attach_async(job, utterance_id="u", pasted_text=PRE, on_done=lambda o, u: done.set())
    assert done.wait(3)
    pending = coord.take_pending()
    assert pending is not None and pending.improved_text == GOOD


def test_pipeline_attaches_the_outcome_callback_regardless_of_injection_success() -> None:
    """Guard the call site: attach must not be gated on inject_ok; only the replaceable flag may depend on it."""
    src = (Path(__file__).resolve().parents[2] / "src" / "voiceflow" / "ui" / "cli_enhanced.py").read_text(encoding="utf-8")
    m = re.search(r"if recon_job is not None and recon_outcome is None([^\n]*):\n\s+self\.reconstruction\.attach_async\(", src)
    assert m, "attach_async call site not found"
    assert "inject_ok" not in m.group(1), "attach is gated on inject_ok again"
    call = src[m.end():m.end() + 800]
    assert "replaceable=inject_ok" in call
