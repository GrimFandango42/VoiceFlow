"""VF-17 item 4: guards on the reconstruction are enforced in code, not in the prompt.

A hallucinating model must lose to the guards, and the caller must then paste
the pre-reconstruction text unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from voiceflow.ai.reconstruction import (
    Reconstructor,
    check_candidate,
    parse_model_output,
    pick_reconstruction_model,
)

VOCAB = ["Claude Code", "PyInstaller", "faster-whisper", "Ollama", "VoiceFlow"]


def ok(pre: str, cand: str, **kw) -> None:
    result = check_candidate(pre, cand, vocab_terms=kw.pop("vocab_terms", VOCAB), **kw)
    assert result.ok, f"expected accept, got {result.reason}: {result.detail}"


def bad(pre: str, cand: str, reason: str, **kw) -> None:
    result = check_candidate(pre, cand, vocab_terms=kw.pop("vocab_terms", VOCAB), **kw)
    assert not result.ok, f"expected reject({reason}) but accepted: {cand!r}"
    assert result.reason == reason, f"rejected for {result.reason} ({result.detail}), wanted {reason}"


# --- what the pass is FOR: form repairs must get through -------------------

@pytest.mark.parametrize(
    "pre,cand",
    [
        ("so i was thinking we could move the review to thursday",
         "So, I was thinking we could move the review to Thursday."),
        ("we should send the notes and the the team the budget numbers",
         "We should send the notes and the team the budget numbers."),
        ("it works on my machine but not on the build server so check the log",
         "It works on my machine, but not on the build server, so check the log."),
        ("i need the report by friday and and then we can ship",
         "I need the report by Friday, and then we can ship."),
        # dropped function word restored
        ("send the draft maya after lunch", "Send the draft to Maya after lunch."),
        # phonetic repair toward a vocabulary term
        ("we build it with pie installer on the server", "We build it with PyInstaller on the server."),
    ],
)
def test_legitimate_form_repairs_are_accepted(pre: str, cand: str) -> None:
    ok(pre, cand)


def test_already_clean_text_is_accepted_as_is() -> None:
    ok("Send the notes to Maya on Friday.", "Send the notes to Maya on Friday.")


# --- the hallucinations the guards exist to stop ---------------------------

def test_changed_number_is_rejected() -> None:
    bad("the budget is 45 thousand dollars due in 3 weeks",
        "The budget is 54 thousand dollars due in 3 weeks.", "number_changed")


def test_dropped_number_is_rejected() -> None:
    bad("we need 12 licenses by next week for the team here",
        "We need licenses by next week for the team here.", "number_changed")


def test_spelled_number_changed_is_rejected() -> None:
    bad("we have three options and two of them are cheap",
        "We have four options and two of them are cheap.", "number_changed")


def test_invented_number_is_rejected() -> None:
    bad("we have options and some of them are cheap enough",
        "We have 4 options and some of them are cheap enough.", "number_changed")


def test_dropped_url_is_rejected() -> None:
    bad("open https://example.com/docs and read the install section",
        "Open the docs link and read the install section now.", "protected_token_lost")


def test_altered_path_is_rejected() -> None:
    bad(r"the log is at C:\Users\Nithin\logs\app.log if you want to look",
        r"The log is at C:\Users\Nithin\log\app.log if you want to look.", "protected_token_lost")


def test_respelled_code_identifier_is_rejected() -> None:
    bad("call get_user_name before you render the header please",
        "Call get user name before you render the header, please.", "protected_token_lost")


def test_camelcase_token_respelled_is_rejected() -> None:
    bad("the fix is in handleClick for the button component today",
        "The fix is in handle click for the button component today.", "protected_token_lost")


def test_file_extension_token_dropped_is_rejected() -> None:
    bad("edit config.json and then restart the service after that",
        "Edit the config and then restart the service after that.", "protected_token_lost")


def test_lost_proper_noun_is_rejected() -> None:
    bad("please ask Maya about the schedule before Friday arrives",
        "Please ask her about the schedule before Friday arrives.", "proper_noun_lost")


def test_respelled_proper_noun_is_rejected() -> None:
    bad("please ask Maya about the schedule before the review",
        "Please ask Mia about the schedule before the review.", "proper_noun_lost")


def test_invented_entity_is_rejected() -> None:
    bad("we should talk to the vendor about the contract soon enough",
        "We should talk to the vendor about the contract with Acme soon enough.", "new_entity",
        )


def test_invented_sentence_initial_entity_is_rejected() -> None:
    bad("we should talk to the vendor about the contract soon enough",
        "Jennifer said we should talk to the vendor about the contract soon enough.", "new_entity")


def test_invented_sentence_initial_name_same_length_is_rejected() -> None:
    bad("we should talk to the vendor about the new contract soon enough",
        "Jennifer should talk to the vendor about the new contract soon enough.", "new_entity")


def test_vocabulary_entity_is_allowed() -> None:
    ok("we build it with pie installer on the server", "We build it with PyInstaller on the server.")


def test_too_long_is_rejected() -> None:
    bad("send the notes to the team", "Send the notes to the team and make sure that everyone reads them carefully before Monday.", "word_ratio")


def test_too_short_is_rejected() -> None:
    bad("so we should send the notes to the whole team before the meeting starts",
        "Send the notes.", "word_ratio")


def test_ratio_boundaries_are_exact() -> None:
    pre = "one two three four five six seven eight nine ten"  # 10 words
    assert not check_candidate(pre, "a b c d e f g").ok  # 7 < 8
    assert check_candidate(pre, "alpha beta gamma delta epsilon zeta eta theta iota kappa").reason != "word_ratio"
    assert check_candidate(pre, " ".join(["x"] * 15)).reason == "word_ratio"  # 15 > 14


def test_invented_clause_without_numbers_or_names_is_rejected() -> None:
    bad("we should ship the release on schedule and tell everyone about it",
        "We should ship the release on schedule and tell everyone about it, which will definitely impress the board.",
        "word_ratio")
    bad("we should ship the release on schedule and tell everyone about it later today",
        "We should ship the release on schedule and tell everyone about the pricing later today.",
        "novel_content")


def test_empty_candidate_is_rejected() -> None:
    bad("send the notes to the team", "", "empty_output")


# --- end to end: a hallucinating model never reaches the paste --------------

@dataclass
class _Resp:
    text: str
    success: bool = True
    error: str | None = None
    model: str = "fake:1b"


class _FakeClient:
    model = "fake:1b"

    def __init__(self, reply: str, success: bool = True, error: str | None = None) -> None:
        self.reply, self.success, self.error = reply, success, error
        self.calls: list[dict] = []

    def generate(self, prompt, system=None, temperature=0.1, max_tokens=500, **kw):
        self.calls.append(dict(prompt=prompt, system=system, **kw))
        return _Resp(self.reply, self.success, self.error)


def _reconstructor(reply: str, **kw) -> tuple[Reconstructor, _FakeClient]:
    client = _FakeClient(reply, **kw)
    return Reconstructor(None, client_factory=lambda: client, vocab_provider=lambda: VOCAB), client


PRE = "so i think we need 12 licenses and maya should send the budget to the team by friday"


def test_hallucinating_model_is_rejected_and_pre_text_stands() -> None:
    rec, _ = _reconstructor("<out>So I think we need 15 licenses and Maya should send the budget to the team by Friday.</out>")
    outcome = rec.reconstruct(PRE)
    assert outcome.status == "rejected" and outcome.reason == "number_changed"
    assert not outcome.accepted


def test_good_reply_is_accepted() -> None:
    rec, client = _reconstructor("<out>So I think we need 12 licenses, and maya should send the budget to the team by Friday.</out>")
    outcome = rec.reconstruct(PRE)
    assert outcome.accepted
    assert outcome.text.startswith("So I think")
    # CPU only: the GPU belongs to Reachy.
    assert client.calls[0]["extra_options"]["num_gpu"] == 0


def test_unchanged_reply_is_not_an_improvement() -> None:
    rec, _ = _reconstructor(f"<out>{PRE}</out>")
    assert rec.reconstruct(PRE).status == "unchanged"


def test_llm_failure_and_timeout_are_not_accepted() -> None:
    rec, _ = _reconstructor("", success=False, error="Ollama not available")
    assert rec.reconstruct(PRE).status == "failed"
    rec, _ = _reconstructor("", success=False, error="timed out")
    assert rec.reconstruct(PRE).status == "timeout"


def test_exception_in_client_is_contained() -> None:
    def boom():
        raise RuntimeError("no model installed")

    rec = Reconstructor(None, client_factory=boom)
    outcome = rec.reconstruct(PRE)
    assert outcome.status == "failed" and not outcome.accepted


def test_chatty_reply_is_rejected() -> None:
    rec, _ = _reconstructor("I'm sorry, I cannot help with that request.")
    assert rec.reconstruct(PRE).status == "rejected"


# --- parsing + model choice --------------------------------------------------

def test_parse_strips_preamble_tags_and_quotes() -> None:
    assert parse_model_output("<out>Hello there.</out>") == "Hello there."
    assert parse_model_output("Here is the repaired text:\n\nHello there.") == "Hello there."
    assert parse_model_output('"Hello there."') == "Hello there."
    assert parse_model_output("<out>Hello there.") == "Hello there."
    assert parse_model_output("") == ""


def test_model_pick_skips_unsuitable_models() -> None:
    available = ["nomic-embed-text:latest", "qwen2.5-coder:1.5b-base", "deepseek-r1:14b", "qwen3:14b", "llama3.1:8b", "gemma3:12b"]
    assert pick_reconstruction_model(available) == "llama3.1:8b"
    assert pick_reconstruction_model(available + ["llama3.2:3b"]) == "llama3.2:3b"
    assert pick_reconstruction_model(["nomic-embed-text:latest"]) == ""
    assert pick_reconstruction_model(available, "gemma3") == "gemma3:12b"


def test_should_run_policy() -> None:
    rec = Reconstructor(None)
    assert rec.should_run(PRE) == (True, "")
    assert rec.should_run("ok thanks") == (False, "too_short")
    assert rec.should_run(PRE, code_mode=True) == (False, "destination_excluded")
    assert rec.should_run(PRE, destination_profile="terminal") == (False, "destination_excluded")
    assert rec.should_run("x " * 1500) == (False, "too_long")
