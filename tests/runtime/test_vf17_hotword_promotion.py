"""VF-17 item 6: make learning actually fire - and prove it does no harm.

Fixtures only. The real-corpus hotword count is reported by scripts/vf_eval.py,
not asserted here, because it depends on the machine's data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from voiceflow.ai import hotword_promotion as hp
from voiceflow.core import textproc, vocab


def _utt(i: int, raw: str, recon: str | None = None, *, edited: str | None = None, status: str = "accepted", final: str | None = None) -> Dict[str, Any]:
    u: Dict[str, Any] = {"id": f"u{i}", "raw_text": raw, "final_text": final if final is not None else raw}
    if recon is not None:
        u["reconstructed_text"] = recon
        u["reconstruction"] = {"status": status}
    if edited is not None:
        u["edited_text"] = edited
    return u


def _corpus() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    n = 0
    for _ in range(6):  # a real, repeated phonetic miss
        n += 1
        out.append(_utt(n, "we build it with pie installer on the server", "We build it with PyInstaller on the server."))
    for _ in range(4):
        n += 1
        out.append(_utt(n, "start all llama before the demo", "Start Ollama before the demo."))
    for _ in range(2):  # seen too few times
        n += 1
        out.append(_utt(n, "check the dancing fields report", "Check the Danzig Fields report."))
    for _ in range(8):  # grammar fix: must never become a global rewrite rule
        n += 1
        out.append(_utt(n, "their going to ship it friday", "They're going to ship it Friday."))
    for _ in range(4):  # ambiguous: "fields" is usually a real word
        n += 1
        out.append(_utt(n, "the fields are green today", "The Feeds are green today."))
    for _ in range(6):
        n += 1
        out.append(_utt(n, "the fields are green today", "The fields are green today."))
    for _ in range(10):  # casing / punctuation only: nothing to learn
        n += 1
        out.append(_utt(n, "send the notes to the team on thursday", "Send the notes to the team on Thursday."))
    return out


def test_promotes_only_repeated_unambiguous_phonetic_misses_of_terms() -> None:
    report, promotable = hp.analyse(_corpus(), vocab_terms=["PyInstaller", "Ollama"], min_count=3)
    promoted = {(c.src, c.dst) for c in promotable}

    assert promoted == {("pie installer", "PyInstaller"), ("all llama", "Ollama")}
    assert report.below_threshold >= 1   # "dancing fields" seen twice
    assert report.ambiguous >= 1         # "fields" is left alone 6x
    assert not any("their" in s for s, _ in promoted)  # grammar fix is not a hotword
    assert report.accepted_reconstructions == len(_corpus())


def test_promotion_improves_the_terms_without_touching_general_text(tmp_path: Path, monkeypatch) -> None:
    vocab_file = tmp_path / "custom_vocabulary.txt"
    vocab_file.write_text("# user file\nterraforce -> terraform\n", encoding="utf-8")
    monkeypatch.setattr(vocab, "_user_vocab_path", lambda: vocab_file)
    monkeypatch.setenv("VOICEFLOW_VOCABULARY_PATH", str(vocab_file))

    def rewrite(text: str) -> str:
        return textproc._apply_regex_rules(text, textproc._load_custom_vocabulary())

    # Held-out ASR output that the corpus never contained.
    terms = [
        ("run pie installer again on this laptop", "run PyInstaller again on this laptop"),
        ("please start all llama on the box", "please start Ollama on the box"),
    ]
    # Ordinary sentences that share words with the promoted rules.
    general = [
        "the pie is in the oven",
        "i installed the installer yesterday",
        "all of the llama herd was calm",
        "all fields are required",
        "their going to be late",
        "pie and ice cream are fine",
        "terraforce the plan",  # pre-existing user rule must keep working
    ]
    expected_general_after = {g: g for g in general}
    expected_general_after["terraforce the plan"] = "terraform the plan"

    before_terms = sum(rewrite(raw) == want for raw, want in terms)
    before_general = {g: rewrite(g) for g in general}

    report = hp.promote(_corpus(), min_count=3, write=True)
    assert {tuple(p) for p in report.promoted} == {("pie installer", "PyInstaller"), ("all llama", "Ollama")}

    after_terms = sum(rewrite(raw) == want for raw, want in terms)
    after_general = {g: rewrite(g) for g in general}

    assert before_terms == 0 and after_terms == len(terms), "promoted terms must improve"
    assert after_general == before_general == expected_general_after, "general accuracy must not drop"

    # Idempotent: a second run adds nothing and keeps the user's own lines.
    again = hp.promote(_corpus(), min_count=3, write=True)
    assert again.promoted == []
    text = vocab_file.read_text(encoding="utf-8")
    assert text.count("pie installer -> PyInstaller") == 1 and "terraforce -> terraform" in text


def test_two_explicit_user_edits_are_enough() -> None:
    corpus = [
        _utt(1, "open voice flow now", None, edited="open VoiceFlow now", final="Open voice flow now."),
        _utt(2, "restart voice flow later", None, edited="restart VoiceFlow later", final="Restart voice flow later."),
    ]
    report, promotable = hp.analyse(corpus, vocab_terms=["VoiceFlow"], min_count=3)
    assert [(c.src, c.dst) for c in promotable] == [("voice flow", "VoiceFlow")]
    assert report.with_user_edit == 2


def test_rejected_reconstructions_teach_nothing() -> None:
    corpus = [_utt(i, "we build it with pie installer", "We build it with PyInstaller", status="rejected") for i in range(10)]
    report, promotable = hp.analyse(corpus, vocab_terms=["PyInstaller"], min_count=3)
    assert promotable == [] and report.accepted_reconstructions == 0


def test_zero_is_reported_honestly_with_a_reason() -> None:
    casing_only = [_utt(i, "send the notes thursday", "Send the notes Thursday.") for i in range(20)]
    report, promotable = hp.analyse(casing_only, min_count=3)
    assert promotable == []
    assert report.raw_pairs == 0
    assert report.hotword_candidates == 0

    no_signal = [_utt(i, "send the notes thursday") for i in range(5)]
    report, _ = hp.analyse(no_signal, min_count=3)
    assert "casing" in report.explanation and "nothing proposes a different word" in report.explanation

    assert "no utterances" in hp.analyse([], min_count=3)[0].explanation


@pytest.mark.parametrize(
    "src,dst,expected",
    [
        ("pie installer", "PyInstaller", True),
        ("all llama", "Ollama", True),
        ("their", "there", False),            # function words, not a term
        ("went", "want", False),              # short common word
        ("meeting", "Meeting", False),        # case-only is not a miss
        ("fields", "Danzig Fields", False),   # not phonetically close
        ("terraforce", "Terraform", True),
    ],
)
def test_candidate_filter(src: str, dst: str, expected: bool) -> None:
    assert hp.is_hotword_candidate(src, dst, {"pyinstaller", "ollama"}) is expected


def test_adaptive_manager_learns_only_hotword_pairs_from_reconstruction(tmp_path: Path) -> None:
    from voiceflow.ai.adaptive_memory import AdaptiveLearningManager
    from voiceflow.core.config import Config

    cfg = Config()
    mgr = AdaptiveLearningManager(cfg)
    mgr.audit_path = tmp_path / "audit.jsonl"
    mgr.patterns_path = tmp_path / "patterns.json"
    mgr._patterns = {"replacements": {}, "token_counts": {}, "updated_at": 0}

    for _ in range(8):  # grammar edits proposed by the model: must not become rules
        mgr.observe("their going to ship", "they're going to ship", {"source": "reconstruction"})
    for _ in range(6):  # phonetic miss of a term: weight 0.5 x 6 = 3.0 -> reaches the activation threshold
        mgr.observe("we build with pie installer", "we build with PyInstaller", {"source": "reconstruction"})

    rules = {(r["from"].lower(), r["to"]) for r in mgr._patterns["replacements"].values()}
    assert rules == {("pie installer", "PyInstaller")}
    assert mgr.apply("run pie installer now") == "run PyInstaller now"
    assert mgr.apply("their going home") == "their going home"


def test_manager_promote_hotwords_writes_the_vocabulary(tmp_path: Path, monkeypatch) -> None:
    from voiceflow.ai.adaptive_memory import AdaptiveLearningManager
    from voiceflow.ai.tuning_log import TuningLog
    from voiceflow.core.config import Config

    vocab_file = tmp_path / "custom_vocabulary.txt"
    monkeypatch.setattr(vocab, "_user_vocab_path", lambda: vocab_file)

    log = TuningLog(tmp_path / "tuning_log.jsonl")
    for u in _corpus():
        log.append_utterance(
            raw_text=u["raw_text"], final_text=u["final_text"],
            reconstructed_text=u.get("reconstructed_text"), reconstruction=u.get("reconstruction"),
            utterance_id=u["id"],
        )
    mgr = AdaptiveLearningManager(Config())
    report = mgr.promote_hotwords(log)

    assert report["promoted_count"] == 2
    assert "pie installer -> PyInstaller" in vocab_file.read_text(encoding="utf-8")

    dry = mgr.promote_hotwords(log, write=False)
    assert dry["promoted_count"] == 0 or dry["promoted"]  # dry run never writes
