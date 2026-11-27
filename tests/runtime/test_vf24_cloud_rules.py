"""VF-24 item 4: "cloud" becomes "Claude" only inside phrases that cannot mean a cloud.

And no route may create or apply a bare ``cloud -> Claude`` (or ``do it -> Duet``) rule:
not the adaptive learner (new or already on disk), not custom_vocabulary.txt, not a
review-queue approval, not a VF-17 promotion.
"""

from __future__ import annotations

import json

import pytest

from voiceflow.ai import hotword_learning as hw
from voiceflow.ai import review
from voiceflow.ai.adaptive_memory import AdaptiveLearningManager
from voiceflow.core import textproc, vocab
from voiceflow.core.config import Config
from voiceflow.core.rewrite_policy import is_unsafe_global_source
from voiceflow.core.textproc import normalize_context_terms


@pytest.fixture(autouse=True)
def _no_user_files(tmp_path, monkeypatch):
    monkeypatch.setenv("VOICEFLOW_VOCABULARY_PATH", str(tmp_path / "none.txt"))
    monkeypatch.setenv("VOICEFLOW_TERMS_PATH", str(tmp_path / "none.json"))


@pytest.mark.parametrize("aggressive", [False, True])
@pytest.mark.parametrize(
    ("heard", "expected"),
    [
        ("open cloud code and run the tests", "Claude Code"),
        ("I left it in cloud desktop", "Claude Desktop"),
        ("my cloud max plan renews today", "Claude Max"),
        ("my CloudMax plan renews today", "Claude Max"),
        ("we tried cloud duet yesterday", "Claude Duet"),
    ],
)
def test_product_phrases_become_claude(heard: str, expected: str, aggressive: bool) -> None:
    assert expected in normalize_context_terms(heard, aggressive=aggressive, light=True)


@pytest.mark.parametrize("aggressive", [False, True])
@pytest.mark.parametrize(
    "sentence",
    [
        "We deploy to Google Cloud and AWS.",
        "It is a cloud-based service.",
        "All the photos are stored in the cloud.",
        "The cloud side of the pipeline is slow.",
        "I use Claude Code to deploy to the cloud.",
        "Anthropic's cloud spend went up.",
        "Ask the coding assistant to check the cloud bill.",
        "Please do it now.",
    ],
)
def test_real_clouds_stay_clouds(sentence: str, aggressive: bool) -> None:
    out = normalize_context_terms(sentence, aggressive=aggressive, light=True)
    expected_claude = sentence.lower().count("claude")
    assert out.lower().count("claude") == expected_claude, out
    assert out.lower().count("cloud") == sentence.lower().count("cloud"), out
    if "do it" in sentence:
        assert "do it" in out.lower()


def test_policy_set() -> None:
    for unsafe in ("cloud", "Cloud", " CLOUDS ", "cloud's", "do it", "Do  it"):
        assert is_unsafe_global_source(unsafe)
    for safe in ("cloud max", "cloud code", "Jamelan", "doet", "do it now"):
        assert not is_unsafe_global_source(safe)


def _manager(tmp_path, monkeypatch) -> AdaptiveLearningManager:
    monkeypatch.setattr("voiceflow.ai.adaptive_memory.config_dir", lambda: tmp_path)
    cfg = Config(adaptive_learning_enabled=True, adaptive_user_correction_min_count=2)
    mgr = AdaptiveLearningManager(cfg)
    mgr._hotword_store = hw.LearnedHotwords(tmp_path / "learned_hotwords.json", min_count=2)
    return mgr


def test_learner_keeps_the_phrase_rule_and_drops_the_bare_one(tmp_path, monkeypatch) -> None:
    mgr = _manager(tmp_path, monkeypatch)
    for _ in range(2):
        mgr.observe("cloud max", "Claude Max", {"source": "manual_correction"})
    keys = set(mgr._patterns["replacements"])
    assert "cloud max->claude max" in keys
    assert "cloud->claude" not in keys
    assert mgr.apply("my cloud max plan") == "my Claude Max plan"
    assert mgr.apply("it is in the cloud") == "it is in the cloud"


def test_do_it_teaches_a_hotword_but_never_a_rewrite(tmp_path, monkeypatch) -> None:
    mgr = _manager(tmp_path, monkeypatch)
    for _ in range(3):
        mgr.observe("do it", "Duet", {"source": "manual_correction"})
    assert not any(k.startswith("do it->") for k in mgr._patterns["replacements"])
    assert mgr.apply("please do it now") == "please do it now"
    assert "Duet" in mgr._hotword_store.terms()


def test_bare_rule_already_on_disk_is_inert(tmp_path, monkeypatch) -> None:
    import time

    now = int(time.time())
    rule = {"from": "cloud", "to": "Claude", "count": 9, "score": 9.0, "first_seen": now,
            "last_seen": now, "sources": {"manual_correction": 9}}
    (tmp_path / "adaptive_patterns.json").write_text(
        json.dumps({"replacements": {"cloud->claude": rule}, "token_counts": {}, "updated_at": now}),
        encoding="utf-8",
    )
    mgr = _manager(tmp_path, monkeypatch)
    assert "cloud->claude" in mgr._patterns["replacements"]  # still on disk, untouched
    assert mgr.apply("store it in the cloud") == "store it in the cloud"


def test_unsafe_custom_vocabulary_line_is_ignored(tmp_path, monkeypatch) -> None:
    vf = tmp_path / "custom_vocabulary.txt"
    vf.write_text("cloud -> Claude\ndo it -> Duet\ncloud max -> Claude Max\njamelan -> Gemini\n", encoding="utf-8")
    monkeypatch.setenv("VOICEFLOW_VOCABULARY_PATH", str(vf))
    out = textproc._apply_technical_term_dictionary("do it in the cloud with cloud max and jamelan", False)
    assert out == "do it in the cloud with Claude Max and Gemini"


def test_unsafe_engineering_terms_exact_entry_is_ignored(tmp_path, monkeypatch) -> None:
    terms = tmp_path / "engineering_terms.json"
    terms.write_text(json.dumps({"exact": {"cloud": "Claude", "fast api": "FastAPI"}}), encoding="utf-8")
    monkeypatch.setenv("VOICEFLOW_TERMS_PATH", str(terms))
    out = textproc._apply_technical_term_dictionary("the fast api runs in the cloud", False)
    assert out == "the FastAPI runs in the cloud"


def test_review_approval_refuses_a_bare_cloud_rule(tmp_path, monkeypatch, capsys) -> None:
    vf = tmp_path / "custom_vocabulary.txt"
    monkeypatch.setattr(review, "_user_vocab_path", lambda: vf)
    recorded = []
    monkeypatch.setattr(review, "_record_in_adaptive_memory", lambda s, d: recorded.append((s, d)))
    review.append_suggestions(
        [{"type": "phrase_correction", "from": "cloud", "to": "Claude"},
         {"type": "phrase_correction", "from": "cloud max", "to": "Claude Max"}],
        source="test", base_dir=tmp_path,
    )
    review.cmd_approve("all", base_dir=tmp_path)
    text = vf.read_text(encoding="utf-8") if vf.exists() else ""
    assert "cloud max -> Claude Max" in text
    assert "cloud -> Claude" not in text.replace("cloud max -> Claude Max", "")
    assert recorded == [("cloud max", "Claude Max")]
    assert "ordinary English" in capsys.readouterr().out


def test_vf17_promotion_skips_a_bare_cloud_rule(tmp_path, monkeypatch) -> None:
    vf = tmp_path / "custom_vocabulary.txt"
    monkeypatch.setattr(vocab, "_user_vocab_path", lambda: vf)
    written = vocab.append_promoted_terms([("cloud", "Claude"), ("jamelan", "Gemini")])
    assert written == [("jamelan", "Gemini")]
    assert "cloud -> Claude" not in vf.read_text(encoding="utf-8")
