from __future__ import annotations

import shutil
from pathlib import Path
from uuid import uuid4

from voiceflow.ai.adaptive_memory import AdaptiveLearningManager, extract_learning_pairs
from voiceflow.core.config import Config


def _test_dir(name: str) -> Path:
    path = Path("build") / "test-runtime" / f"{name}-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _manager(base_dir: Path, **config_overrides) -> AdaptiveLearningManager:
    cfg = Config(adaptive_store_raw_text=False, **config_overrides)
    manager = AdaptiveLearningManager(cfg)
    manager.audit_path = base_dir / "adaptive_audit.jsonl"
    manager.patterns_path = base_dir / "adaptive_patterns.json"
    manager._patterns = {
        "replacements": {},
        "token_counts": {},
        "updated_at": 0,
    }
    return manager


def test_user_corrections_reach_threshold_faster_than_auto_analysis():
    base_dir = _test_dir("adaptive-user-corrections")
    try:
        manager = _manager(base_dir, adaptive_min_count=3)

        manager.observe("jon", "john", {"source": "daily_user_correction"})
        assert manager.apply("jon is on the call") == "jon is on the call"

        manager.observe("jon", "john", {"source": "daily_user_correction"})
        assert manager.apply("jon is on the call") == "john is on the call"
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_auto_analysis_requires_more_repetition_before_auto_apply():
    base_dir = _test_dir("adaptive-auto-analysis")
    try:
        manager = _manager(base_dir, adaptive_min_count=3)

        for _ in range(5):
            manager.observe("terraforce", "terraform", {"source": "daily_auto_analysis"})
        assert manager.apply("terraforce plan") == "terraforce plan"

        manager.observe("terraforce", "terraform", {"source": "daily_auto_analysis"})
        assert manager.apply("terraforce plan") == "terraform plan"
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_snapshot_reports_weighted_rules_and_recent_domain_tokens():
    base_dir = _test_dir("adaptive-snapshot")
    try:
        manager = _manager(base_dir, adaptive_min_count=3)
        manager.observe(
            "send update to jon about terraform",
            "send update to john about terraform",
            {"source": "daily_user_correction"},
        )

        snapshot = manager.snapshot(max_rules=5, max_tokens=5)

        assert snapshot["activation_threshold"] == 3.0
        top_rule = snapshot["top_replacements"][0]
        assert top_rule["from"] == "jon"
        assert top_rule["to"] == "john"
        assert top_rule["score"] == 1.5
        assert top_rule["sources"]["daily_user_correction"] == 1
        assert any(item["token"] == "terraform" for item in snapshot["top_tokens"])
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_extract_learning_pairs_supports_short_phrases():
    pairs = extract_learning_pairs(
        "open cloud desktop for this review",
        "open Claude Desktop for this review",
        max_phrase_tokens=4,
    )
    assert ("cloud desktop", "Claude Desktop") in pairs


def test_phrase_rules_apply_before_single_token_rules():
    base_dir = _test_dir("adaptive-phrase-ordering")
    try:
        manager = _manager(base_dir, adaptive_min_count=1, adaptive_max_phrase_tokens=4)
        manager.observe("cloud", "Claude", {"source": "daily_user_correction"})
        manager.observe("cloud desktop", "Claude Desktop", {"source": "daily_user_correction"})
        assert manager.apply("open cloud desktop now") == "open Claude Desktop now"
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_low_value_contraction_drop_is_not_learned():
    base_dir = _test_dir("adaptive-low-value-contraction")
    try:
        manager = _manager(base_dir, adaptive_min_count=1)
        manager.observe("Let's", "Let", {"source": "runtime_transcription"})
        assert manager.apply("Let's start with the first item") == "Let's start with the first item"
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)
