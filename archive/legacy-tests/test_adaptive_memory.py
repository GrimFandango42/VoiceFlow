from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
src_path = str(SRC)
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)
if "voiceflow" in sys.modules and not hasattr(sys.modules["voiceflow"], "__path__"):
    del sys.modules["voiceflow"]

from voiceflow.ai.adaptive_memory import AdaptiveLearningManager


def _cfg(**overrides):
    base = {
        "adaptive_learning_enabled": True,
        "adaptive_store_raw_text": False,
        "adaptive_retention_hours": 72,
        "adaptive_min_count": 2,
        "adaptive_max_rules": 200,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_adaptive_learning_applies_after_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr("voiceflow.ai.adaptive_memory.config_dir", lambda: tmp_path)
    manager = AdaptiveLearningManager(_cfg(adaptive_min_count=2))

    manager.observe("send to jon", "send to john", {})
    assert manager.apply("send to jon") == "send to jon"

    manager.observe("send to jon", "send to john", {})
    assert manager.apply("send to jon") == "send to john"


def test_adaptive_audit_log_is_redacted_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr("voiceflow.ai.adaptive_memory.config_dir", lambda: tmp_path)
    manager = AdaptiveLearningManager(_cfg(adaptive_store_raw_text=False))

    manager.observe("raw phrase", "clean phrase", {"model_tier": "quick"})

    lines = manager.audit_path.read_text(encoding="utf-8").strip().splitlines()
    event = json.loads(lines[-1])
    assert "raw_text" not in event
    assert "final_text" not in event
    assert event["raw_hash"]
    assert event["final_hash"]


def test_adaptive_purges_expired_events_and_rules(tmp_path, monkeypatch):
    monkeypatch.setattr("voiceflow.ai.adaptive_memory.config_dir", lambda: tmp_path)
    manager = AdaptiveLearningManager(_cfg(adaptive_retention_hours=1))

    now = int(time.time())
    manager._patterns["replacements"] = {
        "old->new": {"from": "old", "to": "new", "count": 9, "last_seen": now - 7200},
        "stay->keep": {"from": "stay", "to": "keep", "count": 3, "last_seen": now - 300},
    }
    manager._save_patterns()

    manager.audit_path.write_text(
        "\n".join(
            [
                json.dumps({"ts": now - 8000, "raw_hash": "a", "final_hash": "b"}),
                json.dumps({"ts": now - 10, "raw_hash": "c", "final_hash": "d"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    manager._purge_expired()

    assert "old->new" not in manager._patterns["replacements"]
    assert "stay->keep" in manager._patterns["replacements"]

    remaining = [json.loads(line) for line in manager.audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(remaining) == 1
    assert remaining[0]["raw_hash"] == "c"
