"""VF-03: with a default config, the nightly batch never selects a cloud client
and the report says so in the product's own words (``enabled: false``,
``error: disabled``). This is the automated twin of the manual acceptance
check in ``_relay/orders/VF-01-findings.md`` step 4.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from voiceflow.ai.daily_learning import DailyLearningJob
from voiceflow.core.config import Config


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_default_config_never_calls_a_cloud_client(monkeypatch):
    base_dir = Path("build") / "test-runtime" / f"daily-learning-opt-in-{uuid4().hex}"
    base_dir.mkdir(parents=True, exist_ok=True)
    try:
        yesterday_epoch = (datetime.now() - timedelta(days=1)).timestamp()
        _write_jsonl(
            base_dir / "recent_history_events.jsonl",
            [
                {
                    "event_epoch": yesterday_epoch,
                    "audio_duration": 4.0,
                    "full_text": "this sentence must stay on this machine",
                }
            ],
        )

        def _explode():
            raise AssertionError(
                "select_client() was called with cloud analysis disabled"
            )

        monkeypatch.setattr("voiceflow.ai.daily_learning.select_client", _explode)

        cfg = Config(
            adaptive_min_count=1, adaptive_store_raw_text=False
        )  # defaults otherwise
        assert cfg.adaptive_ai_analysis_enabled is False
        report = DailyLearningJob(cfg=cfg, base_dir=base_dir).run(
            days_back=1, dry_run=False
        )

        analysis = report["ai_learning_analysis"]
        assert analysis["enabled"] is False
        assert analysis["error"] == "disabled"
        assert analysis["backend"] == ""
        assert analysis["success"] is False
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


# --- one-time consent migration for configs written before the toggle existed


def _legacy_config(base_dir: Path, **extra) -> Path:
    config_file = base_dir / "config.json"
    payload = {
        "model_tier": "quick",
        "device": "cpu",
        "compute_type": "int8",
        "setup_completed": True,
        "setup_flow_version": 3,
        "adaptive_ai_analysis_enabled": True,  # old default, never consented to
    }
    payload.update(extra)
    config_file.write_text(json.dumps(payload), encoding="utf-8")
    return config_file


def test_legacy_config_with_cloud_flag_on_is_reset_once(monkeypatch):
    from voiceflow.utils import settings as settings_mod

    base_dir = Path("build") / "test-runtime" / f"consent-migration-{uuid4().hex}"
    base_dir.mkdir(parents=True, exist_ok=True)
    try:
        config_file = _legacy_config(base_dir)
        monkeypatch.setattr(settings_mod, "config_path", lambda: config_file)
        monkeypatch.setenv("VOICEFLOW_FORCE_CPU", "1")

        cfg = settings_mod.load_config(Config())
        assert cfg.adaptive_ai_analysis_enabled is False
        assert (
            cfg.cloud_learning_consent_version
            == settings_mod.CLOUD_LEARNING_CONSENT_VERSION
        )

        # The reset was persisted, so the next load does not need to migrate.
        saved = json.loads(config_file.read_text(encoding="utf-8"))
        assert saved["adaptive_ai_analysis_enabled"] is False
        assert (
            saved["cloud_learning_consent_version"]
            == settings_mod.CLOUD_LEARNING_CONSENT_VERSION
        )
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_user_choice_survives_reload_after_consent_recorded(monkeypatch):
    """Once the wizard has recorded consent (version 1), an explicit True stays True."""
    from voiceflow.utils import settings as settings_mod

    base_dir = Path("build") / "test-runtime" / f"consent-kept-{uuid4().hex}"
    base_dir.mkdir(parents=True, exist_ok=True)
    try:
        config_file = _legacy_config(base_dir, cloud_learning_consent_version=1)
        monkeypatch.setattr(settings_mod, "config_path", lambda: config_file)
        monkeypatch.setenv("VOICEFLOW_FORCE_CPU", "1")

        cfg = settings_mod.load_config(Config())
        assert cfg.adaptive_ai_analysis_enabled is True
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_wizard_save_records_consent_and_choice():
    from voiceflow.ui.setup_wizard import (
        CLOUD_LEARNING_TOGGLE_LABEL,
        apply_setup_updates,
    )

    assert "off by default" in CLOUD_LEARNING_TOGGLE_LABEL
    assert "Claude" in CLOUD_LEARNING_TOGGLE_LABEL  # destination is named
    cfg = Config()
    restart = apply_setup_updates(
        cfg, {"adaptive_ai_analysis_enabled": True, "cloud_learning_consent_version": 1}
    )
    assert restart is False  # not a runtime-restart field
    assert cfg.adaptive_ai_analysis_enabled is True
    assert cfg.cloud_learning_consent_version == 1
