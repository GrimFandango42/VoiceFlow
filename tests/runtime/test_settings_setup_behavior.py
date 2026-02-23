from __future__ import annotations

import json

from voiceflow.core.config import Config
from voiceflow.utils import settings as settings_mod


def _setup_flow_version() -> int:
    return int(getattr(getattr(Config, "__dataclass_fields__", {}).get("setup_flow_version"), "default", 1))


def test_load_config_legacy_without_setup_marker_prompts_setup(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "model_tier": "quick",
                "device": "cpu",
                "compute_type": "int8",
                "use_tray": True,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(settings_mod, "config_path", lambda: config_file)
    monkeypatch.setenv("VOICEFLOW_FORCE_CPU", "1")

    cfg = settings_mod.load_config(Config())
    assert cfg.setup_completed is False
    assert cfg.show_setup_on_startup is True
    assert cfg.setup_profile == "recommended"
    assert cfg.setup_flow_version == _setup_flow_version()


def test_load_config_respects_explicit_setup_completed(tmp_path, monkeypatch):
    current_flow_version = _setup_flow_version()
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "setup_completed": True,
                "show_setup_on_startup": False,
                "setup_profile": "cpu-compatible",
                "setup_flow_version": current_flow_version,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(settings_mod, "config_path", lambda: config_file)
    monkeypatch.setenv("VOICEFLOW_FORCE_CPU", "1")

    cfg = settings_mod.load_config(Config())
    assert cfg.setup_completed is True
    assert cfg.show_setup_on_startup is False
    assert cfg.setup_profile == "cpu-compatible"


def test_load_config_prompts_once_when_setup_flow_version_is_stale(tmp_path, monkeypatch):
    current_flow_version = _setup_flow_version()
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "setup_completed": True,
                "show_setup_on_startup": False,
                "setup_profile": "recommended",
                "setup_flow_version": max(0, current_flow_version - 1),
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(settings_mod, "config_path", lambda: config_file)
    monkeypatch.setenv("VOICEFLOW_FORCE_CPU", "1")

    cfg = settings_mod.load_config(Config())
    assert cfg.setup_completed is False
    assert cfg.show_setup_on_startup is True
    assert cfg.setup_flow_version == current_flow_version
