#!/usr/bin/env python3
"""Validate current VoiceFlow hotkey configuration."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from voiceflow.core.config import Config
from voiceflow.utils.settings import load_config, config_path


def hotkey_string(cfg: Config) -> str:
    parts = []
    if cfg.hotkey_ctrl:
        parts.append("Ctrl")
    if cfg.hotkey_shift:
        parts.append("Shift")
    if cfg.hotkey_alt:
        parts.append("Alt")
    if cfg.hotkey_key:
        parts.append(cfg.hotkey_key.upper())
    return "+".join(parts) if parts else "None"


def test_hotkey_config() -> bool:
    cfg = load_config(Config())
    expected = "Ctrl+Shift"
    current = hotkey_string(cfg)
    is_match = cfg.hotkey_ctrl and cfg.hotkey_shift and not cfg.hotkey_alt and not cfg.hotkey_key

    print("VoiceFlow Hotkey Configuration")
    print("=" * 40)
    print(f"Config file: {config_path()}")
    print(f"Current: {current}")
    print(f"Expected: {expected}")
    print(f"Status: {'OK' if is_match else 'NEEDS UPDATE'}")
    return is_match


if __name__ == "__main__":
    raise SystemExit(0 if test_hotkey_config() else 1)
