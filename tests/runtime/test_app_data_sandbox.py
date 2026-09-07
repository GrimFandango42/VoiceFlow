"""The suite must never be able to touch a real VoiceFlow installation.

A regression here is silent and destructive: it does not fail a test, it
overwrites the user's learned corrections. So the guard is itself a test.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from voiceflow.utils.settings import config_dir, config_path


class TestSandbox:
    def test_config_dir_is_under_a_temp_directory(self):
        resolved = config_dir().resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
        assert str(resolved).startswith(str(temp_root)), (
            f"config_dir() resolved to {resolved}, which is outside the temp "
            "sandbox. The suite can reach a real installation."
        )

    def test_config_dir_is_not_the_users_appdata(self):
        resolved = str(config_dir().resolve()).lower()
        # The exact path the 2026-09-07 data loss went through.
        assert "appdata\\local\\voiceflow" not in resolved
        assert "appdata/local/voiceflow" not in resolved

    def test_config_path_sits_inside_config_dir(self):
        assert config_path().parent.resolve() == config_dir().resolve()

    def test_adaptive_files_would_land_in_the_sandbox(self):
        # The two files that were destroyed.
        for name in ("adaptive_patterns.json", "adaptive_audit.jsonl"):
            target = (config_dir() / name).resolve()
            assert str(target).startswith(str(Path(tempfile.gettempdir()).resolve()))
