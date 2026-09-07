"""Shared pytest setup for the active VoiceFlow runtime suite."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

#: Kept alive for the process lifetime so the directory is not collected.
_SANDBOX = None


def pytest_configure(config) -> None:
    r"""Import from `src/`, and sandbox the app's data directory.

    The sandbox is not a nicety. `voiceflow.utils.settings.config_dir()` resolves
    to `%LOCALAPPDATA%\VoiceFlow`, the LIVE application's state directory, and
    `AdaptiveLearningManager.__init__` binds `adaptive_patterns.json` and
    `adaptive_audit.jsonl` from it before any test gets a chance to redirect
    those paths. Running this suite against a real installation therefore
    overwrites the user's learned corrections with whatever the test left in
    memory.

    That is not hypothetical. On 2026-09-07 a routine `pytest` run truncated a
    123 KB `adaptive_patterns.json` to an empty 78-byte stub and zeroed a 120 KB
    `adaptive_audit.jsonl` on the developer's own machine. There were no shadow
    copies and the data was not recoverable.

    Repointing LOCALAPPDATA here, before collection imports anything, makes the
    live directory unreachable for the whole session regardless of which test
    constructs which manager.
    """
    global _SANDBOX

    root = Path(__file__).resolve().parent.parent
    src = root / "src"

    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    if str(root) not in sys.path:
        sys.path.append(str(root))

    _SANDBOX = tempfile.TemporaryDirectory(prefix="voiceflow-test-appdata-")
    for var in ("LOCALAPPDATA", "APPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        os.environ[var] = _SANDBOX.name
    # Path.home() is the non-Windows fallback in default_log_dir().
    os.environ["HOME"] = _SANDBOX.name
    os.environ["USERPROFILE"] = _SANDBOX.name
