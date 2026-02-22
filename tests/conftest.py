"""Shared pytest setup for the active VoiceFlow runtime suite."""

from __future__ import annotations

import sys
from pathlib import Path


def pytest_configure(config) -> None:
    """Ensure tests import the package from `src/`."""
    root = Path(__file__).resolve().parent.parent
    src = root / "src"

    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    if str(root) not in sys.path:
        sys.path.append(str(root))
