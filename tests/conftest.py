"""Pytest configuration to ensure project root is importable.

This makes packages like `localflow` and `voiceflow` importable from tests
regardless of the selected testpaths.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def pytest_configure(config):  # noqa: D401
    """Ensure project root is on sys.path."""
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

