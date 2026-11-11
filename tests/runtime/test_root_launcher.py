"""
voiceflow.py sits at the repo root, next to the real package in src/voiceflow/.
Whichever is first on sys.path wins the name `voiceflow`, and running the
script puts the repo root first -- so the launcher shadowed the package it was
trying to load and died with "'voiceflow' is not a package".
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPO_ROOT / "voiceflow.py"


def _load_launcher():
    spec = importlib.util.spec_from_file_location("voiceflow_root_launcher", LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_src_is_placed_ahead_of_repo_root(monkeypatch):
    launcher = _load_launcher()
    src = str(REPO_ROOT / "src")

    # Reproduce the real failure: repo root first, and src already present
    # further back because a dev install's _voiceflow.pth put it there. The
    # old "if src not in sys.path" guard skipped the insert in exactly this
    # arrangement, leaving the shadowing in place.
    monkeypatch.setattr(sys, "path", [str(REPO_ROOT), "/somewhere/else", src])

    launcher._bootstrap_src_path()

    assert sys.path[0] == src
    assert sys.path.index(src) < sys.path.index(str(REPO_ROOT))
    assert sys.path.count(src) == 1, "src should not be duplicated on sys.path"


def test_bootstrap_is_idempotent(monkeypatch):
    launcher = _load_launcher()
    src = str(REPO_ROOT / "src")
    monkeypatch.setattr(sys, "path", [str(REPO_ROOT)])

    launcher._bootstrap_src_path()
    launcher._bootstrap_src_path()

    assert sys.path.count(src) == 1


def test_package_resolves_after_bootstrap(monkeypatch):
    """The point of the whole thing: `voiceflow` must be the package."""
    launcher = _load_launcher()
    monkeypatch.setattr(sys, "path", [str(REPO_ROOT)] + list(sys.path))
    launcher._bootstrap_src_path()

    monkeypatch.delitem(sys.modules, "voiceflow", raising=False)
    spec = importlib.util.find_spec("voiceflow")
    assert spec is not None
    assert spec.submodule_search_locations is not None, "resolved to a module, not a package"
    resolved = Path(list(spec.submodule_search_locations)[0]).resolve()
    assert resolved == (REPO_ROOT / "src" / "voiceflow").resolve()
