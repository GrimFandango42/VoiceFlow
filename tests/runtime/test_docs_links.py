"""Documentation hygiene (VF-14): relative links, image paths and anchors must resolve.

Runs ``scripts/check_docs.py`` against the repository so a renamed file or a deleted
screenshot fails CI instead of leaving a dead link on GitHub.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_docs", REPO_ROOT / "scripts" / "check_docs.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_markdown_links_and_images_resolve():
    checker = _load_checker()
    problems, files_checked = checker.check(REPO_ROOT)
    assert files_checked > 10, "the checker found suspiciously few Markdown files"
    assert not problems, "documentation problems:\n" + "\n".join(problems)


def test_checker_flags_a_broken_link(tmp_path, monkeypatch):
    checker = _load_checker()
    (tmp_path / "a.md").write_text("[gone](missing.md)\n![x](pic.PNG)\n", encoding="utf-8")
    (tmp_path / "pic.png").write_bytes(b"\x89PNG")
    monkeypatch.setattr(checker, "REPO_ROOT", tmp_path)
    problems, _ = checker.check(tmp_path)
    joined = "\n".join(problems)
    assert "missing.md" in joined
    assert "pic.PNG" in joined  # wrong letter case is a broken link on GitHub
