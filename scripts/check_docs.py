#!/usr/bin/env python3
"""Check that every relative link and image path in the repo's Markdown resolves (VF-14).

    python scripts/check_docs.py            # exit 0 = clean, 1 = problems
    python scripts/check_docs.py --verbose  # also list every file checked

Checks, for each ``*.md`` outside build/venv/vendor folders:

* inline links and images ``[text](target)`` / ``![alt](target)``, reference definitions
  ``[id]: target`` and HTML ``<img src=...>`` / ``<a href=...>``;
* the target file or folder exists, with the exact letter case (GitHub is case-sensitive even
  though Windows is not);
* a ``#fragment`` on a Markdown target names a real heading (GitHub-style slug), or an explicit
  ``<a id=...>`` / ``name=...``;
* every image file in the repo (png/jpg/gif/svg/webp) is referenced by some Markdown file, so
  stale screenshots cannot linger.

External ``http(s)``/``mailto`` links are not fetched. Code fences and inline code are ignored.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {
    ".git", ".github-cache", "node_modules", "build", "dist", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "htmlcov", "venv", ".venv", ".venv-gpu", ".venv-test",
    "whisper_env",
}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}

_FENCE = re.compile(r"^\s*(```|~~~)")
_INLINE_CODE = re.compile(r"`[^`\n]*`")
_INLINE_LINK = re.compile(r"!?\[(?:[^\]\\]|\\.)*\]\(\s*(<[^>]*>|[^)\s]*)(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)")
_REF_DEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)")
_HTML_ATTR = re.compile(r"""<(?:img|a|source)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_HTML_ANCHOR = re.compile(r"""<a\b[^>]*?\b(?:id|name)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
_EXTERNAL = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def iter_files(root: Path, suffixes: Iterable[str]) -> List[Path]:
    wanted = {s.lower() for s in suffixes}
    found: List[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in wanted:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        found.append(path)
    return sorted(found)


def slugify(heading: str) -> str:
    """GitHub-style heading anchor."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # links -> their text
    text = text.replace("`", "").replace("*", "").replace("~", "")
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def anchors_of(path: Path, cache: Dict[Path, Set[str]]) -> Set[str]:
    if path in cache:
        return cache[path]
    seen: Dict[str, int] = {}
    anchors: Set[str] = set()
    in_fence = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = _HEADING.match(line)
        if match:
            slug = slugify(match.group(2))
            count = seen.get(slug, 0)
            seen[slug] = count + 1
            anchors.add(slug if count == 0 else f"{slug}-{count}")
        for explicit in _HTML_ANCHOR.findall(line):
            anchors.add(explicit)
    cache[path] = anchors
    return anchors


def exists_exact(path: Path) -> bool:
    """True if ``path`` exists *with this exact case* on every component below the repo root."""
    try:
        rel = path.relative_to(REPO_ROOT)  # no resolve(): on Windows it would normalise the case
    except ValueError:
        return False  # points outside the repository
    current = REPO_ROOT
    for part in rel.parts:
        try:
            names = {entry.name for entry in current.iterdir()}
        except OSError:
            return False
        if part not in names:
            return False
        current = current / part
    return True


def extract_targets(md_path: Path) -> List[Tuple[int, str]]:
    """(line number, raw target) for every link/image in a Markdown file, code excluded."""
    targets: List[Tuple[int, str]] = []
    in_fence = False
    for number, line in enumerate(md_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        visible = _INLINE_CODE.sub("", line)
        for match in _INLINE_LINK.finditer(visible):
            targets.append((number, match.group(1)))
        ref = _REF_DEF.match(visible)
        if ref:
            targets.append((number, ref.group(1)))
        for attr in _HTML_ATTR.findall(visible):
            targets.append((number, attr))
    return targets


def split_target(raw: str) -> Tuple[str, str]:
    target = raw.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    path_part, _, fragment = target.partition("#")
    return path_part.split("?", 1)[0], fragment


def check(root: Path = REPO_ROOT, verbose: bool = False) -> Tuple[List[str], int]:
    problems: List[str] = []
    anchor_cache: Dict[Path, Set[str]] = {}
    referenced: Set[Path] = set()
    md_files = iter_files(root, {".md"})
    for md in md_files:
        rel_md = md.relative_to(root).as_posix()
        if verbose:
            print(f"checking {rel_md}")
        for line_no, raw in extract_targets(md):
            if not raw or _EXTERNAL.match(raw) or raw.startswith("{") or "{{" in raw:
                continue
            path_part, fragment = split_target(raw)
            if not path_part:  # "#anchor" within the same file
                if fragment and fragment not in anchors_of(md, anchor_cache):
                    problems.append(f"{rel_md}:{line_no}: no heading for anchor '#{fragment}'")
                continue
            base = root if path_part.startswith("/") else md.parent
            resolved = Path(os.path.normpath(base / path_part.lstrip("/")))
            if not exists_exact(resolved):
                problems.append(f"{rel_md}:{line_no}: broken link '{raw}' (no such file or wrong letter case)")
                continue
            referenced.add(resolved)
            if fragment and resolved.suffix.lower() == ".md" and resolved.is_file():
                if fragment not in anchors_of(resolved, anchor_cache):
                    problems.append(f"{rel_md}:{line_no}: '{path_part}' has no heading for anchor '#{fragment}'")
    for image in iter_files(root, IMAGE_EXTENSIONS):
        if Path(os.path.normpath(image)) not in referenced:
            problems.append(f"{image.relative_to(root).as_posix()}: image is not referenced by any Markdown file")
    return problems, len(md_files)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--verbose", action="store_true", help="list every Markdown file checked")
    args = parser.parse_args(argv)
    problems, count = check(REPO_ROOT, verbose=args.verbose)
    for problem in problems:
        print(problem)
    print(f"checked {count} Markdown files: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
