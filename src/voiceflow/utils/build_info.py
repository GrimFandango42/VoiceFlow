"""Identify exactly which build is running.

A packaged app and a source checkout look identical from the outside, which
makes "am I actually testing the fix?" unanswerable at the moment it matters --
mid-test, looking at the window. This module answers it in one short string the
UI can show.

Three sources, best first:

1. ``voiceflow._build_stamp`` -- written by the build script at package time.
   The only source that is correct inside a frozen executable, because the git
   directory is not shipped.
2. ``git`` -- for a source checkout, the working state right now, including
   whether it is dirty.
3. Package version plus the executable's own mtime -- always available, never
   wrong, just coarse.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:  # pragma: no cover - trivial
    from voiceflow import __version__ as _PKG_VERSION
except Exception:  # pragma: no cover - defensive
    _PKG_VERSION = "0.0.0"

_UNKNOWN = "unknown"


@dataclass(frozen=True)
class BuildInfo:
    """Identity of the build currently running."""

    version: str
    commit: str
    built_at: str
    source: str
    dirty: bool = False

    def short_label(self) -> str:
        """One compact line for a status bar. Never raises, never empty."""
        parts = [f"v{self.version}"]
        if self.commit and self.commit != _UNKNOWN:
            parts.append(self.commit + ("*" if self.dirty else ""))
        if self.built_at and self.built_at != _UNKNOWN:
            parts.append(self.built_at)
        return " · ".join(parts)

    def detail(self) -> str:
        """Longer form for logs and about dialogs."""
        state = "dirty" if self.dirty else "clean"
        return (
            f"VoiceFlow {self.version} commit={self.commit} built={self.built_at} "
            f"source={self.source} tree={state}"
        )


def _from_stamp() -> BuildInfo | None:
    try:
        from voiceflow import _build_stamp as stamp  # type: ignore[attr-defined]
    except Exception:
        return None
    return BuildInfo(
        version=str(getattr(stamp, "VERSION", _PKG_VERSION)),
        commit=str(getattr(stamp, "COMMIT", _UNKNOWN)),
        built_at=str(getattr(stamp, "BUILT_AT", _UNKNOWN)),
        source="stamp",
        dirty=bool(getattr(stamp, "DIRTY", False)),
    )


def _git(args: list[str], cwd: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def _from_git() -> BuildInfo | None:
    if getattr(sys, "frozen", False):
        # No .git inside a bundle, and shelling out from a packaged app on every
        # UI refresh is not worth the process spawn.
        return None
    root = Path(__file__).resolve().parents[3]
    commit = _git(["rev-parse", "--short", "HEAD"], root)
    if not commit:
        return None
    status = _git(["status", "--porcelain", "--untracked-files=no"], root)
    when = _git(["log", "-1", "--format=%cd", "--date=format:%m-%d %H:%M"], root)
    return BuildInfo(
        version=_PKG_VERSION,
        commit=commit,
        built_at=when or _UNKNOWN,
        source="git",
        dirty=bool(status),
    )


def _from_executable() -> BuildInfo:
    built_at = _UNKNOWN
    try:
        target = Path(sys.executable if getattr(sys, "frozen", False) else __file__)
        stamp = datetime.fromtimestamp(os.path.getmtime(target))
        built_at = stamp.strftime("%m-%d %H:%M")
    except Exception:
        pass
    return BuildInfo(
        version=_PKG_VERSION,
        commit=_UNKNOWN,
        built_at=built_at,
        source="mtime",
    )


def build_info() -> BuildInfo:
    """Best available identification of the running build. Never raises."""
    for source in (_from_stamp, _from_git):
        try:
            info = source()
        except Exception:
            info = None
        if info is not None:
            return info
    return _from_executable()


def short_label() -> str:
    """Compact build identity for the status bar. Never raises."""
    try:
        return build_info().short_label()
    except Exception:  # pragma: no cover - the UI must never crash over a label
        return f"v{_PKG_VERSION}"
