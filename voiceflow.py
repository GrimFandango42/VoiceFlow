#!/usr/bin/env python3
"""Compatibility launcher for the active VoiceFlow runtime."""

from __future__ import annotations

import sys
from pathlib import Path


def _bootstrap_src_path() -> None:
    """
    Put src/ ahead of the repo root on sys.path.

    This file is named voiceflow.py and sits next to the real package in
    src/voiceflow/, so whichever comes first on sys.path wins the name
    `voiceflow`. Running this script puts the repo root at sys.path[0], and
    `import voiceflow` then resolves to this module -- which has no `ui`
    submodule, so the launcher fails with "'voiceflow' is not a package".

    Checking `not in sys.path` before inserting is not enough: a development
    install drops a _voiceflow.pth naming src/, so src/ is already present but
    *behind* the repo root. The guard then skips the insert and the shadowing
    stands. Move it to the front regardless of whether it appears later.
    """
    repo_root = Path(__file__).resolve().parent
    src = str(repo_root / "src")
    while src in sys.path:
        sys.path.remove(src)
    sys.path.insert(0, src)


def main() -> int:
    _bootstrap_src_path()
    from voiceflow.ui.cli_enhanced import main as cli_main

    return int(cli_main(sys.argv[1:]) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
