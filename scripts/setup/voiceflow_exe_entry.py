#!/usr/bin/env python3
"""
PyInstaller entrypoint for VoiceFlow on Windows.

This module preserves the same default runtime path as `VoiceFlow_Quick.bat`:
`voiceflow.ui.cli_enhanced:main`.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_src_on_path() -> None:
    """Allow direct invocation from source tree during local packaging."""
    if getattr(sys, "frozen", False):
        return
    repo_root = Path(__file__).resolve().parents[2]
    src_root = repo_root / "src"
    src_text = str(src_root)
    if src_text not in sys.path:
        sys.path.insert(0, src_text)


def main() -> int:
    _ensure_src_on_path()
    from voiceflow.ui.cli_enhanced import main as cli_main

    result = cli_main()
    return int(result) if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
