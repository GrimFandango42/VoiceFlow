#!/usr/bin/env python3
"""Log a mis-hearing from any folder, the repository root included (VF-26).

    python scripts\\dev\\correct.py add --heard "Jamelan" --meant "Gemini"
    python scripts\\dev\\correct.py list

Same commands and options as ``python -m voiceflow.ai.corrections``. That form fails
from the repository root, where ``voiceflow.py`` shadows the ``src\\voiceflow`` package;
running a script puts this folder, not the cwd, first on ``sys.path``, so this does not.
"""

from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    src = str(Path(__file__).resolve().parents[2] / "src")
    while src in sys.path:
        sys.path.remove(src)
    sys.path.insert(0, src)
    from voiceflow.ai.corrections import main as corrections_main

    return int(corrections_main(sys.argv[1:] if argv is None else argv) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
