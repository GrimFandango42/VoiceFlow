from __future__ import annotations

import sys
from pathlib import Path

# Allow direct script execution from repo root without editable install.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from voiceflow.core.config import Config
from voiceflow.integrations.inject import ClipboardInjector
from voiceflow.core.textproc import apply_code_mode


def main():
    cfg = Config(paste_injection=False, type_if_len_le=50)
    inj = ClipboardInjector(cfg)
    text = "open bracket hello close bracket comma new line tab world"
    mapped = apply_code_mode(text)
    ok = inj.inject(mapped)
    print("mapped:", mapped)
    print("inject ok:", ok)


if __name__ == "__main__":
    main()

