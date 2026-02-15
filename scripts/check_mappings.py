from __future__ import annotations

import sys
from pathlib import Path

# Allow direct script execution from repo root without editable install.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from voiceflow.core.textproc import apply_code_mode

samples = [
    "function open paren x close paren open brace new line return x plus 1 semicolon new line close brace",
    "open bracket a comma b close bracket equals open bracket 1 comma 2 close bracket",
    "if x double equals 10 colon new line tab print open paren hello close paren",
]

for s in samples:
    print("IN: ", s)
    print("OUT:", apply_code_mode(s))
    print()

