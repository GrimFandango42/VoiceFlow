"""
Dev-mode entry point for VoiceFlow.

Bypasses the singleton/bootstrap process detection in cli_enhanced.py,
which terminates processes whose cmdline contains '-m voiceflow.ui.cli_enhanced'.
The frozen exe (VoiceFlow.exe) was immune to this because its cmdline was different.
This wrapper achieves the same by having a cmdline like 'python _app_entry.py'.
"""
import sys
import os
from pathlib import Path

# Ensure src/ is at the front of sys.path (before repo root)
src = str(Path(__file__).resolve().parent / "src")
if sys.path[0] != src:
    sys.path.insert(0, src)

from voiceflow.ui.cli_enhanced import main
sys.exit(main(sys.argv[1:]) or 0)
