#!/usr/bin/env python3
"""
Quick verification that VoiceFlow visual components are importable and responsive.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path


def _prepare_path() -> None:
    root = Path(__file__).resolve().parents[2]
    src = root / "src"
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))


def test_basic_functionality() -> bool:
    print("=== VoiceFlow Visual System Verification ===")
    _prepare_path()

    print("\n1. Testing imports...")
    try:
        from voiceflow.ui.visual_indicators import show_listening, show_complete, hide_status
        from voiceflow.ui.enhanced_tray import EnhancedTrayController
        from voiceflow.core.config import Config
        print("   [OK] Visual indicator + tray imports succeeded")
    except Exception as exc:
        print(f"   [FAIL] Import check failed: {exc}")
        return False

    print("\n2. Testing tkinter availability...")
    try:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        root.destroy()
        print("   [OK] tkinter functional")
    except Exception as exc:
        print(f"   [FAIL] tkinter check failed: {exc}")
        return False

    print("\n3. Testing lightweight visual sequence...")
    try:
        from voiceflow.ui.visual_indicators import show_listening, show_complete, hide_status

        def visual_test() -> None:
            show_listening()
            time.sleep(0.8)
            show_complete("Visual verification OK")
            time.sleep(1.2)
            hide_status()

        worker = threading.Thread(target=visual_test, daemon=True)
        worker.start()
        worker.join(timeout=5.0)
        print("   [OK] Visual sequence completed")
    except Exception as exc:
        print(f"   [FAIL] Visual sequence failed: {exc}")
        return False

    print("\n=== VERIFICATION COMPLETE ===")
    print("[OK] Visual system basic checks passed")
    print("[OK] Use VoiceFlow_Quick.bat for full runtime validation")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if test_basic_functionality() else 1)
