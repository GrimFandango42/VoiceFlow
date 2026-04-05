#!/usr/bin/env python3
"""Screenshot capture script for VoiceFlow overlay.

Usage (from repo root, with venv active):
    python scripts/take_screenshots.py

Saves PNGs to assets/screenshots/.
"""
import os
import sys
import threading
import time

# Ensure the project src is on the path.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from PIL import ImageGrab

OUTPUT_DIR = os.path.join(ROOT, "assets", "screenshots")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _capture_window(win, out_path: str):
    """Capture a tkinter window by its screen coordinates."""
    win.update_idletasks()
    win.update()
    time.sleep(0.12)                    # let the canvas render fully
    x = win.winfo_rootx()
    y = win.winfo_rooty()
    w = win.winfo_width()
    h = win.winfo_height()
    img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
    img.save(out_path)
    print(f"  saved: {out_path}")


def _run_demo(state: str, audio_level: float, out_path: str):
    """Show the overlay in `state` with `audio_level` and capture it."""
    from voiceflow.ui.visual_indicators import (
        BottomScreenIndicator,
        TranscriptionStatus,
    )

    STATUS_MAP = {
        "idle": TranscriptionStatus.IDLE,
        "listening": TranscriptionStatus.LISTENING,
        "processing": TranscriptionStatus.PROCESSING,
        "transcribing": TranscriptionStatus.TRANSCRIBING,
        "complete": TranscriptionStatus.COMPLETE,
    }

    indicator = BottomScreenIndicator()

    def _demo():
        time.sleep(0.5)     # wait for GUI thread to be ready

        # Inject a fake audio level so the waveform looks alive.
        indicator.audio_level_target = audio_level
        indicator.audio_level_smoothed = audio_level * 0.8

        # Show the overlay in the target state.
        indicator.show_status(STATUS_MAP[state])

        time.sleep(0.9)     # let animation run a few frames

        # Capture the overlay window.
        if indicator.window:
            _capture_window(indicator.window, out_path)
        else:
            print(f"  WARNING: window not found for state={state}")

        time.sleep(0.1)
        indicator.hide()
        time.sleep(0.2)

        # Signal the root to quit.
        try:
            if indicator.root:
                indicator.root.quit()
        except Exception:
            pass

    t = threading.Thread(target=_demo, daemon=True)
    t.start()

    # Block in the Tk main loop until _demo calls root.quit().
    try:
        if indicator.root:
            indicator.root.mainloop()
    except Exception:
        pass

    t.join(timeout=5)
    print(f"  done: {state}")


def main():
    scenarios = [
        ("idle",        0.02,  "overlay_idle.png"),
        ("listening",   0.65,  "overlay_listening.png"),
        ("processing",  0.40,  "overlay_processing.png"),
        ("transcribing",0.55,  "overlay_transcribing.png"),
        ("complete",    0.10,  "overlay_complete.png"),
    ]

    for state, level, filename in scenarios:
        print(f"Capturing: {state} (level={level})")
        out = os.path.join(OUTPUT_DIR, filename)
        try:
            _run_demo(state, level, out)
        except Exception as exc:
            print(f"  ERROR: {exc}")
        time.sleep(0.3)

    print(f"\nAll screenshots saved to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
