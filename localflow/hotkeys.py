from __future__ import annotations

import threading
from typing import Callable, Optional

# Graceful import for environments without the keyboard module during tests
try:
    import keyboard  # type: ignore
except Exception:  # pragma: no cover
    class keyboard:  # type: ignore
        @staticmethod
        def is_pressed(key: str) -> bool:
            return False

        @staticmethod
        def hook(callback):
            return None

        @staticmethod
        def unhook(h):
            return None

        @staticmethod
        def wait():
            pass

from .config import Config


class PTTHotkeyListener:
    """Push-to-talk listener with dynamic, modifier-only chord support.

    Reads current config on every key event, so hotkey can be changed at runtime
    (e.g., from the tray). Supports modifier-only chords like Ctrl+Alt.
    """

    def __init__(self, cfg: Config, on_start: Callable[[], None], on_stop: Callable[[], None]):
        self.cfg = cfg
        self.on_start = on_start
        self.on_stop = on_stop
        self._recording = False
        self._lock = threading.Lock()
        self._hook: Optional[Callable] = None

    def _chord_active(self) -> bool:
        # Evaluate chord from current keyboard state
        if self.cfg.hotkey_ctrl and not keyboard.is_pressed('ctrl'):
            return False
        if self.cfg.hotkey_shift and not keyboard.is_pressed('shift'):
            return False
        if self.cfg.hotkey_alt and not keyboard.is_pressed('alt'):
            return False
        key = (self.cfg.hotkey_key or '').strip()
        if key:
            if not keyboard.is_pressed(key):
                return False
        return True

    def _on_event(self, event):  # noqa: D401
        # On any key event, recompute chord and toggle recording state
        with self._lock:
            active = self._chord_active()
            if active and not self._recording:
                self._recording = True
                try:
                    self.on_start()
                except Exception:
                    self._recording = False
            elif not active and self._recording:
                self._recording = False
                try:
                    self.on_stop()
                except Exception:
                    pass

    def start(self):
        if self._hook is None:
            self._hook = keyboard.hook(self._on_event)

    def stop(self):
        if self._hook is not None:
            try:
                keyboard.unhook(self._hook)
            finally:
                self._hook = None

    def run_forever(self):
        print("Ready. Hold your configured hotkey to dictate. Press Ctrl+C to exit.")
        keyboard.wait()
