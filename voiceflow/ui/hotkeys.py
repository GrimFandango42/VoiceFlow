from __future__ import annotations

from typing import Callable, Optional

# Graceful import for environments without keyboard
try:
    import keyboard  # type: ignore
except Exception:  # pragma: no cover
    class _KeyboardFallback:  # type: ignore
        def add_hotkey(self, *_args, **_kwargs):
            return None

        def wait(self, *_args, **_kwargs):
            return None

        def unhook_all(self):
            return None

    keyboard = _KeyboardFallback()  # type: ignore


class HotkeyManager:
    """Manage registration and listening for two hotkeys.

    Supports two construction patterns used across tests:
      - HotkeyManager(config)
      - HotkeyManager(record_hotkey, paste_hotkey, on_toggle, on_paste)
    """

    def __init__(
        self,
        a,
        paste_hotkey: Optional[str] = None,
        on_toggle: Optional[Callable[[], None]] = None,
        on_paste: Optional[Callable[[], None]] = None,
    ) -> None:
        # Detect signature variant
        if paste_hotkey is None and on_toggle is None and on_paste is None:
            # Single-arg form: config object
            config = a
            self.record_hotkey: str = getattr(config, "hotkey", "f12")
            self.paste_hotkey: str = getattr(config, "paste_hotkey", "ctrl+v")
            self._on_toggle: Optional[Callable[[], None]] = None
            self._on_paste: Optional[Callable[[], None]] = None
        else:
            # Explicit-arg form
            self.record_hotkey = str(a)
            self.paste_hotkey = str(paste_hotkey) if paste_hotkey is not None else "ctrl+v"
            self._on_toggle = on_toggle
            self._on_paste = on_paste

        self._listening = False

    # Backward-compatible single-hotkey register used by some tests
    def register_hotkey(self, *args) -> None:
        """Register callback for a hotkey.

        Supports two forms:
          - register_hotkey(callback)
          - register_hotkey(name, combo, callback)
        """
        if len(args) == 1 and callable(args[0]):
            callback: Callable[[], None] = args[0]
            keyboard.add_hotkey(self.record_hotkey, callback)
        elif len(args) == 3:
            name, combo, callback = args  # type: ignore[misc]
            # Store mapping for tests that call _on_activate(name)
            if not hasattr(self, "_named_callbacks"):
                self._named_callbacks: dict[str, Callable[[], None]] = {}
            self._named_callbacks[str(name)] = callback  # type: ignore[assignment]
            # Best-effort bind if real keyboard is present
            try:
                keyboard.add_hotkey(str(combo), callback)
            except Exception:
                pass
        else:
            raise TypeError("register_hotkey expects (callback) or (name, combo, callback)")

    def start_listening(self) -> None:
        if self._on_toggle:
            keyboard.add_hotkey(self.record_hotkey, self._on_toggle)
        if self._on_paste:
            keyboard.add_hotkey(self.paste_hotkey, self._on_paste)
        self._listening = True

    def stop_listening(self) -> None:
        keyboard.unhook_all()
        self._listening = False

    # Some tests patch this to inject behavior
    def wait_for_hotkey(self) -> None:
        keyboard.wait()

    def cleanup(self) -> None:
        keyboard.unhook_all()

    # Test helper used by tests\test_windows_basic.py
    def _on_activate(self, name: str) -> None:  # pragma: no cover
        cb = getattr(self, "_named_callbacks", {}).get(name)
        if cb:
            cb()
