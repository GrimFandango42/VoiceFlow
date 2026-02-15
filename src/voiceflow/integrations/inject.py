from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Optional
import logging
import re
import ctypes

# Graceful imports for testing environments without system packages
try:
    import pyperclip  # type: ignore
except Exception:  # pragma: no cover - fallback for minimal environments
    class _PyperclipFallback:  # type: ignore
        @staticmethod
        def copy(text: str) -> None:
            return None

        @staticmethod
        def paste() -> str:
            return ""

    pyperclip = _PyperclipFallback()  # type: ignore

try:
    import keyboard  # type: ignore
except Exception:  # pragma: no cover - fallback for minimal environments
    class _KeyboardFallback:  # type: ignore
        @staticmethod
        def send(seq: str) -> None:
            return None

        @staticmethod
        def write(text: str, delay: float = 0) -> None:
            return None

    keyboard = _KeyboardFallback()  # type: ignore

from voiceflow.core.config import Config
from voiceflow.utils.validation import validate_text_input, ValidationError


@contextmanager
def _preserve_clipboard(enabled: bool):
    prev: Optional[str] = None
    if enabled:
        try:
            prev = pyperclip.paste()
        except Exception:
            prev = None
    try:
        yield
    finally:
        if enabled and prev is not None:
            try:
                pyperclip.copy(prev)
            except Exception:
                pass


class ClipboardInjector:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._last_inject_ts = 0.0
        self._log = logging.getLogger("localflow")
        self._target_hwnd: Optional[int] = None

    def _sanitize(self, text: str) -> str:
        """Enhanced sanitization with security validation"""
        try:
            # First apply comprehensive validation
            validated_text = validate_text_input(text, "injection_text")
        except ValidationError as e:
            self._log.warning(f"Input validation failed: {e}")
            return ""  # Reject invalid input

        # Normalize CRLF/CR -> LF
        s = validated_text.replace("\r\n", "\n").replace("\r", "\n")
        # Remove control chars except tab/newline
        s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
        # Trim excessive length (validation already checks, but double-check)
        if len(s) > self.cfg.max_inject_chars:
            s = s[: self.cfg.max_inject_chars]
            self._log.info(f"Text truncated to {self.cfg.max_inject_chars} chars")
        return s

    def _throttle(self):
        # Simple rate limit to avoid spamming injection
        min_interval = max(0, self.cfg.min_inject_interval_ms) / 1000.0
        now = time.time()
        wait = (self._last_inject_ts + min_interval) - now
        if wait > 0:
            time.sleep(wait)
        self._last_inject_ts = time.time()

    def paste_text(self, text: str) -> bool:
        text = self._sanitize(text)
        if not text.strip():
            return False

        with _preserve_clipboard(self.cfg.restore_clipboard):
            pyperclip.copy(text)
            time.sleep(0.03)  # allow clipboard to settle
            keyboard.send(self.cfg.paste_shortcut)
            # Some apps read clipboard asynchronously; avoid restoring too quickly.
            restore_delay = max(0, int(getattr(self.cfg, "clipboard_restore_delay_ms", 150))) / 1000.0
            time.sleep(restore_delay)
            if self.cfg.press_enter_after_paste:
                keyboard.send('enter')
        return True

    def type_text(self, text: str) -> bool:
        text = self._sanitize(text)
        if not text:
            return False
        keyboard.write(text, delay=0)
        if self.cfg.press_enter_after_paste:
            keyboard.send('enter')
        return True

    def inject(self, text: str) -> bool:
        self._throttle()
        # Optional switch: for short payloads, prefer typing to avoid clipboard exposure
        if self.cfg.type_if_len_le > 0 and len(text) <= self.cfg.type_if_len_le:
            method = 'type'
            ok = self.type_text(text)
            self._log.info("inject len=%d method=%s ok=%s", len(text), method, ok)
            return ok

        if self.cfg.paste_injection:
            method = 'paste'
            ok = self.paste_text(text)
            if not ok:
                # Fallback to typing if paste fails
                method = 'type'
                ok = self.type_text(text)
            self._log.info("inject len=%d method=%s ok=%s", len(text), method, ok)
            return ok
        else:
            method = 'type'
            ok = self.type_text(text)
            self._log.info("inject len=%d method=%s ok=%s", len(text), method, ok)
            return ok

    def capture_target_window(self) -> None:
        """Capture current foreground window as preferred injection target."""
        try:
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            if hwnd:
                self._target_hwnd = int(hwnd)
        except Exception:
            self._target_hwnd = None

    def clear_target_window(self) -> None:
        self._target_hwnd = None

    def _focus_target_window(self) -> None:
        if not self._target_hwnd:
            return
        try:
            ctypes.windll.user32.SetForegroundWindow(int(self._target_hwnd))
            time.sleep(0.01)
        except Exception:
            pass

    def _foreground_window(self) -> Optional[int]:
        try:
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            return int(hwnd) if hwnd else None
        except Exception:
            return None

    def inject_live_checkpoint(self, text: str) -> bool:
        """
        Inject while PTT keys may still be held.
        Keep this path low-risk for continuous hold:
        do not force focus changes mid-recording, only inject into the captured target
        when it is already foreground.
        """
        self._throttle()
        text = self._sanitize(text)
        if not text.strip():
            return False
        fg = self._foreground_window()
        if self._target_hwnd and fg and int(fg) != int(self._target_hwnd):
            # Focus drifted (e.g., overlay/tray). Skip this checkpoint to avoid typing into
            # the wrong target and to avoid aggressive focus-stealing during active hold.
            return False
        return self.type_text(text)
