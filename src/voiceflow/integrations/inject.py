from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Optional, Any, Dict
import logging
import re
import ctypes
from ctypes import wintypes

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

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


class _RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


@contextmanager
def _preserve_clipboard(enabled: bool):
    prev: Optional[str] = None
    if enabled:
        try:
            prev = _clipboard_paste_with_retry()
        except Exception:
            prev = None
    try:
        yield
    finally:
        if enabled and prev is not None:
            try:
                _clipboard_copy_with_retry(prev)
            except Exception:
                pass


def _clipboard_copy_with_retry(text: str, attempts: int = 6, base_delay: float = 0.03) -> None:
    """Retry clipboard writes to tolerate transient OpenClipboard contention on Windows."""
    last_error: Optional[Exception] = None
    for attempt in range(max(1, int(attempts))):
        try:
            pyperclip.copy(text)
            return
        except Exception as exc:
            last_error = exc
            time.sleep(base_delay * (attempt + 1))
    if last_error is not None:
        raise last_error


def _clipboard_paste_with_retry(attempts: int = 4, base_delay: float = 0.02) -> str:
    last_error: Optional[Exception] = None
    for attempt in range(max(1, int(attempts))):
        try:
            return str(pyperclip.paste() or "")
        except Exception as exc:
            last_error = exc
            time.sleep(base_delay * (attempt + 1))
    if last_error is not None:
        raise last_error
    return ""


class ClipboardInjector:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._last_inject_ts = 0.0
        self._log = logging.getLogger("localflow")
        self._target_hwnd: Optional[int] = None
        self._target_context: Dict[str, Any] = {}

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

    def copy_text_to_clipboard(self, text: str) -> bool:
        """Best-effort fallback so users can manually paste if live injection misses."""
        text = self._sanitize(text)
        if not text.strip():
            return False
        try:
            _clipboard_copy_with_retry(text)
            return True
        except Exception as e:
            self._log.warning("clipboard_fallback_copy_failed error=%s", e)
            return False

    def paste_text(self, text: str) -> bool:
        text = self._sanitize(text)
        if not text.strip():
            return False

        with _preserve_clipboard(self.cfg.restore_clipboard):
            try:
                _clipboard_copy_with_retry(text)
            except Exception as e:
                self._log.warning("clipboard_copy_failed error=%s", e)
                return False
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
        if not self._ensure_target_focus_for_release():
            fg = self._foreground_window()
            self._log.warning(
                "inject_focus_drift target_hwnd=%s foreground_hwnd=%s",
                str(self._target_hwnd),
                str(fg),
            )
            return False

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
                self._target_context = self._build_window_context(self._target_hwnd)
        except Exception:
            self._target_hwnd = None
            self._target_context = {}

    def clear_target_window(self) -> None:
        self._target_hwnd = None
        self._target_context = {}

    def get_target_context(self, refresh: bool = False) -> Dict[str, Any]:
        """
        Return cached target window context captured at recording start.
        Falls back to current foreground window when target is unavailable.
        """
        hwnd = self._target_hwnd
        if refresh or not self._target_context:
            if not hwnd:
                fg = self._foreground_window()
                hwnd = int(fg) if fg else None
            if hwnd:
                self._target_context = self._build_window_context(hwnd)
        return dict(self._target_context)

    def _focus_target_window(self) -> None:
        if not self._target_hwnd:
            return
        try:
            ctypes.windll.user32.SetForegroundWindow(int(self._target_hwnd))
            time.sleep(0.01)
        except Exception:
            pass

    def _is_target_foreground(self) -> bool:
        if not self._target_hwnd:
            return True
        fg = self._foreground_window()
        if not fg:
            return False
        return int(fg) == int(self._target_hwnd)

    def _ensure_target_focus_for_release(self) -> bool:
        """
        Guardrail for release-time injection.
        If focus drifted away from the captured target window, attempt bounded re-focus.
        """
        require_focus = bool(getattr(self.cfg, "inject_require_target_focus", True))
        if not require_focus or not self._target_hwnd:
            return True
        if self._is_target_foreground():
            return True

        allow_refocus = bool(getattr(self.cfg, "inject_refocus_on_miss", True))
        if not allow_refocus:
            return False

        attempts = max(1, int(getattr(self.cfg, "inject_refocus_attempts", 3)))
        delay_s = max(0, int(getattr(self.cfg, "inject_refocus_delay_ms", 90))) / 1000.0

        for attempt in range(attempts):
            self._focus_target_window()
            if delay_s > 0:
                time.sleep(delay_s)
            if self._is_target_foreground():
                if attempt > 0:
                    self._log.info(
                        "inject_refocus_recovered attempts=%d target_hwnd=%s",
                        attempt + 1,
                        str(self._target_hwnd),
                    )
                return True
        return False

    def _foreground_window(self) -> Optional[int]:
        try:
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            return int(hwnd) if hwnd else None
        except Exception:
            return None

    def _build_window_context(self, hwnd: int) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "hwnd": int(hwnd),
            "window_title": "",
            "window_class": "",
            "process_name": "",
            "window_width": 0,
            "window_height": 0,
        }
        if not hwnd:
            return context
        try:
            title_buffer = ctypes.create_unicode_buffer(512)
            ctypes.windll.user32.GetWindowTextW(int(hwnd), title_buffer, len(title_buffer))
            context["window_title"] = (title_buffer.value or "").strip()
        except Exception:
            pass
        try:
            class_buffer = ctypes.create_unicode_buffer(256)
            ctypes.windll.user32.GetClassNameW(int(hwnd), class_buffer, len(class_buffer))
            context["window_class"] = (class_buffer.value or "").strip()
        except Exception:
            pass
        try:
            rect = _RECT()
            if ctypes.windll.user32.GetWindowRect(int(hwnd), ctypes.byref(rect)):
                width = max(0, int(rect.right - rect.left))
                height = max(0, int(rect.bottom - rect.top))
                context["window_width"] = width
                context["window_height"] = height
        except Exception:
            pass
        try:
            pid = wintypes.DWORD(0)
            ctypes.windll.user32.GetWindowThreadProcessId(int(hwnd), ctypes.byref(pid))
            context["process_id"] = int(pid.value)
            if psutil and int(pid.value) > 0:
                pname = psutil.Process(int(pid.value)).name()
                context["process_name"] = str(pname or "").strip()
        except Exception:
            pass
        return context

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
