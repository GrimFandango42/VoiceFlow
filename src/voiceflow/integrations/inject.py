from __future__ import annotations

import ctypes
import logging
import re
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Optional

try:
    from ctypes import wintypes
except Exception:  # pragma: no cover
    class _WinTypesFallback:
        DWORD = ctypes.c_ulong

    wintypes = _WinTypesFallback()

# Graceful imports for testing environments without system packages
try:
    import win32clipboard as _win32clipboard  # type: ignore
    _HAS_WIN32CLIPBOARD = True
except Exception:
    _win32clipboard = None  # type: ignore
    _HAS_WIN32CLIPBOARD = False

# Handle-based clipboard formats that cannot be serialized or re-set via SetClipboardData.
# GetClipboardData returns a GDI/kernel handle for these — meaningless after restore.
_SKIP_CLIPBOARD_FORMATS: frozenset = frozenset([
    2,   # CF_BITMAP
    3,   # CF_METAFILEPICT
    9,   # CF_PALETTE
    14,  # CF_ENHMETAFILE
])

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
from voiceflow.utils.validation import ValidationError, validate_text_input

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None

_HAS_WIN32_API = bool(getattr(ctypes, "windll", None) and hasattr(ctypes.windll, "user32"))


class _RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


def _snapshot_clipboard_all_formats() -> Optional[dict]:
    """Capture all serializable clipboard formats via win32clipboard.

    Returns a {format_id: data} dict, or None if win32clipboard is unavailable or the
    clipboard is empty/inaccessible.  Handle-based formats in _SKIP_CLIPBOARD_FORMATS
    are silently skipped — they cannot be round-tripped through SetClipboardData.
    """
    if not _HAS_WIN32CLIPBOARD or _win32clipboard is None:
        return None
    snapshot: dict = {}
    try:
        _win32clipboard.OpenClipboard(None)
        try:
            fmt = _win32clipboard.EnumClipboardFormats(0)
            while fmt:
                if fmt not in _SKIP_CLIPBOARD_FORMATS:
                    try:
                        snapshot[fmt] = _win32clipboard.GetClipboardData(fmt)
                    except Exception:
                        pass
                fmt = _win32clipboard.EnumClipboardFormats(fmt)
        finally:
            _win32clipboard.CloseClipboard()
    except Exception:
        return None
    return snapshot if snapshot else None


def _restore_clipboard_all_formats(snapshot: dict) -> None:
    """Restore clipboard contents from a snapshot produced by _snapshot_clipboard_all_formats.

    Opens the clipboard, empties it, then calls SetClipboardData for each saved format.
    Formats that fail SetClipboardData (e.g. stale handle-based data) are skipped silently.
    """
    if not _HAS_WIN32CLIPBOARD or _win32clipboard is None or not snapshot:
        return
    _win32clipboard.OpenClipboard(None)
    try:
        _win32clipboard.EmptyClipboard()
        for fmt, data in snapshot.items():
            try:
                _win32clipboard.SetClipboardData(fmt, data)
            except Exception:
                pass
    finally:
        _win32clipboard.CloseClipboard()


def _schedule_clipboard_restore_all(
    snapshot: dict,
    *,
    retry_window_seconds: float,
    log: Optional[logging.Logger] = None,
) -> None:
    """Best-effort background restore for a multi-format clipboard snapshot."""
    window = max(0.5, float(retry_window_seconds))

    def _worker() -> None:
        deadline = time.time() + window
        last_error: Optional[Exception] = None
        while time.time() < deadline:
            try:
                _restore_clipboard_all_formats(snapshot)
                if log:
                    log.info("clipboard_restore_async_all_success window_s=%.2f", window)
                return
            except Exception as exc:
                last_error = exc
                time.sleep(0.35)
        if log:
            log.warning("clipboard_restore_async_all_failed window_s=%.2f error=%s", window, last_error)

    thread = threading.Thread(target=_worker, name="ClipboardRestoreAll", daemon=True)
    thread.start()


def _schedule_clipboard_restore(
    text: str,
    *,
    retry_window_seconds: float,
    attempts_per_try: int,
    base_delay: float,
    log: Optional[logging.Logger] = None,
) -> None:
    """Best-effort background clipboard restore when immediate restore fails.
    This reduces risk of losing user clipboard contents under transient lock contention.
    """
    window = max(0.5, float(retry_window_seconds))
    per_try_attempts = max(1, int(attempts_per_try))
    delay = max(0.005, float(base_delay))

    def _worker() -> None:
        deadline = time.time() + window
        last_error: Optional[Exception] = None
        while time.time() < deadline:
            try:
                _clipboard_copy_with_retry(text, attempts=per_try_attempts, base_delay=delay)
                if log:
                    log.info("clipboard_restore_async_success window_s=%.2f", window)
                return
            except Exception as exc:
                last_error = exc
                time.sleep(min(0.35, delay * 2.0))
        if log:
            log.warning("clipboard_restore_async_failed window_s=%.2f error=%s", window, last_error)

    thread = threading.Thread(target=_worker, name="ClipboardRestore", daemon=True)
    thread.start()


@contextmanager
def _preserve_clipboard(
    enabled: bool,
    *,
    restore_attempts: int = 10,
    restore_base_delay: float = 0.03,
    restore_async_retry_seconds: float = 8.0,
    log: Optional[logging.Logger] = None,
):
    snapshot: Optional[dict] = None
    prev: Optional[str] = None
    if enabled:
        # Prefer multi-format snapshot (preserves images, files, etc.)
        snapshot = _snapshot_clipboard_all_formats()
        if snapshot is None:
            # Fallback: text-only via pyperclip for environments without win32clipboard
            try:
                prev = _clipboard_paste_with_retry()
            except Exception as exc:
                if log:
                    log.warning("clipboard_snapshot_failed error=%s", exc)
    try:
        yield
    finally:
        if enabled:
            if snapshot is not None:
                try:
                    _restore_clipboard_all_formats(snapshot)
                except Exception as exc:
                    if log:
                        log.warning("clipboard_restore_immediate_failed error=%s", exc)
                    _schedule_clipboard_restore_all(
                        snapshot,
                        retry_window_seconds=float(restore_async_retry_seconds),
                        log=log,
                    )
            elif prev is not None:
                try:
                    _clipboard_copy_with_retry(
                        prev,
                        attempts=max(1, int(restore_attempts)),
                        base_delay=max(0.005, float(restore_base_delay)),
                    )
                except Exception as exc:
                    if log:
                        log.warning("clipboard_restore_immediate_failed error=%s", exc)
                    _schedule_clipboard_restore(
                        prev,
                        retry_window_seconds=float(restore_async_retry_seconds),
                        attempts_per_try=max(2, int(restore_attempts)),
                        base_delay=max(0.005, float(restore_base_delay)),
                        log=log,
                    )


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
        self._log = logging.getLogger("voiceflow")
        self._target_hwnd: Optional[int] = None
        self._target_context: Dict[str, Any] = {}
        # VF-17 "replace last paste": what we last put on screen, where, and how
        # many real keystrokes the user has made since.
        self._last_paste: Optional[Dict[str, Any]] = None
        self._keys_typed = 0
        self._injecting = False
        self._ignore_until = 0.0
        self._key_counter_ready = False

    # ------------------------------------------------------------------ #
    # VF-17: replace-last-paste support
    # ------------------------------------------------------------------ #
    _MODIFIER_NAMES = frozenset({
        "ctrl", "left ctrl", "right ctrl", "shift", "left shift", "right shift", "alt", "left alt", "right alt",
        "alt gr", "windows", "left windows", "right windows", "caps lock", "num lock", "scroll lock",
    })

    def enable_replace_tracking(self) -> bool:
        """Opt in to 'replace last paste' (installs a key-press counter hook). Returns True when live."""
        self._ensure_key_counter()
        return self._key_counter_live

    def _ensure_key_counter(self) -> None:
        """Count real (non-modifier, non-hotkey) key presses so a replace can be refused after typing."""
        if self._key_counter_ready:
            return
        self._key_counter_ready = True  # one attempt per process
        try:
            if hasattr(keyboard, "on_press"):
                keyboard.on_press(self._on_key_event)
                self._key_counter_live = True
        except Exception as exc:
            self._log.warning("key_counter_unavailable error=%s", exc)

    _key_counter_live = False

    def _on_key_event(self, event: Any) -> None:
        if self._injecting:
            return
        stamp = getattr(event, "time", None)
        if isinstance(stamp, (int, float)) and stamp <= self._ignore_until:
            return  # generated by our own injection
        name = str(getattr(event, "name", "") or "").lower()
        if not name or name in self._MODIFIER_NAMES:
            return
        try:
            # ctrl+alt+<key> is a hotkey (including the replace hotkey itself), not typing.
            if keyboard.is_pressed("ctrl") and keyboard.is_pressed("alt"):
                return
        except Exception:
            pass
        self._keys_typed += 1

    def _record_last_paste(self, text: str) -> None:
        hwnd = self._target_hwnd or self._foreground_window()
        self._last_paste = {
            "text": text,
            "hwnd": int(hwnd) if hwnd else None,
            "ts": time.time(),
            "keys": self._keys_typed,
        }

    def last_paste_text(self) -> str:
        return str((self._last_paste or {}).get("text", ""))

    def _replace_refusal(self, old_text: str, max_age_s: float) -> str:
        """Why replacing in place would be unsafe ("" = safe)."""
        last = self._last_paste
        if not last:
            return "no_recent_paste"
        old = self._sanitize(old_text)
        if old != last["text"]:
            return "text_mismatch"
        if time.time() - float(last["ts"]) > max_age_s:
            return "too_old"
        if "\n" in old:
            return "multiline"
        if len(old) > 4000:
            return "too_long"
        if bool(getattr(self.cfg, "press_enter_after_paste", False)):
            return "enter_was_sent"
        if not self._key_counter_live:
            return "keystroke_tracking_unavailable"
        if self._keys_typed != last["keys"]:
            return "typed_since_paste"
        fg = self._foreground_window()
        if last["hwnd"] is None or fg is None or int(fg) != int(last["hwnd"]):
            return "window_changed"
        return ""

    @staticmethod
    def _wait_for_hotkey_release(timeout_s: float = 1.5) -> bool:
        """The replace chord's ctrl/alt are still down when its callback fires; backspace under them is ctrl+alt+backspace."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                if not (keyboard.is_pressed("ctrl") or keyboard.is_pressed("alt") or keyboard.is_pressed("shift")):
                    return True
            except Exception:
                return True
            time.sleep(0.02)
        return False

    def replace_last_paste(self, old_text: str, new_text: str, *, max_age_s: float = 120.0) -> str:
        """Swap ``old_text`` (what we pasted) for ``new_text`` in place.

        Returns ``replaced`` or ``clipboard:<why>`` (improved text copied for a
        manual paste) or ``failed:<why>``. Refuses -- and falls back to the
        clipboard -- whenever deleting characters could hit the wrong text.
        """
        new = self._sanitize(new_text)
        refusal = self._replace_refusal(old_text, max_age_s) if new.strip() else "empty"
        if not refusal and not self._wait_for_hotkey_release():
            refusal = "modifiers_held"
        if refusal:
            copied = bool(new.strip()) and self.copy_text_to_clipboard(new_text)
            self._log.info("replace_last_paste refused reason=%s clipboard=%s", refusal, copied)
            return f"clipboard:{refusal}" if copied else f"failed:{refusal}"
        old = self._sanitize(old_text)
        self._injecting = True
        try:
            for _ in range(len(old)):
                keyboard.send("backspace")
            ok = self.paste_text(new) if self.cfg.paste_injection else self.type_text(new)
            if not ok:
                ok = self.type_text(new)
        finally:
            self._ignore_until = time.time() + 0.02
            self._injecting = False
        if ok:
            self._record_last_paste(new)
        self._log.info("replace_last_paste ok=%s deleted=%d inserted=%d", ok, len(old), len(new))
        return "replaced" if ok else "failed:paste"

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

        with _preserve_clipboard(
            self.cfg.restore_clipboard,
            restore_attempts=max(1, int(getattr(self.cfg, "clipboard_restore_retry_attempts", 10))),
            restore_base_delay=max(
                0.005,
                int(getattr(self.cfg, "clipboard_restore_retry_base_delay_ms", 30)) / 1000.0,
            ),
            restore_async_retry_seconds=max(
                0.5,
                float(getattr(self.cfg, "clipboard_restore_async_retry_seconds", 8.0)),
            ),
            log=self._log,
        ):
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
        self._injecting = True
        try:
            ok = self._inject_impl(text)
        finally:
            # No sleep (paste latency must not regress): events our own paste
            # generated carry timestamps <= now, whenever the hook thread
            # gets round to delivering them, and are skipped by _on_key_event.
            self._ignore_until = time.time() + 0.02
            self._injecting = False
        if ok:
            self._record_last_paste(self._sanitize(text))
        return ok

    def _inject_impl(self, text: str) -> bool:
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
        if not _HAS_WIN32_API:
            self._target_hwnd = None
            self._target_context = {}
            return
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
        """Return cached target window context captured at recording start.
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
        if not _HAS_WIN32_API:
            return
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
        """Guardrail for release-time injection.
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
        if not _HAS_WIN32_API:
            return None
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
        if not _HAS_WIN32_API:
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
        """Inject while PTT keys may still be held.
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
