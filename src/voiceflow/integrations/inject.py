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


class _PendingRestore:
    """A clipboard restore that has been scheduled but has not finished yet."""

    def __init__(self, snapshot: Optional[dict], prev: Optional[str]) -> None:
        self.snapshot = snapshot
        self.prev = prev
        self.timer: Optional[threading.Timer] = None
        self.claimed = False          # a later paste took over the original contents
        self.running = False          # the restore body has started
        self.finished = threading.Event()
        self.run: Optional[Any] = None  # the restore body, for flush


# At most one restore is ever pending. Without this, two dictations less than the
# restore delay apart would snapshot the *first dictation's text* as the "user's
# clipboard", and the real clipboard would be gone for good.
_pending_lock = threading.Lock()
_pending_restore: Optional[_PendingRestore] = None

#: Kill switch for the deferred restore. The test suite turns it off by default (see
#: tests/conftest.py) so a timer can never outlive a test and touch a real clipboard.
_ALLOW_DEFERRED_RESTORE = True


def _cancel_pending_restore_without_running() -> None:
    """Drop a pending restore without running it. Test teardown only."""
    global _pending_restore
    with _pending_lock:
        pending, _pending_restore = _pending_restore, None
    if pending is not None and pending.timer is not None:
        pending.timer.cancel()


def _claim_pending_restore(log: Optional[logging.Logger] = None) -> Optional[_PendingRestore]:
    """Take over the original clipboard contents from a restore that has not run yet.

    Returns the pending restore (its snapshot/prev are the user's real clipboard) with
    its timer cancelled, or None if there was nothing pending. If the restore is
    already running, waits for it to finish and returns None: the clipboard then holds
    the real contents and can be snapshotted normally.
    """
    global _pending_restore
    with _pending_lock:
        pending = _pending_restore
        if pending is None:
            return None
        if not pending.running and not pending.claimed:
            if pending.timer is not None:
                pending.timer.cancel()
            pending.claimed = True
            _pending_restore = None
            return pending
    pending.finished.wait(timeout=2.0)
    with _pending_lock:
        if _pending_restore is pending:
            _pending_restore = None
    return None


def flush_pending_clipboard_restore(timeout: float = 2.0) -> None:
    """Run any pending restore now (call at shutdown so the clipboard is never left holding a dictation)."""
    with _pending_lock:
        pending = _pending_restore
    if pending is None or pending.run is None:
        return
    if pending.timer is not None:
        pending.timer.cancel()
    pending.run()
    pending.finished.wait(timeout=max(0.0, float(timeout)))


def _restore_now(
    snapshot: Optional[dict],
    prev: Optional[str],
    *,
    restore_attempts: int,
    restore_base_delay: float,
    restore_async_retry_seconds: float,
    log: Optional[logging.Logger],
) -> None:
    """Restore the user's clipboard; on failure hand off to the bounded background retry."""
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


@contextmanager
def _preserve_clipboard(
    enabled: bool,
    *,
    restore_attempts: int = 10,
    restore_base_delay: float = 0.03,
    restore_async_retry_seconds: float = 8.0,
    restore_delay: float = 0.0,
    log: Optional[logging.Logger] = None,
):
    """Snapshot the clipboard, run the body, then put the clipboard back.

    ``restore_delay`` > 0 defers the restore to a background timer so the caller
    returns as soon as the body is done (the paste has landed). The restore is never
    dropped: a following call inherits a still-pending original instead of
    snapshotting the dictation, and ``flush_pending_clipboard_restore`` forces it.
    ``restore_delay`` == 0 restores before returning.
    """
    global _pending_restore
    snapshot: Optional[dict] = None
    prev: Optional[str] = None
    if enabled:
        inherited = _claim_pending_restore(log)
        if inherited is not None:
            snapshot, prev = inherited.snapshot, inherited.prev
        else:
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
        if enabled and (snapshot is not None or prev is not None):
            restore_kwargs = dict(
                restore_attempts=restore_attempts,
                restore_base_delay=restore_base_delay,
                restore_async_retry_seconds=restore_async_retry_seconds,
                log=log,
            )
            if float(restore_delay) <= 0.0 or not _ALLOW_DEFERRED_RESTORE:
                _restore_now(snapshot, prev, **restore_kwargs)
            else:
                pending = _PendingRestore(snapshot, prev)

                def _run(pending: _PendingRestore = pending) -> None:
                    global _pending_restore
                    with _pending_lock:
                        if pending.claimed or pending.running:
                            return
                        pending.running = True
                    try:
                        _restore_now(pending.snapshot, pending.prev, **restore_kwargs)
                    finally:
                        with _pending_lock:
                            if _pending_restore is pending:
                                _pending_restore = None
                        pending.finished.set()

                pending.run = _run
                timer = threading.Timer(float(restore_delay), _run)
                timer.daemon = True
                pending.timer = timer
                with _pending_lock:
                    _pending_restore = pending
                timer.start()


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

        # Some apps read the clipboard asynchronously, so the restore must not run
        # right after the paste keystroke. That wait used to block this call (the
        # bulk of the ~190 ms median paste step); it now happens on a timer and
        # the call returns as soon as the keystroke is sent. When Enter must follow
        # the paste we keep the old inline wait, since Enter has to land after it.
        restore_delay = max(0, int(getattr(self.cfg, "clipboard_restore_delay_ms", 150))) / 1000.0
        press_enter = bool(self.cfg.press_enter_after_paste)

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
            restore_delay=0.0 if press_enter else restore_delay,
            log=self._log,
        ):
            try:
                _clipboard_copy_with_retry(text)
            except Exception as e:
                self._log.warning("clipboard_copy_failed error=%s", e)
                return False
            time.sleep(0.03)  # allow clipboard to settle
            keyboard.send(self.cfg.paste_shortcut)
            if press_enter:
                time.sleep(restore_delay)
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
