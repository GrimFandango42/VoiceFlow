from __future__ import annotations

import ctypes
import logging
import os
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


class _GUITHREADINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("hwndActive", ctypes.c_void_p),
        ("hwndFocus", ctypes.c_void_p),
        ("hwndCapture", ctypes.c_void_p),
        ("hwndMenuOwner", ctypes.c_void_p),
        ("hwndMoveSize", ctypes.c_void_p),
        ("hwndCaret", ctypes.c_void_p),
        ("rcCaret", _RECT),
    ]


def _gui_focus_snapshot() -> Optional[Dict[str, Any]]:
    """Which control has keyboard focus, and where its caret is, in the foreground thread (VF-17).

    ``caret`` is ``None`` for apps that do not expose a system caret (Chromium, Electron, UWP): for those the
    focus handle, the keystroke counter and the mouse-click counter are the only evidence there is.
    """
    if not _HAS_WIN32_API:
        return None
    try:
        info = _GUITHREADINFO()
        info.cbSize = ctypes.sizeof(_GUITHREADINFO)
        if not ctypes.windll.user32.GetGUIThreadInfo(0, ctypes.byref(info)):
            return None
        rect = info.rcCaret
        caret = (rect.left, rect.top, rect.right, rect.bottom)
        return {
            "active": int(info.hwndActive or 0),
            "focus": int(info.hwndFocus or 0),
            "caret_hwnd": int(info.hwndCaret or 0),
            "caret": caret if any(caret) else None,
        }
    except Exception:
        return None


class _MouseClickTracker:
    """Counts mouse button presses system-wide (low-level hook on its own message-pump thread).

    A click can move the caret or change the focused field without a single keystroke, which the keyboard counter
    cannot see. The hook never swallows or alters an event.
    """

    _DOWN = frozenset({0x0201, 0x0204, 0x0207, 0x020B, 0x0206})  # L/R/M/X button down, L double-click

    def __init__(self) -> None:
        self.count = 0
        self.live = False
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._thread_id = 0
        self._proc: Any = None

    def note(self, message: int) -> None:
        if message in self._DOWN:
            self.count += 1

    def start(self, timeout_s: float = 2.0) -> bool:
        if self.live:
            return True
        if not _HAS_WIN32_API:
            return False
        self._ready.clear()
        self._thread = threading.Thread(target=self._pump, daemon=True, name="VFMouseClickTracker")
        self._thread.start()
        self._ready.wait(timeout_s)
        return self.live

    def stop(self) -> None:
        if self.live and self._thread_id:
            try:
                ctypes.windll.user32.PostThreadMessageW(self._thread_id, 0x0012, 0, 0)  # WM_QUIT
            except Exception:
                pass
        self.live = False

    def _pump(self) -> None:
        from ctypes import wintypes

        user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
        hook_proc_type = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, ctypes.c_size_t, ctypes.c_ssize_t)
        user32.SetWindowsHookExW.argtypes = [ctypes.c_int, hook_proc_type, ctypes.c_void_p, ctypes.c_uint32]
        user32.SetWindowsHookExW.restype = ctypes.c_void_p
        user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t, ctypes.c_ssize_t]
        user32.CallNextHookEx.restype = ctypes.c_ssize_t
        user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]
        kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]

        def _proc(n_code: int, w_param: int, l_param: int) -> int:
            try:
                if n_code >= 0:
                    self.note(int(w_param))
            except Exception:
                pass
            return user32.CallNextHookEx(None, n_code, w_param, l_param)

        self._proc = hook_proc_type(_proc)  # keep a reference or the callback is collected
        try:
            hook = user32.SetWindowsHookExW(14, self._proc, kernel32.GetModuleHandleW(None), 0)  # WH_MOUSE_LL
            if not hook:
                return
            self._thread_id = int(kernel32.GetCurrentThreadId())
            self.live = True
        finally:
            self._ready.set()
        if not self.live:
            return
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        user32.UnhookWindowsHookEx(hook)
        self.live = False


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


class _PendingRestore:
    """The user's original clipboard, owed back to them.

    Lives from the end of a paste until the original is restored (or restoring has
    definitively failed), *including* any background retries. While one is
    outstanding, the next paste inherits it instead of snapshotting the clipboard,
    which by then holds the previous dictation.
    """

    def __init__(self, snapshot: Optional[dict], prev: Optional[str]) -> None:
        self.snapshot = snapshot
        self.prev = prev
        self.timer: Optional[threading.Timer] = None
        self.claimed = False          # a later paste took over the original contents
        self.started = False          # the restore body has begun (timer fired / inline)
        self.done = False             # restored, taken over, or definitively given up
        self.attempt_lock = threading.Lock()  # held for the duration of one write attempt
        self.wake = threading.Event()         # interrupts the retry back-off when claimed
        self.finished = threading.Event()
        self.run: Optional[Any] = None  # the restore body, for flush


# At most one restore is ever pending. Without this, two dictations less than the
# restore delay apart would snapshot the *first dictation's text* as the "user's
# clipboard", and the real clipboard would be gone for good.
_pending_lock = threading.Lock()
#: Notified whenever ``_active_preserves`` drops, so a shutdown flush can wait out a
#: paste that is mid-flight (it holds the user's original, unregistered, until its end).
_pending_cond = threading.Condition(_pending_lock)
_pending_restore: Optional[_PendingRestore] = None
#: Number of ``_preserve_clipboard`` bodies currently running with restore enabled.
_active_preserves = 0

#: Kill switch for the deferred restore. The test suite turns it off by default (see
#: tests/conftest.py) so a timer can never outlive a test and touch a real clipboard.
_ALLOW_DEFERRED_RESTORE = True

_RETRY_BACKOFF_S = 0.35

#: How long a paste waits on an in-flight restore write before logging that it is slow.
#: It keeps waiting after this; it only stops waiting once the write has finished.
_CLAIM_SLOW_WARN_S = 2.0


def _cancel_pending_restore_without_running() -> None:
    """Drop a pending restore without running it. Test teardown only."""
    global _pending_restore
    with _pending_lock:
        pending, _pending_restore = _pending_restore, None
    if pending is not None:
        pending.claimed = True
        pending.wake.set()
        if pending.timer is not None:
            pending.timer.cancel()


def _claim_pending_restore(log: Optional[logging.Logger] = None) -> Optional[_PendingRestore]:
    """Take over the original clipboard contents from a restore that has not finished.

    Returns the pending restore (its snapshot/prev are the user's real clipboard) with
    its timer cancelled or its retry loop told to stop, or None if there was nothing
    to take over (nothing pending, or the restore already completed so the clipboard
    holds the real contents and can be snapshotted normally).
    """
    global _pending_restore
    with _pending_lock:
        pending = _pending_restore
        if pending is None:
            return None
        if not pending.started:
            if pending.timer is not None:
                pending.timer.cancel()
            pending.claimed = True
            _pending_restore = None
            # Its obligation now belongs to the claiming paste; anyone waiting on this
            # pending (a shutdown flush) must move on to that paste's restore.
            pending.finished.set()
            return pending
    # The restore body is running: wait out any in-flight write, then stop its retries.
    # Never give up and snapshot instead: until the write finishes the clipboard holds
    # the previous dictation, and snapshotting it would lose the user's original for
    # good (VF-11b review finding 1). Each write attempt is itself bounded
    # (restore_attempts x back-off), so this wait always ends.
    if not pending.attempt_lock.acquire(timeout=_CLAIM_SLOW_WARN_S):
        if log:
            log.warning("clipboard_restore_claim_slow waited_s=%.1f", _CLAIM_SLOW_WARN_S)
        pending.attempt_lock.acquire()
    try:
        with _pending_lock:
            if _pending_restore is pending:
                _pending_restore = None
            if pending.done:
                return None
            pending.claimed = True
    finally:
        pending.attempt_lock.release()
    pending.wake.set()
    return pending


_FLUSH_SLOW_LOG_S = 2.0


def flush_pending_clipboard_restore(
    timeout: Optional[float] = None,
    log: Optional[logging.Logger] = None,
) -> bool:
    """Complete every restore still owed before returning (call at shutdown).

    Waits out a paste that is mid-flight, runs a not-yet-fired deferred restore inline,
    and waits for one that is already running -- including a slow write and the bounded
    background retries after an immediate failure. Returns True once nothing is owed
    (restored, or definitively given up after its bounded retries).

    ``timeout`` None (the default, used at shutdown) waits for completion. That wait is
    bounded by construction: each write attempt is ``restore_attempts`` x back-off and
    the retry window is ``restore_async_retry_seconds`` (8 s default), so a wedged
    clipboard can hold shutdown for roughly that long -- the price of never exiting
    with the user's clipboard still holding a dictation (VF-11b review finding 1).
    A finite ``timeout`` returns False if it expires first.
    """
    log = log or logging.getLogger("voiceflow")
    started_at = time.monotonic()
    deadline = None if timeout is None else started_at + max(0.0, float(timeout))
    warned = False

    def remaining() -> Optional[float]:
        if deadline is None:
            return _FLUSH_SLOW_LOG_S
        return max(0.0, min(_FLUSH_SLOW_LOG_S, deadline - time.monotonic()))

    def expired() -> bool:
        nonlocal warned
        if deadline is not None and time.monotonic() >= deadline:
            log.warning("clipboard_restore_flush_timeout waited_s=%.1f", time.monotonic() - started_at)
            return True
        if not warned and time.monotonic() - started_at >= _FLUSH_SLOW_LOG_S:
            warned = True
            log.warning("clipboard_restore_flush_slow waited_s=%.1f still_waiting=1", time.monotonic() - started_at)
        return False

    while True:
        with _pending_cond:
            # A paste mid-flight holds the original (claimed, not yet re-registered).
            while _active_preserves > 0:
                _pending_cond.wait(timeout=remaining())
                if _active_preserves > 0 and expired():
                    return False
            pending = _pending_restore
        if pending is None:
            return True
        if pending.timer is not None:
            pending.timer.cancel()
        if pending.run is not None:
            pending.run()  # inline if the timer has not fired; no-op if already running
        # Immediate-mode pendings (run is None) are retrying on a background thread;
        # waiting on ``finished`` covers them. (Do not set ``wake``: it stays set and
        # would turn the retry back-off into a busy loop.)
        while not pending.finished.wait(timeout=remaining()):
            if expired():
                return False
        # Loop: a paste that landed meanwhile may have registered a new pending.


def _restore_attempt(pending: _PendingRestore, *, attempts: int, base_delay: float) -> None:
    """One write of the original contents. Raises on failure; no-op once claimed."""
    with pending.attempt_lock:
        if pending.claimed:
            return
        if pending.snapshot is not None:
            _restore_clipboard_all_formats(pending.snapshot)
        elif pending.prev is not None:
            _clipboard_copy_with_retry(
                pending.prev,
                attempts=max(1, int(attempts)),
                base_delay=max(0.005, float(base_delay)),
            )


def _finish_restore(pending: _PendingRestore) -> None:
    global _pending_restore
    with _pending_lock:
        pending.done = True
        if _pending_restore is pending:
            _pending_restore = None
    pending.finished.set()


def _retry_restore(
    pending: _PendingRestore,
    first_error: Exception,
    *,
    restore_attempts: int,
    restore_base_delay: float,
    restore_async_retry_seconds: float,
    log: Optional[logging.Logger],
) -> None:
    """Bounded retries after an immediate failure. Runs inside the pending's lifecycle:
    the pending stays registered (so the next paste inherits it) until this returns."""
    window = max(0.5, float(restore_async_retry_seconds))
    deadline = time.time() + window
    last_error: Optional[Exception] = first_error
    try:
        while not pending.claimed and time.time() < deadline:
            pending.wake.wait(timeout=_RETRY_BACKOFF_S)
            if pending.claimed:
                break
            try:
                _restore_attempt(
                    pending,
                    attempts=max(2, int(restore_attempts)),
                    base_delay=restore_base_delay,
                )
                last_error = None
                if log and not pending.claimed:
                    log.info("clipboard_restore_async_success window_s=%.2f", window)
                break
            except Exception as exc:
                last_error = exc
        if last_error is not None and not pending.claimed and log:
            log.warning("clipboard_restore_async_failed window_s=%.2f error=%s", window, last_error)
    finally:
        _finish_restore(pending)


def _run_restore(
    pending: _PendingRestore,
    *,
    retry_in_background: bool,
    restore_attempts: int,
    restore_base_delay: float,
    restore_async_retry_seconds: float,
    log: Optional[logging.Logger],
) -> None:
    """First attempt, then (if it failed) bounded retries in the pending's lifecycle."""
    try:
        _restore_attempt(pending, attempts=restore_attempts, base_delay=restore_base_delay)
    except Exception as exc:
        if log:
            log.warning("clipboard_restore_immediate_failed error=%s", exc)

        failure = exc  # `exc` is unbound once the except block exits; retry() may run later

        def retry() -> None:
            _retry_restore(
                pending,
                failure,
                restore_attempts=restore_attempts,
                restore_base_delay=restore_base_delay,
                restore_async_retry_seconds=restore_async_retry_seconds,
                log=log,
            )

        if retry_in_background:
            threading.Thread(target=retry, name="ClipboardRestoreRetry", daemon=True).start()
        else:
            retry()
        return
    _finish_restore(pending)


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
    dropped: until it succeeds (or definitively fails after its bounded retries) it
    stays registered, and a following call inherits it instead of snapshotting the
    dictation. ``flush_pending_clipboard_restore`` forces it.
    ``restore_delay`` == 0 makes the first restore attempt before returning.

    While the body runs the call is counted in ``_active_preserves``: between claiming
    an inherited restore and registering its own, it is the only holder of the user's
    original, and a shutdown flush must wait for it.
    """
    global _pending_restore, _active_preserves
    if not enabled:
        yield
        return
    snapshot: Optional[dict] = None
    prev: Optional[str] = None
    with _pending_cond:
        _active_preserves += 1
    try:
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
            if snapshot is not None or prev is not None:
                restore_kwargs = dict(
                    restore_attempts=restore_attempts,
                    restore_base_delay=restore_base_delay,
                    restore_async_retry_seconds=restore_async_retry_seconds,
                    log=log,
                )
                pending = _PendingRestore(snapshot, prev)
                if float(restore_delay) <= 0.0 or not _ALLOW_DEFERRED_RESTORE:
                    pending.started = True
                    with _pending_lock:
                        _pending_restore = pending
                    _run_restore(pending, retry_in_background=True, **restore_kwargs)
                else:

                    def _run(pending: _PendingRestore = pending) -> None:
                        with _pending_lock:
                            if pending.claimed or pending.started:
                                return
                            pending.started = True
                        _run_restore(pending, retry_in_background=False, **restore_kwargs)

                    pending.run = _run
                    timer = threading.Timer(float(restore_delay), _run)
                    timer.daemon = True
                    pending.timer = timer
                    with _pending_lock:
                        _pending_restore = pending
                    timer.start()
    finally:
        with _pending_cond:
            _active_preserves -= 1
            _pending_cond.notify_all()


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
        self._mouse = _MouseClickTracker()
        self._settle_s = 0.4
        # Why the last inject() returned False: "" | "target_closed" | "focus_drift".
        # The app reads it to pick the overlay message and the history status.
        self.last_failure_reason: str = ""

    # ------------------------------------------------------------------ #
    # VF-17: replace-last-paste support
    # ------------------------------------------------------------------ #
    _MODIFIER_NAMES = frozenset({
        "ctrl", "left ctrl", "right ctrl", "shift", "left shift", "right shift", "alt", "left alt", "right alt",
        "alt gr", "windows", "left windows", "right windows", "caps lock", "num lock", "scroll lock",
    })

    def enable_replace_tracking(self) -> bool:
        """Opt in to 'replace last paste': key-press counter + mouse-click counter. True only when both are live."""
        self._ensure_key_counter()
        try:
            self._mouse.start()
        except Exception as exc:
            self._log.warning("mouse_tracker_unavailable error=%s", exc)
        return bool(self._key_counter_live and self._mouse.live)

    def _focus_snapshot(self) -> Optional[Dict[str, Any]]:
        return _gui_focus_snapshot()

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
        record = {
            "text": text,
            "hwnd": int(hwnd) if hwnd else None,
            "ts": time.time(),
            "keys": self._keys_typed,
            "clicks": self._mouse.count,
            "focus": None,  # the focused control / caret once the target app has finished handling the paste
        }
        self._last_paste = record
        if self._settle_s > 0:
            # Off the paste's critical path: the target processes Ctrl+V asynchronously, so the caret only reaches
            # its final position a moment later. A snapshot taken any earlier would make every replace look "moved".
            timer = threading.Timer(self._settle_s, self._settle_last_paste, args=(record,))
            timer.daemon = True
            timer.start()

    def _settle_last_paste(self, record: Dict[str, Any]) -> None:
        if self._last_paste is not record:
            return
        if record["keys"] != self._keys_typed or record["clicks"] != self._mouse.count:
            return  # the user already did something; leave "focus" unset so a replace is refused
        record["focus"] = self._focus_snapshot()

    @staticmethod
    def _focus_drift(before: Optional[Dict[str, Any]], now: Optional[Dict[str, Any]]) -> str:
        """"" when the same control still has focus with the caret where the paste left it."""
        if before is None or now is None:
            return "focus_unverifiable"
        if before.get("active") != now.get("active") or before.get("focus") != now.get("focus"):
            return "focus_changed"
        if before.get("caret_hwnd") != now.get("caret_hwnd"):
            return "focus_changed"
        if before.get("caret") != now.get("caret"):
            return "caret_moved"
        return ""

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
        # Same window is not proof of the same spot: a click or a focus change between fields leaves the
        # key counter at zero and the window handle unchanged, and a backspace run there deletes someone else's text.
        if not self._mouse.live:
            return "mouse_tracking_unavailable"
        if self._mouse.count != last.get("clicks"):
            return "clicked_since_paste"
        if last.get("focus") is None:
            return "paste_not_settled" if time.time() - float(last["ts"]) < self._settle_s + 0.5 else "focus_unverifiable"
        return self._focus_drift(last["focus"], self._focus_snapshot())

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

    def _refuse_replace(self, reason: str, new_text: str) -> str:
        copied = bool(self._sanitize(new_text).strip()) and self.copy_text_to_clipboard(new_text)
        self._log.info("replace_last_paste refused reason=%s clipboard=%s", reason, copied)
        return f"clipboard:{reason}" if copied else f"failed:{reason}"

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
            return self._refuse_replace(refusal, new_text)
        old = self._sanitize(old_text)
        if not bool(getattr(self.cfg, "paste_injection", True)):
            # Typing mode has no way to stage the replacement before the old text is deleted.
            return self._refuse_replace("typing_mode", new_text)
        self._injecting = True
        deleted = False
        ok = False
        try:
            with _preserve_clipboard(
                self.cfg.restore_clipboard,
                restore_attempts=max(1, int(getattr(self.cfg, "clipboard_restore_retry_attempts", 10))),
                restore_base_delay=max(0.005, int(getattr(self.cfg, "clipboard_restore_retry_base_delay_ms", 30)) / 1000.0),
                restore_async_retry_seconds=max(0.5, float(getattr(self.cfg, "clipboard_restore_async_retry_seconds", 8.0))),
                log=self._log,
            ):
                # 1. Prepare: the replacement must already be on the clipboard before anything is deleted.
                try:
                    _clipboard_copy_with_retry(new)
                except Exception as exc:
                    self._log.warning("replace_last_paste clipboard_prepare_failed error=%s", exc)
                    return "failed:clipboard"
                time.sleep(0.03)
                # 2. Re-verify after the staging delay: the user may have clicked or typed while we waited.
                late = self._replace_refusal(old_text, max_age_s)
                if late:
                    refused_late = late
                else:
                    refused_late = ""
                    # 3. Only now delete, then paste what is already staged.
                    deleted = True
                    for _ in range(len(old)):
                        keyboard.send("backspace")
                    keyboard.send(self.cfg.paste_shortcut)
                    ok = True
                    time.sleep(max(0, int(getattr(self.cfg, "clipboard_restore_delay_ms", 150))) / 1000.0)
            if refused_late:
                return self._refuse_replace(refused_late, new_text)
        except Exception as exc:
            self._log.warning("replace_last_paste failed deleted=%s error=%s", deleted, exc)
            if deleted:
                # The old text is gone and the paste did not complete: leave the replacement on the clipboard.
                self.copy_text_to_clipboard(new_text)
            return "failed:paste"
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
        self.last_failure_reason = ""
        if not self.target_window_exists():
            # The window we were going to paste into is gone. Pasting would land in whatever
            # has focus now; refusing lets the caller keep the text (history + clipboard).
            self.last_failure_reason = "target_closed"
            self._log.warning("inject_target_closed target_hwnd=%s", str(self._target_hwnd))
            return False
        if not self._ensure_target_focus_for_release():
            self.last_failure_reason = "focus_drift"
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

    def target_window_exists(self) -> bool:
        """False only when a captured target window is known to be destroyed."""
        hwnd = self._target_hwnd
        if not hwnd or not _HAS_WIN32_API:
            return True
        try:
            return bool(ctypes.windll.user32.IsWindow(int(hwnd)))
        except Exception:
            return True

    def foreground_snapshot(self) -> Optional[int]:
        """Cheap, non-blocking read of the foreground window handle (no title lookup).

        The hotkey listener calls this synchronously the instant a release is confirmed, then
        hands the handle to ``retarget_to_foreground`` later, off the hook thread.
        """
        return self._foreground_window()

    def retarget_to_foreground(self, hwnd: Optional[int] = None) -> bool:
        """Make a window the paste target (inject_target_policy=release).

        ``hwnd`` is the handle sampled at release (see ``foreground_snapshot``); when omitted the
        window that has focus NOW is used. Skips VoiceFlow's own windows (overlay, panels): if one
        of those is in front, the window captured at key-down stays the target. Returns True when
        the target changed.
        """
        fg = int(hwnd) if hwnd else self._foreground_window()
        if not fg or not _HAS_WIN32_API:
            return False
        try:
            pid = wintypes.DWORD(0)
            ctypes.windll.user32.GetWindowThreadProcessId(int(fg), ctypes.byref(pid))
            if int(pid.value) == os.getpid():
                return False
        except Exception:
            return False
        if self._target_hwnd == int(fg):
            return False
        self._target_hwnd = int(fg)
        self._target_context = self._build_window_context(int(fg))
        return True

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
