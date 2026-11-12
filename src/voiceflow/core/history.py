"""Local transcript history: the last N dictations, kept so none is ever lost.

Purpose (VF-12 item 3): a paste can miss (target window closed, focus stolen,
clipboard busy) and the recognised text must not vanish with it. Every final
transcript is written here *before* the paste is attempted; the paste outcome is
recorded afterwards. The tray's "Recent" list and the re-paste hotkey read from here.

Privacy: a small JSON file under the VoiceFlow data directory
(``%LOCALAPPDATA%\\VoiceFlow``), written atomically, never uploaded. It stores the
text, a timestamp, the word count, the paste outcome and the target *process name*
(never window titles). ``clear()`` deletes the content; the tray offers it.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

HISTORY_FILENAME = "transcript_history.json"
DEFAULT_MAX_ITEMS = 50
_MAX_TEXT_CHARS = 20000

#: Paste outcomes recorded on an entry.
STATUS_PENDING = "pending"
STATUS_PASTED = "pasted"
STATUS_SAVED = "saved"            # recognised and kept, not pasted (e.g. target closed)
STATUS_CLIPBOARD = "clipboard"    # not pasted but placed on the clipboard
STATUS_FAILED = "failed"          # nothing was pasted because nothing usable was recognised

#: Why a dictation produced no paste. Keys are stable (they are logged and stored);
#: values are what the user reads.
FAILURE_REASONS: Dict[str, str] = {
    "no_audio": "The microphone delivered no audio",
    "silent": "Only silence was recorded",
    "no_speech": "No speech was detected (nothing pasted)",
    "non_speech": "It sounded like a noise burst, not speech",
    "filtered": "Discarded as a likely silence artifact",
    "too_short": "The recognised text was too short to paste",
    "empty": "The speech model returned no text",
    "timeout": "Transcription timed out",
    "error": "Transcription failed with an error",
}


def failure_summary(entry: Dict[str, Any]) -> str:
    """One readable line saying why an entry was not transcribed."""
    reason = str(entry.get("reason", "") or "")
    line = FAILURE_REASONS.get(reason, reason.replace("_", " ").capitalize() or "Not transcribed")
    detail = str(entry.get("detail", "") or "").strip()
    seconds = float(entry.get("audio_seconds", 0.0) or 0.0)
    parts = [line]
    if detail:
        parts.append(detail)
    if seconds > 0:
        parts.append(f"{seconds:.1f}s of audio")
    return " - ".join(parts)


def copy_text(entry: Dict[str, Any]) -> str:
    """What "copy" puts on the clipboard for an entry.

    The transcript when there is one, including text a filter threw away, so a
    wrongly discarded dictation is recoverable. Otherwise the failure line.
    """
    text = str(entry.get("text", "") or "").strip()
    if text:
        return text
    return "VoiceFlow did not transcribe this: " + failure_summary(entry)


def default_history_path() -> Path:
    from voiceflow.utils.settings import config_dir

    return config_dir() / HISTORY_FILENAME


class TranscriptHistory:
    """Bounded, thread-safe, crash-safe list of recent transcripts (newest last)."""

    def __init__(self, path: Optional[Path] = None, max_items: int = DEFAULT_MAX_ITEMS) -> None:
        self.path = Path(path) if path is not None else default_history_path()
        self.max_items = max(1, int(max_items))
        self._lock = threading.RLock()
        self._items: List[Dict[str, Any]] = []
        self._next_id = 1
        self._load()

    # ---------------------------------------------------------------- persistence
    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except Exception as exc:
            logger.warning("history_load_failed path=%s error=%s", self.path, exc)
            self._quarantine_corrupt()
            return
        items = raw.get("items") if isinstance(raw, dict) else None
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            if str(item.get("text", "")).strip() or item.get("status") == STATUS_FAILED:
                self._items.append(item)
        self._items = self._items[-self.max_items:]
        self._next_id = max((int(i.get("id", 0) or 0) for i in self._items), default=0) + 1

    def _quarantine_corrupt(self) -> None:
        """Keep an unreadable file for inspection instead of silently overwriting it."""
        try:
            self.path.replace(self.path.with_suffix(".corrupt"))
        except Exception:
            pass

    def _save_locked(self) -> None:
        payload = {"version": 1, "items": self._items}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".history-", suffix=".tmp", dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, ensure_ascii=False)
                os.replace(tmp, self.path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except Exception as exc:
            logger.warning("history_save_failed path=%s error=%s", self.path, exc)

    # ---------------------------------------------------------------- API
    def add(self, text: str, *, target: str = "", status: str = STATUS_PENDING) -> int:
        """Record a transcript. Returns its id (0 when there was nothing to record)."""
        clean = str(text or "").strip()
        if not clean:
            return 0
        with self._lock:
            entry = {
                "id": self._next_id,
                "ts": time.time(),
                "text": clean[:_MAX_TEXT_CHARS],
                "words": len(clean.split()),
                "status": status,
                "target": str(target or "")[:80],
            }
            self._next_id += 1
            self._items.append(entry)
            self._items = self._items[-self.max_items:]
            self._save_locked()
            return int(entry["id"])

    def add_failure(
        self,
        reason: str,
        *,
        detail: str = "",
        text: str = "",
        audio_seconds: float = 0.0,
        target: str = "",
    ) -> int:
        """Record a dictation that produced nothing to paste, and why.

        ``text`` is whatever was recognised before it was thrown away (a
        filtered or too-short result); it stays copyable.
        """
        clean = str(text or "").strip()
        with self._lock:
            entry = {
                "id": self._next_id,
                "ts": time.time(),
                "text": clean[:_MAX_TEXT_CHARS],
                "words": len(clean.split()),
                "status": STATUS_FAILED,
                "reason": str(reason or "error")[:40],
                "detail": str(detail or "")[:300],
                "audio_seconds": round(float(audio_seconds or 0.0), 2),
                "target": str(target or "")[:80],
            }
            self._next_id += 1
            self._items.append(entry)
            self._items = self._items[-self.max_items:]
            self._save_locked()
            return int(entry["id"])

    def set_status(self, entry_id: int, status: str) -> None:
        with self._lock:
            for item in self._items:
                if int(item.get("id", -1)) == int(entry_id):
                    item["status"] = status
                    self._save_locked()
                    return

    def recent(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Newest first."""
        with self._lock:
            items = list(reversed(self._items))
        return items[: int(limit)] if limit else items

    def last(self) -> Optional[Dict[str, Any]]:
        """The most recent entry that has text (a failure with no text cannot be re-pasted)."""
        with self._lock:
            for item in reversed(self._items):
                if str(item.get("text", "")).strip():
                    return dict(item)
        return None

    def get(self, entry_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            for item in self._items:
                if int(item.get("id", -1)) == int(entry_id):
                    return dict(item)
        return None

    def clear(self) -> None:
        with self._lock:
            self._items = []
            self._save_locked()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


def menu_pages(entries: List[Dict[str, Any]], first: int = 10, page: int = 10) -> List[tuple]:
    """Split newest-first ``entries`` into tray-menu pages so every retained item is reachable.

    Returns ``[(title, [entry, ...]), ...]``. The first page (title ``None``) is shown inline in
    the Recent menu; the rest become submenus titled e.g. ``"Older (11-20)"``.
    """
    entries = list(entries)
    pages: List[tuple] = [(None, entries[:first])]
    start = first
    while start < len(entries):
        chunk = entries[start : start + page]
        pages.append((f"Older ({start + 1}-{start + len(chunk)})", chunk))
        start += page
    return pages


def menu_label(entry: Dict[str, Any], width: int = 56) -> str:
    """One-line label for a tray menu item: ``12:41  first words of the transcript...``."""
    failed = entry.get("status") == STATUS_FAILED
    text = " ".join(str(entry.get("text", "")).split())
    if failed:
        # With recovered text, keep the tag short: the text is what the user is looking for.
        tag = {"filtered": "discarded", "too_short": "too short", "no_speech": "no speech"}.get(str(entry.get("reason", "")), "failed")
        text = f"[{tag}] {text}" if text else f"[failed] {failure_summary(entry)}"
    if len(text) > width:
        text = text[: width - 1].rstrip() + "…"
    try:
        stamp = time.strftime("%H:%M", time.localtime(float(entry.get("ts", 0.0))))
    except Exception:
        stamp = "--:--"
    marker = "" if entry.get("status") in (STATUS_PASTED, STATUS_PENDING, STATUS_FAILED) else " (not pasted)"
    # '&' is a menu accelerator marker in Win32 menus; double it so text shows literally.
    return f"{stamp}  {text}{marker}".replace("&", "&&")
