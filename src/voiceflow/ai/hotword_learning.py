"""Corrections that stick: terms the user fixes repeatedly become Whisper hotwords.

The adaptive learner keeps replacement rules for ``adaptive_retention_hours`` (72 by
default) after they were last seen, which is right for sloppy auto-detected patterns but
wrong for a word the user has told us, twice, is spelled "Ollama": that should not decay
because it went unused for a long weekend. This store keeps only the *corrected term* (a
short word or phrase, never a transcript), only from EXPLICIT user corrections, only after
``min_count`` of them, and feeds them into the hotword string sent to Whisper
(``effective_hotwords``).

Local only. The file is ``learned_hotwords.json`` in the VoiceFlow data directory, it is
never uploaded, and the cloud-learning opt-in (VF-03) is unrelated: nothing here sends
anything anywhere.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

#: Always present, regardless of what an older saved config says (saved configs override
#: dataclass defaults, so a default change alone never reaches an existing install).
SEED_HOTWORDS: Tuple[str, ...] = (
    "VoiceFlow", "Wispr", "Claude", "Codex", "Gemini", "Ollama", "Atlas", "LIMS", "Veeva", "Madison",
)

#: Sources that count as the user explicitly correcting a transcript.
EXPLICIT_CORRECTION_SOURCES = frozenset(
    {"manual_correction", "correction_feedback", "daily_user_correction"}
)

#: Character budget for the whole hotword string. Hotwords are prepended to every 30 s
#: decode window, so they compete with the text conditioning for Whisper's prompt tokens.
MAX_HOTWORD_CHARS = 320

_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9'\-]*")
_COMMON = frozenset(
    "the and for that this with have from they will would there their what about which when "
    "your you are was were been being not but can could should just like then than them some "
    "into over also more most very much such only other these those here where who whom why "
    "how its it's i'm don't isn't".split()
)


def is_term_like(term: str) -> bool:
    """A corrected phrase worth biasing the decoder toward: 1-3 words, not common words."""
    tokens = _TOKEN.findall(term or "")
    if not 1 <= len(tokens) <= 3:
        return False
    if " ".join(tokens).strip().lower() != re.sub(r"\s+", " ", (term or "").strip().lower()):
        return False  # punctuation or digits-only words in the middle: not a plain term
    if all(t.lower() in _COMMON for t in tokens):
        return False
    return all(len(t) >= 3 or t.isupper() for t in tokens)


def default_store_path() -> Path:
    from voiceflow.utils.settings import config_dir

    return config_dir() / "learned_hotwords.json"


class LearnedHotwords:
    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        min_count: int = 2,
        max_terms: int = 24,
        max_stored: int = 200,
    ) -> None:
        self.path = Path(path) if path is not None else default_store_path()
        self.min_count = max(1, int(min_count))
        self.max_terms = max(0, int(max_terms))
        self.max_stored = max(self.max_terms, int(max_stored))
        self._lock = threading.RLock()
        self._terms: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------ persistence
    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except Exception as exc:
            logger.warning("learned_hotwords_load_failed path=%s error=%s", self.path, exc)
            return
        terms = raw.get("terms") if isinstance(raw, dict) else None
        if isinstance(terms, dict):
            for key, entry in terms.items():
                if isinstance(entry, dict) and str(entry.get("term", "")).strip():
                    self._terms[str(key)] = {
                        "term": str(entry["term"]).strip(),
                        "count": int(entry.get("count", 1) or 1),
                        "last_seen": float(entry.get("last_seen", 0.0) or 0.0),
                    }

    def _save_locked(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".hotwords-", suffix=".tmp", dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump({"version": 1, "terms": self._terms}, handle, ensure_ascii=False)
                os.replace(tmp, self.path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except Exception as exc:
            logger.warning("learned_hotwords_save_failed path=%s error=%s", self.path, exc)

    # ------------------------------------------------------------------ learning
    def observe_pairs(self, pairs: Iterable[Tuple[str, str]]) -> int:
        """Count the corrected side (``dst``) of each ``(wrong, right)`` pair. Returns how many
        pairs were counted."""
        counted = 0
        now = time.time()
        with self._lock:
            for _src, dst in pairs:
                dst = " ".join(str(dst or "").split())
                if not is_term_like(dst):
                    continue
                key = dst.lower()
                entry = self._terms.get(key) or {"term": dst, "count": 0, "last_seen": now}
                # Keep the spelling the user typed most recently (they are the authority).
                entry["term"] = dst
                entry["count"] = int(entry["count"]) + 1
                entry["last_seen"] = now
                self._terms[key] = entry
                counted += 1
            if counted:
                if len(self._terms) > self.max_stored:
                    ranked = sorted(
                        self._terms.items(),
                        key=lambda kv: (kv[1]["count"], kv[1]["last_seen"]),
                        reverse=True,
                    )
                    self._terms = dict(ranked[: self.max_stored])
                self._save_locked()
        return counted

    def forget(self, term: str) -> bool:
        with self._lock:
            removed = self._terms.pop(" ".join(str(term or "").split()).lower(), None) is not None
            if removed:
                self._save_locked()
            return removed

    def terms(self) -> List[str]:
        """Promoted terms: corrected at least ``min_count`` times, most-corrected first."""
        with self._lock:
            promoted = [e for e in self._terms.values() if int(e["count"]) >= self.min_count]
        promoted.sort(key=lambda e: (int(e["count"]), float(e["last_seen"])), reverse=True)
        return [str(e["term"]) for e in promoted[: self.max_terms]]


# ---------------------------------------------------------------------- hotword string

_CACHE: Dict[str, Tuple[float, List[str]]] = {}


def _learned_terms(path: Optional[Path], min_count: int, max_terms: int) -> List[str]:
    target = Path(path) if path is not None else default_store_path()
    try:
        mtime = target.stat().st_mtime
    except OSError:
        return []
    key = f"{target}|{min_count}|{max_terms}"
    cached = _CACHE.get(key)
    if cached and cached[0] == mtime:
        return cached[1]
    terms = LearnedHotwords(target, min_count=min_count, max_terms=max_terms).terms()
    _CACHE[key] = (mtime, terms)
    return terms


def effective_hotwords(
    configured: str = "",
    *,
    learned_enabled: bool = True,
    min_count: int = 2,
    max_terms: int = 24,
    store_path: Optional[Path] = None,
    max_chars: int = MAX_HOTWORD_CHARS,
) -> str:
    """Seed terms + configured terms + learned terms, de-duplicated, within the budget.

    Order is priority order: seeds and the user's configured terms are never crowded out by
    learned ones; learned terms fill what is left, most-corrected first.
    """
    configured_terms = [t.strip() for t in str(configured or "").split(",") if t.strip()]
    learned = _learned_terms(store_path, min_count, max_terms) if learned_enabled else []
    seen: set = set()
    out: List[str] = []
    length = 0
    for term in (*SEED_HOTWORDS, *configured_terms, *learned):
        key = term.lower()
        if key in seen:
            continue
        added = len(term) + (2 if out else 0)
        if length + added > max_chars:
            continue
        seen.add(key)
        out.append(term)
        length += added
    return ", ".join(out)


def effective_hotwords_for_config(cfg: Any) -> str:
    return effective_hotwords(
        str(getattr(cfg, "asr_hotwords", "") or ""),
        learned_enabled=bool(getattr(cfg, "learned_hotwords_enabled", True)),
        min_count=int(getattr(cfg, "learned_hotword_min_count", 2)),
        max_terms=int(getattr(cfg, "learned_hotwords_max", 24)),
    )


__all__: Sequence[str] = (
    "SEED_HOTWORDS",
    "EXPLICIT_CORRECTION_SOURCES",
    "LearnedHotwords",
    "effective_hotwords",
    "effective_hotwords_for_config",
    "is_term_like",
)
