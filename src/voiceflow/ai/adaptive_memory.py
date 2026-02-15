"""
Privacy-first adaptive learning for VoiceFlow.

This module keeps a temporary local audit log and learns lightweight
replacement patterns from recurring correction deltas.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Tuple

from voiceflow.utils.settings import config_dir

logger = logging.getLogger(__name__)

TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9']+")
STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "i", "in",
    "is", "it", "of", "on", "or", "that", "the", "this", "to", "was", "we",
    "with", "you",
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _tokenize(text: str) -> List[str]:
    return TOKEN_RE.findall(text)


class AdaptiveLearningManager:
    """Local temporary pattern learner with retention-based purging."""

    def __init__(self, cfg: Any):
        self.enabled = bool(getattr(cfg, "adaptive_learning_enabled", True))
        self.store_raw_text = bool(getattr(cfg, "adaptive_store_raw_text", False))
        self.retention_hours = int(getattr(cfg, "adaptive_retention_hours", 72))
        self.min_count = int(getattr(cfg, "adaptive_min_count", 3))
        self.max_rules = int(getattr(cfg, "adaptive_max_rules", 200))
        self._max_preview_len = int(getattr(cfg, "adaptive_snippet_chars", 200))

        base = config_dir()
        self.audit_path = base / "adaptive_audit.jsonl"
        self.patterns_path = base / "adaptive_patterns.json"
        self._patterns = {
            "replacements": {},
            "token_counts": {},
            "updated_at": int(time.time()),
        }

        self._load_patterns()
        self._purge_expired()

    def apply(self, text: str) -> str:
        """Apply learned replacements that reached confidence threshold."""
        if not self.enabled or not text.strip():
            return text

        output = text
        now = int(time.time())
        replacements = self._patterns.get("replacements", {})

        for entry in replacements.values():
            if entry.get("count", 0) < self.min_count:
                continue
            if not self._is_fresh(entry.get("last_seen", 0), now):
                continue

            src = entry.get("from", "")
            dst = entry.get("to", "")
            if not src or not dst or src.lower() == dst.lower():
                continue

            pattern = re.compile(rf"\b{re.escape(src)}\b", re.IGNORECASE)
            output = pattern.sub(lambda m, replacement=dst: self._match_case(m.group(0), replacement), output)

        return output

    def observe(
        self,
        raw_text: str,
        final_text: str,
        metadata: Dict[str, Any] | None = None,
    ) -> None:
        """Learn from raw->final deltas and append temp audit event."""
        if not self.enabled:
            return

        raw = (raw_text or "").strip()
        final = (final_text or "").strip()
        if not raw and not final:
            return

        now = int(time.time())
        learned_pairs = self._extract_replacements(raw, final)
        replacements = self._patterns.setdefault("replacements", {})

        for src, dst in learned_pairs:
            key = f"{src.lower()}->{dst.lower()}"
            current = replacements.get(key, {
                "from": src,
                "to": dst,
                "count": 0,
                "first_seen": now,
                "last_seen": now,
            })
            current["count"] = int(current.get("count", 0)) + 1
            current["last_seen"] = now
            replacements[key] = current

        # Keep only the most recently updated rules.
        if len(replacements) > self.max_rules:
            ranked = sorted(
                replacements.items(),
                key=lambda kv: (int(kv[1].get("last_seen", 0)), int(kv[1].get("count", 0))),
                reverse=True,
            )
            self._patterns["replacements"] = dict(ranked[: self.max_rules])

        token_counts = self._patterns.setdefault("token_counts", {})
        for token in _tokenize(final):
            normalized = token.lower()
            if len(normalized) < 3 or normalized in STOP_WORDS:
                continue
            token_counts[normalized] = int(token_counts.get(normalized, 0)) + 1

        self._patterns["updated_at"] = now
        self._append_event(raw, final, learned_pairs, metadata or {}, now)
        self._save_patterns()
        self._purge_expired()

    def _extract_replacements(self, raw_text: str, final_text: str) -> List[Tuple[str, str]]:
        raw_tokens = _tokenize(raw_text)
        final_tokens = _tokenize(final_text)
        if not raw_tokens or not final_tokens:
            return []

        matches: List[Tuple[str, str]] = []
        matcher = SequenceMatcher(a=[t.lower() for t in raw_tokens], b=[t.lower() for t in final_tokens])
        for tag, a0, a1, b0, b1 in matcher.get_opcodes():
            if tag != "replace":
                continue
            if (a1 - a0) != 1 or (b1 - b0) != 1:
                continue
            src = raw_tokens[a0]
            dst = final_tokens[b0]
            if src.lower() == dst.lower():
                continue
            if len(src) < 2 or len(dst) < 2:
                continue
            matches.append((src, dst))
        return matches

    def _append_event(
        self,
        raw_text: str,
        final_text: str,
        learned_pairs: List[Tuple[str, str]],
        metadata: Dict[str, Any],
        timestamp: int,
    ) -> None:
        event: Dict[str, Any] = {
            "ts": timestamp,
            "raw_hash": _sha(raw_text),
            "final_hash": _sha(final_text),
            "raw_chars": len(raw_text),
            "final_chars": len(final_text),
            "learned_pairs": [[a, b] for a, b in learned_pairs],
            "metadata": metadata,
        }

        if self.store_raw_text:
            event["raw_text"] = raw_text[: self._max_preview_len]
            event["final_text"] = final_text[: self._max_preview_len]

        try:
            with self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=True) + "\n")
        except Exception as exc:
            logger.warning(f"Failed to write adaptive audit event: {exc}")

    def _load_patterns(self) -> None:
        if not self.patterns_path.exists():
            return
        try:
            data = json.loads(self.patterns_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._patterns.update(data)
        except Exception as exc:
            logger.warning(f"Failed to load adaptive patterns: {exc}")

    def _save_patterns(self) -> None:
        try:
            self.patterns_path.write_text(
                json.dumps(self._patterns, indent=2, ensure_ascii=True),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning(f"Failed to save adaptive patterns: {exc}")

    def _purge_expired(self) -> None:
        cutoff = int(time.time()) - max(1, self.retention_hours) * 3600

        replacements = self._patterns.get("replacements", {})
        fresh = {
            key: value
            for key, value in replacements.items()
            if self._is_fresh(int(value.get("last_seen", 0)), cutoff=cutoff)
        }
        self._patterns["replacements"] = fresh

        if not self.audit_path.exists():
            return

        kept_lines: List[str] = []
        try:
            with self.audit_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                        ts = int(payload.get("ts", 0))
                        if ts >= cutoff:
                            kept_lines.append(json.dumps(payload, ensure_ascii=True))
                    except Exception:
                        continue
            self.audit_path.write_text(
                "".join(f"{item}\n" for item in kept_lines),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning(f"Failed to purge adaptive audit logs: {exc}")

    def _is_fresh(self, timestamp: int, now: int | None = None, cutoff: int | None = None) -> bool:
        if cutoff is None:
            current = now or int(time.time())
            cutoff = current - max(1, self.retention_hours) * 3600
        return int(timestamp) >= int(cutoff)

    @staticmethod
    def _match_case(source_word: str, replacement: str) -> str:
        if source_word.isupper():
            return replacement.upper()
        if source_word[:1].isupper():
            return replacement[:1].upper() + replacement[1:]
        return replacement.lower()
