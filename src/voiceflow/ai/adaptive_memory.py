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
        self.retention_hours = int(getattr(cfg, "adaptive_retention_hours", 336))  # 14 days
        self.min_count = int(getattr(cfg, "adaptive_min_count", 3))
        # User-provided corrections are high-signal; activate after fewer observations.
        self.user_correction_min_count = int(getattr(cfg, "adaptive_user_correction_min_count", 2))
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
            score = float(entry.get("score", entry.get("count", 0)))
            sources = entry.get("sources", {})
            user_correction_sources = {
                "daily_user_correction", "correction_feedback", "manual_correction"
            }
            has_user_correction = any(
                k in user_correction_sources for k in sources
            )
            threshold = (
                float(self.user_correction_min_count)
                if has_user_correction
                else float(self.min_count)
            )
            if score < threshold:
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
        meta = dict(metadata or {})
        source_key = self._normalize_source(meta)
        weight = self._observation_weight(source_key)
        learned_pairs = self._extract_replacements(raw, final)
        replacements = self._patterns.setdefault("replacements", {})

        for src, dst in learned_pairs:
            key = f"{src.lower()}->{dst.lower()}"
            current = replacements.get(key, {
                "from": src,
                "to": dst,
                "count": 0,
                "score": 0.0,
                "first_seen": now,
                "last_seen": now,
                "sources": {},
            })
            current["count"] = int(current.get("count", 0)) + 1
            current["score"] = round(float(current.get("score", current.get("count", 0))) + weight, 3)
            current["last_seen"] = now
            sources = current.setdefault("sources", {})
            sources[source_key] = int(sources.get(source_key, 0)) + 1
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
            current_token = token_counts.get(normalized, {"token": normalized, "count": 0, "last_seen": now})
            if isinstance(current_token, dict):
                count_value = int(current_token.get("count", 0))
            else:
                count_value = int(current_token or 0)
                current_token = {"token": normalized, "count": count_value, "last_seen": now}
            current_token["token"] = normalized
            current_token["count"] = count_value + 1
            current_token["last_seen"] = now
            token_counts[normalized] = current_token

        self._patterns["updated_at"] = now
        self._append_event(raw, final, learned_pairs, meta, now)
        self._save_patterns()
        self._purge_expired()

    @staticmethod
    def _normalize_source(metadata: Dict[str, Any]) -> str:
        source = str(metadata.get("source", "") or "").strip().lower()
        return source or "runtime_transcription"

    @staticmethod
    def _observation_weight(source: str) -> float:
        weighted_sources = {
            "daily_user_correction": 1.5,
            "correction_feedback": 1.5,
            "manual_correction": 1.5,
            "daily_instruction_pass": 1.0,
            "runtime_transcription": 1.0,
            "daily_auto_analysis": 0.5,
        }
        return float(weighted_sources.get(str(source or "").strip().lower(), 1.0))

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

        token_counts = self._patterns.get("token_counts", {})
        fresh_tokens: Dict[str, Dict[str, Any]] = {}
        fallback_last_seen = int(self._patterns.get("updated_at", 0) or 0)
        for key, value in token_counts.items():
            if isinstance(value, dict):
                token_name = str(value.get("token", key) or key).strip().lower()
                token_count = int(value.get("count", 0) or 0)
                last_seen = int(value.get("last_seen", fallback_last_seen) or fallback_last_seen)
            else:
                token_name = str(key or "").strip().lower()
                token_count = int(value or 0)
                last_seen = fallback_last_seen
            if not token_name or token_count <= 0:
                continue
            if not self._is_fresh(last_seen, cutoff=cutoff):
                continue
            fresh_tokens[token_name] = {
                "token": token_name,
                "count": token_count,
                "last_seen": last_seen,
            }
        self._patterns["token_counts"] = fresh_tokens

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

    def snapshot(self, *, max_rules: int = 12, max_tokens: int = 20) -> Dict[str, Any]:
        replacements = []
        for entry in self._patterns.get("replacements", {}).values():
            count = int(entry.get("count", 0) or 0)
            score = float(entry.get("score", count))
            sources = entry.get("sources", {})
            replacements.append(
                {
                    "from": str(entry.get("from", "")),
                    "to": str(entry.get("to", "")),
                    "count": count,
                    "score": score,
                    "last_seen": int(entry.get("last_seen", 0) or 0),
                    "sources": {
                        str(k): int(v)
                        for k, v in dict(sources).items()
                        if str(k).strip()
                    },
                }
            )
        replacements.sort(
            key=lambda item: (float(item.get("score", 0.0)), int(item.get("count", 0)), int(item.get("last_seen", 0))),
            reverse=True,
        )

        tokens = []
        for key, value in self._patterns.get("token_counts", {}).items():
            if isinstance(value, dict):
                token_name = str(value.get("token", key) or key).strip().lower()
                token_count = int(value.get("count", 0) or 0)
            else:
                token_name = str(key or "").strip().lower()
                token_count = int(value or 0)
            if not token_name or token_count <= 0:
                continue
            tokens.append({"token": token_name, "count": token_count})
        tokens.sort(key=lambda item: (int(item.get("count", 0)), str(item.get("token", ""))), reverse=True)

        return {
            "activation_threshold": float(self.min_count),
            "retention_hours": int(self.retention_hours),
            "top_replacements": replacements[: max(1, int(max_rules))],
            "top_tokens": tokens[: max(1, int(max_tokens))],
        }
