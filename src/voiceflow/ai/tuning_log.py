"""Full-fidelity local tuning log (VF-17 item 2).

``adaptive_audit.jsonl`` already stores a raw/final pair per dictation, but it
truncates both at ~200 characters and is purged by ``adaptive_retention_hours``
(72 h on the live install), so it cannot serve as a corpus to tune or score
against. This log keeps the *whole* utterance (cap ``max_chars``, default
8000) for each stage of the pipeline:

    raw_text            what the ASR said
    final_text          what was pasted
    reconstructed_text  what the reconstruction pass proposed (if it ran)
    reconstruction      status / guard reason / latency / model
    metadata            model tier, durations, retry path, ...

It is a local file under ``%LOCALAPPDATA%\\VoiceFlow``. It is **never uploaded**
(VF-03's local-only decision stands): nothing in this module imports a network
client, and the cloud learning paths read the audit/history files, not this one.

Rotation: when the active file reaches ``max_entries`` lines or its oldest
entry is older than ``max_age_days`` (whichever first) it is moved to
``tuning_log.prev.jsonl`` (replacing the previous generation) and a fresh file
is started. Disk use is therefore bounded to two generations.

Records are append-only. Later facts about an utterance (the async
reconstruction verdict, a user edit) are separate records sharing the same
``id``; ``load_utterances()`` merges them.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
ACTIVE_NAME = "tuning_log.jsonl"
PREVIOUS_NAME = "tuning_log.prev.jsonl"


def _cap(text: Any, limit: int) -> tuple[str, bool]:
    value = "" if text is None else str(text)
    if len(value) <= limit:
        return value, False
    return value[:limit], True


class TuningLog:
    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        max_chars: int = 8000,
        max_entries: int = 2000,
        max_age_days: float = 30.0,
        enabled: bool = True,
    ) -> None:
        if path is None:
            from voiceflow.utils.settings import config_dir

            path = config_dir() / ACTIVE_NAME
        self.path = Path(path)
        self.previous_path = self.path.with_name(PREVIOUS_NAME)
        self.max_chars = max(100, int(max_chars))
        self.max_entries = max(10, int(max_entries))
        self.max_age_seconds = max(1.0, float(max_age_days) * 86400.0)
        self.enabled = bool(enabled)
        self._lock = threading.Lock()
        self._count: Optional[int] = None
        self._oldest_ts: Optional[float] = None

    @classmethod
    def from_config(cls, cfg: Any, path: Optional[Path] = None) -> "TuningLog":
        return cls(
            path,
            max_chars=int(getattr(cfg, "tuning_log_max_chars", 8000)),
            max_entries=int(getattr(cfg, "tuning_log_max_entries", 2000)),
            max_age_days=float(getattr(cfg, "tuning_log_max_age_days", 30)),
            enabled=bool(getattr(cfg, "tuning_log_enabled", True)),
        )

    # ------------------------------------------------------------------ write

    def append_utterance(
        self,
        *,
        raw_text: str,
        final_text: str,
        reconstructed_text: Optional[str] = None,
        reconstruction: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        utterance_id: Optional[str] = None,
    ) -> str:
        """Record one dictation. Returns its id (empty string when disabled)."""
        if not self.enabled:
            return ""
        uid = utterance_id or uuid.uuid4().hex[:12]
        raw, raw_trunc = _cap(raw_text, self.max_chars)
        final, final_trunc = _cap(final_text, self.max_chars)
        record: Dict[str, Any] = {
            "v": SCHEMA_VERSION,
            "kind": "utterance",
            "id": uid,
            "ts": time.time(),
            "raw_text": raw,
            "final_text": final,
            "truncated": bool(raw_trunc or final_trunc),
            "metadata": dict(metadata or {}),
        }
        if reconstructed_text is not None:
            recon, recon_trunc = _cap(reconstructed_text, self.max_chars)
            record["reconstructed_text"] = recon
            record["truncated"] = bool(record["truncated"] or recon_trunc)
        if reconstruction:
            record["reconstruction"] = dict(reconstruction)
        self._write(record)
        return uid

    def append_reconstruction(
        self,
        utterance_id: str,
        *,
        reconstructed_text: Optional[str],
        reconstruction: Dict[str, Any],
    ) -> None:
        """Late verdict from the async reconstruction path."""
        if not self.enabled or not utterance_id:
            return
        record: Dict[str, Any] = {
            "v": SCHEMA_VERSION,
            "kind": "reconstruction",
            "id": utterance_id,
            "ts": time.time(),
            "reconstruction": dict(reconstruction),
        }
        if reconstructed_text is not None:
            record["reconstructed_text"], _ = _cap(reconstructed_text, self.max_chars)
        self._write(record)

    def append_user_edit(self, utterance_id: str, edited_text: str) -> None:
        """The text the user actually settled on (raw -> reconstructed -> edited)."""
        if not self.enabled or not utterance_id:
            return
        text, _ = _cap(edited_text, self.max_chars)
        self._write({
            "v": SCHEMA_VERSION,
            "kind": "user_edit",
            "id": utterance_id,
            "ts": time.time(),
            "edited_text": text,
        })

    def _write(self, record: Dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=True)
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._rotate_if_needed(float(record["ts"]))
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                self._count = (self._count or 0) + 1
                if self._oldest_ts is None:
                    self._oldest_ts = float(record["ts"])
            except Exception as exc:  # logging must never break dictation
                logger.warning("tuning_log write failed: %s", exc)

    def _prime(self) -> None:
        """Count lines / find the oldest timestamp once per process."""
        if self._count is not None:
            return
        count = 0
        oldest: Optional[float] = None
        if self.path.exists():
            try:
                with self.path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        count += 1
                        if oldest is None:
                            try:
                                oldest = float(json.loads(line).get("ts"))
                            except Exception:
                                oldest = None
            except Exception as exc:
                logger.warning("tuning_log prime failed: %s", exc)
        self._count = count
        self._oldest_ts = oldest

    def _rotate_if_needed(self, now: float) -> None:
        self._prime()
        too_many = (self._count or 0) >= self.max_entries
        too_old = self._oldest_ts is not None and (now - self._oldest_ts) >= self.max_age_seconds
        if not (too_many or too_old) or not self.path.exists():
            return
        try:
            if self.previous_path.exists():
                self.previous_path.unlink()
            self.path.replace(self.previous_path)
        except Exception as exc:
            logger.warning("tuning_log rotation failed: %s", exc)
            return
        self._count = 0
        self._oldest_ts = None

    # ------------------------------------------------------------------- read

    def iter_records(self) -> Iterable[Dict[str, Any]]:
        for target in (self.previous_path, self.path):
            if not target.exists():
                continue
            try:
                with target.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except Exception:
                            continue
            except Exception as exc:
                logger.warning("tuning_log read failed for %s: %s", target, exc)

    def load_utterances(self) -> List[Dict[str, Any]]:
        """Utterances with later reconstruction / user-edit records merged in."""
        merged: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        for rec in self.iter_records():
            uid = str(rec.get("id", ""))
            kind = rec.get("kind")
            if kind == "utterance":
                if uid not in merged:
                    order.append(uid)
                merged[uid] = dict(rec)
            elif uid in merged:
                if kind == "reconstruction":
                    if "reconstructed_text" in rec:
                        merged[uid]["reconstructed_text"] = rec["reconstructed_text"]
                    merged[uid]["reconstruction"] = rec.get("reconstruction", {})
                elif kind == "user_edit":
                    merged[uid]["edited_text"] = rec.get("edited_text", "")
        return [merged[u] for u in order]
