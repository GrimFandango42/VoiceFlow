"""Suggest-only review queue for daily learning.

The daily learning batch (``daily_learning.py``) writes proposed vocabulary
additions and phrase corrections to a per-user JSONL queue. Nothing is
auto-applied — the user decides via this CLI:

    python -m voiceflow.ai.review pending           # list outstanding suggestions
    python -m voiceflow.ai.review approve <id>      # apply one
    python -m voiceflow.ai.review approve --all     # apply every pending suggestion
    python -m voiceflow.ai.review reject <id>       # discard one
    python -m voiceflow.ai.review clear             # discard all

Each suggestion carries a stable ``id`` (the line index at the time it was
queued — survives reads but new approvals shift later ids, so the CLI
re-numbers after each mutation).
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PENDING_FILENAME = "pending_review.jsonl"


def _queue_path(base_dir: Optional[Path] = None) -> Path:
    if base_dir is not None:
        return Path(base_dir) / PENDING_FILENAME
    from voiceflow.utils.settings import config_dir
    return config_dir() / PENDING_FILENAME


def _read_queue(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    except Exception as exc:
        logger.warning("Failed reading review queue at %s: %s", path, exc)
    return rows


def _write_queue(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows)
    path.write_text(payload, encoding="utf-8")


def append_suggestions(
    suggestions: List[Dict[str, Any]],
    *,
    source: str,
    base_dir: Optional[Path] = None,
) -> int:
    """Append suggestions to the review queue. Returns count appended.

    Each item is stamped with a UTC timestamp and source label (e.g.,
    "daily_claude_analysis_2026-05-08") so reviewers can see where it came
    from. Duplicate phrase rewrites already in the queue are deduped.
    """
    if not suggestions:
        return 0
    path = _queue_path(base_dir)
    existing = _read_queue(path)
    existing_keys = {_dedupe_key(item) for item in existing}

    appended = 0
    out_rows = list(existing)
    now = time.time()
    for item in suggestions:
        if not isinstance(item, dict):
            continue
        record = {
            "ts": now,
            "source": source,
            "type": str(item.get("type", "phrase_correction")),
            "from": str(item.get("from", "") or "").strip(),
            "to": str(item.get("to", "") or "").strip(),
            "confidence": str(item.get("confidence", "") or "medium").strip().lower(),
            "reason": str(item.get("reason", "") or "").strip()[:240],
        }
        # Vocab-only suggestions don't have a from/to pair.
        if record["type"] == "vocab_addition":
            record["term"] = str(item.get("term", item.get("to", "")) or "").strip()
            record["from"] = ""
            record["to"] = record["term"]
            if not record["term"]:
                continue
        else:
            if not record["from"] or not record["to"]:
                continue
            if record["from"].lower() == record["to"].lower():
                continue
        key = _dedupe_key(record)
        if key in existing_keys:
            continue
        existing_keys.add(key)
        out_rows.append(record)
        appended += 1

    if appended > 0:
        _write_queue(path, out_rows)
    return appended


def _dedupe_key(record: Dict[str, Any]) -> str:
    if str(record.get("type")) == "vocab_addition":
        return f"vocab::{str(record.get('term', '')).lower()}"
    return f"phrase::{str(record.get('from', '')).lower()}->{str(record.get('to', '')).lower()}"


def _format_row(row: Dict[str, Any], idx: int) -> str:
    when = ""
    try:
        when = time.strftime("%Y-%m-%d", time.localtime(float(row.get("ts", 0.0))))
    except Exception:
        pass
    rtype = str(row.get("type", "phrase_correction"))
    confidence = str(row.get("confidence", "medium"))
    if rtype == "vocab_addition":
        body = f"vocab + '{row.get('term', '')}'"
    else:
        body = f"'{row.get('from', '')}' -> '{row.get('to', '')}'"
    reason = str(row.get("reason", ""))
    suffix = f"  ({reason})" if reason else ""
    return f"[{idx:>3}] {when} {confidence:<6} {body}{suffix}"


def cmd_pending(base_dir: Optional[Path] = None) -> int:
    rows = _read_queue(_queue_path(base_dir))
    if not rows:
        print("No pending review suggestions.")
        return 0
    print(f"{len(rows)} pending suggestion(s):")
    for idx, row in enumerate(rows):
        print(_format_row(row, idx))
    return 0


def cmd_approve(
    target: str,
    *,
    base_dir: Optional[Path] = None,
) -> int:
    """Apply suggestion(s) and remove them from the queue.

    ``target`` may be a numeric id or the literal string ``all``.
    """
    path = _queue_path(base_dir)
    rows = _read_queue(path)
    if not rows:
        print("Nothing to approve.")
        return 0

    if target == "all":
        applied = _apply_many(rows)
        _write_queue(path, [])
        print(f"Approved {applied} suggestion(s); queue is now empty.")
        return 0

    try:
        idx = int(target)
    except ValueError:
        print(f"Unknown target: {target!r}. Use a number or 'all'.")
        return 2
    if idx < 0 or idx >= len(rows):
        print(f"Index {idx} out of range; valid range is 0..{len(rows) - 1}.")
        return 2

    row = rows[idx]
    applied = _apply_many([row])
    remaining = [r for i, r in enumerate(rows) if i != idx]
    _write_queue(path, remaining)
    print(f"Approved {applied} suggestion. Remaining: {len(remaining)}.")
    return 0


def cmd_reject(
    target: str,
    *,
    base_dir: Optional[Path] = None,
) -> int:
    path = _queue_path(base_dir)
    rows = _read_queue(path)
    if not rows:
        print("Nothing to reject.")
        return 0
    if target == "all":
        _write_queue(path, [])
        print(f"Rejected and cleared {len(rows)} suggestion(s).")
        return 0
    try:
        idx = int(target)
    except ValueError:
        print(f"Unknown target: {target!r}. Use a number or 'all'.")
        return 2
    if idx < 0 or idx >= len(rows):
        print(f"Index {idx} out of range; valid range is 0..{len(rows) - 1}.")
        return 2
    remaining = [r for i, r in enumerate(rows) if i != idx]
    _write_queue(path, remaining)
    print(f"Rejected suggestion {idx}. Remaining: {len(remaining)}.")
    return 0


def _apply_many(rows: List[Dict[str, Any]]) -> int:
    """Apply each row to the user's vocab and adaptive memory."""
    applied = 0
    vocab_path = _user_vocab_path()
    vocab_path.parent.mkdir(parents=True, exist_ok=True)

    for row in rows:
        rtype = str(row.get("type", "phrase_correction"))
        if rtype == "vocab_addition":
            term = str(row.get("term", row.get("to", ""))).strip()
            if not term:
                continue
            _append_vocab_canonical(vocab_path, term)
            applied += 1
        else:
            src = str(row.get("from", "")).strip()
            dst = str(row.get("to", "")).strip()
            if not src or not dst or src.lower() == dst.lower():
                continue
            _append_vocab_correction(vocab_path, src, dst)
            _record_in_adaptive_memory(src, dst)
            applied += 1

    # Force the runtime initial_prompt to pick up new vocab on the next call.
    try:
        from voiceflow.core.vocab import invalidate_cache
        invalidate_cache()
    except Exception:
        pass

    return applied


def _user_vocab_path() -> Path:
    from voiceflow.utils.settings import config_dir
    return config_dir() / "custom_vocabulary.txt"


def _append_vocab_canonical(path: Path, term: str) -> None:
    """Add a canonical-only term (no left-hand correction) to vocab."""
    line = f"{term} -> {term}\n"
    if not _line_already_present(path, line):
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)


def _append_vocab_correction(path: Path, src: str, dst: str) -> None:
    line = f"{src} -> {dst}\n"
    if not _line_already_present(path, line):
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)


def _line_already_present(path: Path, needle: str) -> bool:
    if not path.exists():
        return False
    try:
        contents = path.read_text(encoding="utf-8")
    except Exception:
        return False
    return needle.strip() in contents


def _record_in_adaptive_memory(src: str, dst: str) -> None:
    """Feed an approved correction into the runtime adaptive_memory engine.

    Uses ``source="manual_correction"`` so the runtime weight is 1.5 — same as
    a UI-driven correction. Applies after a single observation given that this
    is an explicit user approval.
    """
    try:
        from voiceflow.ai.adaptive_memory import AdaptiveLearningManager
        from voiceflow.core.config import Config
        from voiceflow.utils.settings import load_config

        cfg = load_config(Config())
        manager = AdaptiveLearningManager(cfg)
        manager.observe(
            raw_text=src,
            final_text=dst,
            metadata={"source": "manual_correction", "reason": "review_queue_approval"},
        )
    except Exception as exc:
        logger.warning("Failed to record approved correction in adaptive memory: %s", exc)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="voiceflow.ai.review",
        description="Review and approve daily-learning suggestions before they apply.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pending", help="List all pending suggestions")
    approve_p = sub.add_parser("approve", help="Approve a suggestion (by id or 'all')")
    approve_p.add_argument("target", help="Numeric id or the literal string 'all'")
    reject_p = sub.add_parser("reject", help="Reject a suggestion (by id or 'all')")
    reject_p.add_argument("target", help="Numeric id or the literal string 'all'")
    sub.add_parser("clear", help="Discard every pending suggestion")
    args = parser.parse_args(argv)

    if args.cmd == "pending":
        return cmd_pending()
    if args.cmd == "approve":
        return cmd_approve(args.target)
    if args.cmd == "reject":
        return cmd_reject(args.target)
    if args.cmd == "clear":
        return cmd_reject("all")
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
