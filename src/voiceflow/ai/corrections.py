"""Record "heard X, meant Y" for the nightly learner (VF-24).

    python -m voiceflow.ai.corrections add --heard "Jamelan" --meant "Gemini"
    python -m voiceflow.ai.corrections list

``add`` appends one row to ``transcription_corrections.jsonl`` in the VoiceFlow data
folder, the file ``daily_learning.py`` already reads, in the same shape the app writes
when you correct a transcript (``source: manual_correction``). Nothing else is written:
the nightly job turns the rows into adaptive rules through the existing path, so a pair
logged ``adaptive_user_correction_min_count`` times (2 by default) becomes an active
rewrite rule, and the corrected term also counts toward a durable Whisper hotword.

Timing: the nightly job processes *yesterday's* rows, so a correction logged today takes
effect after the next run (08:00, or the catch-up at the next app start).

Ordinary English on the "heard" side ("cloud", "do it") is still recorded, because the
corrected term is worth learning as a hotword, but it never becomes a global rewrite
rule (``core/rewrite_policy.py``). Use a phrase when one exists: ``--heard "cloud max"
--meant "Claude Max"``.

Local only. ``--data-dir`` points at another folder (tests, or a scratch copy).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

CORRECTIONS_FILENAME = "transcription_corrections.jsonl"

#: Same bounds as the app's own correction writer (ui/cli_enhanced.py).
_MAX_FILE_BYTES = 786432
_KEEP_LINES = 1000
_MAX_LINE_CHARS = 8192


def _data_dir(override: Optional[str]) -> Path:
    if override:
        return Path(override).expanduser()
    from voiceflow.utils.settings import config_dir

    return config_dir()


def _clean(text: str) -> str:
    return " ".join(str(text or "").split())


def add_correction(heard: str, meant: str, *, data_dir: Path) -> Dict[str, Any]:
    """Append one correction row. Raises ``ValueError`` for an empty or no-op pair."""
    from voiceflow.utils.settings import append_jsonl_bounded

    heard, meant = _clean(heard), _clean(meant)
    if not heard or not meant:
        raise ValueError("both --heard and --meant are required")
    if heard.lower() == meant.lower():
        raise ValueError("--heard and --meant are the same; nothing to learn")
    row: Dict[str, Any] = {
        "ts": time.time(),
        "local_ts": datetime.now().isoformat(timespec="seconds"),
        "original_text": heard,
        "corrected_text": meant,
        "source": "manual_correction",
        "entry_point": "cli",
    }
    path = Path(data_dir) / CORRECTIONS_FILENAME
    if not append_jsonl_bounded(
        path, row, max_file_bytes=_MAX_FILE_BYTES, keep_lines=_KEEP_LINES, max_line_chars=_MAX_LINE_CHARS
    ):
        raise OSError(f"could not write {path}")
    return row


def list_corrections(*, data_dir: Path, limit: int = 50) -> List[Dict[str, Any]]:
    """Newest first. Read-only."""
    path = Path(data_dir) / CORRECTIONS_FILENAME
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("original_text") and payload.get("corrected_text"):
            rows.append(payload)
    rows.reverse()
    return rows[: max(1, int(limit))] if limit else rows


def _when(row: Dict[str, Any]) -> str:
    local = str(row.get("local_ts", "") or "")
    if local:
        return local.replace("T", " ")[:16]
    try:
        return datetime.fromtimestamp(float(row.get("ts", 0))).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError):
        return "?"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m voiceflow.ai.corrections",
        description="Record what VoiceFlow mis-heard so the nightly learner can fix it.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_add = sub.add_parser("add", help="record one 'heard X, meant Y' correction")
    p_add.add_argument("--heard", required=True, help="what VoiceFlow wrote, e.g. 'Jamelan'")
    p_add.add_argument("--meant", required=True, help="what you said, e.g. 'Gemini'")
    p_add.add_argument("--data-dir", default="", help="data folder (default: the VoiceFlow data folder)")
    p_list = sub.add_parser("list", help="show recorded corrections, newest first")
    p_list.add_argument("--limit", type=int, default=50)
    p_list.add_argument("--data-dir", default="", help="data folder (default: the VoiceFlow data folder)")
    args = parser.parse_args(argv)

    data_dir = _data_dir(args.data_dir)
    if args.command == "add":
        try:
            row = add_correction(args.heard, args.meant, data_dir=data_dir)
        except ValueError as exc:
            print(f"Not recorded: {exc}.", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"Not recorded: {exc}.", file=sys.stderr)
            return 1
        print(f"Recorded: {row['original_text']} -> {row['corrected_text']}  ({data_dir / CORRECTIONS_FILENAME})")
        from voiceflow.core.rewrite_policy import is_unsafe_global_source

        if is_unsafe_global_source(row["original_text"]):
            print(
                f"Note: {row['original_text']!r} is ordinary English, so it will not become a "
                f"rewrite rule; {row['corrected_text']!r} still counts toward a Whisper hotword. "
                "Log the phrase it appeared in when there is one (e.g. --heard \"cloud max\" "
                "--meant \"Claude Max\")."
            )
        print("Takes effect after the next nightly learning run; two entries make an active rule.")
        return 0

    rows = list_corrections(data_dir=data_dir, limit=args.limit)
    if not rows:
        print(f"No corrections recorded in {data_dir / CORRECTIONS_FILENAME}.")
        return 0
    print(f"{len(rows)} correction(s), newest first:")
    for row in rows:
        source = str(row.get("source", "") or "")
        print(f"  {_when(row)}  {row['original_text']} -> {row['corrected_text']}  [{source}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
