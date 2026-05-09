from __future__ import annotations

import json
from pathlib import Path

import pytest

from voiceflow.ai import review


@pytest.fixture()
def queue_dir(tmp_path: Path) -> Path:
    return tmp_path


def test_append_phrase_correction_writes_record(queue_dir: Path) -> None:
    written = review.append_suggestions(
        [
            {
                "type": "phrase_correction",
                "from": "cloud desktop",
                "to": "Claude Desktop",
                "confidence": "high",
                "reason": "Observed product-name confusion.",
            }
        ],
        source="daily_test",
        base_dir=queue_dir,
    )

    assert written == 1
    queue = queue_dir / review.PENDING_FILENAME
    rows = [json.loads(line) for line in queue.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 1
    assert rows[0]["type"] == "phrase_correction"
    assert rows[0]["from"] == "cloud desktop"
    assert rows[0]["to"] == "Claude Desktop"
    assert rows[0]["source"] == "daily_test"


def test_append_dedupes_existing_phrase_corrections(queue_dir: Path) -> None:
    payload = [
        {
            "type": "phrase_correction",
            "from": "cloud desktop",
            "to": "Claude Desktop",
            "confidence": "high",
            "reason": "first",
        }
    ]
    review.append_suggestions(payload, source="run1", base_dir=queue_dir)
    review.append_suggestions(payload, source="run2", base_dir=queue_dir)

    rows = [
        json.loads(line)
        for line in (queue_dir / review.PENDING_FILENAME).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 1


def test_append_handles_vocab_addition_type(queue_dir: Path) -> None:
    written = review.append_suggestions(
        [{"type": "vocab_addition", "term": "Anthropic", "confidence": "medium"}],
        source="daily_test",
        base_dir=queue_dir,
    )
    assert written == 1
    rows = [json.loads(line) for line in (queue_dir / review.PENDING_FILENAME).read_text(encoding="utf-8").splitlines()]
    assert rows[0]["type"] == "vocab_addition"
    assert rows[0]["term"] == "Anthropic"


def test_append_skips_invalid_phrase_correction(queue_dir: Path) -> None:
    written = review.append_suggestions(
        [
            {"type": "phrase_correction", "from": "", "to": "Claude"},
            {"type": "phrase_correction", "from": "cloud", "to": ""},
            {"type": "phrase_correction", "from": "cloud", "to": "cloud"},
        ],
        source="test",
        base_dir=queue_dir,
    )
    assert written == 0
    queue = queue_dir / review.PENDING_FILENAME
    assert not queue.exists() or queue.read_text(encoding="utf-8").strip() == ""


def test_cmd_pending_lists_all_suggestions(queue_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    review.append_suggestions(
        [
            {"type": "phrase_correction", "from": "cloud", "to": "Claude"},
            {"type": "vocab_addition", "term": "Anthropic"},
        ],
        source="test",
        base_dir=queue_dir,
    )
    review.cmd_pending(base_dir=queue_dir)
    captured = capsys.readouterr().out
    assert "2 pending suggestion" in captured
    assert "cloud" in captured
    assert "Anthropic" in captured


def test_cmd_reject_by_index_removes_one(queue_dir: Path) -> None:
    review.append_suggestions(
        [
            {"type": "phrase_correction", "from": "first wrong", "to": "first right"},
            {"type": "phrase_correction", "from": "second wrong", "to": "second right"},
        ],
        source="test",
        base_dir=queue_dir,
    )
    review.cmd_reject("0", base_dir=queue_dir)
    rows = [
        json.loads(line)
        for line in (queue_dir / review.PENDING_FILENAME).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 1
    assert rows[0]["from"] == "second wrong"


def test_cmd_reject_all_clears_queue(queue_dir: Path) -> None:
    review.append_suggestions(
        [
            {"type": "phrase_correction", "from": "first wrong", "to": "first right"},
            {"type": "phrase_correction", "from": "second wrong", "to": "second right"},
        ],
        source="test",
        base_dir=queue_dir,
    )
    review.cmd_reject("all", base_dir=queue_dir)
    queue = queue_dir / review.PENDING_FILENAME
    assert queue.read_text(encoding="utf-8").strip() == ""


def test_cmd_pending_empty_queue(queue_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    review.cmd_pending(base_dir=queue_dir)
    captured = capsys.readouterr().out
    assert "No pending review suggestions" in captured
