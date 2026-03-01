from __future__ import annotations

import json

from voiceflow.utils.settings import (
    append_jsonl_bounded,
    atomic_write_text,
    load_json_dict_bounded,
    read_text_tail_lines,
)


def test_atomic_write_text_replaces_target(tmp_path):
    target = tmp_path / "config.json"
    assert atomic_write_text(target, '{"a": 1}')
    assert target.read_text(encoding="utf-8") == '{"a": 1}'
    assert atomic_write_text(target, '{"a": 2}')
    assert target.read_text(encoding="utf-8") == '{"a": 2}'


def test_load_json_dict_bounded_rejects_oversized_payload(tmp_path):
    target = tmp_path / "config.json"
    target.write_text(json.dumps({"x": "a" * 2000}), encoding="utf-8")
    loaded = load_json_dict_bounded(target, max_bytes=128)
    assert loaded is None


def test_read_text_tail_lines_bounds_line_length_and_tail(tmp_path):
    target = tmp_path / "events.jsonl"
    rows = [
        '{"id": 1}',
        "x" * 5000,
        '{"id": 2}',
        '{"id": 3}',
    ]
    target.write_text("\n".join(rows) + "\n", encoding="utf-8")

    lines = read_text_tail_lines(
        target,
        max_lines=3,
        max_bytes=4096,
        max_line_chars=128,
    )
    assert '{"id": 1}' not in lines
    assert '{"id": 2}' in lines
    assert '{"id": 3}' in lines
    assert not any(len(line) > 128 for line in lines)


def test_append_jsonl_bounded_trims_file_growth(tmp_path):
    target = tmp_path / "bounded.jsonl"
    for i in range(30):
        ok = append_jsonl_bounded(
            target,
            {"i": i, "msg": "x" * 20},
            max_file_bytes=320,
            keep_lines=6,
            max_line_chars=256,
        )
        assert ok

    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) <= 6
    assert json.loads(lines[-1])["i"] == 29

