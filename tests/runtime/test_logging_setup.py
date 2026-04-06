from __future__ import annotations

import logging
from pathlib import Path

from voiceflow.utils.logging_setup import AsyncLogger


def test_async_logger_falls_back_when_primary_log_file_is_locked(monkeypatch, tmp_path):
    created_paths: list[Path] = []
    real_handler = logging.handlers.RotatingFileHandler

    def _fake_rotating_handler(path, *args, **kwargs):
        candidate = Path(path)
        created_paths.append(candidate)
        if candidate.name == "voiceflow.log":
            raise PermissionError("locked")
        return real_handler(path, *args, **kwargs)

    monkeypatch.setattr(logging.handlers, "RotatingFileHandler", _fake_rotating_handler)

    alog = AsyncLogger(tmp_path)
    try:
        logger = alog.get()
        logger.info("hello")
    finally:
        alog.stop()

    assert created_paths
    assert created_paths[0].name == "voiceflow.log"
    assert alog.active_log_path.name.startswith("voiceflow-")
    assert alog.active_log_path.parent == tmp_path
    assert alog.active_log_marker_path.read_text(encoding="utf-8") == str(alog.active_log_path)
    fallback_marker = alog.active_log_path.parent / "active_log_path.txt"
    assert fallback_marker.read_text(encoding="utf-8") == str(alog.active_log_path)
