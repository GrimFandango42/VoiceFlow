"""
A log that fails silently is worse than no log, because it is trusted.

VoiceFlow ran for days with voiceflow.log open and nothing in it: the queue
listener was not draining, so every log call succeeded and every record was
eventually discarded. AsyncLogger now proves one record reaches disk and falls
back to direct writes if it does not.
"""

from __future__ import annotations

import logging

from voiceflow.utils.logging_setup import AsyncLogger


def test_records_reach_disk(tmp_path):
    alog = AsyncLogger(tmp_path)
    try:
        alog.get().info("hello_from_test")
        alog.stop()
        text = alog.active_log_path.read_text(encoding="utf-8")
        assert "hello_from_test" in text
        assert alog.async_delivery is True, "queue delivery worked; no fallback expected"
    finally:
        alog.stop()


def test_falls_back_when_listener_never_drains(tmp_path, monkeypatch):
    """
    Simulate the real failure: a listener whose start() does nothing.

    Without the delivery check this logger would accept records forever and
    write none of them.
    """
    class _DeadListener:
        def __init__(self, *a, **k):
            self.started = False

        def start(self):
            self.started = True  # but never drains the queue

        def stop(self):
            pass

    monkeypatch.setattr(logging.handlers, "QueueListener", _DeadListener)

    alog = AsyncLogger(tmp_path)
    try:
        assert alog.async_delivery is False, "fallback did not engage"

        alog.get().info("after_fallback")
        text = alog.active_log_path.read_text(encoding="utf-8")
        assert "after_fallback" in text, "records still not reaching disk after fallback"
        # The reason is recorded, so this is diagnosable next time.
        assert "logging_queue_listener_not_delivering" in text
    finally:
        alog.stop()


def test_reinit_does_not_double_log(tmp_path):
    """The logger is module-level; constructing twice must not duplicate lines."""
    first = AsyncLogger(tmp_path)
    first.stop()
    second = AsyncLogger(tmp_path)
    try:
        second.get().info("unique_marker_xyz")
        second.stop()
        text = second.active_log_path.read_text(encoding="utf-8")
        assert text.count("unique_marker_xyz") == 1, "record written more than once"
    finally:
        second.stop()
