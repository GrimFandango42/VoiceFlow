"""The app's side of the live caption: which engine, what gets logged, what stays on screen."""

from __future__ import annotations

import logging
import threading
from types import SimpleNamespace

import numpy as np
import pytest

cli = pytest.importorskip("voiceflow.ui.cli_enhanced")

SR = 16000


class Ring:
    def __init__(self, audio):
        self.audio = audio

    def get_samples_since(self, cursor):
        return self.audio[cursor:], len(self.audio)


def make_app(monkeypatch, *, engine, fast=None, fast_ready=False, model_ready=True):
    shown, cleared = [], []
    monkeypatch.setattr(cli, "VISUAL_INDICATORS_AVAILABLE", True)
    monkeypatch.setattr(cli, "visual_show_preview", shown.append)
    monkeypatch.setattr(cli, "visual_clear_preview", lambda: cleared.append(1))
    app = cli.EnhancedApp.__new__(cli.EnhancedApp)
    app.cfg = SimpleNamespace(sample_rate=SR, live_caption_start_delay_seconds=0.0)
    app._log = logging.getLogger("caption.test")
    app.visual_indicators_enabled = True
    app.streaming_enabled = True
    app.asr, app.asr_fast, app._fast_model_ready = engine, fast, fast_ready
    app._model_ready = model_ready
    app._preloader = SimpleNamespace(is_ready=model_ready)
    app._caption_session = None
    app._caption_engine_name = "main"
    app._last_caption_summary = {}
    audio = (np.sin(np.arange(SR * 3) / 20.0) * 0.2).astype(np.float32)
    app.rec = SimpleNamespace(_ring_buffer=Ring(audio))
    return app, shown, cleared


class Engine:
    def __init__(self, text="hello from the caption"):
        self.text, self.calls, self.heard = text, [], threading.Event()

    def transcribe(self, audio, initial_prompt=None, beam_size_override=None, vad_filter_override=None):
        self.calls.append({"beam": beam_size_override, "vad": vad_filter_override})
        self.heard.set()
        return self.text


def test_caption_reaches_the_overlay_and_is_summarised_in_the_log(monkeypatch, caplog):
    engine = Engine()
    app, shown, cleared = make_app(monkeypatch, engine=engine)
    app._schedule_streaming_preview()
    assert engine.heard.wait(5)
    for _ in range(200):
        if shown:
            break
        threading.Event().wait(0.01)
    with caplog.at_level(logging.INFO, logger="caption.test"):
        app._stop_streaming_preview()
    assert shown == ["hello from the caption"]
    assert cleared == [], "the caption stays up until the result replaces it"
    # never the final pass's settings, never the onnxruntime-dependent VAD
    assert engine.calls[0] == {"beam": 1, "vad": False}
    line = next(r.getMessage() for r in caplog.records if "live_caption_summary" in r.getMessage())
    assert "outcome=ok" in line and "engine=main" in line and "published=1" in line


def test_a_fast_model_that_has_not_finished_loading_is_not_used(monkeypatch):
    main, fast = Engine("main"), Engine("fast")
    app, _, _ = make_app(monkeypatch, engine=main, fast=fast, fast_ready=False)
    assert app._caption_engine() == (main, "main")
    app._fast_model_ready = True
    assert app._caption_engine() == (fast, "fast")


def test_model_not_ready_says_so_on_screen_and_in_the_log(monkeypatch, caplog):
    app, shown, _ = make_app(monkeypatch, engine=Engine(), model_ready=False)
    with caplog.at_level(logging.INFO, logger="caption.test"):
        app._schedule_streaming_preview()
    assert app._caption_session is None
    assert shown and "still loading" in shown[0]
    assert any("live_caption_skipped reason=model_not_ready" in r.getMessage() for r in caplog.records)


def test_stop_without_a_session_is_a_no_op(monkeypatch):
    app, shown, _ = make_app(monkeypatch, engine=Engine())
    app._stop_streaming_preview()
    assert shown == []
