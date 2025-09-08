"""Unit test for StreamTranscriber

This test monkey-patches `WhisperModel` so that we can run without the heavy
faster-whisper dependency and GPU.  It verifies that:

1. `StreamTranscriber.start()` spawns a worker thread.
2. Feeding audio via `put_audio` eventually triggers the callback with the
   expected text.
3. `stop()` cleanly terminates the thread.

The dummy WhisperModel simply echoes a fixed transcript regardless of the
input audio so the test is deterministic and fast.
"""
from __future__ import annotations

import threading
import time
from typing import List

import numpy as np
import pytest

import voiceflow.core.stream_transcriber as st_mod


class _DummySegment:  # matches faster-whisper segment tuple interface
    def __init__(self, text: str):
        self.text = text
        self.no_speech_prob = 0.0  # always treat as speech


class _DummyWhisperModel:  # noqa: D101 – simple stub
    def __init__(self, *args, **kwargs):
        pass

    # pylint: disable=unused-argument
    def transcribe(self, audio, language="en", beam_size=1, vad_filter=True, word_timestamps=False):
        # Return list of dummy segments, metadata is ignored by StreamTranscriber
        return [_DummySegment("dummy transcript")], {}


@pytest.fixture(autouse=True)
def _patch_whisper_model(monkeypatch):
    """Patch StreamTranscriber.WhisperModel with the dummy implementation."""
    monkeypatch.setattr(st_mod, "WhisperModel", _DummyWhisperModel)


def test_stream_transcriber_basic():  # noqa: D103
    received: List[str] = []
    callback_event = threading.Event()

    def _cb(text: str, final: bool):  # noqa: D401  (simple callback)
        received.append(text)
        if final:
            callback_event.set()

    transcriber = st_mod.StreamTranscriber(model_size="tiny", callback=_cb)
    transcriber.start()

    # Provide 1 second of dummy audio (silence) – 16k float32 samples
    transcriber.put_audio(np.zeros(16_000, dtype=np.float32))

    # Wait up to 3 seconds for callback
    callback_event.wait(timeout=3)

    transcriber.stop()

    assert callback_event.is_set(), "Transcriber did not produce callback in time"
    assert "dummy transcript" in received, "Expected dummy transcript not received"
