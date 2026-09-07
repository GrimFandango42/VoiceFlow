"""The live caption must survive a missing VAD dependency.

The frozen Windows build does not ship onnxruntime, so faster-whisper raises
on every streaming preview pass. Observed in production as a blank live caption
for the entire hold plus one identical warning per second in the log.
"""

from __future__ import annotations

import numpy as np
import pytest

from voiceflow.core.streaming import StreamingTranscriber, _is_missing_vad_dependency

VAD_ERROR = ValueError("Applying the VAD filter requires the onnxruntime package")


class TestErrorRecognition:
    def test_recognises_the_real_message(self):
        assert _is_missing_vad_dependency(VAD_ERROR)

    @pytest.mark.parametrize(
        "exc",
        [
            RuntimeError("CUDA out of memory"),
            ValueError("audio is empty"),
            OSError("model file not found"),
        ],
    )
    def test_does_not_swallow_unrelated_errors(self, exc):
        assert not _is_missing_vad_dependency(exc)


class _ASR:
    """Fails while VAD is requested, succeeds once it is off."""

    def __init__(self):
        self.calls = []

    def transcribe(self, audio, initial_prompt=None, beam_size_override=None,
                   vad_filter_override=None):
        self.calls.append(vad_filter_override)
        if vad_filter_override is not False:
            raise VAD_ERROR
        return "hello world"


def _transcriber(asr, **kw):
    t = StreamingTranscriber.__new__(StreamingTranscriber)
    t.asr = asr
    t.sample_rate = 16000
    t.partial_max_audio_seconds = 8.0
    t.beam_size = 1
    t.vad_filter = kw.get("vad_filter", True)
    t._last_transcription = ""
    t._start_time = 0.0
    t.on_partial = None

    class _Q:
        def __init__(self):
            self.items = []

        def put(self, x):
            self.items.append(x)

    t._results_queue = _Q()
    return t


class TestFallback:
    def test_preview_recovers_on_the_retry(self):
        asr = _ASR()
        t = _transcriber(asr)
        t._do_partial_transcription(np.zeros(16000, dtype=np.float32))

        assert asr.calls == [True, False], "should retry once with VAD off"
        assert t.vad_filter is False, "fallback must stick for the session"
        assert [r.text for r in t._results_queue.items] == ["hello world"]

    def test_fallback_is_not_re_attempted_every_pass(self):
        asr = _ASR()
        t = _transcriber(asr)
        audio = np.zeros(16000, dtype=np.float32)
        t._do_partial_transcription(audio)
        t._last_transcription = ""
        t._do_partial_transcription(audio)

        # First pass: True then False. Second pass: straight to False.
        assert asr.calls == [True, False, False]

    def test_unrelated_failure_still_just_warns(self):
        class _Broken:
            def transcribe(self, *a, **k):
                raise RuntimeError("CUDA out of memory")

        t = _transcriber(_Broken())
        t._do_partial_transcription(np.zeros(16000, dtype=np.float32))
        assert t.vad_filter is True, "must not disable VAD for unrelated errors"
        assert t._results_queue.items == []
