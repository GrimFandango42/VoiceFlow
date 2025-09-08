"""Streaming transcription utilities for VoiceFlow.

This module provides a `StreamTranscriber` class that continuously consumes
PCM float32 audio samples (16 kHz, mono) from a thread-safe queue, performs
incremental decoding with `faster-whisper`, and invokes a user-supplied
callback with partial and final transcript fragments.

The implementation is intentionally lightweight so that it can run on a
low-power laptop in real time.  A single Whisper model instance is reused and
fed overlapping chunks (~30 s window, 5 s stride) to keep context while
limiting GPU/CPU memory.

NOTE: This is an initial skeleton; buffer sizes and overlap parameters may be
made configurable via `VoiceFlowConfig` once empirically tuned.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from typing import Callable, Deque, Optional

import numpy as np

try:
    from faster_whisper import WhisperModel  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "faster-whisper is required for streaming transcription. Install with\n"
        "    pip install 'faster-whisper>=1.1.1'"
    ) from exc

logger = logging.getLogger(__name__)


class StreamTranscriber:
    """Continuously transcribe audio fed via `put_audio`.

    Audio samples should be mono float32 at 16 kHz.  A background thread
    collects data into a rolling buffer and performs incremental decoding.
    """

    def __init__(
        self,
        model_size: str = "tiny",
        segment_seconds: float = 1.0,
        stride_seconds: float = 0.5,
        callback: Optional[Callable[[str, bool], None]] = None,
    ) -> None:
        """Create a new streaming transcriber.

        Args:
            model_size: Whisper model size ("tiny", "base", "small", …).
            segment_seconds: Length of the analysis window.
            stride_seconds: Amount of new audio that must accumulate before the
                next decode (overlap keeps some context).
            callback: Function invoked for every transcription update.
                It receives `(text, is_final)` where *is_final* is ``True`` at
                the end of each segment (can be used to flush to disk).
        """
        self.segment_samples = int(segment_seconds * 16_000)
        self.stride_samples = int(stride_seconds * 16_000)
        self._buffer: Deque[np.ndarray] = deque()
        self._buffer_len = 0

        self._audio_q: "queue.Queue[np.ndarray]" = queue.Queue()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True)

        self.callback = callback or (lambda text, final: None)

        logger.info("Loading faster-whisper model `%s`…", model_size)
        self._model = WhisperModel(model_size, device="cpu", compute_type="int8")

    # Public API ---------------------------------------------------------
    def start(self) -> None:
        """Start background transcription thread."""
        logger.debug("Starting StreamTranscriber thread…")
        self._thread.start()

    def stop(self, join: bool = True) -> None:
        """Request transcription thread shutdown."""
        logger.debug("Stopping StreamTranscriber thread…")
        self._stop_event.set()
        if join:
            self._thread.join(timeout=5)

    def put_audio(self, data: np.ndarray) -> None:
        """Enqueue raw PCM samples for transcription."""
        if data.dtype != np.float32:
            data = data.astype(np.float32, copy=False)
        self._audio_q.put(data)

    # Internal worker ----------------------------------------------------
    def _worker(self) -> None:  # noqa: C901  (keep it simple for now)
        last_decode_time = 0.0
        try:
            while not self._stop_event.is_set():
                try:
                    chunk = self._audio_q.get(timeout=0.1)
                    self._buffer.append(chunk)
                    self._buffer_len += len(chunk)
                except queue.Empty:
                    pass

                # If buffer exceeds window, drop oldest chunks
                while self._buffer_len > self.segment_samples:
                    left = self._buffer.popleft()
                    self._buffer_len -= len(left)

                now = time.time()
                if (
                    self._buffer_len >= self.segment_samples
                    and now - last_decode_time >= (self.stride_samples / 16_000)
                ):
                    # Concatenate buffer into 1-D float32 array
                    audio_segment = np.concatenate(list(self._buffer))
                    last_decode_time = now
                    self._decode(audio_segment)
        except Exception:
            logger.exception("StreamTranscriber worker crashed")

    # Decoding -----------------------------------------------------------
    def _decode(self, audio: np.ndarray) -> None:
        logger.debug("Decoding %.2f s of audio", len(audio) / 16_000)
        try:
            segments, _ = self._model.transcribe(
                audio,
                language="en",
                beam_size=1,
                vad_filter=True,
                word_timestamps=False,
            )
            for seg in segments:
                text = seg.text.strip()
                if text:
                    self.callback(text, seg.no_speech_prob < 0.5)
        except Exception:
            logger.exception("Error during streaming decode")
