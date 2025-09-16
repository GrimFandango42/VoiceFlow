from __future__ import annotations

import threading
from typing import Optional, List

import numpy as np
import sounddevice as sd

from voiceflow.core.config import Config


class AudioRecorder:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._stream: Optional[sd.InputStream] = None
        self._frames: List[np.ndarray] = []
        self._lock = threading.Lock()
        self._recording = False

        # Pre-allocated buffer for mono conversion (OPTIMIZATION 1)
        self._mono_buffer = np.zeros(cfg.blocksize, dtype=np.float32)

    def _callback(self, indata, frames, time, status):  # noqa: D401
        if status:
            # Non-fatal warnings from PortAudio; keep going.
            pass
        if not self._recording:
            return

        with self._lock:
            # Optimized mono conversion without unnecessary copies (OPTIMIZATION 1)
            if indata.ndim == 2 and indata.shape[1] > 1:
                # Use pre-allocated buffer for mono conversion
                np.mean(indata, axis=1, out=self._mono_buffer[:frames])
                self._frames.append(self._mono_buffer[:frames].copy())
            else:
                # Already mono or single channel
                self._frames.append(indata.reshape(-1).copy())

    def start(self):
        if self._recording:
            return
        self._frames.clear()
        self._stream = sd.InputStream(
            channels=self.cfg.channels,
            samplerate=self.cfg.sample_rate,
            dtype="float32",
            blocksize=self.cfg.blocksize,
            callback=self._callback,
        )
        self._stream.start()
        self._recording = True

    def stop(self) -> np.ndarray:
        if not self._recording:
            return np.array([], dtype=np.float32)
        self._recording = False
        if self._stream is not None:
            self._stream.stop()
            self._stream.close()
            self._stream = None
        with self._lock:
            if not self._frames:
                return np.array([], dtype=np.float32)
            audio = np.concatenate(self._frames).astype(np.float32)
            # Clear frames to prevent buffer overflow on next recording (OPTIMIZATION 4)
            self._frames.clear()
            # Clamp just in case
            audio = np.clip(audio, -1.0, 1.0)
            return audio

    def is_recording(self) -> bool:
        return self._recording

