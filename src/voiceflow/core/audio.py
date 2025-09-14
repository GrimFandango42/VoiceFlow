from __future__ import annotations

import threading
from typing import Optional, List

import numpy as np
import sounddevice as sd

from voiceflow.utils.config import Config


class AudioRecorder:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._stream: Optional[sd.InputStream] = None
        self._frames: List[np.ndarray] = []
        self._lock = threading.Lock()
        self._recording = False

    def _callback(self, indata, frames, time, status):  # noqa: D401
        if status:
            # Non-fatal warnings from PortAudio; keep going.
            pass
        if not self._recording:
            return
        with self._lock:
            # Ensure mono
            data = indata.copy()
            if data.ndim == 2 and data.shape[1] > 1:
                data = np.mean(data, axis=1, keepdims=True)
            self._frames.append(data.reshape(-1))

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
            # Clamp just in case
            audio = np.clip(audio, -1.0, 1.0)
            return audio

    def is_recording(self) -> bool:
        return self._recording

