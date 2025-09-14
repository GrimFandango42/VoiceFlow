from __future__ import annotations

from typing import Iterable, Optional

import numpy as np

from voiceflow.utils.config import Config


class WhisperASR:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._model = None

    def load(self):
        # Lazy import so the package is optional until used
        try:
            from faster_whisper import WhisperModel
        except Exception as e:
            raise RuntimeError(
                "faster-whisper is not installed or failed to import. "
                "Run LAUNCH_LOCALFLOW.bat to install dependencies, and ensure network is available for the first model download."
            ) from e

        self._model = WhisperModel(
            self.cfg.model_name,
            device=self.cfg.device,
            compute_type=self.cfg.compute_type,
        )

        # Warmup with a second of silence to reduce first-call latency
        silence = np.zeros(16000, dtype=np.float32)
        segs, _info = self._model.transcribe(silence, language=self.cfg.language)
        _ = list(segs)

    def transcribe(self, audio: np.ndarray) -> str:
        if self._model is None:
            self.load()
        assert self._model is not None

        # faster-whisper accepts numpy float32 PCM at 16k
        segments, _info = self._model.transcribe(
            audio,
            language=self.cfg.language,
            vad_filter=self.cfg.vad_filter,
            beam_size=self.cfg.beam_size,
            temperature=self.cfg.temperature,
        )
        parts = []
        for seg in segments:
            parts.append(seg.text)
        text = " ".join(p.strip() for p in parts).strip()
        return text
