from __future__ import annotations

import logging
import threading
from typing import Optional, List

import numpy as np
import sounddevice as sd

from voiceflow.core.config import Config
from voiceflow.utils.guardrails import validate_and_sanitize_audio, with_error_recovery

logger = logging.getLogger(__name__)


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
            logger.debug(f"Audio callback status: {status}")
        if not self._recording:
            return

        try:
            with self._lock:
                # CRITICAL GUARDRAIL: Validate and sanitize audio input
                try:
                    indata = validate_and_sanitize_audio(indata)
                except Exception as e:
                    logger.error(f"Audio validation failed: {e}")
                    return  # Skip this frame rather than crash

                # Optimized mono conversion without unnecessary copies (OPTIMIZATION 1)
                if indata.ndim == 2 and indata.shape[1] > 1:
                    # Use pre-allocated buffer for mono conversion
                    np.mean(indata, axis=1, out=self._mono_buffer[:frames])
                    self._frames.append(self._mono_buffer[:frames].copy())
                else:
                    # Already mono or single channel
                    self._frames.append(indata.reshape(-1).copy())

        except Exception as e:
            logger.error(f"Audio callback error: {e}")
            # Don't propagate the error to avoid audio system crashes

    @with_error_recovery(fallback_value=None)
    def start(self):
        if self._recording:
            return

        try:
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
            logger.debug("Audio recording started successfully")
        except Exception as e:
            logger.error(f"Failed to start audio recording: {e}")
            self._recording = False
            if self._stream:
                try:
                    self._stream.close()
                except:
                    pass
                self._stream = None
            raise

    @with_error_recovery(fallback_value=np.array([], dtype=np.float32))
    def stop(self) -> np.ndarray:
        if not self._recording:
            return np.array([], dtype=np.float32)

        self._recording = False

        try:
            if self._stream is not None:
                self._stream.stop()
                self._stream.close()
                self._stream = None
        except Exception as e:
            logger.error(f"Error stopping audio stream: {e}")

        try:
            with self._lock:
                if not self._frames:
                    logger.debug("No audio frames recorded")
                    return np.array([], dtype=np.float32)

                # CRITICAL GUARDRAIL: Validate concatenated audio
                audio = np.concatenate(self._frames).astype(np.float32)

                # Clear frames to prevent buffer overflow on next recording (OPTIMIZATION 4)
                self._frames.clear()

                # Final validation and sanitization before returning
                audio = validate_and_sanitize_audio(audio)
                logger.debug(f"Audio recording stopped, returning {len(audio)} samples")
                return audio

        except Exception as e:
            logger.error(f"Error processing recorded audio: {e}")
            # Clear frames even if processing failed
            with self._lock:
                self._frames.clear()
            return np.array([], dtype=np.float32)

    def is_recording(self) -> bool:
        return self._recording

