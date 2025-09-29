"""
Modern ASR Implementation

Simple, efficient implementation based on 2024 best practices:
- Persistent model loading (load once, use many times)
- Proper memory management without aggressive reloading
- Based on faster-whisper production patterns
"""

import logging
import time
import threading
from typing import Optional
import numpy as np

from voiceflow.core.config import Config

logger = logging.getLogger(__name__)

class ModernWhisperASR:
    """
    Modern ASR implementation following 2024 best practices.

    Key principles:
    - Load model once, keep it loaded
    - Simple error handling without aggressive reloading
    - Efficient memory usage
    - Fast transcription times
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._model = None
        self._model_lock = threading.RLock()

        # Simple statistics
        self.transcription_count = 0
        self.total_processing_time = 0.0
        self.last_error_time = 0.0

        # Error tracking - reload only on consistent failures
        self.consecutive_errors = 0
        self.max_consecutive_errors = 5

        logger.info(f"Modern ASR initialized - model: {cfg.model_name}, device: {cfg.device}")

    def load(self):
        """Load the Whisper model once and keep it loaded"""
        with self._model_lock:
            if self._model is not None:
                return

            logger.info(f"Loading Whisper model: {self.cfg.model_name}")
            start_time = time.time()

            try:
                from faster_whisper import WhisperModel

                self._model = WhisperModel(
                    self.cfg.model_name,
                    device=self.cfg.device,
                    compute_type=self.cfg.compute_type,
                    cpu_threads=4,  # Optimize thread usage
                    num_workers=1   # Single worker for consistency
                )

                # Quick warmup with minimal audio
                warmup_audio = np.zeros(1600, dtype=np.float32)  # 0.1 second
                list(self._model.transcribe(warmup_audio, language="en"))

                load_time = time.time() - start_time
                logger.info(f"Model loaded successfully in {load_time:.2f}s")

            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self._model = None
                raise

    def transcribe(self, audio: np.ndarray) -> str:
        """
        Simple, efficient transcription.

        Args:
            audio: Audio data as numpy array

        Returns:
            Transcribed text or empty string on error
        """
        if audio is None or audio.size == 0:
            return ""

        start_time = time.time()

        try:
            # Load model if not already loaded
            if self._model is None:
                self.load()

            if self._model is None:
                logger.error("Model failed to load")
                return ""

            # Basic audio validation
            if len(audio) < 1600:  # Less than 0.1 second
                logger.debug("Audio too short, skipping")
                return ""

            # Check for silent audio
            energy = np.mean(audio ** 2)
            if energy < 1e-6:  # Very quiet audio
                logger.debug("Audio too quiet, skipping")
                return ""

            # Transcribe with faster-whisper
            with self._model_lock:
                segments, info = self._model.transcribe(
                    audio,
                    language="en",
                    beam_size=1,  # Faster beam search
                    best_of=1,    # No alternative generation
                    temperature=0.0,  # Deterministic output
                    condition_on_previous_text=False,  # Avoid context pollution
                    vad_filter=True,  # Use built-in VAD
                    vad_parameters={
                        "threshold": 0.5,
                        "min_speech_duration_ms": 250,
                        "max_speech_duration_s": 300
                    }
                )

                # Extract text from segments
                text_parts = []
                for segment in segments:
                    if segment.text and segment.text.strip():
                        text_parts.append(segment.text.strip())

                result = " ".join(text_parts).strip()

            # Update statistics
            processing_time = time.time() - start_time
            self.transcription_count += 1
            self.total_processing_time += processing_time
            self.consecutive_errors = 0  # Reset error count on success

            # Log performance
            if result:
                audio_duration = len(audio) / 16000  # Assume 16kHz
                rtf = processing_time / audio_duration  # Real-time factor
                logger.debug(f"Transcribed {audio_duration:.2f}s audio in {processing_time:.2f}s (RTF: {rtf:.2f})")

            return result

        except Exception as e:
            processing_time = time.time() - start_time
            self.consecutive_errors += 1
            self.last_error_time = time.time()

            logger.error(f"Transcription failed: {e} (consecutive errors: {self.consecutive_errors})")

            # Reload model only after many consecutive errors
            if self.consecutive_errors >= self.max_consecutive_errors:
                logger.warning(f"Too many consecutive errors ({self.consecutive_errors}), reloading model")
                self._reload_model()

            return ""

    def _reload_model(self):
        """Reload model after persistent errors"""
        with self._model_lock:
            logger.info("Reloading model due to persistent errors")

            # Clear current model
            self._model = None

            # Force garbage collection
            import gc
            gc.collect()

            # Try to reload
            try:
                self.load()
                self.consecutive_errors = 0
                logger.info("Model reloaded successfully")
            except Exception as e:
                logger.error(f"Model reload failed: {e}")

    def get_stats(self) -> dict:
        """Get transcription statistics"""
        avg_processing = self.total_processing_time / max(self.transcription_count, 1)

        return {
            "transcription_count": self.transcription_count,
            "total_processing_time": self.total_processing_time,
            "avg_processing_time": avg_processing,
            "consecutive_errors": self.consecutive_errors,
            "model_loaded": self._model is not None
        }

    def cleanup(self):
        """Clean shutdown"""
        with self._model_lock:
            self._model = None
            logger.info("ASR model cleaned up")


# Compatibility alias for existing code
BufferSafeWhisperASR = ModernWhisperASR