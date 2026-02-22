"""
Reliable ASR Implementation
===========================
Based on research findings, implements a simpler but more reliable
approach to prevent hanging and memory issues.

Key strategies:
- Model reloading after N transcriptions (prevents memory leaks)
- Aggressive timeouts (prevents hanging)
- Explicit memory cleanup
- Simple error recovery
"""

import logging
import time
import threading
import gc
from typing import Optional, Dict, Any
import numpy as np
from dataclasses import dataclass

from voiceflow.core.config import Config

logger = logging.getLogger(__name__)

@dataclass
class ReliableResult:
    """Simple transcription result"""
    text: str
    confidence: float
    duration: float
    processing_time: float
    success: bool
    error_message: Optional[str] = None

class ReliableWhisperASR:
    """
    Reliable Whisper ASR that prevents hanging and memory leaks
    using proven production patterns from community research.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.model_name = getattr(cfg, 'model_name', 'tiny.en')
        self.device = getattr(cfg, 'device', 'cpu')

        # Model management
        self._model = None
        self._model_lock = threading.RLock()

        # Reliability settings based on community findings
        self.transcription_count = 0
        self.max_transcriptions_before_reload = 25  # Reload every 25 transcriptions
        self.transcription_timeout = 60  # 60 second timeout per transcription
        self.consecutive_failures = 0
        self.max_consecutive_failures = 3

        # Stats
        self.total_processing_time = 0.0
        self.model_reload_count = 0

        logger.info(f"Reliable ASR initialized - model: {self.model_name}, device: {self.device}")

    def transcribe(self, audio: np.ndarray) -> ReliableResult:
        """
        Transcribe audio with reliability safeguards.
        """
        start_time = time.time()

        try:
            # Input validation
            if audio is None or audio.size == 0:
                return ReliableResult("", 0.0, 0.0, 0.0, False, "Empty audio")

            audio_duration = len(audio) / getattr(self.cfg, 'sample_rate', 16000)

            # Skip very short/quiet audio
            if audio_duration < 0.1:
                return ReliableResult("", 0.0, audio_duration, 0.0, False, "Audio too short")

            energy = np.mean(audio ** 2)
            if energy < 1e-6:
                return ReliableResult("", 0.0, audio_duration, 0.0, False, "Audio too quiet")

            # Ensure model is loaded and healthy
            with self._model_lock:
                if not self._ensure_model_loaded():
                    return ReliableResult("", 0.0, audio_duration, 0.0, False, "Failed to load model")

                # Check if we need to reload model (prevent memory leaks)
                if self.transcription_count >= self.max_transcriptions_before_reload:
                    logger.info(f"Reloading model after {self.transcription_count} transcriptions")
                    self._reload_model()

                # Transcribe with timeout
                result = self._transcribe_with_timeout(audio, audio_duration)

                # Update counters
                self.transcription_count += 1
                if result.success:
                    self.consecutive_failures = 0
                else:
                    self.consecutive_failures += 1

                # If too many failures, reload model
                if self.consecutive_failures >= self.max_consecutive_failures:
                    logger.warning(f"Reloading model after {self.consecutive_failures} consecutive failures")
                    self._reload_model()

                result.processing_time = time.time() - start_time
                self.total_processing_time += result.processing_time

                return result

        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Transcription failed: {e}")
            return ReliableResult("", 0.0, 0.0, processing_time, False, str(e))

    def _ensure_model_loaded(self) -> bool:
        """Ensure model is loaded, load if necessary"""
        if self._model is not None:
            return True

        try:
            logger.info("Loading Whisper model...")
            from faster_whisper import WhisperModel

            self._model = WhisperModel(
                self.model_name,
                device=self.device,
                compute_type="float16" if self.device != "cpu" else "int8",
                cpu_threads=4,
                num_workers=1
            )

            # Warmup with silence
            warmup_audio = np.zeros(1600, dtype=np.float32)  # 0.1 seconds of silence
            list(self._model.transcribe(warmup_audio, language="en"))

            logger.info("Model loaded successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self._model = None
            return False

    def _reload_model(self):
        """Reload model to prevent memory leaks"""
        try:
            # Clean up existing model
            if self._model is not None:
                del self._model
                self._model = None

            # Force garbage collection
            gc.collect()

            # Try to clear CUDA cache if available
            try:
                import torch
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except ImportError:
                pass

            # Reset counters
            self.transcription_count = 0
            self.consecutive_failures = 0
            self.model_reload_count += 1

            logger.info(f"Model reloaded (reload #{self.model_reload_count})")

        except Exception as e:
            logger.error(f"Model reload failed: {e}")

    def _transcribe_with_timeout(self, audio: np.ndarray, duration: float) -> ReliableResult:
        """Transcribe with aggressive timeout to prevent hanging"""
        import threading
        import queue

        result_queue = queue.Queue()

        def transcribe_worker():
            """Worker thread for transcription"""
            try:
                segments, info = self._model.transcribe(
                    audio,
                    language="en",
                    beam_size=1,
                    condition_on_previous_text=False,
                    temperature=0.0,
                    vad_filter=True,
                    word_timestamps=False  # Disable for speed/stability
                )

                # Extract text and confidence
                text_segments = []
                total_confidence = 0
                segment_count = 0

                for segment in segments:
                    if segment.text and segment.text.strip():
                        text_segments.append(segment.text.strip())
                        if hasattr(segment, 'avg_logprob'):
                            total_confidence += segment.avg_logprob
                            segment_count += 1

                text = " ".join(text_segments).strip()
                confidence = total_confidence / max(segment_count, 1) if segment_count > 0 else 0.0

                result_queue.put(('success', text, confidence))

            except Exception as e:
                result_queue.put(('error', str(e), 0.0))

        # Start worker thread
        worker = threading.Thread(target=transcribe_worker, daemon=True)
        worker.start()

        # Wait with timeout
        try:
            result_type, text_or_error, confidence = result_queue.get(timeout=self.transcription_timeout)

            if result_type == 'success':
                return ReliableResult(text_or_error, confidence, duration, 0.0, True)
            else:
                return ReliableResult("", 0.0, duration, 0.0, False, f"Worker error: {text_or_error}")

        except queue.Empty:
            return ReliableResult("", 0.0, duration, 0.0, False, f"Timeout after {self.transcription_timeout}s")

    def get_stats(self) -> Dict[str, Any]:
        """Get reliability statistics"""
        avg_processing_time = self.total_processing_time / max(self.transcription_count, 1)

        return {
            "transcription_count": self.transcription_count,
            "model_reload_count": self.model_reload_count,
            "consecutive_failures": self.consecutive_failures,
            "avg_processing_time": avg_processing_time,
            "max_transcriptions_per_load": self.max_transcriptions_before_reload,
            "timeout_seconds": self.transcription_timeout,
            "model_loaded": self._model is not None,
            "reliability_method": "periodic_reload_with_timeouts"
        }

    def cleanup(self):
        """Clean shutdown"""
        with self._model_lock:
            if self._model is not None:
                del self._model
                self._model = None

            gc.collect()

            try:
                import torch
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except ImportError:
                pass

        logger.info("Reliable ASR cleaned up")

# Compatibility alias
ReliableWhisperASR = ReliableWhisperASR