"""
Cold Start Elimination for VoiceFlow

Handles background model preloading to eliminate first-transcription delays:
- Background thread loading during app startup
- Realistic warmup with speech-like audio
- Progress reporting for UI feedback
- Model validation before use
"""

import logging
import threading
import time
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)


class PreloadState(Enum):
    """Model preload state"""
    NOT_STARTED = "not_started"
    LOADING = "loading"
    WARMING_UP = "warming_up"
    READY = "ready"
    FAILED = "failed"


@dataclass
class PreloadProgress:
    """Progress update during preloading"""
    state: PreloadState
    progress: float  # 0.0 to 1.0
    message: str
    elapsed: float = 0.0
    estimated_total: float = 0.0


class ModelPreloader:
    """
    Handles background model preloading for cold start elimination.

    Usage:
        preloader = ModelPreloader(asr_engine)
        preloader.start_preload()

        # Check status
        if preloader.is_ready():
            # Model is loaded and warmed up
            text = asr_engine.transcribe(audio)

        # Or wait for completion
        preloader.wait_for_ready(timeout=30.0)
    """

    def __init__(
        self,
        asr_engine,
        on_progress: Optional[Callable[[PreloadProgress], None]] = None,
    ):
        """
        Initialize the preloader.

        Args:
            asr_engine: The ASR engine to preload
            on_progress: Optional callback for progress updates
        """
        self.asr = asr_engine
        self.on_progress = on_progress

        self._state = PreloadState.NOT_STARTED
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._ready_event = threading.Event()
        self._error: Optional[str] = None
        self._start_time: float = 0.0
        self._load_time: float = 0.0
        self._warmup_time: float = 0.0

    @property
    def state(self) -> PreloadState:
        """Current preload state"""
        with self._lock:
            return self._state

    @property
    def is_ready(self) -> bool:
        """Check if model is ready for use"""
        return self.state == PreloadState.READY

    @property
    def error(self) -> Optional[str]:
        """Get error message if preload failed"""
        with self._lock:
            return self._error

    def start_preload(self) -> None:
        """Start background preloading"""
        with self._lock:
            if self._state not in (PreloadState.NOT_STARTED, PreloadState.FAILED):
                return

            self._state = PreloadState.LOADING
            self._start_time = time.time()
            self._error = None
            self._ready_event.clear()

        self._thread = threading.Thread(
            target=self._preload_worker,
            name="ModelPreloader",
            daemon=True,
        )
        self._thread.start()
        logger.info("Background model preloading started")

    def wait_for_ready(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for preloading to complete.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if ready, False if timeout or failed
        """
        return self._ready_event.wait(timeout=timeout)

    def get_load_times(self) -> Dict[str, float]:
        """Get loading times for metrics"""
        return {
            "load_time": self._load_time,
            "warmup_time": self._warmup_time,
            "total_time": self._load_time + self._warmup_time,
        }

    def _update_progress(self, state: PreloadState, progress: float, message: str) -> None:
        """Update progress and notify callback"""
        elapsed = time.time() - self._start_time

        with self._lock:
            self._state = state

        if self.on_progress:
            try:
                self.on_progress(PreloadProgress(
                    state=state,
                    progress=progress,
                    message=message,
                    elapsed=elapsed,
                ))
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")

    def _preload_worker(self) -> None:
        """Background worker for model preloading"""
        try:
            # Phase 1: Load model
            self._update_progress(PreloadState.LOADING, 0.1, "Loading model...")

            load_start = time.time()
            self.asr.load()
            self._load_time = time.time() - load_start

            self._update_progress(PreloadState.LOADING, 0.6, f"Model loaded ({self._load_time:.1f}s)")

            # Phase 2: Warmup with realistic audio
            self._update_progress(PreloadState.WARMING_UP, 0.7, "Warming up...")

            warmup_start = time.time()
            self._run_warmup()
            self._warmup_time = time.time() - warmup_start

            self._update_progress(PreloadState.READY, 1.0,
                f"Ready (load: {self._load_time:.1f}s, warmup: {self._warmup_time:.1f}s)")

            logger.info(f"Model preloading complete - load: {self._load_time:.2f}s, "
                       f"warmup: {self._warmup_time:.2f}s")

            self._ready_event.set()

        except Exception as e:
            logger.error(f"Model preloading failed: {e}")
            with self._lock:
                self._state = PreloadState.FAILED
                self._error = str(e)

            self._update_progress(PreloadState.FAILED, 0.0, f"Failed: {e}")

    def _run_warmup(self) -> None:
        """Run warmup transcription with realistic audio"""
        # Generate warmup audio: short burst of speech-like frequencies
        # This is more realistic than silence and ensures all code paths are exercised
        sample_rate = getattr(self.asr, 'sample_rate', 16000)
        duration = 1.0  # 1 second warmup
        num_samples = int(sample_rate * duration)

        # Create speech-like audio with fundamental frequency around 150Hz
        # and formants around 500Hz, 1500Hz, 2500Hz (typical vowel sound)
        t = np.linspace(0, duration, num_samples, dtype=np.float32)

        # Base frequency (fundamental)
        audio = 0.3 * np.sin(2 * np.pi * 150 * t)
        # Formants
        audio += 0.15 * np.sin(2 * np.pi * 500 * t)
        audio += 0.1 * np.sin(2 * np.pi * 1500 * t)
        audio += 0.05 * np.sin(2 * np.pi * 2500 * t)

        # Add slight amplitude variation (like speech)
        envelope = 0.5 + 0.5 * np.sin(2 * np.pi * 3 * t)
        audio = (audio * envelope).astype(np.float32)

        # Normalize to reasonable level
        audio = audio * 0.3  # Keep at moderate level

        # Run warmup transcription
        try:
            result = self.asr.transcribe(audio)
            logger.debug(f"Warmup transcription result: '{result.text if hasattr(result, 'text') else result}'")
        except Exception as e:
            # Warmup errors are non-fatal - model is still loaded
            logger.warning(f"Warmup transcription warning: {e}")


class AsyncPreloader:
    """
    Convenience class for async-style preloading with status checking.

    Usage:
        async_preload = AsyncPreloader()
        async_preload.preload_model(cfg)

        # Later, get the engine (waits if needed)
        asr = async_preload.get_engine()
    """

    def __init__(self):
        self._engine = None
        self._preloader: Optional[ModelPreloader] = None
        self._lock = threading.Lock()

    def preload_model(self, cfg, on_progress: Optional[Callable] = None) -> None:
        """Start preloading model in background"""
        from voiceflow.core.asr_engine import ModernWhisperASR

        with self._lock:
            if self._engine is not None:
                return

            # Create engine
            self._engine = ModernWhisperASR(cfg)

            # Start preloading
            self._preloader = ModelPreloader(self._engine, on_progress)
            self._preloader.start_preload()

    def is_ready(self) -> bool:
        """Check if model is ready"""
        return self._preloader is not None and self._preloader.is_ready

    def get_state(self) -> PreloadState:
        """Get current preload state"""
        if self._preloader is None:
            return PreloadState.NOT_STARTED
        return self._preloader.state

    def get_engine(self, timeout: float = 30.0):
        """
        Get the ASR engine, waiting for preload if needed.

        Args:
            timeout: Maximum time to wait

        Returns:
            The ASR engine, or None if not available
        """
        if self._preloader is None:
            return None

        self._preloader.wait_for_ready(timeout)
        return self._engine

    def get_error(self) -> Optional[str]:
        """Get error message if preload failed"""
        return self._preloader.error if self._preloader else None


# Global preloader instance
_global_preloader: Optional[AsyncPreloader] = None


def get_global_preloader() -> AsyncPreloader:
    """Get the global preloader instance"""
    global _global_preloader
    if _global_preloader is None:
        _global_preloader = AsyncPreloader()
    return _global_preloader


def preload_model(cfg, on_progress: Optional[Callable] = None) -> AsyncPreloader:
    """
    Convenience function to start global model preloading.

    Args:
        cfg: VoiceFlow configuration
        on_progress: Optional progress callback

    Returns:
        The AsyncPreloader instance
    """
    preloader = get_global_preloader()
    preloader.preload_model(cfg, on_progress)
    return preloader


def get_preloaded_engine(timeout: float = 30.0):
    """
    Get the preloaded engine, waiting if needed.

    Returns:
        The ASR engine or None
    """
    return get_global_preloader().get_engine(timeout)


def is_model_ready() -> bool:
    """Check if the global model is ready"""
    return get_global_preloader().is_ready()
