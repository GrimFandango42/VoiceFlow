"""
Streaming Transcription for VoiceFlow

Provides real-time transcription preview while recording:
- Periodic partial transcriptions during recording
- Low-latency feedback for user
- Efficient batching for performance
"""

import logging
import threading
import time
import queue
from typing import Optional, Callable, List
from dataclasses import dataclass
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)


class StreamState(Enum):
    """Streaming state"""
    IDLE = "idle"
    RECORDING = "recording"
    PROCESSING = "processing"
    PAUSED = "paused"


@dataclass
class StreamingResult:
    """Result from streaming transcription"""
    text: str
    is_final: bool
    timestamp: float
    audio_duration: float
    confidence: float = 1.0


class StreamingTranscriber:
    """
    Provides real-time streaming transcription preview.

    Usage:
        streamer = StreamingTranscriber(asr_engine)
        streamer.start()

        # Feed audio chunks as they come
        streamer.add_audio(chunk)

        # Get partial results
        while streamer.has_results():
            result = streamer.get_result()
            print(f"Preview: {result.text}")

        # Stop and get final transcription
        final = streamer.stop()
    """

    def __init__(
        self,
        asr_engine,
        sample_rate: int = 16000,
        chunk_duration: float = 1.0,  # Process audio in 1-second chunks
        min_audio_duration: float = 0.5,  # Minimum audio before first transcription
        partial_max_audio_seconds: float = 8.0,  # Limit partial ASR window to keep cost stable
        on_partial: Optional[Callable[[StreamingResult], None]] = None,
        on_final: Optional[Callable[[StreamingResult], None]] = None,
    ):
        """
        Initialize the streaming transcriber.

        Args:
            asr_engine: ASR engine to use for transcription
            sample_rate: Audio sample rate
            chunk_duration: How often to process audio (seconds)
            min_audio_duration: Minimum audio before first transcription
            partial_max_audio_seconds: Max trailing audio used for each partial transcription
            on_partial: Callback for partial results
            on_final: Callback for final result
        """
        self.asr = asr_engine
        self.sample_rate = sample_rate
        self.chunk_duration = chunk_duration
        self.min_audio_duration = min_audio_duration
        self.partial_max_audio_seconds = max(1.0, float(partial_max_audio_seconds))
        self.on_partial = on_partial
        self.on_final = on_final

        # State
        self._state = StreamState.IDLE
        self._state_lock = threading.Lock()

        # Audio buffer
        self._audio_buffer: List[np.ndarray] = []
        self._audio_lock = threading.Lock()
        self._total_samples = 0

        # Results queue
        self._results_queue: queue.Queue[StreamingResult] = queue.Queue()

        # Processing thread
        self._process_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Timing
        self._start_time: float = 0.0
        self._last_process_time: float = 0.0
        self._last_transcription: str = ""

    @property
    def state(self) -> StreamState:
        """Current state"""
        with self._state_lock:
            return self._state

    @property
    def audio_duration(self) -> float:
        """Total audio duration in seconds"""
        return self._total_samples / self.sample_rate

    def start(self) -> None:
        """Start streaming transcription"""
        with self._state_lock:
            if self._state != StreamState.IDLE:
                return

            self._state = StreamState.RECORDING
            self._start_time = time.time()
            self._last_process_time = self._start_time
            self._stop_event.clear()

        # Clear buffers
        with self._audio_lock:
            self._audio_buffer.clear()
            self._total_samples = 0

        # Clear results
        while not self._results_queue.empty():
            try:
                self._results_queue.get_nowait()
            except queue.Empty:
                break

        self._last_transcription = ""

        # Start processing thread
        self._process_thread = threading.Thread(
            target=self._process_loop,
            name="StreamingTranscriber",
            daemon=True,
        )
        self._process_thread.start()

        logger.info("Streaming transcription started")

    def stop(self, discard_final: bool = False) -> Optional[StreamingResult]:
        """
        Stop streaming and get final result.

        Returns:
            Final transcription result or None
        """
        with self._state_lock:
            if self._state == StreamState.IDLE:
                return None
            self._state = StreamState.PROCESSING

        # Signal thread to stop
        self._stop_event.set()

        # Wait for thread
        if self._process_thread and self._process_thread.is_alive():
            self._process_thread.join(timeout=10.0)

        final_result = None
        if not discard_final:
            # Process any remaining audio for final result
            final_result = self._process_final()

        with self._state_lock:
            self._state = StreamState.IDLE

        logger.info(
            "Streaming transcription stopped. Final%s",
            (f": '{final_result.text}'" if final_result else " skipped"),
        )

        return final_result

    def add_audio(self, audio: np.ndarray) -> None:
        """
        Add audio chunk for processing.

        Args:
            audio: Audio samples as numpy array
        """
        if self.state != StreamState.RECORDING:
            return

        with self._audio_lock:
            self._audio_buffer.append(audio.astype(np.float32))
            self._total_samples += len(audio)

    def has_results(self) -> bool:
        """Check if there are pending results"""
        return not self._results_queue.empty()

    def get_result(self, timeout: Optional[float] = None) -> Optional[StreamingResult]:
        """
        Get next result from queue.

        Args:
            timeout: Max time to wait

        Returns:
            StreamingResult or None if timeout
        """
        try:
            return self._results_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_all_audio(self) -> np.ndarray:
        """Get all buffered audio as single array"""
        with self._audio_lock:
            if not self._audio_buffer:
                return np.array([], dtype=np.float32)
            return np.concatenate(self._audio_buffer)

    def _process_loop(self) -> None:
        """Background processing loop"""
        while not self._stop_event.is_set():
            try:
                # Wait for chunk duration
                time.sleep(self.chunk_duration / 2)  # Check twice as often as chunk duration

                # Check if we have enough audio
                if self.audio_duration < self.min_audio_duration:
                    continue

                # Check if it's time to process
                now = time.time()
                if now - self._last_process_time < self.chunk_duration:
                    continue

                self._last_process_time = now

                # Get current audio
                audio = self.get_all_audio()
                if len(audio) < self.sample_rate * self.min_audio_duration:
                    continue

                # Transcribe
                with self._state_lock:
                    if self._state != StreamState.RECORDING:
                        break

                self._do_partial_transcription(audio)

            except Exception as e:
                logger.warning(f"Streaming processing error: {e}")

    def _do_partial_transcription(self, audio: np.ndarray) -> None:
        """Process partial transcription"""
        try:
            max_samples = int(self.partial_max_audio_seconds * self.sample_rate)
            if max_samples > 0 and len(audio) > max_samples:
                audio = audio[-max_samples:]

            result = self.asr.transcribe(audio)

            # Handle result (could be string or TranscriptionResult)
            if hasattr(result, 'text'):
                text = result.text
            else:
                text = str(result)

            # Only emit if text changed
            if text and text != self._last_transcription:
                self._last_transcription = text

                streaming_result = StreamingResult(
                    text=text,
                    is_final=False,
                    timestamp=time.time() - self._start_time,
                    audio_duration=len(audio) / self.sample_rate,
                )

                self._results_queue.put(streaming_result)

                if self.on_partial:
                    try:
                        self.on_partial(streaming_result)
                    except Exception as e:
                        logger.warning(f"Partial callback error: {e}")

        except Exception as e:
            logger.warning(f"Partial transcription error: {e}")

    def _process_final(self) -> Optional[StreamingResult]:
        """Process final transcription"""
        audio = self.get_all_audio()

        if len(audio) < self.sample_rate * 0.1:  # Less than 0.1s
            return None

        try:
            result = self.asr.transcribe(audio)

            if hasattr(result, 'text'):
                text = result.text
            else:
                text = str(result)

            final_result = StreamingResult(
                text=text,
                is_final=True,
                timestamp=time.time() - self._start_time,
                audio_duration=len(audio) / self.sample_rate,
            )

            self._results_queue.put(final_result)

            if self.on_final:
                try:
                    self.on_final(final_result)
                except Exception as e:
                    logger.warning(f"Final callback error: {e}")

            return final_result

        except Exception as e:
            logger.error(f"Final transcription error: {e}")
            return None


# Integration with EnhancedAudioRecorder
class StreamingAudioCallback:
    """
    Callback adapter to connect audio recorder with streaming transcriber.

    Usage:
        streamer = StreamingTranscriber(asr)
        callback = StreamingAudioCallback(streamer)

        # Pass to audio recorder
        recorder = EnhancedAudioRecorder(cfg, on_audio=callback.on_audio)
    """

    def __init__(self, streamer: StreamingTranscriber):
        self.streamer = streamer

    def on_audio(self, audio: np.ndarray) -> None:
        """Called by audio recorder with new audio chunks"""
        self.streamer.add_audio(audio)


# Convenience function for CLI integration
def create_streaming_session(asr_engine, on_preview: Optional[Callable[[str], None]] = None):
    """
    Create a streaming transcription session.

    Args:
        asr_engine: ASR engine
        on_preview: Callback for preview text updates

    Returns:
        StreamingTranscriber instance
    """
    def handle_partial(result: StreamingResult):
        if on_preview and result.text:
            on_preview(result.text)

    return StreamingTranscriber(
        asr_engine,
        chunk_duration=1.5,  # Update every 1.5 seconds
        min_audio_duration=0.8,  # Wait for 0.8s before first preview
        on_partial=handle_partial,
    )
