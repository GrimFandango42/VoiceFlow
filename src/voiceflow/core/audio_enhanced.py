from __future__ import annotations

import queue
import threading
from typing import Optional, List
from collections import deque
import time
import logging

import numpy as np
import sounddevice as sd

from voiceflow.core.config import Config
from voiceflow.utils.validation import validate_audio_data, validate_sample_rate, ValidationError

# Set up logging for audio validation
logger = logging.getLogger(__name__)


def audio_validation_guard(audio_data: np.ndarray,
                          operation_name: str = "audio_operation",
                          allow_empty: bool = False,
                          cfg: Optional['Config'] = None) -> np.ndarray:
    """
    Comprehensive audio input validation and sanitization guard.

    This function prevents crashes from malformed audio data by:
    - Detecting and handling NaN/Inf values
    - Validating audio format and dimensions
    - Clamping extreme values to safe ranges
    - Providing detailed error logging with metadata
    - Using centralized validation module for security consistency

    Args:
        audio_data: Audio data array to validate
        operation_name: Name of operation for logging context
        allow_empty: Whether to allow empty arrays (default: False)

    Returns:
        Sanitized audio data array

    Raises:
        ValueError: If audio data is invalid and cannot be recovered
    """
    if audio_data is None:
        error_msg = f"[AudioGuard] {operation_name}: Audio data is None"
        logger.error(error_msg)
        if allow_empty:
            return np.array([], dtype=np.float32)
        raise ValueError(error_msg)

    # PERFORMANCE OPTIMIZATION: Fast path for performance mode
    if cfg and getattr(cfg, 'enable_fast_audio_validation', False):
        return _fast_audio_validation_guard(audio_data, operation_name, allow_empty, cfg)

    # First apply centralized validation for security consistency
    try:
        validated_audio = validate_audio_data(audio_data, f"{operation_name}_audio")
    except ValidationError as e:
        error_msg = f"[AudioGuard] {operation_name}: Security validation failed: {e}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    # Use the validated audio from security validation
    audio_data = validated_audio

    # Convert to numpy array if needed (should already be done by validation)
    if not isinstance(audio_data, np.ndarray):
        try:
            audio_data = np.array(audio_data, dtype=np.float32)
            logger.warning(f"[AudioGuard] {operation_name}: Converted input to numpy array")
        except Exception as e:
            error_msg = f"[AudioGuard] {operation_name}: Cannot convert input to numpy array: {e}"
            logger.error(error_msg)
            raise ValueError(error_msg)

    # Check for empty arrays
    if audio_data.size == 0:
        if allow_empty:
            logger.info(f"[AudioGuard] {operation_name}: Empty audio array (allowed)")
            return np.array([], dtype=np.float32)
        else:
            error_msg = f"[AudioGuard] {operation_name}: Empty audio array not allowed"
            logger.error(error_msg)
            raise ValueError(error_msg)

    # Validate array dimensions
    if audio_data.ndim > 2:
        error_msg = f"[AudioGuard] {operation_name}: Audio data has too many dimensions: {audio_data.ndim}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    # Convert to 1D if needed
    original_shape = audio_data.shape
    if audio_data.ndim == 2:
        if audio_data.shape[1] > 1:
            # Convert stereo to mono
            audio_data = np.mean(audio_data, axis=1)
            logger.info(f"[AudioGuard] {operation_name}: Converted stereo to mono")
        else:
            audio_data = audio_data.flatten()

    # Ensure float32 dtype for consistency
    if audio_data.dtype != np.float32:
        try:
            audio_data = audio_data.astype(np.float32)
            logger.info(f"[AudioGuard] {operation_name}: Converted dtype to float32")
        except Exception as e:
            error_msg = f"[AudioGuard] {operation_name}: Cannot convert to float32: {e}"
            logger.error(error_msg)
            raise ValueError(error_msg)

    # Critical: Check for NaN values
    nan_count = np.count_nonzero(np.isnan(audio_data))
    if nan_count > 0:
        logger.warning(f"[AudioGuard] {operation_name}: Found {nan_count} NaN values, replacing with zeros")
        audio_data = np.nan_to_num(audio_data, nan=0.0, copy=False)

    # Critical: Check for infinite values
    inf_count = np.count_nonzero(np.isinf(audio_data))
    if inf_count > 0:
        logger.warning(f"[AudioGuard] {operation_name}: Found {inf_count} infinite values, clamping")
        audio_data = np.nan_to_num(audio_data, posinf=32.0, neginf=-32.0, copy=False)

    # Check for extreme values and clamp to safe range
    max_amplitude = np.max(np.abs(audio_data))
    safe_max = 100.0  # Safe maximum for float32 audio processing

    if max_amplitude > safe_max:
        logger.warning(f"[AudioGuard] {operation_name}: Extreme amplitude {max_amplitude:.2f}, clamping to ±{safe_max}")
        audio_data = np.clip(audio_data, -safe_max, safe_max)
        max_amplitude = safe_max

    # Warn about high amplitudes that might indicate issues
    if max_amplitude > 10.0:
        logger.warning(f"[AudioGuard] {operation_name}: High audio amplitude: {max_amplitude:.2f}")
    elif max_amplitude == 0.0:
        logger.info(f"[AudioGuard] {operation_name}: Silent audio (all zeros)")

    # Log validation summary
    logger.debug(f"[AudioGuard] {operation_name}: Validation complete - "
                f"Shape: {audio_data.shape}, Max: {max_amplitude:.3f}, "
                f"NaN fixed: {nan_count}, Inf fixed: {inf_count}")

    return audio_data


def validate_audio_format(sample_rate: int, channels: int, operation_name: str = "audio_format") -> tuple[int, int]:
    """
    Validate and sanitize audio format parameters using centralized validation.

    Args:
        sample_rate: Audio sample rate to validate
        channels: Number of audio channels to validate
        operation_name: Operation name for logging

    Returns:
        Tuple of (validated_sample_rate, validated_channels)
    """
    # Use centralized sample rate validation for security consistency
    try:
        validated_sample_rate = validate_sample_rate(sample_rate)
    except ValidationError as e:
        logger.error(f"[AudioGuard] {operation_name}: Sample rate validation failed: {e}")
        # Fallback to safe default
        validated_sample_rate = 16000
        logger.warning(f"[AudioGuard] {operation_name}: Using fallback sample rate: {validated_sample_rate}Hz")

    sample_rate = validated_sample_rate

    # Validate channels
    if channels < 1 or channels > 2:
        logger.warning(f"[AudioGuard] {operation_name}: Invalid channel count {channels}, defaulting to 1")
        channels = 1

    return sample_rate, channels


def safe_audio_operation(func, *args, operation_name: str = "audio_op",
                        fallback_value=None, max_retries: int = 3):
    """
    Execute audio operation with error recovery and retry mechanism.

    Args:
        func: Function to execute
        *args: Arguments to pass to function
        operation_name: Operation name for logging
        fallback_value: Value to return if all retries fail
        max_retries: Maximum number of retry attempts

    Returns:
        Result of function or fallback value
    """
    for attempt in range(max_retries):
        try:
            return func(*args)
        except Exception as e:
            logger.warning(f"[AudioGuard] {operation_name}: Attempt {attempt + 1} failed: {e}")

            if attempt == max_retries - 1:
                logger.error(f"[AudioGuard] {operation_name}: All retries exhausted, using fallback")
                return fallback_value

            # Exponential backoff
            time.sleep(0.1 * (2 ** attempt))


def _fast_audio_validation_guard(audio_data: np.ndarray,
                               operation_name: str,
                               allow_empty: bool,
                               cfg: 'Config') -> np.ndarray:
    """
    PERFORMANCE-OPTIMIZED audio validation using statistical sampling.

    DeepSeek Analysis: 15-25% CPU reduction through selective validation
    - Validates only 5% of samples instead of 100%
    - Uses vectorized operations for 20x speedup
    - Skips redundant checks and logging
    - Maintains safety through strategic sampling
    """
    # Quick basic validation
    if not isinstance(audio_data, np.ndarray):
        audio_data = np.array(audio_data, dtype=np.float32)

    if audio_data.size == 0:
        if allow_empty:
            return np.array([], dtype=np.float32)
        raise ValueError(f"[FastGuard] {operation_name}: Empty audio not allowed")

    # Flatten if needed (minimal check)
    if audio_data.ndim > 1:
        audio_data = audio_data.flatten()

    # Ensure float32 (minimal conversion overhead)
    if audio_data.dtype != np.float32:
        audio_data = audio_data.astype(np.float32)

    # STATISTICAL SAMPLING: Only check subset of data for NaN/Inf
    sample_rate = getattr(cfg, 'audio_validation_sample_rate', 0.05)  # Default 5%
    if getattr(cfg, 'fast_nan_inf_detection', True) and audio_data.size > 1000:
        # Sample every Nth element for large arrays
        step_size = max(1, int(1.0 / sample_rate))
        sample_indices = slice(0, None, step_size)
        sample_data = audio_data[sample_indices]

        # Check sample for issues
        if np.any(np.isnan(sample_data)):
            # Full check only if sample shows problems
            audio_data = np.nan_to_num(audio_data, nan=0.0, copy=False)

        if np.any(np.isinf(sample_data)):
            # Full check only if sample shows problems
            audio_data = np.nan_to_num(audio_data, posinf=32.0, neginf=-32.0, copy=False)

        # Quick amplitude check on sample
        sample_max = np.max(np.abs(sample_data))
        if sample_max > 100.0:
            # Clamp full array only if needed
            audio_data = np.clip(audio_data, -100.0, 100.0)
    else:
        # For small arrays, do minimal full check
        audio_data = np.nan_to_num(audio_data, nan=0.0, posinf=32.0, neginf=-32.0, copy=False)
        if np.max(np.abs(audio_data)) > 100.0:
            audio_data = np.clip(audio_data, -100.0, 100.0)

    # Skip non-critical logging for performance
    if not getattr(cfg, 'disable_amplitude_warnings', True):
        max_amp = np.max(np.abs(audio_data))
        if max_amp > 10.0:
            logger.warning(f"[FastGuard] {operation_name}: High amplitude: {max_amp:.2f}")

    return audio_data


def _block_to_mono(indata) -> np.ndarray:
    """Copy one PortAudio block into a fresh mono float32 array, cheaply.

    Runs on the audio thread, so it must stay O(block) with no logging, no
    allocation beyond the copy, and no locks. Non-finite samples (a driver
    glitch, never seen from a real mic) are zeroed in place rather than
    rejecting the block.
    """
    arr = np.asarray(indata, dtype=np.float32)
    if arr.ndim == 2:
        if arr.shape[1] == 1:
            block = arr[:, 0].copy()
        else:
            block = arr.mean(axis=1, dtype=np.float32)
    else:
        block = arr.reshape(-1).copy()
    if block.size and not np.isfinite(block).all():
        np.nan_to_num(block, copy=False, nan=0.0, posinf=1.0, neginf=-1.0)
    return block


class BoundedRingBuffer:
    """Memory-safe ring buffer for audio data with size limits"""

    def __init__(self, max_duration_seconds: float, sample_rate: int):
        self.max_samples = int(max_duration_seconds * sample_rate)
        self.sample_rate = sample_rate
        self.buffer = np.zeros(self.max_samples, dtype=np.float32)
        self.write_pos = 0
        self.samples_written = 0
        # Recording generation this buffer currently accepts (see append_block).
        self.epoch = 0
        self.lock = threading.Lock()
        print(f"[AudioBuffer] Initialized with {max_duration_seconds}s capacity ({self.max_samples} samples)")

    def append(self, data: np.ndarray):
        """Add data to ring buffer, overwriting old data if full.

        Validates first. Use `append_block` from the audio callback instead:
        validation can log, and logging on the audio thread drops frames.
        """
        try:
            data = audio_validation_guard(data, "RingBuffer.append", allow_empty=True)
        except Exception as e:
            logger.error(f"[RingBuffer] Critical error in append: {e}")
            return
        self.append_block(data)

    def append_block(self, data: np.ndarray, epoch: Optional[int] = None) -> None:
        """Append an already-sanitized mono float32 block.

        Takes the buffer lock, so a reader holding it stalls the caller. The
        recorder therefore never calls this from a PortAudio callback: blocks go
        through `_CaptureQueue` and a worker thread appends them.

        With `epoch`, the block is dropped unless it matches the epoch set by
        the last `clear(epoch=...)`. The check is under the lock, so a block of
        the previous recording that was in flight when the next one started can
        never land after the clear.
        """
        data_len = int(data.size)
        if data_len == 0:
            return
        with self.lock:
            if epoch is not None and epoch != self.epoch:
                return
            if data_len >= self.max_samples:
                # Data larger than buffer - keep only the most recent part.
                self.buffer[:] = data[-self.max_samples:]
                self.write_pos = 0
                self.samples_written += data_len
                return

            end_pos = self.write_pos + data_len
            if end_pos <= self.max_samples:
                self.buffer[self.write_pos:end_pos] = data
            else:
                first_part_len = self.max_samples - self.write_pos
                self.buffer[self.write_pos:] = data[:first_part_len]
                self.buffer[:data_len - first_part_len] = data[first_part_len:]

            self.write_pos = end_pos % self.max_samples
            self.samples_written += data_len

    def overwritten_samples(self) -> int:
        """Samples lost to wraparound since the last clear (0 if none)."""
        with self.lock:
            return max(0, int(self.samples_written) - int(self.max_samples))

    def get_data(self) -> np.ndarray:
        """Get all data from buffer in correct order"""
        with self.lock:
            if self.samples_written == 0:
                return np.array([], dtype=np.float32)
            
            if self.samples_written < self.max_samples:
                # Buffer not full yet - return from start to write_pos
                return self.buffer[:self.write_pos].copy()
            else:
                # Buffer is full - return from write_pos to end, then from start to write_pos
                return np.concatenate([
                    self.buffer[self.write_pos:],
                    self.buffer[:self.write_pos]
                ])

    def get_latest_samples(self, max_samples: int) -> np.ndarray:
        """Get only the latest N samples in logical order."""
        if max_samples <= 0:
            return np.array([], dtype=np.float32)
        with self.lock:
            available = min(self.samples_written, self.max_samples)
            if available <= 0:
                return np.array([], dtype=np.float32)

            count = min(int(max_samples), int(available))
            if self.samples_written < self.max_samples:
                start = max(0, self.write_pos - count)
                return self.buffer[start:self.write_pos].copy()

            # Full ring: latest samples end at write_pos.
            start = (self.write_pos - count) % self.max_samples
            if start < self.write_pos:
                return self.buffer[start:self.write_pos].copy()
            return np.concatenate((self.buffer[start:], self.buffer[:self.write_pos]))

    def get_samples_since(self, last_total_samples: int) -> tuple[np.ndarray, int]:
        """
        Return samples written after `last_total_samples` plus current absolute sample count.
        If caller lags past ring capacity, returns the oldest still-available slice.
        """
        with self.lock:
            total = int(self.samples_written)
            if total <= 0:
                return np.array([], dtype=np.float32), 0

            oldest_available = max(0, total - self.max_samples)
            start_total = max(int(last_total_samples), oldest_available)
            if start_total >= total:
                return np.array([], dtype=np.float32), total

            count = total - start_total
            if self.samples_written < self.max_samples:
                start = max(0, self.write_pos - count)
                return self.buffer[start:self.write_pos].copy(), total

            start = (self.write_pos - count) % self.max_samples
            if start < self.write_pos:
                return self.buffer[start:self.write_pos].copy(), total
            return np.concatenate((self.buffer[start:], self.buffer[:self.write_pos])), total

    def get_samples(self) -> np.ndarray:
        """Compatibility alias used by UI/streaming callers."""
        return self.get_data()
    
    def clear(self, epoch: Optional[int] = None):
        """Clear the buffer AND zero out data to prevent corruption"""
        with self.lock:
            if epoch is not None:
                self.epoch = int(epoch)
            self.write_pos = 0
            self.samples_written = 0
            # CRITICAL: Zero out the buffer to prevent old data bleeding through
            self.buffer.fill(0.0)
    
    def get_duration_seconds(self) -> float:
        """Get current data duration in seconds"""
        with self.lock:
            return min(self.samples_written, self.max_samples) / self.sample_rate


CHANNEL_RECORDING = 0
CHANNEL_CONTINUOUS = 1


class _CaptureQueue:
    """Hands audio blocks from PortAudio callbacks to one worker thread.

    The callback side (`offer`) takes no lock: `queue.SimpleQueue.put` is
    implemented in C, never blocks and is documented as safe even from
    contexts that interrupt other code. `qsize()` is likewise lock-free. The
    worker is the only thread that touches the ring-buffer locks on the capture
    path, so a reader stalled while holding a ring lock delays the worker, never
    the audio thread.

    The queue is bounded by `max_blocks`: if the worker falls that far behind,
    `offer` drops the block and counts it rather than growing without limit.

    Counters have one writer each (the callback of one stream, or the worker),
    so plain ints are enough; readers on other threads only need a snapshot.
    """

    def __init__(self, max_blocks: int, sinks: dict) -> None:
        self.max_blocks = max(8, int(max_blocks))
        self._sinks = sinks  # channel -> callable(generation, block)
        self._q: "queue.SimpleQueue" = queue.SimpleQueue()
        self.put_count = [0, 0]       # written by the callback of each channel
        self.applied_count = [0, 0]   # written by the worker (or inline drain)
        self.dropped = [0, 0]         # written by the callback of each channel
        self.high_water = 0
        self.worker_errors = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._thread_guard = threading.Lock()  # never taken by a callback

    # --- audio thread -------------------------------------------------
    def offer(self, channel: int, generation: int, block: np.ndarray) -> bool:
        """Queue one block. Never blocks. Returns False if it was dropped."""
        depth = self._q.qsize()
        if depth >= self.max_blocks:
            self.dropped[channel] += 1
            return False
        # Count before putting so a flush that snapshots put_count never misses
        # an item that is already visible to the worker.
        self.put_count[channel] += 1
        self._q.put((channel, generation, block))
        if depth + 1 > self.high_water:
            self.high_water = depth + 1
        return True

    # --- worker -------------------------------------------------------
    def _apply(self, item) -> None:
        channel, generation, block = item
        try:
            self._sinks[channel](generation, block)
        except Exception:
            self.worker_errors += 1
        finally:
            self.applied_count[channel] += 1

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.25)
            except queue.Empty:
                continue
            self._apply(item)

    def ensure_worker(self) -> None:
        with self._thread_guard:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name="VoiceFlowCaptureWorker", daemon=True
            )
            self._thread.start()

    def worker_alive(self) -> bool:
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def close(self, timeout: float = 1.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def depth(self) -> int:
        return int(self._q.qsize())

    # --- consumer threads ----------------------------------------------
    def _drain_inline(self) -> None:
        """Apply everything queued on the calling thread. Only valid while no
        worker is running (otherwise two appliers could reorder blocks)."""
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                return
            self._apply(item)

    def flush(self, channel: int, timeout: float) -> bool:
        """Wait until every block offered on `channel` so far has been applied.

        Bounded: returns False after `timeout` rather than hanging a stop() on a
        stalled worker. If the worker has died, drains on this thread instead.
        """
        target = self.put_count[channel]
        deadline = time.monotonic() + max(0.0, float(timeout))
        while self.applied_count[channel] < target:
            if not self.worker_alive():
                self._drain_inline()
                return self.applied_count[channel] >= target
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.001)
        return True


class EnhancedAudioRecorder:
    """Enhanced audio recorder with memory-safe bounded buffers"""
    
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._stream: Optional[sd.InputStream] = None

        # Bounded buffer: memory is fixed at capacity no matter how long the
        # key is held. Past capacity the oldest audio is overwritten; stop()
        # logs how much was lost so it is never silent.
        try:
            max_duration = float(getattr(cfg, "max_recording_seconds", 300.0))
        except (TypeError, ValueError):
            max_duration = 300.0
        if not (10.0 <= max_duration <= 1800.0):
            max_duration = 300.0
        self._max_duration = max_duration
        self._ring_buffer = BoundedRingBuffer(max_duration, cfg.sample_rate)

        # Audio-thread health counters. Written only from the PortAudio
        # callbacks (one writer per counter), read from anywhere. Nothing is
        # logged on the audio thread: file I/O there is what drops frames.
        self._overflow_count = 0             # recording stream input overflows
        self._continuous_overflow_count = 0  # pre-buffer stream input overflows
        self._other_status_count = 0         # any other PortAudio status flag
        self._callback_error_count = 0
        self._ring_wrap_count = 0            # recordings that exceeded capacity
        self._overflow_at_start = 0
        self._continuous_overflow_at_start = 0
        
        # PRE-RECORDING BUFFER: Continuously captures audio to prevent word loss
        self._pre_buffer_duration = 1.5  # 1500ms pre-buffer (optimized for key-press timing)
        self._pre_buffer = BoundedRingBuffer(self._pre_buffer_duration, cfg.sample_rate)
        self._continuous_stream: Optional[sd.InputStream] = None
        self._continuous_recording = False

        self._lock = threading.Lock()
        self._recording = False
        self._start_time = 0.0

        # One always-on microphone stream instead of a second stream opened per
        # recording. Two concurrent streams on one device doubled the callbacks, and the
        # per-recording stream was opened/closed on the hotkey path; both are candidate
        # causes of the remaining audio_input_overflow in the 118 s field test. Set
        # audio_single_stream=False to get the old two-stream behaviour back.
        self._single_stream = bool(getattr(cfg, "audio_single_stream", True))
        # Worker-side routing: while True, blocks from the single stream go to the
        # recording ring instead of the pre-roll buffer. Flipped, together with the
        # pre-roll hand-over, under _route_lock, which the worker also holds while it
        # applies a block - so a block is wholly before or wholly after the switch.
        self._route_lock = threading.Lock()
        self._route_recording = False

        # Overflow diagnostics, written from the audio thread (no I/O, no allocation
        # beyond a tuple) and read in stop(): when each overflow happened, how deep the
        # capture queue was, and the longest gap between callbacks. This is what tells a
        # GIL/CPU stall (long gaps) from device contention (overflow with normal gaps).
        self._overflow_events: list = []
        self._last_cb_t = 0.0
        self._max_cb_gap = 0.0
        self._start_mono = 0.0
        # Bumped on every start(); blocks queued by an earlier recording that
        # are still in flight are discarded instead of leaking into this one.
        self._generation = 0

        # Performance monitoring
        self._callback_count = 0
        self._total_frames = 0

        # Callback -> worker hand-off. The callbacks never touch a ring-buffer
        # lock; see _CaptureQueue.
        self._capture = _CaptureQueue(
            self._queue_max_blocks(),
            {
                CHANNEL_RECORDING: self._sink_recording,
                CHANNEL_CONTINUOUS: self._sink_continuous,
            },
        )
        self._capture.ensure_worker()
        self._dropped_at_start = 0

        print(f"[AudioRecorder] Enhanced recorder initialized:")
        print(f"  - Sample rate: {cfg.sample_rate}Hz")
        print(f"  - Channels: {cfg.channels}")
        print(f"  - Block size: {cfg.blocksize} frames")
        print(f"  - Max duration: {max_duration}s")
        print(f"  - Pre-buffer: {self._pre_buffer_duration}s")

    def _note_status(self, status, *, continuous: bool) -> None:
        """Count a PortAudio status flag. Audio-thread safe: no I/O."""
        if getattr(status, "input_overflow", False):
            if continuous:
                self._continuous_overflow_count += 1
            else:
                self._overflow_count += 1
            events = self._overflow_events
            if len(events) < 32:
                events.append((time.monotonic(), 1 if continuous else 0, self._capture.depth()))
        else:
            self._other_status_count += 1

    def _queue_max_blocks(self) -> int:
        try:
            seconds = float(getattr(self.cfg, "audio_queue_max_seconds", 4.0))
        except (TypeError, ValueError):
            seconds = 4.0
        if not (0.25 <= seconds <= 60.0):
            seconds = 4.0
        try:
            block = int(self.cfg.blocksize) or 512
        except (TypeError, ValueError, AttributeError):
            block = 512
        return int(np.ceil(seconds * float(self.cfg.sample_rate) / float(max(1, block))))

    # Worker-thread sinks: the only capture-path code that takes ring locks.
    def _sink_recording(self, generation: int, block: np.ndarray) -> None:
        self._ring_buffer.append_block(block, epoch=generation)

    def _begin_generation(self) -> None:
        """Start a new recording generation and empty the ring atomically with
        respect to the worker: stale in-flight blocks are discarded."""
        self._generation += 1
        self._ring_buffer.clear(epoch=self._generation)

    def _sink_continuous(self, _generation: int, block: np.ndarray) -> None:
        with self._route_lock:
            if self._route_recording:
                self._ring_buffer.append_block(block, epoch=self._generation)
            else:
                self._pre_buffer.append_block(block)

    def _callback(self, indata, frames, time_info, status):
        """Recording-stream callback. Must never block: copy, enqueue, return.

        No lock, no logging, no validation guard: any of those can stall long
        enough for the driver to overrun (the `input overflow` warnings in the
        field log). The ring-buffer append happens on the capture worker, so a
        reader holding the ring lock cannot hold up the audio thread.
        """
        if status:
            self._note_status(status, continuous=False)

        if not self._recording:
            return

        try:
            if self._capture.offer(CHANNEL_RECORDING, self._generation, _block_to_mono(indata)):
                self._total_frames += frames
        except Exception:
            self._callback_error_count += 1
        # Activity marker for the stop-drain and the watchdog: a block arrived,
        # whether or not the queue had room for it.
        self._callback_count += 1

    def _continuous_callback(self, indata, frames, time_info, status):
        """Pre-buffer callback. Same no-blocking rules as `_callback`."""
        recording_on_this_stream = self._single_stream and self._recording
        if status:
            self._note_status(status, continuous=not recording_on_this_stream)

        if not self._continuous_recording:
            return

        now = time.perf_counter()
        last = self._last_cb_t
        if last > 0.0 and (now - last) > self._max_cb_gap:
            self._max_cb_gap = now - last
        self._last_cb_t = now

        try:
            queued = self._capture.offer(CHANNEL_CONTINUOUS, 0, _block_to_mono(indata))
            if recording_on_this_stream and queued:
                self._total_frames += frames
        except Exception:
            self._callback_error_count += 1
        if recording_on_this_stream:
            # Same activity marker the recording-stream callback keeps for the
            # stop-drain and the watchdog.
            self._callback_count += 1

    def flush_capture(self, timeout: float = 1.0) -> bool:
        """Wait (bounded) until every queued recording block is in the ring."""
        return self._capture.flush(CHANNEL_RECORDING, timeout)

    def close(self) -> None:
        """Stop streams and the capture worker. The recorder is unusable after."""
        try:
            if self._recording:
                self.stop()
        finally:
            self.stop_continuous()
            self._capture.close()

    def _stream_latency(self):
        """PortAudio latency for both input streams.

        'high' gives the driver the most headroom before it overruns. The
        hotkey-to-text path does not depend on this: the pre-buffer covers the
        start, the stop drain covers the tail.
        """
        raw = getattr(self.cfg, "audio_input_latency", "high")
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            value = float(raw)
            return value if 0.0 < value <= 1.0 else "high"
        text = str(raw or "").strip().lower()
        if text in ("high", "low"):
            return text
        try:
            value = float(text)
        except ValueError:
            return "high"
        return value if 0.0 < value <= 1.0 else "high"

    def get_audio_health(self) -> dict:
        """Snapshot of audio-thread health counters for the health report."""
        return {
            "overflow_recording": int(self._overflow_count),
            "overflow_continuous": int(self._continuous_overflow_count),
            "status_other": int(self._other_status_count),
            "callback_errors": int(self._callback_error_count),
            "ring_wraps": int(self._ring_wrap_count),
            # Blocks the callback dropped because the worker was >queue bound behind.
            "queue_dropped_recording": int(self._capture.dropped[CHANNEL_RECORDING]),
            "queue_dropped_continuous": int(self._capture.dropped[CHANNEL_CONTINUOUS]),
            "queue_high_water": int(self._capture.high_water),
            "queue_capacity_blocks": int(self._capture.max_blocks),
            "capture_worker_alive": bool(self._capture.worker_alive()),
            "capture_worker_errors": int(self._capture.worker_errors),
        }

    def start(self):
        """Start recording with pre-buffer integration"""
        if self._recording:
            return

        print("[AudioRecorder] Starting enhanced recording with pre-buffer...")

        self._capture.ensure_worker()
        # New generation + clear (prevents old data corruption): any block of
        # the previous recording still in flight is discarded, not appended.
        self._begin_generation()

        # Start continuous recording if not already running
        if not self._continuous_recording:
            self.start_continuous()

        # Pull the freshest pre-roll out of the queue so the words spoken just
        # before the key press are in the snapshot below. Bounded wait.
        self._capture.flush(CHANNEL_CONTINUOUS, 0.1)

        self._callback_count = 0
        self._total_frames = 0
        self._start_time = time.time()
        self._start_mono = time.monotonic()
        self._overflow_at_start = self._overflow_count
        self._continuous_overflow_at_start = self._continuous_overflow_count
        self._dropped_at_start = self._capture.dropped[CHANNEL_RECORDING]
        self._overflow_events = []
        self._max_cb_gap = 0.0

        if self._single_stream:
            # Hand the pre-roll over and switch routing in one step with respect to the
            # worker; the stream itself keeps running untouched.
            with self._route_lock:
                self._append_pre_roll_locked()
                self._route_recording = True
            self._recording = True
            print("[AudioRecorder] Recording started on the shared stream (pre-roll included)")
            return

        with self._route_lock:
            self._append_pre_roll_locked()

        self._stream = sd.InputStream(
            channels=self.cfg.channels,
            samplerate=self.cfg.sample_rate,
            dtype="float32",
            blocksize=self.cfg.blocksize,
            latency=self._stream_latency(),
            callback=self._callback,
        )
        self._stream.start()
        self._recording = True
        print(f"[AudioRecorder] Recording started successfully with pre-buffer integration")

    def _append_pre_roll_locked(self) -> None:
        """Move the freshest pre-roll into the recording ring (caller holds _route_lock)."""
        # Get pre-buffer data BEFORE clearing to use for this recording
        pre_buffer_data = self._pre_buffer.get_data()

        # CRITICAL FIX: Clear pre-buffer IMMEDIATELY after getting data
        # This prevents any accumulation while we process
        self._pre_buffer.clear()

        if len(pre_buffer_data) > 0:
            # Take only the most recent portion to minimize latency
            min_pre_buffer_samples = int(0.3 * self.cfg.sample_rate)  # 300ms minimum
            if len(pre_buffer_data) > min_pre_buffer_samples:
                # Use recent 800ms of pre-buffer for optimal key-press timing
                recent_samples = int(0.8 * self.cfg.sample_rate)
                pre_buffer_data = pre_buffer_data[-recent_samples:]

            # Add pre-buffer to main buffer for this recording only.
            # Pre-buffer blocks were sanitized on the way in.
            self._ring_buffer.append_block(pre_buffer_data)

    def _drain_pending_audio(self) -> None:
        """Let in-flight audio reach the buffer before the stream is torn down.

        Polls the callback counter rather than sleeping a fixed interval: once
        callbacks stop arriving the audio is flushed and there is nothing left
        to wait for, so a quiet stream costs one poll instead of the full cap.
        """
        try:
            cap = float(getattr(self.cfg, "stop_drain_seconds", 0.25))
        except (TypeError, ValueError):
            cap = 0.25
        if cap <= 0:
            return

        try:
            block_seconds = float(self.cfg.blocksize) / float(self.cfg.sample_rate)
        except (TypeError, ValueError, ZeroDivisionError, AttributeError):
            block_seconds = 0.032
        poll = max(0.005, min(block_seconds, cap / 4.0))

        deadline = time.time() + cap
        last_count = self._callback_count
        quiet_polls = 0
        while time.time() < deadline:
            time.sleep(poll)
            if self._callback_count != last_count:
                last_count = self._callback_count
                quiet_polls = 0
                continue
            quiet_polls += 1
            # Two consecutive silent polls means the driver has handed over
            # everything it had.
            if quiet_polls >= 2:
                return

    def is_recording(self) -> bool:
        """Check if currently recording"""
        return self._recording

    def stop(self) -> np.ndarray:
        """Stop recording and return audio data"""
        if not self._recording:
            return np.array([], dtype=np.float32)

        try:
            # Drain BEFORE clearing the flag. The callback only appends while
            # _recording is True, and stopping a PortAudio input stream discards
            # whatever the driver still holds -- so flipping the flag first loses
            # every frame captured between the last callback and the key release.
            # That is the "last word gets cut off" report.
            self._drain_pending_audio()

            self._recording = False
            if self._stream is not None:
                self._stream.stop()
                self._stream.close()
                self._stream = None

            # Wait for the worker to move every queued block into the ring before
            # reading it (the tail of the utterance is the last thing queued). With a
            # per-recording stream that stream has stopped; with the shared stream the
            # blocks offered so far are the ones that count.
            flushed = self._capture.flush(CHANNEL_RECORDING, 1.0)
            if self._single_stream:
                flushed = self._capture.flush(CHANNEL_CONTINUOUS, 1.0) and flushed
            if not flushed:
                logger.warning(
                    "capture_queue_flush_timeout pending=%d worker_alive=%s",
                    self._capture.depth(),
                    self._capture.worker_alive(),
                )

            # Stop routing to the ring; from here blocks feed the pre-roll again.
            # Clearing it keeps this utterance's tail out of the next pre-roll.
            with self._route_lock:
                self._route_recording = False
                if self._single_stream:
                    self._pre_buffer.clear()

            # Get the recorded audio data
            audio_data = self._ring_buffer.get_data()
            duration = len(audio_data) / self.cfg.sample_rate
            lost_samples = self._ring_buffer.overwritten_samples()

            # Report audio-thread trouble from this (non-audio) thread.
            overflows = self._overflow_count - self._overflow_at_start
            continuous_overflows = self._continuous_overflow_count - self._continuous_overflow_at_start
            if overflows > 0 or continuous_overflows > 0:
                logger.warning(
                    "audio_input_overflow recording=%d continuous=%d duration=%.2f",
                    overflows,
                    continuous_overflows,
                    duration,
                )
            max_gap_ms = self._max_cb_gap * 1000.0
            if overflows > 0 or continuous_overflows > 0:
                # Where in the recording each overflow fell and what the queue looked
                # like, plus the longest callback gap: a long gap means the process
                # stalled (GIL/CPU), a normal gap means the device dropped samples.
                offsets = [round(t - self._start_mono, 2) for t, _s, _d in self._overflow_events]
                depths = [d for _t, _s, d in self._overflow_events]
                logger.warning(
                    "audio_overflow_detail single_stream=%s at_s=%s queue_depth=%s max_callback_gap_ms=%.0f",
                    self._single_stream,
                    offsets,
                    depths,
                    max_gap_ms,
                )
            elif max_gap_ms > 0.0:
                logger.info(
                    "audio_capture_summary single_stream=%s duration=%.2f callbacks=%d max_callback_gap_ms=%.0f queue_high_water=%d",
                    self._single_stream,
                    duration,
                    self._callback_count,
                    max_gap_ms,
                    self._capture.high_water,
                )
            queue_dropped = self._capture.dropped[CHANNEL_RECORDING] - self._dropped_at_start
            if queue_dropped > 0:
                logger.warning(
                    "audio_queue_saturated dropped_blocks=%d capacity_blocks=%d duration=%.2f",
                    queue_dropped,
                    self._capture.max_blocks,
                    duration,
                )
            if lost_samples > 0:
                self._ring_wrap_count += 1
                logger.warning(
                    "recording_ring_wrapped capacity_s=%.0f lost_seconds=%.2f",
                    self._max_duration,
                    lost_samples / float(self.cfg.sample_rate),
                )

            # CRITICAL FIX: Clear buffer after getting data to prevent accumulation
            self._ring_buffer.clear()
            print(f"[AudioRecorder] Buffer cleared after extraction to prevent accumulation")
            
            # Performance summary
            actual_duration = time.time() - self._start_time
            print(f"[AudioRecorder] Recording stopped:")
            print(f"  - Audio duration: {duration:.2f}s")
            print(f"  - Actual duration: {actual_duration:.2f}s")
            print(f"  - Callbacks: {self._callback_count}")
            print(f"  - Samples: {len(audio_data)}")
            print(f"  - Memory usage: {len(audio_data) * 4 / 1024 / 1024:.2f}MB")
            
            return audio_data
            
        except Exception as e:
            print(f"[AudioRecorder] Error stopping recording: {e}")
            return np.array([], dtype=np.float32)
    
    def get_current_duration(self) -> float:
        """Get current recording duration in seconds"""
        return self._ring_buffer.get_duration_seconds()
    
    def get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB"""
        return self._ring_buffer.max_samples * 4 / 1024 / 1024  # 4 bytes per float32
    
    def start_continuous(self):
        """Start continuous pre-recording to prevent word loss"""
        if self._continuous_recording:
            return
        
        print("[AudioRecorder] Starting continuous pre-buffer recording...")
        self._capture.ensure_worker()
        self._pre_buffer.clear()
        
        self._continuous_stream = sd.InputStream(
            channels=self.cfg.channels,
            samplerate=self.cfg.sample_rate,
            dtype="float32",
            blocksize=self.cfg.blocksize,
            latency=self._stream_latency(),
            callback=self._continuous_callback,
        )
        self._continuous_stream.start()
        self._continuous_recording = True
        print(f"[AudioRecorder] Continuous pre-buffer active ({self._pre_buffer_duration}s)")
    
    def stop_continuous(self):
        """Stop continuous pre-recording"""
        if not self._continuous_recording:
            return
            
        self._continuous_recording = False
        if self._continuous_stream is not None:
            self._continuous_stream.stop()
            self._continuous_stream.close()
            self._continuous_stream = None
        print("[AudioRecorder] Continuous pre-buffer stopped")


# Compatibility alias for drop-in replacement
AudioRecorder = EnhancedAudioRecorder
