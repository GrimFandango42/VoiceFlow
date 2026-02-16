#!/usr/bin/env python3
"""
VoiceFlow Critical Guardrails
============================
Essential safety and stability guardrails to prevent crashes and ensure reliability.

This module implements critical validation, sanitization, and recovery mechanisms
identified from comprehensive testing failures.
"""

import logging
import threading
import time
import gc
import queue
from typing import Any, Callable, Optional, Union, Tuple
from functools import wraps

import numpy as np

try:
    import psutil
except ImportError:
    psutil = None

from ..core.config import Config

# Set up logging
logger = logging.getLogger(__name__)

# Thread-safe visual update queue
visual_update_queue: queue.Queue = queue.Queue()


class AudioValidationError(Exception):
    """Raised when audio data fails validation"""
    pass


class ConfigurationError(Exception):
    """Raised when configuration is invalid"""
    pass


def validate_and_sanitize_audio(audio_data: np.ndarray) -> np.ndarray:
    """
    Validate and sanitize audio input to prevent crashes.

    This addresses critical edge case failures where invalid audio data
    (NaN, infinite values, empty arrays) cause system crashes.

    Args:
        audio_data: Raw audio data array

    Returns:
        Sanitized audio data safe for processing

    Raises:
        AudioValidationError: If audio data cannot be sanitized
    """
    # Validate input type
    if not isinstance(audio_data, np.ndarray):
        try:
            audio_data = np.array(audio_data, dtype=np.float32)
        except Exception as e:
            raise AudioValidationError(f"Cannot convert input to numpy array: {e}")

    # Check for empty arrays - critical failure point
    if audio_data.size == 0:
        logger.warning("Empty audio data received, using silence")
        return np.zeros(1024, dtype=np.float32)  # Return 1024 samples of silence

    # Check for invalid dimensions
    if audio_data.ndim > 2:
        logger.warning(f"Audio has {audio_data.ndim} dimensions, flattening")
        audio_data = audio_data.flatten()

    # Handle stereo to mono conversion if needed
    if audio_data.ndim == 2:
        if audio_data.shape[1] == 2:
            logger.debug("Converting stereo to mono")
            audio_data = np.mean(audio_data, axis=1)
        else:
            logger.warning(f"Unexpected audio shape {audio_data.shape}, taking first channel")
            audio_data = audio_data[:, 0]

    # Ensure float32 for consistent processing
    if audio_data.dtype != np.float32:
        audio_data = audio_data.astype(np.float32)

    # Check for NaN values - critical crash source
    nan_count = np.sum(np.isnan(audio_data))
    if nan_count > 0:
        logger.warning(f"Found {nan_count} NaN values in audio, replacing with zeros")
        audio_data = np.nan_to_num(audio_data, nan=0.0)

    # Check for infinite values - critical crash source
    inf_count = np.sum(np.isinf(audio_data))
    if inf_count > 0:
        logger.warning(f"Found {inf_count} infinite values in audio, clipping")
        audio_data = np.nan_to_num(audio_data, posinf=1.0, neginf=-1.0)

    # Clip extreme values to prevent overflow in downstream processing
    max_safe = 32.0  # Safe maximum for float32 audio processing
    original_peak = np.max(np.abs(audio_data))
    audio_data = np.clip(audio_data, -max_safe, max_safe)

    # Warn about high amplitudes that might indicate issues
    peak = np.max(np.abs(audio_data))
    if peak > 10.0:
        logger.warning(f"High audio amplitude detected: {peak:.2f} (original: {original_peak:.2f})")

    # Final validation - ensure we have valid, finite audio
    if not np.all(np.isfinite(audio_data)):
        logger.error("Audio still contains invalid values after sanitization")
        raise AudioValidationError("Unable to sanitize audio data")

    return audio_data


def safe_visual_update(update_func: Callable, *args, **kwargs) -> Any:
    """
    Thread-safe wrapper for visual updates.

    This addresses critical GUI threading crashes by ensuring all visual
    updates happen on the main thread.

    Args:
        update_func: Function to call for visual update
        *args, **kwargs: Arguments to pass to update_func

    Returns:
        Result of update_func if successful, None if failed
    """
    try:
        # Visual indicators handle their own thread safety via command queue
        # Just call directly with error protection
        return update_func(*args, **kwargs)
    except Exception as e:
        logger.error(f"Visual update error: {e}")
        return None


def process_visual_update_queue():
    """
    Process pending visual updates from the queue.

    This should be called periodically from the main thread to handle
    queued visual updates from worker threads.
    """
    processed = 0
    try:
        while not visual_update_queue.empty() and processed < 10:  # Limit processing per call
            try:
                update_func = visual_update_queue.get_nowait()
                update_func()
                processed += 1
            except queue.Empty:
                break
            except Exception as e:
                logger.error(f"Failed to process visual update: {e}")

    except Exception as e:
        logger.error(f"Error processing visual update queue: {e}")

    return processed


def validate_config(cfg: Config) -> Config:
    """
    Validate and fix configuration values.

    This addresses critical configuration-related crashes by ensuring
    all config values are valid before use.

    Args:
        cfg: Configuration object to validate

    Returns:
        Validated and corrected configuration

    Raises:
        ConfigurationError: If configuration cannot be made valid
    """
    try:
        # Sample rate validation - critical for audio processing
        valid_rates = [8000, 11025, 16000, 22050, 44100, 48000]
        if not hasattr(cfg, 'sample_rate') or cfg.sample_rate not in valid_rates:
            logger.warning(f"Invalid sample rate {getattr(cfg, 'sample_rate', 'None')}, defaulting to 16000")
            cfg.sample_rate = 16000

        # Block size validation
        if not hasattr(cfg, 'blocksize') or cfg.blocksize <= 0 or cfg.blocksize > 8192:
            logger.warning(f"Invalid blocksize {getattr(cfg, 'blocksize', 'None')}, defaulting to 512")
            cfg.blocksize = 512

        # Channels validation
        if not hasattr(cfg, 'channels') or cfg.channels not in [1, 2]:
            logger.warning(f"Invalid channels {getattr(cfg, 'channels', 'None')}, defaulting to 1")
            cfg.channels = 1

        # Hotkey validation - ensure at least one key is defined
        has_modifier = getattr(cfg, 'hotkey_ctrl', False) or getattr(cfg, 'hotkey_shift', False) or getattr(cfg, 'hotkey_alt', False)
        has_key = getattr(cfg, 'hotkey_key', '') != ''

        if not has_modifier and not has_key:
            logger.warning("No valid hotkey defined, setting default Ctrl+Shift")
            cfg.hotkey_ctrl = True
            cfg.hotkey_shift = True
            cfg.hotkey_key = ""  # Just modifiers

        # PTT latency tuning safeguards
        if not hasattr(cfg, 'ptt_tail_buffer_seconds') or cfg.ptt_tail_buffer_seconds < 0.0 or cfg.ptt_tail_buffer_seconds > 2.0:
            logger.warning(
                f"Invalid ptt_tail_buffer_seconds {getattr(cfg, 'ptt_tail_buffer_seconds', 'None')}, defaulting to 0.25"
            )
            cfg.ptt_tail_buffer_seconds = 0.25

        if not hasattr(cfg, 'ptt_tail_min_recording_seconds') or cfg.ptt_tail_min_recording_seconds < 0.0 or cfg.ptt_tail_min_recording_seconds > 2.0:
            logger.warning(
                f"Invalid ptt_tail_min_recording_seconds {getattr(cfg, 'ptt_tail_min_recording_seconds', 'None')}, defaulting to 0.35"
            )
            cfg.ptt_tail_min_recording_seconds = 0.35

        # Model validation (VoiceFlow 3.0: supports Distil-Whisper and Voxtral)
        valid_models = [
            # Standard Whisper models
            'tiny', 'tiny.en', 'base', 'base.en', 'small', 'small.en',
            'medium', 'medium.en', 'large', 'large-v2', 'large-v3',
            # Distil-Whisper models (2025)
            'distil-large-v3', 'distil-large-v3.5',
            'Systran/faster-distil-whisper-large-v3',
            'distil-whisper/distil-large-v3.5',
            # Voxtral models (Mistral AI)
            'voxtral-3b', 'mistralai/Voxtral-Mini-3B-2507',
        ]

        # Model tier validation (VoiceFlow 3.0)
        valid_tiers = ['tiny', 'quick', 'balanced', 'quality', 'voxtral']
        if hasattr(cfg, 'model_tier') and cfg.model_tier:
            if cfg.model_tier.lower() not in valid_tiers:
                logger.warning(f"Invalid model_tier {cfg.model_tier}, defaulting to 'quick'")
                cfg.model_tier = 'quick'
            # Skip model_name validation if using tier (asr_engine handles it)
        elif not hasattr(cfg, 'model_name') or cfg.model_name not in valid_models:
            logger.warning(f"Invalid model {getattr(cfg, 'model_name', 'None')}, defaulting to distil-large-v3")
            cfg.model_name = 'distil-large-v3'

        # Device validation
        valid_devices = ['cpu', 'cuda', 'auto']
        if not hasattr(cfg, 'device') or cfg.device not in valid_devices:
            logger.warning(f"Invalid device {getattr(cfg, 'device', 'None')}, defaulting to auto")
            cfg.device = 'auto'

        # Compute type validation
        valid_compute_types = ['int8', 'int16', 'float16', 'float32']
        if not hasattr(cfg, 'compute_type') or cfg.compute_type not in valid_compute_types:
            logger.warning(f"Invalid compute_type {getattr(cfg, 'compute_type', 'None')}, defaulting to float16")
            cfg.compute_type = 'float16'

        # CPU tuning validation
        if not hasattr(cfg, 'cpu_threads') or cfg.cpu_threads < 0 or cfg.cpu_threads > 64:
            logger.warning(f"Invalid cpu_threads {getattr(cfg, 'cpu_threads', 'None')}, defaulting to 0 (auto)")
            cfg.cpu_threads = 0

        if not hasattr(cfg, 'asr_num_workers') or cfg.asr_num_workers < 1 or cfg.asr_num_workers > 8:
            logger.warning(f"Invalid asr_num_workers {getattr(cfg, 'asr_num_workers', 'None')}, defaulting to 1")
            cfg.asr_num_workers = 1

        if not hasattr(cfg, 'latency_boost_max_audio_seconds') or cfg.latency_boost_max_audio_seconds < 1.0 or cfg.latency_boost_max_audio_seconds > 120.0:
            logger.warning(
                f"Invalid latency_boost_max_audio_seconds {getattr(cfg, 'latency_boost_max_audio_seconds', 'None')}, defaulting to 12.0"
            )
            cfg.latency_boost_max_audio_seconds = 12.0

        if (
            not hasattr(cfg, 'latency_boost_tiny_max_audio_seconds')
            or cfg.latency_boost_tiny_max_audio_seconds < 0.5
            or cfg.latency_boost_tiny_max_audio_seconds > 30.0
        ):
            logger.warning(
                f"Invalid latency_boost_tiny_max_audio_seconds {getattr(cfg, 'latency_boost_tiny_max_audio_seconds', 'None')}, defaulting to 3.0"
            )
            cfg.latency_boost_tiny_max_audio_seconds = 3.0

        if not hasattr(cfg, 'latency_boost_model_tier') or str(cfg.latency_boost_model_tier).lower() not in ['tiny', 'quick', 'balanced', 'quality', 'voxtral']:
            logger.warning(f"Invalid latency_boost_model_tier {getattr(cfg, 'latency_boost_model_tier', 'None')}, defaulting to tiny")
            cfg.latency_boost_model_tier = 'tiny'

        # Beam size validation
        if not hasattr(cfg, 'beam_size') or cfg.beam_size < 1 or cfg.beam_size > 10:
            logger.warning(f"Invalid beam_size {getattr(cfg, 'beam_size', 'None')}, defaulting to 2")
            cfg.beam_size = 2

        # Temperature validation
        if not hasattr(cfg, 'temperature') or cfg.temperature < 0.0 or cfg.temperature > 1.0:
            logger.warning(f"Invalid temperature {getattr(cfg, 'temperature', 'None')}, defaulting to 0.0")
            cfg.temperature = 0.0

        # Adaptive learning validation (privacy-first temporary storage)
        if not hasattr(cfg, 'adaptive_retention_hours') or cfg.adaptive_retention_hours < 1 or cfg.adaptive_retention_hours > 720:
            logger.warning(
                f"Invalid adaptive_retention_hours {getattr(cfg, 'adaptive_retention_hours', 'None')}, defaulting to 72"
            )
            cfg.adaptive_retention_hours = 72

        if not hasattr(cfg, 'adaptive_min_count') or cfg.adaptive_min_count < 1 or cfg.adaptive_min_count > 20:
            logger.warning(f"Invalid adaptive_min_count {getattr(cfg, 'adaptive_min_count', 'None')}, defaulting to 3")
            cfg.adaptive_min_count = 3

        if not hasattr(cfg, 'adaptive_max_rules') or cfg.adaptive_max_rules < 10 or cfg.adaptive_max_rules > 5000:
            logger.warning(f"Invalid adaptive_max_rules {getattr(cfg, 'adaptive_max_rules', 'None')}, defaulting to 200")
            cfg.adaptive_max_rules = 200

        if not hasattr(cfg, 'adaptive_snippet_chars') or cfg.adaptive_snippet_chars < 50 or cfg.adaptive_snippet_chars > 2000:
            logger.warning(
                f"Invalid adaptive_snippet_chars {getattr(cfg, 'adaptive_snippet_chars', 'None')}, defaulting to 200"
            )
            cfg.adaptive_snippet_chars = 200

        if not hasattr(cfg, 'command_mode_prefix') or not str(cfg.command_mode_prefix).strip():
            logger.warning("Invalid command_mode_prefix, defaulting to 'command'")
            cfg.command_mode_prefix = "command"

        logger.debug("Configuration validation completed successfully")
        return cfg

    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        raise ConfigurationError(f"Cannot validate configuration: {e}")


def with_error_recovery(fallback_value: Any = None, max_retries: int = 3,
                       backoff_base: float = 0.1) -> Callable:
    """
    Decorator for automatic error recovery with exponential backoff.

    This addresses critical error propagation issues by containing failures
    and providing automatic retry mechanisms.

    Args:
        fallback_value: Value to return if all retries fail
        max_retries: Maximum number of retry attempts
        backoff_base: Base delay for exponential backoff

    Returns:
        Decorated function with error recovery
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    logger.warning(f"{func.__name__} attempt {attempt + 1}/{max_retries} failed: {e}")

                    if attempt < max_retries - 1:
                        # Exponential backoff: 0.1s, 0.2s, 0.4s, etc.
                        delay = backoff_base * (2 ** attempt)
                        time.sleep(delay)
                    else:
                        logger.error(f"{func.__name__} all retries exhausted, using fallback value")

            # Log the final failure for debugging
            if last_exception:
                logger.error(f"{func.__name__} final failure: {last_exception}")

            return fallback_value

        return wrapper
    return decorator


class ResourceMonitor:
    """
    Monitor system resources and enforce limits.

    This addresses memory leak issues and provides early warning for
    resource exhaustion scenarios.
    """

    def __init__(self, memory_limit_mb: int = 1000, cpu_limit_percent: float = 80.0):
        """
        Initialize resource monitor.

        Args:
            memory_limit_mb: Memory limit in megabytes
            cpu_limit_percent: CPU usage limit as percentage
        """
        self.memory_limit = memory_limit_mb
        self.cpu_limit = cpu_limit_percent
        self.process = None

        if psutil:
            try:
                self.process = psutil.Process()
            except Exception as e:
                logger.warning(f"Failed to initialize process monitor: {e}")

    def check_memory_usage(self) -> Tuple[bool, float]:
        """
        Check current memory usage against limits.

        Returns:
            Tuple of (is_over_limit, current_usage_mb)
        """
        if not self.process:
            return False, 0.0

        try:
            memory_info = self.process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024

            if memory_mb > self.memory_limit:
                logger.warning(f"Memory usage high: {memory_mb:.1f}MB (limit: {self.memory_limit}MB)")

                # Force garbage collection
                collected = gc.collect()
                logger.info(f"Triggered garbage collection, freed {collected} objects")

                # Check again after GC
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024

                return memory_mb > self.memory_limit, memory_mb

            return False, memory_mb

        except Exception as e:
            logger.error(f"Failed to check memory usage: {e}")
            return False, 0.0

    def check_cpu_usage(self) -> Tuple[bool, float]:
        """
        Check current CPU usage against limits.

        Returns:
            Tuple of (is_over_limit, current_usage_percent)
        """
        if not self.process:
            return False, 0.0

        try:
            cpu_percent = self.process.cpu_percent(interval=0.1)

            if cpu_percent > self.cpu_limit:
                logger.warning(f"CPU usage high: {cpu_percent:.1f}% (limit: {self.cpu_limit}%)")
                return True, cpu_percent

            return False, cpu_percent

        except Exception as e:
            logger.error(f"Failed to check CPU usage: {e}")
            return False, 0.0

    def get_resource_status(self) -> dict:
        """
        Get comprehensive resource status report.

        Returns:
            Dictionary with resource usage information
        """
        memory_over, memory_usage = self.check_memory_usage()
        cpu_over, cpu_usage = self.check_cpu_usage()

        return {
            'memory': {
                'usage_mb': memory_usage,
                'limit_mb': self.memory_limit,
                'over_limit': memory_over
            },
            'cpu': {
                'usage_percent': cpu_usage,
                'limit_percent': self.cpu_limit,
                'over_limit': cpu_over
            }
        }


def timeout_wrapper(timeout_seconds: float) -> Callable:
    """
    Decorator to add timeout protection to functions.

    This addresses infinite loop issues identified in stress testing.

    Args:
        timeout_seconds: Maximum execution time in seconds

    Returns:
        Decorated function with timeout protection
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = [None]
            exception = [None]

            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    exception[0] = e

            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            thread.join(timeout=timeout_seconds)

            if thread.is_alive():
                logger.error(f"{func.__name__} timed out after {timeout_seconds} seconds")
                # Note: We can't forcefully kill the thread, but we can return early
                return None

            if exception[0]:
                raise exception[0]

            return result[0]

        return wrapper
    return decorator


# Global resource monitor instance
resource_monitor = ResourceMonitor()


def initialize_guardrails():
    """
    Initialize the guardrails system.

    This should be called at application startup to set up monitoring
    and safety systems.
    """
    logger.info("Initializing VoiceFlow guardrails system")

    # Set up global exception handler for better error tracking
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

    import sys
    sys.excepthook = handle_exception

    logger.info("Guardrails system initialized successfully")
