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
        # Check if we're already on the main thread
        if threading.current_thread() is threading.main_thread():
            return update_func(*args, **kwargs)
        else:
            # Queue update for main thread execution
            result_container = {}

            def wrapped_update():
                try:
                    result_container['result'] = update_func(*args, **kwargs)
                except Exception as e:
                    result_container['error'] = e
                    logger.error(f"Visual update failed: {e}")

            visual_update_queue.put(wrapped_update)

            # Wait briefly for result (non-blocking approach)
            time.sleep(0.001)  # 1ms wait

            if 'error' in result_container:
                logger.warning(f"Queued visual update failed: {result_container['error']}")
                return None

            return result_container.get('result')

    except Exception as e:
        logger.warning(f"Visual update wrapper failed: {e}")
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

        # Model validation
        valid_models = ['tiny', 'tiny.en', 'base', 'base.en', 'small', 'small.en', 'medium', 'medium.en', 'large', 'large-v2', 'large-v3']
        if not hasattr(cfg, 'model_name') or cfg.model_name not in valid_models:
            logger.warning(f"Invalid model {getattr(cfg, 'model_name', 'None')}, defaulting to base.en")
            cfg.model_name = 'base.en'

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

        # Beam size validation
        if not hasattr(cfg, 'beam_size') or cfg.beam_size < 1 or cfg.beam_size > 10:
            logger.warning(f"Invalid beam_size {getattr(cfg, 'beam_size', 'None')}, defaulting to 2")
            cfg.beam_size = 2

        # Temperature validation
        if not hasattr(cfg, 'temperature') or cfg.temperature < 0.0 or cfg.temperature > 1.0:
            logger.warning(f"Invalid temperature {getattr(cfg, 'temperature', 'None')}, defaulting to 0.0")
            cfg.temperature = 0.0

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