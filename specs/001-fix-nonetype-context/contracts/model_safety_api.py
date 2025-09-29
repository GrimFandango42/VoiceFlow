"""
API Contract: Model Safety Interface
Purpose: Define safe model access patterns that prevent NoneType errors
"""

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from typing import Optional, Union, Any
import numpy as np

class SafeModelInterface(ABC):
    """Contract for safe model access with guaranteed context managers"""

    @abstractmethod
    def get_safe_context(self) -> AbstractContextManager:
        """
        Returns a safe context manager for model operations.

        Guarantees:
        - Never returns None
        - Always provides valid context manager
        - Falls back to null context if model unavailable
        - Thread-safe operation

        Returns:
            AbstractContextManager: Safe context for model operations
        """
        pass

    @abstractmethod
    def transcribe_safely(self, audio: np.ndarray) -> str:
        """
        Perform safe transcription with automatic error recovery.

        Preconditions:
        - audio is valid numpy array
        - audio contains finite values (no NaN/Inf)

        Guarantees:
        - Returns string result (empty on failure, never None)
        - Never raises NoneType context manager error
        - Attempts automatic recovery on failure
        - Preserves model state on error

        Args:
            audio: Input audio data as numpy array

        Returns:
            str: Transcription result (empty string on failure)
        """
        pass

    @abstractmethod
    def reload_model_atomically(self) -> bool:
        """
        Reload model using atomic swap pattern.

        Guarantees:
        - Current model preserved until new model validated
        - No intermediate None state during reload
        - Thread-safe operation with proper locking
        - Cleanup of old model after successful swap

        Returns:
            bool: True if reload successful, False otherwise
        """
        pass

    @abstractmethod
    def is_model_healthy(self) -> bool:
        """
        Check if model is currently healthy and available.

        Returns:
            bool: True if model is loaded and functional
        """
        pass

    @abstractmethod
    def get_model_stats(self) -> dict:
        """
        Get current model statistics and health information.

        Returns:
            dict: Model statistics including load time, transcription count, errors
        """
        pass

class ErrorRecoveryInterface(ABC):
    """Contract for automatic error recovery operations"""

    @abstractmethod
    def attempt_recovery(self, error: Exception) -> bool:
        """
        Attempt to recover from model error.

        Args:
            error: The error that triggered recovery

        Returns:
            bool: True if recovery successful
        """
        pass

    @abstractmethod
    def enable_fallback_mode(self) -> None:
        """
        Enable fallback mode with null object pattern.
        """
        pass

    @abstractmethod
    def is_fallback_active(self) -> bool:
        """
        Check if system is currently in fallback mode.

        Returns:
            bool: True if fallback mode is active
        """
        pass

class NullObjectModel(AbstractContextManager):
    """
    Null object implementation for safe fallback operations.
    Provides valid context manager that returns empty results.
    """

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def transcribe(self, audio: Any) -> str:
        """Always returns empty string - safe fallback"""
        return ""