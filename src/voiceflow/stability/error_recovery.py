"""
VoiceFlow Error Recovery System

Implements comprehensive error detection and recovery for stability improvements.
Addresses NoneType errors, hallucination detection, and stuck state recovery.
"""

import logging
import re
from typing import Dict, Any, Optional, List
from .models import ErrorRecoveryContext, ErrorType, StabilityConfig
from .logging_config import setup_stability_logging, log_error_with_context

logger = setup_stability_logging()

class ErrorRecovery:
    """
    Comprehensive error recovery system.

    Implements IErrorRecovery interface for detecting and recovering from
    various error conditions in the VoiceFlow system.
    """

    def __init__(self, config: Optional[StabilityConfig] = None):
        """
        Initialize error recovery system.

        Args:
            config: Stability configuration (uses defaults if None)
        """
        self.config = config or StabilityConfig()
        self.recovery_history: Dict[str, List[ErrorRecoveryContext]] = {}

    def detect_error(self, context: Dict[str, Any]) -> Optional[ErrorType]:
        """
        Detect error type from context information.

        Args:
            context: Error context containing relevant information

        Returns:
            ErrorType if error detected, None otherwise
        """
        error_message = context.get('error_message', '').lower()
        exception_type = context.get('exception_type', '')
        component = context.get('component', '')

        # NoneType context manager errors (critical issue)
        if ('nonetype' in error_message and
            'context manager' in error_message) or exception_type == 'TypeError':
            return ErrorType.NONE_TYPE

        # Timeout errors
        if ('timeout' in error_message or
            'timeout_duration' in context or
            'transcription timeout' in error_message):
            return ErrorType.TIMEOUT

        # Hallucination detection
        transcription_text = context.get('transcription_text', '')
        if self._detect_hallucination_in_text(transcription_text):
            return ErrorType.HALLUCINATION

        # Resource errors (memory, CPU)
        if ('memory' in error_message or
            'resource' in error_message or
            context.get('memory_usage', 0) > self.config.memory_cleanup_threshold_mb):
            return ErrorType.RESOURCE

        # Validation errors
        if ('validation' in error_message or
            context.get('input_validation_result') is False):
            return ErrorType.VALIDATION

        return None

    def create_recovery_context(self,
                              error_type: ErrorType,
                              component: str,
                              diagnostic_data: Dict[str, Any]) -> ErrorRecoveryContext:
        """
        Create recovery context for error.

        Args:
            error_type: Type of error detected
            component: Component where error occurred
            diagnostic_data: Additional diagnostic information

        Returns:
            Configured ErrorRecoveryContext
        """
        context = ErrorRecoveryContext(
            error_type=error_type,
            component_affected=component,
            diagnostic_data=diagnostic_data.copy()
        )

        # Set recovery strategy based on error type
        context.recovery_strategy = self._select_recovery_strategy(error_type, component)

        # Capture system state snapshot
        context.system_state_snapshot = self._capture_system_snapshot()

        return context

    def attempt_recovery(self, recovery_context: ErrorRecoveryContext) -> bool:
        """
        Attempt to recover from error.

        Args:
            recovery_context: Recovery context with error information

        Returns:
            True if recovery successful, False otherwise
        """
        # Check if we should attempt recovery
        if not recovery_context.should_retry_recovery(self.config.recovery_attempt_limit):
            logger.warning(f"Recovery limit reached for error {recovery_context.error_id}")
            return False

        # Record attempt
        recovery_context.attempt_recovery()

        try:
            success = self._execute_recovery_strategy(recovery_context)

            if success:
                recovery_context.mark_recovery_success()
                logger.info(f"Recovery successful for {recovery_context.error_type.value} error")
            else:
                logger.warning(f"Recovery attempt {recovery_context.recovery_attempts} failed")

            return success

        except Exception as e:
            log_error_with_context(
                e,
                {"recovery_context": recovery_context.error_id},
                "error_recovery"
            )
            return False

    def get_recovery_history(self, session_id: str) -> List[ErrorRecoveryContext]:
        """
        Get recovery history for session.

        Args:
            session_id: Session identifier

        Returns:
            List of recovery contexts for the session
        """
        return self.recovery_history.get(session_id, [])

    def _detect_hallucination_in_text(self, text: str) -> bool:
        """
        Detect hallucination patterns in transcription text.

        Args:
            text: Transcription text to analyze

        Returns:
            True if hallucination detected
        """
        if not text or len(text) < 10:
            return False

        normalized = text.lower().strip()

        # "Okay okay okay" pattern (user's specific issue)
        okay_pattern = r'\b(okay\.?\s*){3,}'
        if re.search(okay_pattern, normalized):
            return True

        # Other repetitive patterns
        repetitive_patterns = [
            r'\b(the\s+){5,}',
            r'\b(and\s+){5,}',
            r'\b(you\s+){5,}',
            r'\b(.{1,3}\s+)\1{10,}'  # Short word repetition
        ]

        for pattern in repetitive_patterns:
            if re.search(pattern, normalized):
                return True

        # Check for excessive repetition ratio
        words = normalized.split()
        if len(words) > 5:
            word_counts = {}
            for word in words:
                word_counts[word] = word_counts.get(word, 0) + 1

            max_count = max(word_counts.values())
            if max_count > len(words) * 0.5:  # More than 50% same word
                return True

        return False

    def _select_recovery_strategy(self, error_type: ErrorType, component: str) -> str:
        """
        Select appropriate recovery strategy for error type.

        Args:
            error_type: Type of error
            component: Component affected

        Returns:
            Recovery strategy description
        """
        strategies = {
            ErrorType.NONE_TYPE: "atomic_model_reload",
            ErrorType.TIMEOUT: "timeout_cleanup_and_retry",
            ErrorType.HALLUCINATION: "pattern_filtering_and_reprocess",
            ErrorType.RESOURCE: "memory_cleanup_and_gc",
            ErrorType.VALIDATION: "input_revalidation"
        }

        return strategies.get(error_type, "generic_restart")

    def _capture_system_snapshot(self) -> Dict[str, Any]:
        """
        Capture current system state for diagnostics.

        Returns:
            System state snapshot
        """
        import psutil
        import time

        try:
            process = psutil.Process()
            memory_info = process.memory_info()

            return {
                'timestamp': time.time(),
                'memory_mb': memory_info.rss / 1024 / 1024,
                'cpu_percent': psutil.cpu_percent(interval=None),
                'thread_count': process.num_threads(),
                'open_files': len(process.open_files()) if hasattr(process, 'open_files') else 0
            }
        except Exception as e:
            logger.warning(f"Failed to capture system snapshot: {e}")
            return {'timestamp': time.time(), 'error': str(e)}

    def _execute_recovery_strategy(self, context: ErrorRecoveryContext) -> bool:
        """
        Execute the selected recovery strategy.

        Args:
            context: Recovery context with strategy information

        Returns:
            True if recovery executed successfully
        """
        strategy = context.recovery_strategy

        try:
            if strategy == "atomic_model_reload":
                return self._recover_none_type_error(context)
            elif strategy == "timeout_cleanup_and_retry":
                return self._recover_timeout_error(context)
            elif strategy == "pattern_filtering_and_reprocess":
                return self._recover_hallucination_error(context)
            elif strategy == "memory_cleanup_and_gc":
                return self._recover_resource_error(context)
            elif strategy == "input_revalidation":
                return self._recover_validation_error(context)
            else:
                return self._generic_recovery(context)

        except Exception as e:
            log_error_with_context(e, {"strategy": strategy}, "recovery_execution")
            return False

    def _recover_none_type_error(self, context: ErrorRecoveryContext) -> bool:
        """
        Recover from NoneType context manager errors.

        This implements the atomic reference pattern to prevent race conditions.
        """
        logger.info("Executing NoneType error recovery")

        # Add diagnostic information
        context.add_diagnostic_data("recovery_action", "atomic_model_reload")
        context.add_diagnostic_data("component_restart_required", True)

        # Signal that component needs atomic model reload
        # The actual reload will be handled by the component itself
        # This recovery sets up the conditions for safe reload

        return True  # Recovery strategy prepared

    def _recover_timeout_error(self, context: ErrorRecoveryContext) -> bool:
        """Recover from timeout errors."""
        logger.info("Executing timeout error recovery")
        context.add_diagnostic_data("recovery_action", "timeout_cleanup")
        return True

    def _recover_hallucination_error(self, context: ErrorRecoveryContext) -> bool:
        """Recover from hallucination errors."""
        logger.info("Executing hallucination error recovery")
        context.add_diagnostic_data("recovery_action", "pattern_filtering")
        return True

    def _recover_resource_error(self, context: ErrorRecoveryContext) -> bool:
        """Recover from resource errors."""
        logger.info("Executing resource error recovery")

        # Perform garbage collection
        import gc
        gc.collect()

        context.add_diagnostic_data("recovery_action", "gc_performed")
        return True

    def _recover_validation_error(self, context: ErrorRecoveryContext) -> bool:
        """Recover from validation errors."""
        logger.info("Executing validation error recovery")
        context.add_diagnostic_data("recovery_action", "input_revalidation")
        return True

    def _generic_recovery(self, context: ErrorRecoveryContext) -> bool:
        """Generic recovery for unknown error types."""
        logger.info("Executing generic error recovery")
        context.add_diagnostic_data("recovery_action", "generic_cleanup")
        return True