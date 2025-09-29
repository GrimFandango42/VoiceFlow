"""
Contract: Session Manager Interface
Defines the interface for managing long-running transcription sessions
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID
from enum import Enum

class SessionState(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    DEGRADED = "degraded"
    RECOVERY = "recovery"

class RequestState(Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class SessionManager(ABC):
    """Interface for managing audio transcription sessions"""

    @abstractmethod
    def start_session(self) -> UUID:
        """
        Start a new transcription session

        Returns:
            UUID: Session identifier

        Raises:
            RuntimeError: If session cannot be started
        """
        pass

    @abstractmethod
    def end_session(self, session_id: UUID) -> bool:
        """
        End an active session with cleanup

        Args:
            session_id: Session to terminate

        Returns:
            bool: True if session ended successfully
        """
        pass

    @abstractmethod
    def get_session_state(self, session_id: UUID) -> SessionState:
        """
        Get current session state

        Args:
            session_id: Session to query

        Returns:
            SessionState: Current state

        Raises:
            KeyError: If session not found
        """
        pass

    @abstractmethod
    def record_activity(self, session_id: UUID) -> None:
        """
        Record user activity to reset idle timers

        Args:
            session_id: Session with activity
        """
        pass

    @abstractmethod
    def check_health(self, session_id: UUID) -> float:
        """
        Check session health score

        Args:
            session_id: Session to check

        Returns:
            float: Health score 0.0-1.0
        """
        pass

    @abstractmethod
    def get_active_sessions(self) -> List[UUID]:
        """
        Get list of all active session IDs

        Returns:
            List[UUID]: Active session identifiers
        """
        pass

class ResourceManager(ABC):
    """Interface for managing system resources (models, memory, etc.)"""

    @abstractmethod
    def load_model(self) -> bool:
        """
        Load ASR model into memory

        Returns:
            bool: True if model loaded successfully
        """
        pass

    @abstractmethod
    def unload_model(self) -> bool:
        """
        Unload ASR model from memory

        Returns:
            bool: True if model unloaded successfully
        """
        pass

    @abstractmethod
    def is_model_loaded(self) -> bool:
        """
        Check if model is currently loaded

        Returns:
            bool: True if model is in memory
        """
        pass

    @abstractmethod
    def get_memory_usage(self) -> float:
        """
        Get current memory usage in MB

        Returns:
            float: Memory usage in megabytes
        """
        pass

    @abstractmethod
    def cleanup_resources(self) -> None:
        """
        Perform resource cleanup and garbage collection
        """
        pass

class HealthMonitor(ABC):
    """Interface for monitoring system health and performance"""

    @abstractmethod
    def record_metric(self, name: str, value: float, timestamp: Optional[datetime] = None) -> None:
        """
        Record a performance metric

        Args:
            name: Metric name
            value: Metric value
            timestamp: When recorded (default: now)
        """
        pass

    @abstractmethod
    def get_metric_history(self, name: str, hours: int = 1) -> List[tuple]:
        """
        Get metric history

        Args:
            name: Metric name
            hours: Hours of history to retrieve

        Returns:
            List[tuple]: (timestamp, value) pairs
        """
        pass

    @abstractmethod
    def detect_degradation(self) -> bool:
        """
        Detect if system performance is degrading

        Returns:
            bool: True if degradation detected
        """
        pass

    @abstractmethod
    def get_health_report(self) -> Dict[str, Any]:
        """
        Get comprehensive health report

        Returns:
            Dict: Health metrics and status
        """
        pass