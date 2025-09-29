"""
VoiceFlow Stability Data Models

Core data structures for stability monitoring and error recovery.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import time
import uuid

# ============================================================================
# Enums
# ============================================================================

class SessionStatus(Enum):
    """Audio session health status."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    DEGRADED = "degraded"
    RECOVERING = "recovering"
    TERMINATED = "terminated"

class RequestStatus(Enum):
    """Transcription request status."""
    PENDING = "pending"
    VALIDATING = "validating"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class SystemState(Enum):
    """System operational state."""
    IDLE = "idle"
    RECORDING = "recording"
    PROCESSING = "processing"
    ERROR = "error"
    TERMINATED = "terminated"

class ErrorType(Enum):
    """Classification of error types."""
    NONE_TYPE = "none_type"
    TIMEOUT = "timeout"
    VALIDATION = "validation"
    RESOURCE = "resource"
    HALLUCINATION = "hallucination"

# ============================================================================
# Data Models
# ============================================================================

@dataclass
class AudioSessionInfo:
    """
    Audio session information for tracking and health monitoring.

    Represents a complete usage period with multiple transcription requests.
    """
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    start_time: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    total_transcriptions: int = 0
    total_duration: float = 0.0
    memory_baseline: int = 0
    memory_current: int = 0
    error_count: int = 0
    status: SessionStatus = SessionStatus.INITIALIZING

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def add_transcription(self, duration: float) -> None:
        """Add a completed transcription to the session."""
        self.total_transcriptions += 1
        self.total_duration += duration
        self.update_activity()

    def add_error(self) -> None:
        """Record an error in the session."""
        self.error_count += 1
        self.update_activity()

    def get_error_rate(self) -> float:
        """Calculate error rate as percentage."""
        if self.total_transcriptions == 0:
            return 0.0
        return (self.error_count / (self.total_transcriptions + self.error_count)) * 100

    def get_session_duration(self) -> float:
        """Get total session duration in seconds."""
        return time.time() - self.start_time

@dataclass
class TranscriptionRequestInfo:
    """
    Individual transcription request with comprehensive tracking.

    Tracks the complete lifecycle of a single transcription operation.
    """
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    audio_duration: float = 0.0
    audio_energy: float = 0.0
    trigger_time: float = field(default_factory=time.time)
    completion_time: Optional[float] = None
    processing_duration: Optional[float] = None
    input_validation_result: bool = False
    transcription_text: Optional[str] = None
    quality_score: Optional[float] = None
    error_details: Optional[str] = None
    status: RequestStatus = RequestStatus.PENDING

    def start_processing(self) -> None:
        """Mark request as processing."""
        self.status = RequestStatus.PROCESSING

    def complete_processing(self, text: str, quality: float) -> None:
        """Complete the request with results."""
        self.completion_time = time.time()
        self.processing_duration = self.completion_time - self.trigger_time
        self.transcription_text = text
        self.quality_score = quality
        self.status = RequestStatus.COMPLETED

    def fail_processing(self, error: str) -> None:
        """Mark request as failed with error details."""
        self.completion_time = time.time()
        self.processing_duration = self.completion_time - self.trigger_time
        self.error_details = error
        self.status = RequestStatus.FAILED

    def get_processing_time(self) -> Optional[float]:
        """Get processing time in seconds."""
        if self.completion_time is None:
            return None
        return self.completion_time - self.trigger_time

@dataclass
class SystemStateInfo:
    """
    System state with validation and transition tracking.

    Tracks current operational status with comprehensive monitoring.
    """
    current_state: SystemState = SystemState.IDLE
    previous_state: SystemState = SystemState.IDLE
    transition_time: float = field(default_factory=time.time)
    state_duration: float = 0.0
    transition_count: int = 0
    stuck_detection_timer: float = 0.0
    recovery_attempts: int = 0
    validation_checkpoints: List[str] = field(default_factory=list)

    def transition_to(self, new_state: SystemState) -> bool:
        """
        Transition to new state with validation.

        Args:
            new_state: Target state to transition to

        Returns:
            True if transition was successful
        """
        # Validate transition is allowed
        valid_transitions = {
            SystemState.IDLE: [SystemState.RECORDING, SystemState.ERROR, SystemState.TERMINATED],
            SystemState.RECORDING: [SystemState.PROCESSING, SystemState.IDLE, SystemState.ERROR],
            SystemState.PROCESSING: [SystemState.IDLE, SystemState.ERROR],
            SystemState.ERROR: [SystemState.IDLE, SystemState.TERMINATED],
            SystemState.TERMINATED: []  # Terminal state
        }

        if new_state not in valid_transitions[self.current_state]:
            return False

        # Update state information
        self.previous_state = self.current_state
        self.current_state = new_state
        current_time = time.time()
        self.state_duration = current_time - self.transition_time
        self.transition_time = current_time
        self.transition_count += 1

        # Reset stuck detection timer on successful transition
        self.stuck_detection_timer = 0.0

        return True

    def add_validation_checkpoint(self, checkpoint: str) -> None:
        """Add a validation checkpoint."""
        timestamp = time.strftime("%H:%M:%S")
        self.validation_checkpoints.append(f"{timestamp}: {checkpoint}")

    def is_stuck(self, timeout_seconds: float = 30.0) -> bool:
        """Check if system is stuck in current state."""
        current_time = time.time()
        time_in_state = current_time - self.transition_time
        return time_in_state > timeout_seconds

    def reset_recovery_attempts(self) -> None:
        """Reset recovery attempt counter."""
        self.recovery_attempts = 0

@dataclass
class ErrorRecoveryContext:
    """
    Error recovery information and diagnostics.

    Contains all information needed to recover from system errors.
    """
    error_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    error_type: ErrorType = ErrorType.VALIDATION
    component_affected: str = ""
    error_timestamp: float = field(default_factory=time.time)
    system_state_snapshot: Dict[str, Any] = field(default_factory=dict)
    recovery_strategy: str = ""
    recovery_attempts: int = 0
    recovery_success: bool = False
    diagnostic_data: Dict[str, Any] = field(default_factory=dict)

    def add_diagnostic_data(self, key: str, value: Any) -> None:
        """Add diagnostic information."""
        self.diagnostic_data[key] = value
        self.diagnostic_data['last_updated'] = time.time()

    def attempt_recovery(self) -> None:
        """Record a recovery attempt."""
        self.recovery_attempts += 1

    def mark_recovery_success(self) -> None:
        """Mark recovery as successful."""
        self.recovery_success = True

    def get_age_seconds(self) -> float:
        """Get age of error in seconds."""
        return time.time() - self.error_timestamp

    def should_retry_recovery(self, max_attempts: int = 3) -> bool:
        """Check if recovery should be retried."""
        return self.recovery_attempts < max_attempts and not self.recovery_success

@dataclass
class PerformanceMetrics:
    """
    Real-time performance monitoring data.

    Tracks system performance for health assessment.
    """
    metric_timestamp: float = field(default_factory=time.time)
    session_id: str = ""
    cpu_usage_percent: float = 0.0
    memory_usage_mb: int = 0
    memory_growth_rate: float = 0.0
    transcription_latency: float = 0.0
    error_rate: float = 0.0
    model_health_score: float = 1.0
    system_responsiveness: float = 0.0

    def update_from_system(self) -> None:
        """Update metrics from current system state."""
        import psutil

        # Update timestamp
        self.metric_timestamp = time.time()

        # CPU usage
        self.cpu_usage_percent = psutil.cpu_percent(interval=None)

        # Memory usage
        process = psutil.Process()
        memory_info = process.memory_info()
        self.memory_usage_mb = int(memory_info.rss / 1024 / 1024)

    def is_healthy(self) -> bool:
        """Check if metrics indicate healthy system state."""
        return (
            self.cpu_usage_percent < 80.0 and
            self.memory_usage_mb < 500 and
            self.error_rate < 5.0 and
            self.model_health_score > 0.8
        )

    def get_health_score(self) -> float:
        """Calculate overall health score (0.0 to 1.0)."""
        cpu_score = max(0, 1.0 - (self.cpu_usage_percent / 100.0))
        memory_score = max(0, 1.0 - (self.memory_usage_mb / 1000.0))  # 1GB baseline
        error_score = max(0, 1.0 - (self.error_rate / 10.0))  # 10% baseline

        return (cpu_score + memory_score + error_score + self.model_health_score) / 4.0

# ============================================================================
# Configuration Model
# ============================================================================

@dataclass
class StabilityConfig:
    """Configuration for stability monitoring."""
    max_session_duration_hours: int = 24
    memory_growth_limit_mb_per_hour: int = 1024
    max_error_rate_percent: float = 5.0
    processing_timeout_seconds: int = 60
    stuck_state_timeout_seconds: int = 30
    recovery_attempt_limit: int = 3
    performance_check_interval_seconds: int = 60
    memory_cleanup_threshold_mb: int = 800
    transcription_quality_threshold: float = 0.8
    audio_energy_threshold: float = 0.01
    enable_performance_monitoring: bool = True
    enable_error_tracking: bool = True
    enable_session_logging: bool = True

# ============================================================================
# Result Models
# ============================================================================

@dataclass
class StabilityTestResult:
    """Results from stability testing."""
    test_name: str = ""
    duration_seconds: float = 0.0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    error_rate: float = 0.0
    memory_start_mb: int = 0
    memory_end_mb: int = 0
    memory_growth_mb: int = 0
    average_response_time_ms: float = 0.0
    errors_by_type: Dict[str, int] = field(default_factory=dict)
    recovery_success_rate: float = 0.0
    overall_success: bool = False

@dataclass
class HealthReport:
    """Comprehensive system health report."""
    session_id: str = ""
    report_timestamp: float = field(default_factory=time.time)
    session_duration_hours: float = 0.0
    total_transcriptions: int = 0
    error_rate: float = 0.0
    memory_usage_mb: int = 0
    memory_growth_rate: float = 0.0
    cpu_usage_percent: float = 0.0
    average_response_time_ms: float = 0.0
    current_status: SessionStatus = SessionStatus.ACTIVE
    recommendations: List[str] = field(default_factory=list)
    critical_issues: List[str] = field(default_factory=list)

    def add_recommendation(self, recommendation: str) -> None:
        """Add a performance recommendation."""
        self.recommendations.append(recommendation)

    def add_critical_issue(self, issue: str) -> None:
        """Add a critical issue that needs attention."""
        self.critical_issues.append(issue)

    def is_healthy(self) -> bool:
        """Check if system is in healthy state."""
        return (
            len(self.critical_issues) == 0 and
            self.error_rate < 5.0 and
            self.memory_usage_mb < 500 and
            self.cpu_usage_percent < 80.0
        )