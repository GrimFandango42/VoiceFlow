"""
VoiceFlow Stability API Contracts
Defines interfaces for stability monitoring and error recovery systems.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any
import time

# ============================================================================
# Enums and Types
# ============================================================================

class SessionStatus(Enum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    DEGRADED = "degraded"
    RECOVERING = "recovering"
    TERMINATED = "terminated"

class RequestStatus(Enum):
    PENDING = "pending"
    VALIDATING = "validating"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class SystemState(Enum):
    IDLE = "idle"
    RECORDING = "recording"
    PROCESSING = "processing"
    ERROR = "error"
    TERMINATED = "terminated"

class ErrorType(Enum):
    NONE_TYPE = "none_type"
    TIMEOUT = "timeout"
    VALIDATION = "validation"
    RESOURCE = "resource"
    HALLUCINATION = "hallucination"

# ============================================================================
# Data Contracts
# ============================================================================

@dataclass
class AudioSessionInfo:
    """Session information for tracking and health monitoring."""
    session_id: str
    start_time: float
    last_activity: float
    total_transcriptions: int
    total_duration: float
    memory_baseline: int
    memory_current: int
    error_count: int
    status: SessionStatus

@dataclass
class TranscriptionRequestInfo:
    """Individual transcription request with comprehensive tracking."""
    request_id: str
    session_id: str
    audio_duration: float
    audio_energy: float
    trigger_time: float
    completion_time: Optional[float]
    processing_duration: Optional[float]
    input_validation_result: bool
    transcription_text: Optional[str]
    quality_score: Optional[float]
    error_details: Optional[str]
    status: RequestStatus

@dataclass
class SystemStateInfo:
    """System state with validation and transition tracking."""
    current_state: SystemState
    previous_state: SystemState
    transition_time: float
    state_duration: float
    transition_count: int
    stuck_detection_timer: float
    recovery_attempts: int
    validation_checkpoints: List[str]

@dataclass
class ErrorRecoveryContext:
    """Error recovery information and diagnostics."""
    error_id: str
    error_type: ErrorType
    component_affected: str
    error_timestamp: float
    system_state_snapshot: Dict[str, Any]
    recovery_strategy: str
    recovery_attempts: int
    recovery_success: bool
    diagnostic_data: Dict[str, Any]

@dataclass
class PerformanceMetrics:
    """Real-time performance monitoring data."""
    metric_timestamp: float
    session_id: str
    cpu_usage_percent: float
    memory_usage_mb: int
    memory_growth_rate: float
    transcription_latency: float
    error_rate: float
    model_health_score: float
    system_responsiveness: float

# ============================================================================
# Interface Contracts
# ============================================================================

class ISessionManager(ABC):
    """Interface for managing long-running audio sessions."""

    @abstractmethod
    def create_session(self) -> AudioSessionInfo:
        """Create new audio session with tracking."""
        pass

    @abstractmethod
    def get_session_health(self, session_id: str) -> SessionStatus:
        """Get current session health status."""
        pass

    @abstractmethod
    def update_session_activity(self, session_id: str) -> None:
        """Update last activity timestamp."""
        pass

    @abstractmethod
    def terminate_session(self, session_id: str) -> None:
        """Clean termination of session."""
        pass

    @abstractmethod
    def get_session_metrics(self, session_id: str) -> PerformanceMetrics:
        """Get current session performance metrics."""
        pass

class IErrorRecovery(ABC):
    """Interface for error detection and recovery."""

    @abstractmethod
    def detect_error(self, context: Dict[str, Any]) -> Optional[ErrorType]:
        """Detect error type from context."""
        pass

    @abstractmethod
    def create_recovery_context(self, error_type: ErrorType,
                               component: str,
                               diagnostic_data: Dict[str, Any]) -> ErrorRecoveryContext:
        """Create recovery context for error."""
        pass

    @abstractmethod
    def attempt_recovery(self, recovery_context: ErrorRecoveryContext) -> bool:
        """Attempt to recover from error."""
        pass

    @abstractmethod
    def get_recovery_history(self, session_id: str) -> List[ErrorRecoveryContext]:
        """Get recovery history for session."""
        pass

class IPerformanceMonitor(ABC):
    """Interface for performance monitoring and health tracking."""

    @abstractmethod
    def collect_metrics(self, session_id: str) -> PerformanceMetrics:
        """Collect current performance metrics."""
        pass

    @abstractmethod
    def detect_degradation(self, session_id: str) -> bool:
        """Detect performance degradation."""
        pass

    @abstractmethod
    def get_health_trend(self, session_id: str, duration: int) -> List[PerformanceMetrics]:
        """Get health trend over specified duration."""
        pass

    @abstractmethod
    def should_trigger_recovery(self, session_id: str) -> bool:
        """Determine if recovery should be triggered."""
        pass

class IStabilityController(ABC):
    """Main controller interface for stability management."""

    @abstractmethod
    def initialize_stability_monitoring(self) -> str:
        """Initialize stability monitoring and return session ID."""
        pass

    @abstractmethod
    def validate_transcription_request(self, audio_data: bytes,
                                     duration: float) -> TranscriptionRequestInfo:
        """Validate and create transcription request."""
        pass

    @abstractmethod
    def process_transcription_safely(self, request: TranscriptionRequestInfo) -> str:
        """Process transcription with full error handling."""
        pass

    @abstractmethod
    def handle_system_state_transition(self, new_state: SystemState) -> bool:
        """Handle state transition with validation."""
        pass

    @abstractmethod
    def get_system_health_report(self) -> Dict[str, Any]:
        """Get comprehensive system health report."""
        pass

    @abstractmethod
    def shutdown_safely(self) -> None:
        """Safe system shutdown with cleanup."""
        pass

# ============================================================================
# Validation Contracts
# ============================================================================

class IAudioValidator(ABC):
    """Interface for audio validation and filtering."""

    @abstractmethod
    def validate_audio_integrity(self, audio_data: bytes) -> bool:
        """Validate audio buffer integrity."""
        pass

    @abstractmethod
    def analyze_audio_content(self, audio_data: bytes) -> Dict[str, float]:
        """Analyze audio content for quality metrics."""
        pass

    @abstractmethod
    def detect_background_noise(self, audio_data: bytes) -> bool:
        """Detect if audio is primarily background noise."""
        pass

    @abstractmethod
    def should_process_audio(self, audio_data: bytes, duration: float) -> bool:
        """Determine if audio should be processed."""
        pass

class IHallucinationDetector(ABC):
    """Interface for detecting and filtering transcription hallucinations."""

    @abstractmethod
    def detect_repetitive_patterns(self, text: str) -> bool:
        """Detect repetitive text patterns."""
        pass

    @abstractmethod
    def detect_okay_hallucination(self, text: str) -> bool:
        """Detect specific 'okay' hallucination pattern."""
        pass

    @abstractmethod
    def clean_transcription(self, text: str) -> str:
        """Clean transcription of hallucination artifacts."""
        pass

    @abstractmethod
    def calculate_quality_score(self, text: str, audio_duration: float) -> float:
        """Calculate transcription quality score."""
        pass

# ============================================================================
# Test Contracts
# ============================================================================

class IStabilityTester(ABC):
    """Interface for comprehensive stability testing."""

    @abstractmethod
    def run_duration_test(self, duration_hours: int) -> Dict[str, Any]:
        """Run extended duration stability test."""
        pass

    @abstractmethod
    def run_stress_test(self, request_rate: int, duration_minutes: int) -> Dict[str, Any]:
        """Run stress test with specified request rate."""
        pass

    @abstractmethod
    def run_edge_case_scenarios(self) -> Dict[str, List[str]]:
        """Run comprehensive edge case testing."""
        pass

    @abstractmethod
    def simulate_error_conditions(self) -> Dict[str, bool]:
        """Simulate various error conditions and test recovery."""
        pass

    @abstractmethod
    def validate_memory_stability(self, duration_hours: int) -> Dict[str, float]:
        """Validate memory usage remains stable over time."""
        pass

# ============================================================================
# Configuration Contracts
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

# ============================================================================
# Result Contracts
# ============================================================================

@dataclass
class StabilityTestResult:
    """Results from stability testing."""
    test_name: str
    duration_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    error_rate: float
    memory_start_mb: int
    memory_end_mb: int
    memory_growth_mb: int
    average_response_time_ms: float
    errors_by_type: Dict[str, int]
    recovery_success_rate: float
    overall_success: bool

@dataclass
class HealthReport:
    """Comprehensive system health report."""
    session_id: str
    report_timestamp: float
    session_duration_hours: float
    total_transcriptions: int
    error_rate: float
    memory_usage_mb: int
    memory_growth_rate: float
    cpu_usage_percent: float
    average_response_time_ms: float
    current_status: SessionStatus
    recommendations: List[str]
    critical_issues: List[str]