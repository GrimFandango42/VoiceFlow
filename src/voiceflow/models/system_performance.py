"""
SystemPerformance model for constitutional compliance monitoring.
Tracks performance metrics to ensure VoiceFlow meets constitutional requirements.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
import threading


@dataclass
class SystemPerformance:
    """
    System performance metrics for constitutional compliance.
    Tracks response times, memory usage, and other metrics to ensure
    VoiceFlow meets its constitutional requirements.
    """
    response_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    audio_latency_ms: float = 0.0
    timestamp: Optional[datetime] = None
    component: str = "system"

    # Thread safety
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self):
        """Initialize SystemPerformance with validation."""
        if self.timestamp is None:
            self.timestamp = datetime.now()
        self.validate()

    def validate(self) -> None:
        """
        Validate performance metrics.
        Raises ValueError if metrics are invalid.
        """
        if self.response_time_ms < 0:
            raise ValueError("Response time cannot be negative")
        if self.memory_usage_mb < 0:
            raise ValueError("Memory usage cannot be negative")
        if not (0 <= self.cpu_usage_percent <= 100):
            raise ValueError("CPU usage must be between 0 and 100")
        if self.audio_latency_ms < 0:
            raise ValueError("Audio latency cannot be negative")

    def is_constitutional_compliant(self) -> bool:
        """
        Check if current metrics meet constitutional requirements.

        Constitutional Requirements:
        - Response time MUST be <= 200ms
        - Memory usage MUST be <= 200MB (idle), <= 500MB (processing)
        - Audio latency SHOULD be minimized

        Returns:
            True if metrics meet constitutional requirements
        """
        with self._lock:
            # Response time requirement (hard limit)
            if self.response_time_ms > 200:
                return False

            # Memory usage requirement (context-dependent)
            if self.component == "idle" and self.memory_usage_mb > 200:
                return False
            elif self.component == "processing" and self.memory_usage_mb > 500:
                return False
            elif self.memory_usage_mb > 500:  # General limit
                return False

            # All requirements met
            return True

    def get_compliance_violations(self) -> Dict[str, str]:
        """
        Get detailed constitutional compliance violations.

        Returns:
            Dictionary of violations with descriptions
        """
        violations = {}

        with self._lock:
            # Response time check
            if self.response_time_ms > 200:
                violations["response_time"] = (
                    f"Response time {self.response_time_ms:.1f}ms exceeds "
                    f"constitutional limit of 200ms"
                )

            # Memory usage check
            if self.component == "idle" and self.memory_usage_mb > 200:
                violations["memory_idle"] = (
                    f"Idle memory usage {self.memory_usage_mb:.1f}MB exceeds "
                    f"constitutional limit of 200MB"
                )
            elif self.component == "processing" and self.memory_usage_mb > 500:
                violations["memory_processing"] = (
                    f"Processing memory usage {self.memory_usage_mb:.1f}MB exceeds "
                    f"constitutional limit of 500MB"
                )
            elif self.memory_usage_mb > 500:
                violations["memory_general"] = (
                    f"Memory usage {self.memory_usage_mb:.1f}MB exceeds "
                    f"general limit of 500MB"
                )

            # Audio latency warning (not a hard violation)
            if self.audio_latency_ms > 100:
                violations["audio_latency"] = (
                    f"Audio latency {self.audio_latency_ms:.1f}ms is high "
                    f"(should be minimized for real-time processing)"
                )

        return violations

    def update_metrics(self,
                      response_time_ms: Optional[float] = None,
                      memory_usage_mb: Optional[float] = None,
                      cpu_usage_percent: Optional[float] = None,
                      audio_latency_ms: Optional[float] = None,
                      component: Optional[str] = None) -> None:
        """
        Update performance metrics atomically.

        Args:
            response_time_ms: Response time in milliseconds
            memory_usage_mb: Memory usage in megabytes
            cpu_usage_percent: CPU usage percentage (0-100)
            audio_latency_ms: Audio latency in milliseconds
            component: Component being measured
        """
        with self._lock:
            if response_time_ms is not None:
                self.response_time_ms = response_time_ms
            if memory_usage_mb is not None:
                self.memory_usage_mb = memory_usage_mb
            if cpu_usage_percent is not None:
                self.cpu_usage_percent = cpu_usage_percent
            if audio_latency_ms is not None:
                self.audio_latency_ms = audio_latency_ms
            if component is not None:
                self.component = component

            self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize SystemPerformance to dictionary.

        Returns:
            Dictionary representation
        """
        with self._lock:
            return {
                "response_time_ms": self.response_time_ms,
                "memory_usage_mb": self.memory_usage_mb,
                "cpu_usage_percent": self.cpu_usage_percent,
                "audio_latency_ms": self.audio_latency_ms,
                "timestamp": self.timestamp.isoformat() if self.timestamp else None,
                "component": self.component,
                "constitutional_compliant": self.is_constitutional_compliant(),
                "violations": self.get_compliance_violations()
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SystemPerformance':
        """
        Deserialize SystemPerformance from dictionary.

        Args:
            data: Dictionary to deserialize from

        Returns:
            SystemPerformance instance
        """
        performance = cls(
            response_time_ms=data.get("response_time_ms", 0.0),
            memory_usage_mb=data.get("memory_usage_mb", 0.0),
            cpu_usage_percent=data.get("cpu_usage_percent", 0.0),
            audio_latency_ms=data.get("audio_latency_ms", 0.0),
            component=data.get("component", "system")
        )

        # Parse timestamp
        if data.get("timestamp"):
            try:
                performance.timestamp = datetime.fromisoformat(data["timestamp"])
            except ValueError:
                performance.timestamp = datetime.now()

        return performance

    def get_performance_grade(self) -> str:
        """
        Get performance grade based on constitutional compliance.

        Returns:
            Performance grade: "EXCELLENT", "GOOD", "ACCEPTABLE", "POOR"
        """
        if not self.is_constitutional_compliant():
            return "POOR"

        # Grade based on how well within limits we are
        response_ratio = self.response_time_ms / 200.0
        memory_limit = 200 if self.component == "idle" else 500
        memory_ratio = self.memory_usage_mb / memory_limit

        max_ratio = max(response_ratio, memory_ratio)

        if max_ratio <= 0.5:
            return "EXCELLENT"
        elif max_ratio <= 0.7:
            return "GOOD"
        elif max_ratio <= 0.9:
            return "ACCEPTABLE"
        else:
            return "POOR"

    def __eq__(self, other) -> bool:
        """Compare SystemPerformance instances for equality."""
        if not isinstance(other, SystemPerformance):
            return False

        return (
            abs(self.response_time_ms - other.response_time_ms) < 0.1 and
            abs(self.memory_usage_mb - other.memory_usage_mb) < 0.1 and
            abs(self.cpu_usage_percent - other.cpu_usage_percent) < 0.1 and
            abs(self.audio_latency_ms - other.audio_latency_ms) < 0.1 and
            self.component == other.component
        )

    def __str__(self) -> str:
        """String representation of SystemPerformance."""
        compliant = "✅" if self.is_constitutional_compliant() else "❌"
        grade = self.get_performance_grade()

        return (
            f"SystemPerformance({self.component}): "
            f"Response={self.response_time_ms:.1f}ms, "
            f"Memory={self.memory_usage_mb:.1f}MB, "
            f"CPU={self.cpu_usage_percent:.1f}%, "
            f"Audio={self.audio_latency_ms:.1f}ms "
            f"[{grade} {compliant}]"
        )