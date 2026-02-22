"""Runtime performance metrics and threshold checks."""

from dataclasses import dataclass, field
from datetime import datetime
import threading
from typing import Any, Dict, Optional


@dataclass
class SystemPerformance:
    """Thread-safe performance snapshot used by tray/status components."""

    response_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    audio_latency_ms: float = 0.0
    timestamp: Optional[datetime] = None
    component: str = "system"

    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.now()
        self.validate()

    def validate(self) -> None:
        """Validate metric value ranges."""
        if self.response_time_ms < 0:
            raise ValueError("Response time cannot be negative")
        if self.memory_usage_mb < 0:
            raise ValueError("Memory usage cannot be negative")
        if not (0 <= self.cpu_usage_percent <= 100):
            raise ValueError("CPU usage must be between 0 and 100")
        if self.audio_latency_ms < 0:
            raise ValueError("Audio latency cannot be negative")

    def meets_targets(self) -> bool:
        """
        Check runtime targets:
        - response time <= 200ms
        - idle memory <= 200MB
        - processing memory <= 500MB
        """
        with self._lock:
            if self.response_time_ms > 200:
                return False
            if self.component == "idle" and self.memory_usage_mb > 200:
                return False
            if self.component == "processing" and self.memory_usage_mb > 500:
                return False
            if self.memory_usage_mb > 500:
                return False
            return True

    def is_constitutional_compliant(self) -> bool:
        """Legacy alias for older integrations."""
        return self.meets_targets()

    def get_target_violations(self) -> Dict[str, str]:
        """Return threshold violations with human-readable messages."""
        violations: Dict[str, str] = {}
        with self._lock:
            if self.response_time_ms > 200:
                violations["response_time"] = (
                    f"Response time {self.response_time_ms:.1f}ms exceeds target of 200ms"
                )
            if self.component == "idle" and self.memory_usage_mb > 200:
                violations["memory_idle"] = (
                    f"Idle memory usage {self.memory_usage_mb:.1f}MB exceeds target of 200MB"
                )
            elif self.component == "processing" and self.memory_usage_mb > 500:
                violations["memory_processing"] = (
                    f"Processing memory usage {self.memory_usage_mb:.1f}MB exceeds target of 500MB"
                )
            elif self.memory_usage_mb > 500:
                violations["memory_general"] = (
                    f"Memory usage {self.memory_usage_mb:.1f}MB exceeds target of 500MB"
                )
            if self.audio_latency_ms > 100:
                violations["audio_latency"] = (
                    f"Audio latency {self.audio_latency_ms:.1f}ms is high"
                )
        return violations

    def get_compliance_violations(self) -> Dict[str, str]:
        """Legacy alias for older integrations."""
        return self.get_target_violations()

    def update_metrics(
        self,
        response_time_ms: Optional[float] = None,
        memory_usage_mb: Optional[float] = None,
        cpu_usage_percent: Optional[float] = None,
        audio_latency_ms: Optional[float] = None,
        component: Optional[str] = None,
    ) -> None:
        """Update metrics atomically."""
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
        """Serialize to dictionary."""
        with self._lock:
            meets_targets = self.meets_targets()
            violations = self.get_target_violations()
            return {
                "response_time_ms": self.response_time_ms,
                "memory_usage_mb": self.memory_usage_mb,
                "cpu_usage_percent": self.cpu_usage_percent,
                "audio_latency_ms": self.audio_latency_ms,
                "timestamp": self.timestamp.isoformat() if self.timestamp else None,
                "component": self.component,
                "performance_target_compliant": meets_targets,
                # Legacy compatibility key for older tooling.
                "constitutional_compliant": meets_targets,
                "violations": violations,
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SystemPerformance":
        """Deserialize from dictionary."""
        perf = cls(
            response_time_ms=data.get("response_time_ms", 0.0),
            memory_usage_mb=data.get("memory_usage_mb", 0.0),
            cpu_usage_percent=data.get("cpu_usage_percent", 0.0),
            audio_latency_ms=data.get("audio_latency_ms", 0.0),
            component=data.get("component", "system"),
        )
        if data.get("timestamp"):
            try:
                perf.timestamp = datetime.fromisoformat(data["timestamp"])
            except ValueError:
                perf.timestamp = datetime.now()
        return perf

    def get_performance_grade(self) -> str:
        """Return EXCELLENT/GOOD/ACCEPTABLE/POOR against targets."""
        if not self.meets_targets():
            return "POOR"

        response_ratio = self.response_time_ms / 200.0
        memory_limit = 200 if self.component == "idle" else 500
        memory_ratio = self.memory_usage_mb / memory_limit
        max_ratio = max(response_ratio, memory_ratio)

        if max_ratio <= 0.5:
            return "EXCELLENT"
        if max_ratio <= 0.7:
            return "GOOD"
        if max_ratio <= 0.9:
            return "ACCEPTABLE"
        return "POOR"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SystemPerformance):
            return False
        return (
            abs(self.response_time_ms - other.response_time_ms) < 0.1
            and abs(self.memory_usage_mb - other.memory_usage_mb) < 0.1
            and abs(self.cpu_usage_percent - other.cpu_usage_percent) < 0.1
            and abs(self.audio_latency_ms - other.audio_latency_ms) < 0.1
            and self.component == other.component
        )

    def __str__(self) -> str:
        ok = "OK" if self.meets_targets() else "WARN"
        grade = self.get_performance_grade()
        return (
            f"SystemPerformance({self.component}): "
            f"response={self.response_time_ms:.1f}ms, "
            f"memory={self.memory_usage_mb:.1f}MB, "
            f"cpu={self.cpu_usage_percent:.1f}%, "
            f"audio={self.audio_latency_ms:.1f}ms "
            f"[{grade} {ok}]"
        )
