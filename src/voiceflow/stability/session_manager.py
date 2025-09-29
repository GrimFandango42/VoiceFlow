"""
Session Manager: Long-Running Service Lifecycle Management

Implements robust session management for 24/7 VoiceFlow operation:
- Session boundaries with clean state isolation
- Activity-based idle detection and resource management
- Health monitoring with automatic degradation detection
- Circuit breaker pattern for error recovery

Based on research of production long-running Python services.
"""

import time
import threading
import logging
import gc
import psutil
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable
from uuid import uuid4, UUID
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class SessionState(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    DEGRADED = "degraded"
    RECOVERY = "recovery"
    TERMINATING = "terminating"

class HealthStatus(Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    RECOVERING = "recovering"

@dataclass
class SessionMetrics:
    """Metrics for session health monitoring"""
    session_id: UUID
    start_time: datetime
    last_activity: datetime
    transcription_count: int = 0
    total_audio_duration: float = 0.0
    total_processing_time: float = 0.0
    memory_usage_peak: float = 0.0
    error_count: int = 0
    recovery_count: int = 0
    health_score: float = 1.0

@dataclass
class PerformanceSnapshot:
    """Point-in-time performance metrics"""
    timestamp: datetime
    memory_mb: float
    cpu_percent: float
    transcription_latency_ms: float
    queue_depth: int
    error_rate_per_hour: float

class SessionManager:
    """
    Production-grade session lifecycle management for long-running operation.

    Features:
    - Clean session boundaries prevent state pollution
    - Activity-based resource management
    - Health monitoring with automatic recovery
    - Circuit breaker pattern for resilience
    """

    def __init__(self,
                 idle_timeout: float = 1800.0,  # 30 minutes idle timeout
                 max_session_duration: float = 14400.0,  # 4 hours max session
                 health_check_interval: float = 60.0,  # 1 minute health checks
                 degradation_threshold: float = 0.7):  # Health score threshold

        self.idle_timeout = idle_timeout
        self.max_session_duration = max_session_duration
        self.health_check_interval = health_check_interval
        self.degradation_threshold = degradation_threshold

        # Session state
        self.current_session: Optional[SessionMetrics] = None
        self.session_state = SessionState.IDLE
        self.state_lock = threading.RLock()

        # Performance monitoring
        self.performance_history: deque = deque(maxlen=1000)  # Last 1000 snapshots
        self.error_history: deque = deque(maxlen=100)  # Last 100 errors
        self.process = psutil.Process()

        # Health monitoring
        self.health_monitor_thread: Optional[threading.Thread] = None
        self.health_monitor_active = False
        self.last_health_check = time.time()

        # Resource management callbacks
        self.cleanup_callbacks: List[Callable] = []
        self.recovery_callbacks: List[Callable] = []

        # Circuit breaker state
        self.consecutive_failures = 0
        self.max_consecutive_failures = 3
        self.circuit_open_until = 0.0
        self.circuit_timeout = 300.0  # 5 minutes

        logger.info("SessionManager initialized for 24/7 operation")

    def start_health_monitoring(self):
        """Start background health monitoring thread"""
        if self.health_monitor_active:
            return

        self.health_monitor_active = True
        self.health_monitor_thread = threading.Thread(
            target=self._health_monitor_loop,
            name="SessionHealthMonitor",
            daemon=True
        )
        self.health_monitor_thread.start()
        logger.info("Health monitoring started")

    def stop_health_monitoring(self):
        """Stop background health monitoring"""
        self.health_monitor_active = False
        if self.health_monitor_thread:
            self.health_monitor_thread.join(timeout=5.0)
        logger.info("Health monitoring stopped")

    def start_session(self) -> UUID:
        """
        Start a new transcription session with clean state.

        Returns:
            UUID: Session identifier
        """
        with self.state_lock:
            # End current session if exists
            if self.current_session:
                self.end_session(self.current_session.session_id)

            # Create new session
            session_id = uuid4()
            now = datetime.now()

            self.current_session = SessionMetrics(
                session_id=session_id,
                start_time=now,
                last_activity=now
            )

            self.session_state = SessionState.ACTIVE
            self.consecutive_failures = 0  # Reset circuit breaker

            # Start health monitoring if not running
            self.start_health_monitoring()

            logger.info(f"New session started: {session_id}")
            return session_id

    def end_session(self, session_id: UUID, force: bool = False) -> bool:
        """
        End session with comprehensive cleanup.

        Args:
            session_id: Session to terminate
            force: Force termination even if session is active

        Returns:
            bool: True if session ended successfully
        """
        with self.state_lock:
            if not self.current_session or self.current_session.session_id != session_id:
                logger.warning(f"Cannot end session {session_id}: not current session")
                return False

            if self.session_state == SessionState.ACTIVE and not force:
                logger.warning(f"Session {session_id} is active, use force=True to terminate")
                return False

            logger.info(f"Ending session {session_id} (state: {self.session_state})")

            # Set terminating state
            self.session_state = SessionState.TERMINATING

            # Execute cleanup callbacks
            cleanup_start = time.time()
            for callback in self.cleanup_callbacks:
                try:
                    callback()
                except Exception as e:
                    logger.error(f"Cleanup callback failed: {e}")

            # Force garbage collection
            gc.collect()

            # Log session summary
            session = self.current_session
            duration = (datetime.now() - session.start_time).total_seconds()

            logger.info(f"Session {session_id} summary: "
                       f"{session.transcription_count} transcriptions, "
                       f"{duration:.1f}s duration, "
                       f"{session.error_count} errors, "
                       f"{session.recovery_count} recoveries")

            # Clear session state
            self.current_session = None
            self.session_state = SessionState.IDLE

            cleanup_time = time.time() - cleanup_start
            logger.info(f"Session cleanup completed in {cleanup_time:.2f}s")

            return True

    def record_activity(self, session_id: Optional[UUID] = None) -> bool:
        """
        Record user activity to reset idle timers.

        Args:
            session_id: Session with activity (optional, uses current if None)

        Returns:
            bool: True if activity recorded successfully
        """
        with self.state_lock:
            if not self.current_session:
                # Start new session on activity
                self.start_session()
                return True

            if session_id and self.current_session.session_id != session_id:
                logger.warning(f"Activity for wrong session: {session_id}")
                return False

            # Update activity timestamp
            self.current_session.last_activity = datetime.now()

            # Reset circuit breaker on successful activity
            if self.consecutive_failures > 0:
                logger.info("Resetting circuit breaker after successful activity")
                self.consecutive_failures = 0

            return True

    def record_transcription(self, audio_duration: float, processing_time: float,
                           success: bool = True, error_info: str = None) -> None:
        """
        Record transcription attempt with performance metrics.

        Args:
            audio_duration: Length of audio processed
            processing_time: Time taken to process
            success: Whether transcription succeeded
            error_info: Error details if failed
        """
        with self.state_lock:
            if not self.current_session:
                logger.warning("No active session for transcription recording")
                return

            session = self.current_session
            session.transcription_count += 1
            session.total_audio_duration += audio_duration
            session.total_processing_time += processing_time

            if success:
                self.consecutive_failures = 0
            else:
                session.error_count += 1
                self.consecutive_failures += 1

                # Record error for analysis
                self.error_history.append({
                    'timestamp': datetime.now(),
                    'session_id': session.session_id,
                    'error_info': error_info,
                    'audio_duration': audio_duration,
                    'processing_time': processing_time
                })

                logger.warning(f"Transcription failed (consecutive: {self.consecutive_failures}): {error_info}")

            # Record performance snapshot
            self._record_performance_snapshot(audio_duration, processing_time)

            # Update memory peak
            current_memory = self.process.memory_info().rss / 1024 / 1024
            session.memory_usage_peak = max(session.memory_usage_peak, current_memory)

            # Check for circuit breaker activation
            if self.consecutive_failures >= self.max_consecutive_failures:
                logger.error(f"Circuit breaker activated after {self.consecutive_failures} failures")
                self._trigger_recovery()

    def get_session_state(self, session_id: Optional[UUID] = None) -> SessionState:
        """
        Get current session state.

        Args:
            session_id: Session to query (optional, uses current if None)

        Returns:
            SessionState: Current state
        """
        with self.state_lock:
            if not self.current_session:
                return SessionState.IDLE

            if session_id and self.current_session.session_id != session_id:
                return SessionState.IDLE

            return self.session_state

    def check_health(self, session_id: Optional[UUID] = None) -> float:
        """
        Calculate comprehensive health score.

        Args:
            session_id: Session to check (optional, uses current if None)

        Returns:
            float: Health score 0.0-1.0
        """
        with self.state_lock:
            if not self.current_session:
                return 1.0  # Idle state is healthy

            session = self.current_session
            now = datetime.now()
            session_duration = (now - session.start_time).total_seconds()

            # Base health score
            health_score = 1.0

            # Penalty for errors
            if session.transcription_count > 0:
                error_rate = session.error_count / session.transcription_count
                health_score *= (1.0 - min(error_rate, 0.5))  # Max 50% penalty

            # Penalty for memory growth
            current_memory = self.process.memory_info().rss / 1024 / 1024
            if current_memory > 500:  # Above 500MB
                memory_penalty = min((current_memory - 500) / 1000, 0.3)  # Max 30% penalty
                health_score *= (1.0 - memory_penalty)

            # Penalty for long session duration
            if session_duration > self.max_session_duration:
                duration_penalty = min((session_duration - self.max_session_duration) / 3600, 0.2)  # Max 20% penalty
                health_score *= (1.0 - duration_penalty)

            # Penalty for consecutive failures
            failure_penalty = min(self.consecutive_failures / self.max_consecutive_failures, 0.4) * 0.5  # Max 20% penalty
            health_score *= (1.0 - failure_penalty)

            # Update session health score
            session.health_score = max(0.0, health_score)

            return session.health_score

    def get_health_report(self) -> Dict[str, Any]:
        """
        Get comprehensive health and performance report.

        Returns:
            Dict: Health metrics and status
        """
        with self.state_lock:
            current_memory = self.process.memory_info().rss / 1024 / 1024
            cpu_percent = self.process.cpu_percent()

            report = {
                'timestamp': datetime.now().isoformat(),
                'session_state': self.session_state.value,
                'health_score': self.check_health(),
                'memory_usage_mb': current_memory,
                'cpu_usage_percent': cpu_percent,
                'consecutive_failures': self.consecutive_failures,
                'circuit_breaker_open': time.time() < self.circuit_open_until,
                'performance_history_count': len(self.performance_history),
                'error_history_count': len(self.error_history)
            }

            if self.current_session:
                session = self.current_session
                now = datetime.now()
                session_duration = (now - session.start_time).total_seconds()
                idle_duration = (now - session.last_activity).total_seconds()

                report.update({
                    'session_id': str(session.session_id),
                    'session_duration_seconds': session_duration,
                    'idle_duration_seconds': idle_duration,
                    'transcription_count': session.transcription_count,
                    'total_audio_duration': session.total_audio_duration,
                    'error_count': session.error_count,
                    'recovery_count': session.recovery_count,
                    'memory_usage_peak': session.memory_usage_peak
                })

            return report

    def add_cleanup_callback(self, callback: Callable) -> None:
        """Add callback to execute during session cleanup"""
        self.cleanup_callbacks.append(callback)

    def add_recovery_callback(self, callback: Callable) -> None:
        """Add callback to execute during error recovery"""
        self.recovery_callbacks.append(callback)

    def _health_monitor_loop(self):
        """Background health monitoring loop"""
        logger.info("Health monitoring loop started")

        while self.health_monitor_active:
            try:
                current_time = time.time()

                # Skip if too soon since last check
                if current_time - self.last_health_check < self.health_check_interval:
                    time.sleep(1.0)
                    continue

                self.last_health_check = current_time

                with self.state_lock:
                    if not self.current_session:
                        time.sleep(5.0)  # Longer sleep when idle
                        continue

                    session = self.current_session
                    now = datetime.now()

                    # Check for idle timeout
                    idle_duration = (now - session.last_activity).total_seconds()
                    if idle_duration > self.idle_timeout:
                        logger.info(f"Session idle timeout ({idle_duration:.1f}s), ending session")
                        self.end_session(session.session_id, force=True)
                        continue

                    # Check for max session duration
                    session_duration = (now - session.start_time).total_seconds()
                    if session_duration > self.max_session_duration:
                        logger.info(f"Session duration limit reached ({session_duration:.1f}s), ending session")
                        self.end_session(session.session_id, force=True)
                        continue

                    # Check health score
                    health_score = self.check_health()
                    if health_score < self.degradation_threshold:
                        if self.session_state != SessionState.DEGRADED:
                            logger.warning(f"Session degradation detected (health: {health_score:.2f})")
                            self.session_state = SessionState.DEGRADED
                            self._trigger_recovery()

                    # Record performance snapshot
                    self._record_performance_snapshot()

                time.sleep(1.0)

            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                time.sleep(5.0)

        logger.info("Health monitoring loop stopped")

    def _trigger_recovery(self):
        """Trigger automatic recovery procedures"""
        if time.time() < self.circuit_open_until:
            logger.info("Circuit breaker open, skipping recovery")
            return

        logger.info("Triggering automatic recovery procedures")

        with self.state_lock:
            if self.current_session:
                self.current_session.recovery_count += 1

            self.session_state = SessionState.RECOVERY

        # Execute recovery callbacks
        recovery_success = True
        for callback in self.recovery_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"Recovery callback failed: {e}")
                recovery_success = False

        # Force garbage collection
        gc.collect()

        if recovery_success:
            logger.info("Recovery completed successfully")
            with self.state_lock:
                self.session_state = SessionState.ACTIVE
                self.consecutive_failures = 0
        else:
            logger.error("Recovery failed, opening circuit breaker")
            self.circuit_open_until = time.time() + self.circuit_timeout

            # End session after failed recovery
            if self.current_session:
                self.end_session(self.current_session.session_id, force=True)

    def _record_performance_snapshot(self, audio_duration: float = 0.0, processing_time: float = 0.0):
        """Record current performance metrics"""
        try:
            memory_mb = self.process.memory_info().rss / 1024 / 1024
            cpu_percent = self.process.cpu_percent()

            # Calculate transcription latency
            latency_ms = 0.0
            if processing_time > 0:
                latency_ms = processing_time * 1000

            # Calculate error rate (errors per hour)
            error_rate = 0.0
            if self.current_session:
                session_hours = max((datetime.now() - self.current_session.start_time).total_seconds() / 3600, 0.1)
                error_rate = self.current_session.error_count / session_hours

            snapshot = PerformanceSnapshot(
                timestamp=datetime.now(),
                memory_mb=memory_mb,
                cpu_percent=cpu_percent,
                transcription_latency_ms=latency_ms,
                queue_depth=0,  # TODO: Integrate with queue depth monitoring
                error_rate_per_hour=error_rate
            )

            self.performance_history.append(snapshot)

        except Exception as e:
            logger.error(f"Failed to record performance snapshot: {e}")


# Global session manager instance
_session_manager: Optional[SessionManager] = None

def get_session_manager() -> SessionManager:
    """Get global session manager instance"""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager

def initialize_session_management():
    """Initialize global session management"""
    manager = get_session_manager()
    logger.info("Session management initialized for 24/7 operation")
    return manager