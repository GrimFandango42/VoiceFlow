"""
Idle-Aware Process Monitor for VoiceFlow
========================================
Designed for long-running background services that wait for hotkey activation.
Distinguishes between healthy idle waiting and problematic hangs.
"""

from __future__ import annotations

import threading
import time
import os
import logging
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ProcessState(Enum):
    """Process states for monitoring"""
    IDLE = "idle"                    # Waiting for user input (healthy)
    RECORDING = "recording"           # Recording audio
    PROCESSING = "processing"         # Processing audio/transcription
    INJECTING = "injecting"          # Injecting text
    ERROR = "error"                  # Error state
    HUNG = "hung"                    # Detected hang


@dataclass
class IdleAwareHealth:
    """Health metrics for idle-aware monitoring"""
    state: ProcessState
    state_duration: float            # How long in current state
    last_state_change: float        # When state last changed
    total_uptime: float             # Total process uptime
    recordings_completed: int        # Total recordings processed
    errors_since_idle: int          # Errors since last idle state
    is_healthy: bool                # Overall health assessment
    memory_mb: Optional[float] = None
    cpu_percent: Optional[float] = None


class IdleAwareMonitor:
    """
    Monitor designed for long-running hotkey-activated services.

    Key principles:
    - IDLE is the normal, healthy state (can last for hours/days)
    - Only monitor for hangs during ACTIVE operations
    - Track state transitions to detect stuck states
    - Support true 24/7 operation
    """

    def __init__(self,
                 operation_timeout: float = 120.0,      # Max time for active operations
                 memory_warning_mb: float = 1024.0,     # Warn at 1GB
                 memory_critical_mb: float = 2048.0,    # Critical at 2GB
                 check_interval: float = 10.0):         # Check every 10 seconds

        self.operation_timeout = operation_timeout
        self.memory_warning_mb = memory_warning_mb
        self.memory_critical_mb = memory_critical_mb
        self.check_interval = check_interval

        # State tracking
        self.current_state = ProcessState.IDLE
        self.state_start_time = time.time()
        self.last_activity_time = time.time()
        self.process_start_time = time.time()

        # Metrics
        self.recordings_completed = 0
        self.total_errors = 0
        self.errors_since_idle = 0

        # Monitoring
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.state_lock = threading.Lock()

        # Callbacks
        self.on_hang_detected: Optional[Callable[[str], None]] = None
        self.on_memory_warning: Optional[Callable[[float], None]] = None
        self.on_health_check: Optional[Callable[[IdleAwareHealth], None]] = None

        logger.info("IdleAwareMonitor initialized for 24/7 operation")
        logger.info(f"  - Operation timeout: {operation_timeout}s")
        logger.info(f"  - Memory warning: {memory_warning_mb}MB")
        logger.info(f"  - Memory critical: {memory_critical_mb}MB")

    def start_monitoring(self):
        """Start the idle-aware monitoring"""
        if self.is_monitoring:
            return

        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="IdleAwareMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("Started idle-aware monitoring")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        logger.info("Stopped idle-aware monitoring")

    def set_state(self, new_state: ProcessState, context: str = ""):
        """
        Change the process state.
        This is the PRIMARY way to track activity.
        """
        with self.state_lock:
            old_state = self.current_state

            # Don't re-enter same state
            if old_state == new_state:
                return

            # Calculate time in previous state
            state_duration = time.time() - self.state_start_time

            # Log state transition
            logger.debug(f"State transition: {old_state.value} -> {new_state.value} "
                        f"(was in {old_state.value} for {state_duration:.1f}s) {context}")

            # Update state
            self.current_state = new_state
            self.state_start_time = time.time()
            self.last_activity_time = time.time()

            # Reset error counter when returning to idle
            if new_state == ProcessState.IDLE:
                self.errors_since_idle = 0
                # Increment completed recordings if coming from processing
                if old_state in [ProcessState.PROCESSING, ProcessState.INJECTING]:
                    self.recordings_completed += 1

            # Track errors
            if new_state == ProcessState.ERROR:
                self.total_errors += 1
                self.errors_since_idle += 1

    def record_heartbeat(self):
        """
        Record a heartbeat to prove the main loop is alive.
        Called periodically from the main event loop.
        """
        with self.state_lock:
            self.last_activity_time = time.time()

    def get_health(self) -> IdleAwareHealth:
        """Get current health assessment"""
        with self.state_lock:
            state_duration = time.time() - self.state_start_time
            total_uptime = time.time() - self.process_start_time

            # Determine if healthy based on state
            is_healthy = self._assess_health(self.current_state, state_duration)

            # Get memory usage if available
            memory_mb = None
            cpu_percent = None
            try:
                import psutil
                process = psutil.Process(os.getpid())
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                cpu_percent = process.cpu_percent(interval=None)
            except:
                pass

            return IdleAwareHealth(
                state=self.current_state,
                state_duration=state_duration,
                last_state_change=self.state_start_time,
                total_uptime=total_uptime,
                recordings_completed=self.recordings_completed,
                errors_since_idle=self.errors_since_idle,
                is_healthy=is_healthy,
                memory_mb=memory_mb,
                cpu_percent=cpu_percent
            )

    def _assess_health(self, state: ProcessState, duration: float) -> bool:
        """
        Assess health based on current state and duration.

        Key logic:
        - IDLE can last forever (days/weeks)
        - RECORDING should complete within operation_timeout
        - PROCESSING should complete within operation_timeout
        - INJECTING should complete quickly (< 10 seconds)
        - ERROR state means unhealthy
        - HUNG state means unhealthy
        """
        if state == ProcessState.IDLE:
            # Idle is always healthy, no matter how long
            return True

        elif state == ProcessState.RECORDING:
            # Recording has a reasonable timeout (e.g., 2 minutes)
            return duration < self.operation_timeout

        elif state == ProcessState.PROCESSING:
            # Processing/transcription has a timeout
            return duration < self.operation_timeout

        elif state == ProcessState.INJECTING:
            # Injection should be very quick (< 10 seconds)
            return duration < 10.0

        elif state in [ProcessState.ERROR, ProcessState.HUNG]:
            # Error states are unhealthy
            return False

        return True

    def _monitor_loop(self):
        """Main monitoring loop"""
        last_report_time = time.time()
        report_interval = 300.0  # Report every 5 minutes when idle

        while self.is_monitoring:
            try:
                health = self.get_health()

                # Check for hung operations (but don't re-detect hangs)
                if not health.is_healthy and health.state not in [ProcessState.IDLE, ProcessState.HUNG]:
                    hang_reason = f"Operation '{health.state.value}' exceeded timeout " \
                                 f"({health.state_duration:.1f}s > {self.operation_timeout}s)"
                    logger.warning(f"Hang detected: {hang_reason}")

                    if self.on_hang_detected:
                        self.on_hang_detected(hang_reason)

                    # Mark as hung
                    with self.state_lock:
                        self.current_state = ProcessState.HUNG

                # Check memory usage
                if health.memory_mb:
                    if health.memory_mb > self.memory_critical_mb:
                        logger.critical(f"Critical memory usage: {health.memory_mb:.1f}MB")
                        if self.on_hang_detected:
                            self.on_hang_detected(f"Memory critical: {health.memory_mb:.1f}MB")

                    elif health.memory_mb > self.memory_warning_mb:
                        logger.warning(f"High memory usage: {health.memory_mb:.1f}MB")
                        if self.on_memory_warning:
                            self.on_memory_warning(health.memory_mb)

                # Periodic health report (only when idle to reduce noise)
                if health.state == ProcessState.IDLE:
                    if time.time() - last_report_time > report_interval:
                        logger.info(f"Health Report: Uptime {health.total_uptime/3600:.1f}h, "
                                  f"{health.recordings_completed} recordings, "
                                  f"Memory {health.memory_mb:.1f}MB" if health.memory_mb else "")
                        last_report_time = time.time()

                # Callback for custom health processing
                if self.on_health_check:
                    self.on_health_check(health)

            except Exception as e:
                logger.error(f"Monitor loop error: {e}")

            time.sleep(self.check_interval)


# Global idle-aware monitor instance
_global_monitor: Optional[IdleAwareMonitor] = None


def get_idle_monitor() -> IdleAwareMonitor:
    """Get or create global idle-aware monitor"""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = IdleAwareMonitor()
    return _global_monitor


def start_idle_monitoring(**kwargs) -> IdleAwareMonitor:
    """Start global idle-aware monitoring"""
    global _global_monitor

    if kwargs:
        _global_monitor = IdleAwareMonitor(**kwargs)
    else:
        _global_monitor = get_idle_monitor()

    _global_monitor.start_monitoring()
    return _global_monitor


def set_process_state(state: str, context: str = ""):
    """Set process state for monitoring"""
    global _global_monitor
    if _global_monitor:
        try:
            state_enum = ProcessState(state)
            _global_monitor.set_state(state_enum, context)
        except ValueError:
            logger.warning(f"Invalid state: {state}")


def record_heartbeat():
    """Record a heartbeat to prove main loop is alive"""
    global _global_monitor
    if _global_monitor:
        _global_monitor.record_heartbeat()


def stop_idle_monitoring():
    """Stop global idle monitoring"""
    global _global_monitor
    if _global_monitor:
        _global_monitor.stop_monitoring()


# Convenience functions for state transitions
def mark_idle():
    """Mark process as idle (waiting for hotkey)"""
    set_process_state("idle", "Waiting for hotkey")


def mark_recording():
    """Mark process as recording audio"""
    set_process_state("recording", "Recording audio")


def mark_processing():
    """Mark process as processing/transcribing"""
    set_process_state("processing", "Processing transcription")


def mark_injecting():
    """Mark process as injecting text"""
    set_process_state("injecting", "Injecting text")


def mark_error(error_msg: str = ""):
    """Mark process as in error state"""
    set_process_state("error", f"Error: {error_msg}")