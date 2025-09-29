"""
VoiceFlow Process Monitor and Watchdog System
============================================
Ensures robust long-running operation with automatic health checks,
timeout handling, and restart capabilities.
"""

from __future__ import annotations

import threading
import time
import psutil
import os
import logging
import signal
import subprocess
from typing import Optional, Callable, Dict, Any, List
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ProcessHealth:
    """Process health metrics"""
    memory_mb: float
    cpu_percent: float
    threads: int
    uptime_seconds: float
    last_activity: float
    is_responsive: bool
    error_count: int


class ProcessWatchdog:
    """
    Watchdog system for monitoring VoiceFlow process health and preventing hangs
    """

    def __init__(self,
                 health_check_interval: float = 30.0,
                 activity_timeout: float = 300.0,  # 5 minutes
                 memory_limit_mb: float = 1024.0,  # 1GB
                 max_errors: int = 5,
                 auto_restart: bool = True):

        self.health_check_interval = health_check_interval
        self.activity_timeout = activity_timeout
        self.memory_limit_mb = memory_limit_mb
        self.max_errors = max_errors
        self.auto_restart = auto_restart

        # State tracking
        self.process_pid: Optional[int] = None
        self.start_time = time.time()
        self.last_activity = time.time()
        self.error_count = 0
        self.is_running = False
        self.health_thread: Optional[threading.Thread] = None

        # Callbacks
        self.on_health_check: Optional[Callable[[ProcessHealth], None]] = None
        self.on_process_hung: Optional[Callable[[], None]] = None
        self.on_restart_needed: Optional[Callable[[], None]] = None

        # Activity tracking
        self.activity_lock = threading.Lock()
        self.last_audio_processed = 0
        self.last_transcription_completed = 0

        logger.info(f"ProcessWatchdog initialized:")
        logger.info(f"  - Health check interval: {health_check_interval}s")
        logger.info(f"  - Activity timeout: {activity_timeout}s")
        logger.info(f"  - Memory limit: {memory_limit_mb}MB")
        logger.info(f"  - Auto-restart: {auto_restart}")

    def start_monitoring(self, process_pid: int = None):
        """Start monitoring the current process or specified PID"""
        if process_pid is None:
            self.process_pid = os.getpid()
        else:
            self.process_pid = process_pid

        self.start_time = time.time()
        self.last_activity = time.time()
        self.error_count = 0
        self.is_running = True

        # Start health check thread
        self.health_thread = threading.Thread(
            target=self._health_check_loop,
            name="ProcessWatchdog",
            daemon=True
        )
        self.health_thread.start()

        logger.info(f"Started monitoring process PID {self.process_pid}")

    def stop_monitoring(self):
        """Stop process monitoring"""
        self.is_running = False
        if self.health_thread:
            self.health_thread.join(timeout=5.0)
        logger.info("Process monitoring stopped")

    def record_activity(self, activity_type: str = "general"):
        """Record process activity to reset timeout"""
        with self.activity_lock:
            self.last_activity = time.time()

            if activity_type == "audio_processed":
                self.last_audio_processed += 1
            elif activity_type == "transcription_completed":
                self.last_transcription_completed += 1

    def get_process_health(self) -> Optional[ProcessHealth]:
        """Get current process health metrics"""
        try:
            if not self.process_pid:
                return None

            process = psutil.Process(self.process_pid)

            if not process.is_running():
                return None

            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)

            cpu_percent = process.cpu_percent(interval=None)
            thread_count = process.num_threads()
            uptime = time.time() - self.start_time

            # Check if process is responsive
            time_since_activity = time.time() - self.last_activity
            is_responsive = time_since_activity < self.activity_timeout

            return ProcessHealth(
                memory_mb=memory_mb,
                cpu_percent=cpu_percent,
                threads=thread_count,
                uptime_seconds=uptime,
                last_activity=self.last_activity,
                is_responsive=is_responsive,
                error_count=self.error_count
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"Could not get process health: {e}")
            return None

    def _health_check_loop(self):
        """Main health check loop"""
        while self.is_running:
            try:
                health = self.get_process_health()

                if health is None:
                    logger.error("Process no longer exists")
                    if self.on_restart_needed:
                        self.on_restart_needed()
                    break

                # Check for issues
                issues = []

                # Memory limit check
                if health.memory_mb > self.memory_limit_mb:
                    issues.append(f"Memory usage {health.memory_mb:.1f}MB exceeds limit {self.memory_limit_mb}MB")

                # Activity timeout check
                if not health.is_responsive:
                    time_since_activity = time.time() - health.last_activity
                    issues.append(f"No activity for {time_since_activity:.1f}s (timeout: {self.activity_timeout}s)")

                # High error count
                if health.error_count > self.max_errors:
                    issues.append(f"Error count {health.error_count} exceeds maximum {self.max_errors}")

                # Log issues and take action
                if issues:
                    for issue in issues:
                        logger.warning(f"Health check issue: {issue}")

                    if self.on_process_hung:
                        self.on_process_hung()

                    if self.auto_restart and self.on_restart_needed:
                        logger.warning("Auto-restart triggered due to health issues")
                        self.on_restart_needed()
                        break

                # Callback for health reporting
                if self.on_health_check:
                    self.on_health_check(health)

                # Log health status periodically
                logger.debug(f"Health: Memory={health.memory_mb:.1f}MB, "
                           f"CPU={health.cpu_percent:.1f}%, "
                           f"Threads={health.threads}, "
                           f"Uptime={health.uptime_seconds:.0f}s, "
                           f"Responsive={health.is_responsive}")

            except Exception as e:
                logger.error(f"Health check error: {e}")
                self.error_count += 1

            # Wait for next check
            time.sleep(self.health_check_interval)

    def force_restart_process(self, restart_command: List[str] = None):
        """Force restart the monitored process"""
        try:
            if self.process_pid:
                logger.warning(f"Force killing process PID {self.process_pid}")

                # Try graceful shutdown first
                try:
                    process = psutil.Process(self.process_pid)
                    process.terminate()
                    process.wait(timeout=10)
                except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                    # Force kill if graceful shutdown fails
                    try:
                        process = psutil.Process(self.process_pid)
                        process.kill()
                    except psutil.NoSuchProcess:
                        pass

                # Restart if command provided
                if restart_command and self.auto_restart:
                    logger.info(f"Restarting with command: {' '.join(restart_command)}")
                    subprocess.Popen(restart_command,
                                   cwd=Path(__file__).parent.parent.parent,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)

        except Exception as e:
            logger.error(f"Failed to restart process: {e}")


class OperationTimeout:
    """
    Context manager for operation timeouts
    """

    def __init__(self, timeout_seconds: float, operation_name: str = "operation"):
        self.timeout_seconds = timeout_seconds
        self.operation_name = operation_name
        self.start_time = None
        self.timer = None
        self.timed_out = False

    def __enter__(self):
        self.start_time = time.time()
        self.timer = threading.Timer(self.timeout_seconds, self._timeout_handler)
        self.timer.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.timer:
            self.timer.cancel()

        if self.timed_out:
            raise TimeoutError(f"{self.operation_name} timed out after {self.timeout_seconds}s")

        # Suppress timeout exception if operation completed
        return False

    def _timeout_handler(self):
        self.timed_out = True
        logger.warning(f"Operation '{self.operation_name}' timed out after {self.timeout_seconds}s")


# Global watchdog instance
_global_watchdog: Optional[ProcessWatchdog] = None


def get_global_watchdog() -> ProcessWatchdog:
    """Get or create global watchdog instance"""
    global _global_watchdog
    if _global_watchdog is None:
        _global_watchdog = ProcessWatchdog()
    return _global_watchdog


def start_process_monitoring(process_pid: int = None, **kwargs):
    """Start global process monitoring"""
    global _global_watchdog

    # Create new watchdog with custom parameters if provided
    if kwargs:
        _global_watchdog = ProcessWatchdog(**kwargs)
    else:
        _global_watchdog = get_global_watchdog()

    _global_watchdog.start_monitoring(process_pid)
    return _global_watchdog


def record_activity(activity_type: str = "general"):
    """Record activity in global watchdog"""
    global _global_watchdog
    if _global_watchdog:
        _global_watchdog.record_activity(activity_type)


def stop_process_monitoring():
    """Stop global process monitoring"""
    global _global_watchdog
    if _global_watchdog:
        _global_watchdog.stop_monitoring()


# Decorator for timeout protection
def timeout_protected(timeout_seconds: float, operation_name: str = None):
    """Decorator to add timeout protection to functions"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            name = operation_name or f"{func.__module__}.{func.__name__}"
            with OperationTimeout(timeout_seconds, name):
                return func(*args, **kwargs)
        return wrapper
    return decorator