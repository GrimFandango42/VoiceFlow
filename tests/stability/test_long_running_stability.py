#!/usr/bin/env python3
"""
Long-Running Stability Test for VoiceFlow
=========================================
Tests the system's ability to run continuously for extended periods
without hanging, memory leaks, or performance degradation.
"""

import sys
import os
import time
import threading
import subprocess
import psutil
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from voiceflow.utils.process_monitor import ProcessWatchdog, ProcessHealth
from voiceflow.core.config import Config


@dataclass
class StabilityMetrics:
    """Metrics collected during stability testing"""
    timestamp: str
    uptime_minutes: float
    memory_mb: float
    cpu_percent: float
    thread_count: int
    error_count: int
    activity_count: int
    is_responsive: bool


class LongRunningStabilityTest:
    """
    Comprehensive stability test for VoiceFlow long-running operations
    """

    def __init__(self,
                 test_duration_hours: float = 24.0,
                 monitoring_interval: float = 60.0,  # 1 minute
                 stress_test_interval: float = 300.0):  # 5 minutes

        self.test_duration_hours = test_duration_hours
        self.monitoring_interval = monitoring_interval
        self.stress_test_interval = stress_test_interval

        # Test state
        self.start_time = None
        self.end_time = None
        self.metrics_history: List[StabilityMetrics] = []
        self.error_log: List[str] = []
        self.is_running = False

        # Process tracking
        self.voiceflow_process: Optional[subprocess.Popen] = None
        self.watchdog: Optional[ProcessWatchdog] = None

        # Test results
        self.passed = False
        self.failure_reason = None

        # Setup logging
        self.logger = logging.getLogger("stability_test")
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def start_test(self):
        """Start the long-running stability test"""
        self.logger.info(f"Starting {self.test_duration_hours}h stability test...")
        self.start_time = datetime.now()
        self.is_running = True

        try:
            # Start VoiceFlow process
            self._start_voiceflow_process()

            # Start monitoring
            self._start_monitoring()

            # Wait for test completion
            self._wait_for_completion()

            # Analyze results
            self._analyze_results()

        except Exception as e:
            self.logger.error(f"Test failed with exception: {e}")
            self.failure_reason = str(e)
            self.passed = False

        finally:
            self._cleanup()
            self.end_time = datetime.now()

    def _start_voiceflow_process(self):
        """Start VoiceFlow CLI process for testing"""
        self.logger.info("Starting VoiceFlow process...")

        # Use a test configuration
        voiceflow_cmd = [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'src'); exec(open('src/voiceflow/ui/cli_enhanced.py').read())"
        ]

        try:
            self.voiceflow_process = subprocess.Popen(
                voiceflow_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=Path(__file__).parent.parent.parent,
                env={**os.environ, 'PYTHONPATH': str(Path(__file__).parent.parent.parent / 'src')}
            )

            # Wait briefly to ensure process starts
            time.sleep(5)

            if self.voiceflow_process.poll() is not None:
                raise RuntimeError(f"VoiceFlow process failed to start (exit code: {self.voiceflow_process.poll()})")

            self.logger.info(f"VoiceFlow started with PID {self.voiceflow_process.pid}")

        except Exception as e:
            raise RuntimeError(f"Failed to start VoiceFlow: {e}")

    def _start_monitoring(self):
        """Start process monitoring and health checks"""
        if not self.voiceflow_process:
            raise RuntimeError("No VoiceFlow process to monitor")

        # Create watchdog for monitoring
        self.watchdog = ProcessWatchdog(
            health_check_interval=30.0,
            activity_timeout=600.0,  # 10 minutes for stability test
            memory_limit_mb=4096.0,  # 4GB limit for stability test
            max_errors=20,           # Allow more errors in long test
            auto_restart=False       # Don't auto-restart during test
        )

        # Set up callbacks
        def on_health_check(health: ProcessHealth):
            self._record_metrics(health)

        def on_process_hung():
            self.logger.error("Process appears to be hung!")
            self.error_log.append(f"{datetime.now()}: Process hung detected")

        def on_restart_needed():
            self.logger.error("Process restart needed!")
            self.error_log.append(f"{datetime.now()}: Restart needed")
            self.failure_reason = "Process required restart"
            self.is_running = False

        self.watchdog.on_health_check = on_health_check
        self.watchdog.on_process_hung = on_process_hung
        self.watchdog.on_restart_needed = on_restart_needed

        # Start monitoring
        self.watchdog.start_monitoring(self.voiceflow_process.pid)
        self.logger.info("Process monitoring started")

    def _record_metrics(self, health: ProcessHealth):
        """Record health metrics for analysis"""
        uptime_minutes = (datetime.now() - self.start_time).total_seconds() / 60

        metrics = StabilityMetrics(
            timestamp=datetime.now().isoformat(),
            uptime_minutes=uptime_minutes,
            memory_mb=health.memory_mb,
            cpu_percent=health.cpu_percent,
            thread_count=health.threads,
            error_count=health.error_count,
            activity_count=0,  # Would be tracked by actual activity
            is_responsive=health.is_responsive
        )

        self.metrics_history.append(metrics)

        # Log significant events
        if health.memory_mb > 1024:  # High memory usage
            self.logger.warning(f"High memory usage: {health.memory_mb:.1f}MB")

        if not health.is_responsive:
            self.logger.warning("Process not responsive")

        # Log regular status
        if len(self.metrics_history) % 10 == 0:  # Every 10 checks
            self.logger.info(f"Status: {uptime_minutes:.1f}min, "
                           f"Memory: {health.memory_mb:.1f}MB, "
                           f"CPU: {health.cpu_percent:.1f}%, "
                           f"Responsive: {health.is_responsive}")

    def _wait_for_completion(self):
        """Wait for test completion or failure"""
        end_time = self.start_time + timedelta(hours=self.test_duration_hours)

        while self.is_running and datetime.now() < end_time:
            # Check if process is still alive
            if self.voiceflow_process and self.voiceflow_process.poll() is not None:
                self.logger.error(f"VoiceFlow process terminated (exit code: {self.voiceflow_process.poll()})")
                self.failure_reason = f"Process terminated with exit code {self.voiceflow_process.poll()}"
                self.is_running = False
                break

            # Periodic stress testing
            if int(time.time()) % int(self.stress_test_interval) == 0:
                self._perform_stress_test()

            time.sleep(self.monitoring_interval)

        if datetime.now() >= end_time:
            self.logger.info("Test duration completed successfully!")

    def _perform_stress_test(self):
        """Perform periodic stress test operations"""
        self.logger.info("Performing stress test cycle...")

        try:
            # Simulate various stress conditions
            # Note: In a real test, you'd send actual audio or trigger transcriptions

            # Memory stress test
            large_data = bytearray(10 * 1024 * 1024)  # 10MB allocation
            time.sleep(1)
            del large_data

            # CPU stress test
            _ = sum(i * i for i in range(10000))

            self.logger.info("Stress test cycle completed")

        except Exception as e:
            self.logger.error(f"Stress test failed: {e}")
            self.error_log.append(f"{datetime.now()}: Stress test error: {e}")

    def _analyze_results(self):
        """Analyze test results and determine pass/fail"""
        if not self.metrics_history:
            self.failure_reason = "No metrics collected"
            self.passed = False
            return

        # Calculate statistics
        memory_values = [m.memory_mb for m in self.metrics_history]
        cpu_values = [m.cpu_percent for m in self.metrics_history]

        avg_memory = sum(memory_values) / len(memory_values)
        max_memory = max(memory_values)
        avg_cpu = sum(cpu_values) / len(cpu_values)

        # Check for memory leaks (significant memory growth over time)
        if len(memory_values) > 10:
            early_memory = sum(memory_values[:5]) / 5
            late_memory = sum(memory_values[-5:]) / 5
            memory_growth = late_memory - early_memory

            if memory_growth > 200:  # More than 200MB growth
                self.failure_reason = f"Memory leak detected: {memory_growth:.1f}MB growth"
                self.passed = False
                return

        # Check for excessive resource usage
        if max_memory > 3072:  # More than 3GB
            self.failure_reason = f"Excessive memory usage: {max_memory:.1f}MB"
            self.passed = False
            return

        # Check for responsiveness issues
        unresponsive_count = sum(1 for m in self.metrics_history if not m.is_responsive)
        unresponsive_ratio = unresponsive_count / len(self.metrics_history)

        if unresponsive_ratio > 0.1:  # More than 10% unresponsive
            self.failure_reason = f"Responsiveness issues: {unresponsive_ratio:.1%} unresponsive"
            self.passed = False
            return

        # Check for excessive errors
        total_errors = len(self.error_log)
        if total_errors > 5:
            self.failure_reason = f"Too many errors: {total_errors}"
            self.passed = False
            return

        # If we get here, test passed
        self.passed = True
        self.logger.info("✅ Stability test PASSED!")
        self.logger.info(f"Average memory: {avg_memory:.1f}MB")
        self.logger.info(f"Max memory: {max_memory:.1f}MB")
        self.logger.info(f"Average CPU: {avg_cpu:.1f}%")
        self.logger.info(f"Errors: {total_errors}")

    def _cleanup(self):
        """Clean up test resources"""
        self.logger.info("Cleaning up test resources...")

        # Stop monitoring
        if self.watchdog:
            self.watchdog.stop_monitoring()

        # Terminate VoiceFlow process
        if self.voiceflow_process:
            try:
                self.voiceflow_process.terminate()
                self.voiceflow_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.voiceflow_process.kill()
            except Exception as e:
                self.logger.error(f"Error terminating process: {e}")

    def save_results(self, output_file: Optional[str] = None):
        """Save test results to file"""
        if output_file is None:
            output_file = f"stability_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        results = {
            'test_config': {
                'duration_hours': self.test_duration_hours,
                'monitoring_interval': self.monitoring_interval,
                'stress_test_interval': self.stress_test_interval
            },
            'test_execution': {
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'passed': self.passed,
                'failure_reason': self.failure_reason
            },
            'metrics': [asdict(m) for m in self.metrics_history],
            'errors': self.error_log
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        self.logger.info(f"Results saved to {output_file}")


def main():
    """Run stability test"""
    import argparse

    parser = argparse.ArgumentParser(description="VoiceFlow Long-Running Stability Test")
    parser.add_argument("--duration", type=float, default=1.0,
                       help="Test duration in hours (default: 1.0)")
    parser.add_argument("--monitoring-interval", type=float, default=60.0,
                       help="Monitoring interval in seconds (default: 60)")
    parser.add_argument("--output", type=str,
                       help="Output file for results")

    args = parser.parse_args()

    # Create and run test
    test = LongRunningStabilityTest(
        test_duration_hours=args.duration,
        monitoring_interval=args.monitoring_interval
    )

    try:
        test.start_test()
        test.save_results(args.output)

        # Exit with appropriate code
        sys.exit(0 if test.passed else 1)

    except KeyboardInterrupt:
        test.logger.info("Test interrupted by user")
        test._cleanup()
        sys.exit(2)


if __name__ == "__main__":
    main()