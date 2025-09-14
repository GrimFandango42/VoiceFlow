#!/usr/bin/env python3
"""
Test Process Monitor
===================
Monitors test processes and provides force-kill capabilities for hanging tests.
Used by the test framework to ensure proper cleanup and timeout handling.
"""

import os
import sys
import time
import psutil
import signal
import subprocess
import threading
from typing import List, Dict, Optional
from dataclasses import dataclass
from pathlib import Path

@dataclass
class ProcessInfo:
    pid: int
    name: str
    cmdline: List[str]
    memory_mb: float
    cpu_percent: float
    create_time: float
    status: str

class TestProcessMonitor:
    """Monitor and manage test processes"""

    def __init__(self):
        self.monitoring = False
        self.monitored_processes: Dict[int, ProcessInfo] = {}
        self.monitor_thread: Optional[threading.Thread] = None
        self.callbacks = []

    def start_monitoring(self, interval: float = 1.0):
        """Start monitoring processes"""
        if self.monitoring:
            return

        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop monitoring processes"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)

    def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self._scan_processes()
                time.sleep(interval)
            except Exception as e:
                print(f"[MONITOR] Error in monitoring loop: {e}")
                time.sleep(interval)

    def _scan_processes(self):
        """Scan for test-related processes"""
        current_processes = {}

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_info', 'cpu_percent', 'create_time', 'status']):
                try:
                    info = proc.info
                    if not info['cmdline']:
                        continue

                    cmdline_str = ' '.join(info['cmdline']).lower()

                    # Look for VoiceFlow test processes
                    if any(keyword in cmdline_str for keyword in [
                        'test_edge_cases.py',
                        'test_integration.py',
                        'test_extreme_stress.py',
                        'run_comprehensive_tests.py',
                        'voiceflow',
                        'localflow'
                    ]):
                        proc_info = ProcessInfo(
                            pid=info['pid'],
                            name=info['name'] or 'unknown',
                            cmdline=info['cmdline'],
                            memory_mb=info['memory_info'].rss / 1024 / 1024 if info['memory_info'] else 0,
                            cpu_percent=info['cpu_percent'] or 0,
                            create_time=info['create_time'] or time.time(),
                            status=info['status'] or 'unknown'
                        )

                        current_processes[info['pid']] = proc_info

                        # Notify callbacks of new/updated processes
                        for callback in self.callbacks:
                            try:
                                callback(proc_info)
                            except Exception:
                                pass

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            print(f"[MONITOR] Error scanning processes: {e}")

        self.monitored_processes = current_processes

    def get_processes(self) -> List[ProcessInfo]:
        """Get list of monitored processes"""
        return list(self.monitored_processes.values())

    def kill_process_tree(self, pid: int, timeout: float = 5.0) -> bool:
        """Kill process and all its children"""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)

            print(f"[MONITOR] Killing process tree for PID {pid}")
            print(f"[MONITOR] Found {len(children)} child processes")

            # Terminate children first
            for child in children:
                try:
                    print(f"[MONITOR] Terminating child PID {child.pid}")
                    child.terminate()
                except psutil.NoSuchProcess:
                    pass

            # Terminate parent
            try:
                print(f"[MONITOR] Terminating parent PID {pid}")
                parent.terminate()
            except psutil.NoSuchProcess:
                pass

            # Wait for graceful termination
            gone, alive = psutil.wait_procs([parent] + children, timeout=timeout)

            # Force kill remaining processes
            for proc in alive:
                try:
                    print(f"[MONITOR] Force killing PID {proc.pid}")
                    proc.kill()
                except psutil.NoSuchProcess:
                    pass

            print(f"[MONITOR] Process tree cleanup complete")
            return True

        except psutil.NoSuchProcess:
            print(f"[MONITOR] Process {pid} already gone")
            return True
        except Exception as e:
            print(f"[MONITOR] Error killing process tree {pid}: {e}")
            return False

    def kill_all_test_processes(self) -> int:
        """Kill all monitored test processes"""
        killed_count = 0
        processes = list(self.monitored_processes.values())

        print(f"[MONITOR] Killing {len(processes)} test processes")

        for proc_info in processes:
            if self.kill_process_tree(proc_info.pid):
                killed_count += 1

        return killed_count

    def find_hanging_processes(self, max_age_seconds: float = 300) -> List[ProcessInfo]:
        """Find processes that have been running too long"""
        hanging = []
        current_time = time.time()

        for proc_info in self.monitored_processes.values():
            age = current_time - proc_info.create_time
            if age > max_age_seconds:
                hanging.append(proc_info)

        return hanging

    def add_callback(self, callback):
        """Add callback for process events"""
        self.callbacks.append(callback)

    def get_system_resources(self) -> Dict[str, float]:
        """Get system resource usage"""
        try:
            return {
                'memory_percent': psutil.virtual_memory().percent,
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'disk_percent': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent,
                'process_count': len(psutil.pids())
            }
        except Exception:
            return {'memory_percent': 0, 'cpu_percent': 0, 'disk_percent': 0, 'process_count': 0}

def cleanup_test_processes(max_age_minutes: float = 10):
    """Standalone function to cleanup old test processes"""
    print(f"[CLEANUP] Scanning for test processes older than {max_age_minutes} minutes")

    monitor = TestProcessMonitor()
    monitor._scan_processes()

    hanging = monitor.find_hanging_processes(max_age_minutes * 60)

    if not hanging:
        print("[CLEANUP] No hanging processes found")
        return 0

    print(f"[CLEANUP] Found {len(hanging)} hanging test processes:")
    for proc in hanging:
        age_minutes = (time.time() - proc.create_time) / 60
        print(f"  PID {proc.pid}: {proc.name} (age: {age_minutes:.1f}min, memory: {proc.memory_mb:.1f}MB)")

    killed = monitor.kill_all_test_processes()
    print(f"[CLEANUP] Cleaned up {killed} processes")

    return killed

def monitor_test_execution(test_command: List[str], timeout_seconds: float = 300) -> Dict[str, any]:
    """Monitor a test execution with timeout and resource tracking"""
    print(f"[EXEC] Starting monitored test execution")
    print(f"[EXEC] Command: {' '.join(test_command)}")
    print(f"[EXEC] Timeout: {timeout_seconds}s")

    monitor = TestProcessMonitor()
    monitor.start_monitoring(interval=0.5)

    start_time = time.time()
    peak_memory = 0
    peak_cpu = 0
    process_count = 0

    # Resource tracking callback
    def track_resources(proc_info: ProcessInfo):
        nonlocal peak_memory, peak_cpu, process_count
        peak_memory = max(peak_memory, proc_info.memory_mb)
        peak_cpu = max(peak_cpu, proc_info.cpu_percent)
        process_count = len(monitor.monitored_processes)

    monitor.add_callback(track_resources)

    try:
        # Start the test process
        process = subprocess.Popen(
            test_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Monitor until completion or timeout
        while True:
            if process.poll() is not None:
                # Process completed
                break

            elapsed = time.time() - start_time
            if elapsed > timeout_seconds:
                # Timeout - kill the process
                print(f"[EXEC] Test timed out after {timeout_seconds}s")
                monitor.kill_process_tree(process.pid)
                process.wait(timeout=5)
                break

            time.sleep(0.5)

        stdout, stderr = process.communicate(timeout=2)
        duration = time.time() - start_time

        result = {
            'exit_code': process.returncode,
            'duration': duration,
            'stdout': stdout,
            'stderr': stderr,
            'timed_out': duration >= timeout_seconds,
            'peak_memory_mb': peak_memory,
            'peak_cpu_percent': peak_cpu,
            'max_processes': process_count
        }

        print(f"[EXEC] Test completed in {duration:.1f}s")
        print(f"[EXEC] Peak memory: {peak_memory:.1f}MB, Peak CPU: {peak_cpu:.1f}%")

        return result

    except Exception as e:
        print(f"[EXEC] Error monitoring test execution: {e}")
        return {
            'exit_code': -1,
            'duration': time.time() - start_time,
            'stdout': '',
            'stderr': str(e),
            'timed_out': False,
            'peak_memory_mb': peak_memory,
            'peak_cpu_percent': peak_cpu,
            'max_processes': process_count
        }

    finally:
        monitor.stop_monitoring()

def main():
    """Main entry point for standalone process monitoring"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python test_process_monitor.py cleanup [max_age_minutes]")
        print("  python test_process_monitor.py monitor <command> [timeout_seconds]")
        print("  python test_process_monitor.py status")
        sys.exit(1)

    command = sys.argv[1]

    if command == "cleanup":
        max_age = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
        cleanup_test_processes(max_age)

    elif command == "monitor":
        if len(sys.argv) < 3:
            print("Error: monitor command requires test command")
            sys.exit(1)

        test_cmd = sys.argv[2:]
        timeout = float(sys.argv[-1]) if sys.argv[-1].isdigit() else 300.0

        # If last arg is timeout, remove it from command
        if sys.argv[-1].isdigit():
            test_cmd = test_cmd[:-1]

        result = monitor_test_execution(test_cmd, timeout)
        print(f"Result: {result}")

        sys.exit(0 if result['exit_code'] == 0 else 1)

    elif command == "status":
        monitor = TestProcessMonitor()
        monitor._scan_processes()
        processes = monitor.get_processes()

        print(f"Found {len(processes)} test-related processes:")
        for proc in processes:
            age = time.time() - proc.create_time
            print(f"  PID {proc.pid}: {proc.name} (age: {age/60:.1f}min, {proc.memory_mb:.1f}MB)")

        resources = monitor.get_system_resources()
        print(f"\nSystem resources:")
        for key, value in resources.items():
            print(f"  {key}: {value}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()