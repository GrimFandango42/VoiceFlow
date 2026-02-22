#!/usr/bin/env python3
"""
VoiceFlow Comprehensive Test Runner
===================================
Automated runner for all test suites with reporting and analysis
FEATURES:
- Process-level isolation with force-kill mechanisms
- Performance monitoring and resource tracking
- Graceful timeout handling and cleanup
- Real-time progress monitoring
"""

import sys
import time
import os
import subprocess
import json
import traceback
import signal
import threading
import gc
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import psutil
import queue

class PerformanceMonitor:
    """Real-time performance monitoring for tests"""

    def __init__(self):
        self.process = psutil.Process()
        self.monitoring = False
        self.metrics = []
        self._monitor_thread = None

    def start_monitoring(self):
        """Start performance monitoring"""
        self.monitoring = True
        self.metrics = []
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)

    def _monitor_loop(self):
        """Performance monitoring loop"""
        while self.monitoring:
            try:
                metric = {
                    'timestamp': time.time(),
                    'memory_mb': self.process.memory_info().rss / 1024 / 1024,
                    'cpu_percent': self.process.cpu_percent()
                }
                self.metrics.append(metric)
                time.sleep(0.5)  # Sample every 500ms
            except Exception:
                break

    def get_summary(self) -> Dict[str, float]:
        """Get performance summary"""
        if not self.metrics:
            return {'peak_memory_mb': 0, 'avg_cpu_percent': 0}

        return {
            'peak_memory_mb': max(m['memory_mb'] for m in self.metrics),
            'avg_cpu_percent': sum(m['cpu_percent'] for m in self.metrics) / len(self.metrics)
        }

class ProcessManager:
    """Manages test processes with timeout and force-kill capabilities"""

    def __init__(self):
        self.active_processes = []
        self.cleanup_handlers = []

    def run_with_timeout(self, cmd: List[str], timeout: float,
                        cwd: Optional[Path] = None) -> Dict[str, Any]:
        """Run process with robust timeout and monitoring"""
        start_time = time.perf_counter()

        try:
            # Create process with process group for better cleanup
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                # Create new process group on Windows
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0,
                # On Unix, create new session
                preexec_fn=None if sys.platform == 'win32' else os.setsid
            )

            self.active_processes.append(process)

            try:
                # Wait with timeout
                stdout, stderr = process.communicate(timeout=timeout)
                duration = time.perf_counter() - start_time

                return {
                    'status': 'completed',
                    'exit_code': process.returncode,
                    'stdout': stdout,
                    'stderr': stderr,
                    'duration': duration,
                    'timed_out': False
                }

            except subprocess.TimeoutExpired:
                duration = time.perf_counter() - start_time

                # Force kill process tree
                self._force_kill_process_tree(process)

                # Try to get partial output
                try:
                    stdout, stderr = process.communicate(timeout=2.0)
                except subprocess.TimeoutExpired:
                    stdout, stderr = "", f"Process killed after {timeout}s timeout"

                return {
                    'status': 'timeout',
                    'exit_code': -1,
                    'stdout': stdout,
                    'stderr': stderr,
                    'duration': duration,
                    'timed_out': True
                }

        except Exception as e:
            duration = time.perf_counter() - start_time
            return {
                'status': 'error',
                'exit_code': -2,
                'stdout': '',
                'stderr': str(e),
                'duration': duration,
                'timed_out': False
            }
        finally:
            # Remove from active processes
            if process in self.active_processes:
                self.active_processes.remove(process)

    def _force_kill_process_tree(self, process):
        """Force kill process and all children"""
        try:
            parent = psutil.Process(process.pid)
            children = parent.children(recursive=True)

            # Kill children first
            for child in children:
                try:
                    child.terminate()
                except psutil.NoSuchProcess:
                    pass

            # Kill parent
            try:
                parent.terminate()
            except psutil.NoSuchProcess:
                pass

            # Wait briefly for graceful termination
            time.sleep(1.0)

            # Force kill if still alive
            try:
                parent = psutil.Process(process.pid)
                if parent.is_running():
                    parent.kill()

                children = parent.children(recursive=True)
                for child in children:
                    try:
                        if child.is_running():
                            child.kill()
                    except psutil.NoSuchProcess:
                        pass
            except psutil.NoSuchProcess:
                pass

        except Exception as e:
            print(f"Error killing process tree: {e}")

    def cleanup_all(self):
        """Cleanup all active processes"""
        for process in self.active_processes.copy():
            try:
                self._force_kill_process_tree(process)
            except Exception:
                pass

        self.active_processes.clear()

        # Run cleanup handlers
        for handler in self.cleanup_handlers:
            try:
                handler()
            except Exception:
                pass

    def add_cleanup_handler(self, handler):
        """Add cleanup handler"""
        self.cleanup_handlers.append(handler)

class ComprehensiveTestRunner:
    """Master test runner for all VoiceFlow test suites with performance monitoring"""

    def __init__(self):
        self.results = {}
        self.start_time = datetime.now()
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        self.test_dir = Path(__file__).parent / "tests" / "comprehensive"

        # Performance and process management
        self.performance_monitor = PerformanceMonitor()
        self.process_manager = ProcessManager()

        # Ensure test directory exists
        self.test_dir.mkdir(parents=True, exist_ok=True)

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Track overall test health
        self.health_metrics = {
            'tests_started': 0,
            'tests_completed': 0,
            'tests_timed_out': 0,
            'tests_crashed': 0,
            'memory_leaks_detected': 0
        }

        # Configure test suites with enhanced timeouts and resource limits
        self.test_suites = [
            {
                "name": "Visual System Verification",
                "script": "verify_visual_system.py",
                "timeout": 45,  # Increased timeout
                "critical": True,
                "max_memory_mb": 500,
                "description": "Quick verification of visual components"
            },
            {
                "name": "Edge Cases",
                "script": "tests/comprehensive/test_edge_cases.py",
                "timeout": 90,  # Reduced timeout for faster feedback
                "critical": False,
                "max_memory_mb": 800,
                "description": "Edge cases and boundary conditions"
            },
            {
                "name": "Integration Tests",
                "script": "tests/comprehensive/test_integration.py",
                "timeout": 120,  # Reduced from 180
                "critical": True,
                "max_memory_mb": 1000,
                "description": "End-to-end system integration tests"
            },
            {
                "name": "Extreme Stress Tests",
                "script": "tests/comprehensive/test_extreme_stress.py",
                "timeout": 180,  # Reduced from 300
                "critical": False,
                "max_memory_mb": 1500,
                "description": "High-load stress testing scenarios"
            }
        ]

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n[INTERRUPT] Received signal {signum}, shutting down...")
        self._emergency_cleanup()
        sys.exit(128 + signum)
    
    def run_test_suite(self, suite_info):
        """Run a single test suite with enhanced monitoring and timeout handling"""
        name = suite_info["name"]
        script = suite_info["script"]
        timeout = suite_info["timeout"]
        critical = suite_info["critical"]
        max_memory_mb = suite_info.get("max_memory_mb", 1000)
        description = suite_info.get("description", "")

        self.health_metrics['tests_started'] += 1

        print(f"\n{'='*70}")
        print(f"RUNNING: {name}")
        print(f"Description: {description}")
        print(f"Script: {script}")
        print(f"Timeout: {timeout}s | Memory Limit: {max_memory_mb}MB | Critical: {critical}")
        print(f"{'='*70}")

        # Start performance monitoring
        self.performance_monitor.start_monitoring()

        # Pre-test cleanup
        self._pre_test_cleanup()

        try:
            # Run with process manager
            result_data = self.process_manager.run_with_timeout(
                [sys.executable, script],
                timeout=timeout,
                cwd=Path(__file__).parent
            )

            # Stop monitoring and get metrics
            self.performance_monitor.stop_monitoring()
            perf_metrics = self.performance_monitor.get_summary()

            # Build comprehensive result
            result = {
                "name": name,
                "script": script,
                "status": self._determine_status(result_data, perf_metrics, max_memory_mb),
                "exit_code": result_data['exit_code'],
                "duration": result_data['duration'],
                "timeout": timeout,
                "critical": critical,
                "stdout": result_data['stdout'],
                "stderr": result_data['stderr'],
                "timed_out": result_data['timed_out'],
                "performance": perf_metrics,
                "memory_limit_exceeded": perf_metrics.get('peak_memory_mb', 0) > max_memory_mb,
                "resource_usage": self._get_resource_usage()
            }

            # Parse detailed test output
            self._parse_test_output(result, result_data['stdout'])

            # Update health metrics
            if result['timed_out']:
                self.health_metrics['tests_timed_out'] += 1
            elif result['status'] == 'PASS':
                self.health_metrics['tests_completed'] += 1
            else:
                self.health_metrics['tests_crashed'] += 1

            # Check for memory leaks
            if result['memory_limit_exceeded']:
                self.health_metrics['memory_leaks_detected'] += 1

            # Display result
            self._display_test_result(result)

            return result

        except Exception as e:
            self.performance_monitor.stop_monitoring()
            self.health_metrics['tests_crashed'] += 1

            result = {
                "name": name,
                "script": script,
                "status": "CRASH",
                "exit_code": -3,
                "duration": 0.0,
                "timeout": timeout,
                "critical": critical,
                "stdout": "",
                "stderr": f"Test runner crashed: {str(e)}",
                "timed_out": False,
                "performance": {},
                "memory_limit_exceeded": False,
                "resource_usage": self._get_resource_usage()
            }

            print(f"\nRESULT: CRASH - {e}")
            traceback.print_exc()
            return result

        finally:
            # Post-test cleanup
            self._post_test_cleanup()

    def _determine_status(self, result_data, perf_metrics, max_memory_mb):
        """Determine final test status based on all factors"""
        if result_data['timed_out']:
            return "TIMEOUT"
        elif result_data['status'] == 'error':
            return "ERROR"
        elif result_data['exit_code'] != 0:
            return "FAIL"
        elif perf_metrics.get('peak_memory_mb', 0) > max_memory_mb:
            return "MEMORY_EXCEEDED"
        else:
            return "PASS"

    def _display_test_result(self, result):
        """Display comprehensive test result"""
        status = result['status']
        duration = result['duration']

        # Status with color coding
        status_display = {
            'PASS': f'✓ PASS',
            'FAIL': f'✗ FAIL',
            'TIMEOUT': f'⏰ TIMEOUT',
            'ERROR': f'[ERROR]',
            'CRASH': f'💀 CRASH',
            'MEMORY_EXCEEDED': f'🧠 MEMORY_EXCEEDED'
        }.get(status, f'❓ {status}')

        print(f"\nRESULT: {status_display} ({duration:.1f}s)")

        # Performance info
        perf = result.get('performance', {})
        if perf:
            print(f"Performance: Peak Memory: {perf.get('peak_memory_mb', 0):.1f}MB, Avg CPU: {perf.get('avg_cpu_percent', 0):.1f}%")

        # Detailed test results
        if 'total_tests' in result:
            print(f"Tests: {result.get('passed_tests', 0)}/{result.get('total_tests', 0)} passed")

        # Error details
        if status != 'PASS' and result.get('stderr'):
            stderr = result['stderr']
            print(f"Error: {stderr[:200]}{'...' if len(stderr) > 200 else ''}")

        # Memory leak warning
        if result.get('memory_limit_exceeded'):
            print(f"⚠️  Memory limit exceeded ({result.get('performance', {}).get('peak_memory_mb', 0):.1f}MB)")

    def _pre_test_cleanup(self):
        """Cleanup before test starts"""
        gc.collect()

        # Clean up any stray processes
        try:
            # Kill any existing Python processes running VoiceFlow tests
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] and 'python' in proc.info['name'].lower():
                        cmdline = ' '.join(proc.info['cmdline'] or [])
                        if ('test_' in cmdline and 'voiceflow' in cmdline.lower()) or \
                           ('comprehensive' in cmdline):
                            proc.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

    def _post_test_cleanup(self):
        """Cleanup after test completes"""
        gc.collect()
        time.sleep(0.5)  # Brief pause for cleanup

    def _get_resource_usage(self):
        """Get current resource usage"""
        try:
            process = psutil.Process()
            return {
                'memory_mb': process.memory_info().rss / 1024 / 1024,
                'cpu_percent': process.cpu_percent(),
                'open_files': len(process.open_files()),
                'threads': process.num_threads()
            }
        except Exception:
            return {'memory_mb': 0, 'cpu_percent': 0, 'open_files': 0, 'threads': 0}

    def _emergency_cleanup(self):
        """Emergency cleanup on shutdown"""
        print("[CLEANUP] Performing emergency cleanup...")
        try:
            self.performance_monitor.stop_monitoring()
            self.process_manager.cleanup_all()

            # Generate partial report
            if self.results:
                self._save_partial_report()

        except Exception as e:
            print(f"[CLEANUP] Error during cleanup: {e}")

    def _save_partial_report(self):
        """Save partial report during emergency shutdown"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = Path(__file__).parent / f"test_report_partial_{timestamp}.json"

            partial_report = {
                "timestamp": timestamp,
                "status": "INTERRUPTED",
                "completed_tests": len(self.results),
                "results": self.results,
                "health_metrics": self.health_metrics
            }

            with open(report_file, 'w') as f:
                json.dump(partial_report, f, indent=2)

            print(f"[CLEANUP] Partial report saved: {report_file}")
        except Exception as e:
            print(f"[CLEANUP] Failed to save partial report: {e}")
    
    def _parse_test_output(self, result, stdout):
        """Parse test output for detailed statistics"""
        lines = stdout.split('\n')
        
        # Look for common test result patterns
        for line in lines:
            if 'Total Tests:' in line:
                try:
                    result['total_tests'] = int(line.split(':')[1].strip())
                except:
                    pass
            elif 'Passed:' in line:
                try:
                    result['passed_tests'] = int(line.split(':')[1].strip())
                except:
                    pass
            elif 'Failed:' in line:
                try:
                    result['failed_tests'] = int(line.split(':')[1].strip())
                except:
                    pass
            elif 'Peak Memory:' in line:
                try:
                    result['peak_memory'] = float(line.split(':')[1].strip().replace('MB', ''))
                except:
                    pass
    
    def generate_report(self):
        """Generate comprehensive test report with performance metrics"""
        total_duration = (datetime.now() - self.start_time).total_seconds()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_delta = final_memory - self.start_memory

        print(f"\n{'='*80}")
        print("COMPREHENSIVE TEST REPORT WITH PERFORMANCE ANALYSIS")
        print(f"{'='*80}")
        print(f"Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Duration: {total_duration:.1f}s ({total_duration/60:.1f} minutes)")
        print(f"Memory Usage: {self.start_memory:.1f}MB → {final_memory:.1f}MB (Δ{memory_delta:+.1f}MB)")

        # Enhanced statistics
        total_suites = len(self.results)
        passed_suites = len([r for r in self.results.values() if r['status'] == 'PASS'])
        failed_suites = len([r for r in self.results.values() if r['status'] == 'FAIL'])
        timeout_suites = len([r for r in self.results.values() if r['status'] == 'TIMEOUT'])
        error_suites = len([r for r in self.results.values() if r['status'] == 'ERROR'])
        crash_suites = len([r for r in self.results.values() if r['status'] == 'CRASH'])
        memory_exceeded_suites = len([r for r in self.results.values() if r['status'] == 'MEMORY_EXCEEDED'])

        critical_failed = len([r for r in self.results.values()
                             if r['status'] not in ['PASS', 'MEMORY_EXCEEDED'] and r.get('critical', False)])

        print(f"\nSUITE SUMMARY:")
        print(f"  Total Suites: {total_suites}")
        print(f"  ✓ Passed: {passed_suites}")
        print(f"  ✗ Failed: {failed_suites}")
        print(f"  ⏰ Timeouts: {timeout_suites}")
        print(f"  [ERRORS] Errors: {error_suites}")
        print(f"  💀 Crashes: {crash_suites}")
        print(f"  🧠 Memory Exceeded: {memory_exceeded_suites}")
        print(f"  🔥 Critical Failures: {critical_failed}")

        # Performance summary
        if self.results:
            avg_duration = sum(r.get('duration', 0) for r in self.results.values()) / len(self.results)
            peak_memory = max(r.get('performance', {}).get('peak_memory_mb', 0) for r in self.results.values())

            print(f"\nPERFORMANCE SUMMARY:")
            print(f"  Average Test Duration: {avg_duration:.1f}s")
            print(f"  Peak Memory Usage: {peak_memory:.1f}MB")
            print(f"  Memory Growth: {memory_delta:+.1f}MB")

            # Health metrics
            print(f"\nHEALTH METRICS:")
            for metric, value in self.health_metrics.items():
                print(f"  {metric.replace('_', ' ').title()}: {value}")
        
        # Detailed results with performance metrics
        print(f"\nDETAILED RESULTS:")
        print(f"{'Status':<15} {'Suite':<30} {'Duration':<10} {'Peak MB':<10} {'Details'}")
        print("-" * 90)

        for result in self.results.values():
            status_icon = {
                'PASS': '✓ PASS',
                'FAIL': '✗ FAIL',
                'TIMEOUT': '⏰ TIMEOUT',
                'ERROR': '[ERROR]',
                'CRASH': '💀 CRASH',
                'MEMORY_EXCEEDED': '🧠 MEM_EXCEED'
            }.get(result['status'], result['status'])

            name = result['name'][:29]
            duration = f"{result.get('duration', 0):.1f}s"
            peak_memory = result.get('performance', {}).get('peak_memory_mb', 0)
            memory_str = f"{peak_memory:.1f}MB"

            # Enhanced details
            details = ""
            if 'total_tests' in result:
                passed = result.get('passed_tests', 0)
                total = result.get('total_tests', 0)
                details = f"{passed}/{total} tests passed"
            elif result.get('timed_out'):
                details = f"Timed out after {result.get('timeout', 0)}s"
            elif result['status'] != 'PASS' and result.get('stderr'):
                error_msg = result['stderr'].replace('\n', ' ')
                details = error_msg[:40] + "..." if len(error_msg) > 40 else error_msg

            print(f"{status_icon:<15} {name:<30} {duration:<10} {memory_str:<10} {details}")
        
        # Failure analysis
        failed_results = [r for r in self.results.values() if r['status'] != 'PASS']
        if failed_results:
            print(f"\nFAILURE ANALYSIS:")
            for result in failed_results:
                print(f"\n{result['name']} ({result['status']}):")
                if result['stderr']:
                    print(f"  Error: {result['stderr'][:200]}")
                if result['critical']:
                    print(f"  ⚠️  CRITICAL FAILURE")
        
        # Enhanced recommendations
        print(f"\nRECOMMENDATIONS:")
        if critical_failed > 0:
            print("  🔥 [CRITICAL] Fix critical test failures before deployment")
            print("     - System core functionality is compromised")
            print("     - Deployment is NOT recommended")
        elif crash_suites > 0:
            print("  💀 [HIGH] Address test crashes - indicates system instability")
        elif timeout_suites > total_suites // 2:
            print("  ⏰ [HIGH] Many tests timing out - performance issues detected")
            print("     - Consider increasing timeouts or optimizing performance")
        elif memory_exceeded_suites > 0:
            print("  🧠 [MEDIUM] Memory usage exceeded limits in some tests")
            print("     - Review memory optimization opportunities")
        elif failed_suites > 0 or error_suites > 0:
            print("  ⚠️  [MEDIUM] Some tests failed - review and address before deployment")
        else:
            print("  ✅ [SUCCESS] ALL TESTS PASSED: System ready for deployment")
            print("     - No critical issues detected")
            print("     - Performance within acceptable limits")

        # Performance recommendations
        if memory_delta > 100:
            print(f"  🧠 [MEMORY] Significant memory growth detected (+{memory_delta:.1f}MB)")
            print("     - Investigate potential memory leaks")

        slow_tests = [r for r in self.results.values() if r.get('duration', 0) > r.get('timeout', 0) * 0.8]
        if slow_tests:
            print(f"  🐌 [PERFORMANCE] {len(slow_tests)} tests approaching timeout limits")
            print("     - Consider optimizing slow operations")

        # Health-based recommendations
        completion_rate = (self.health_metrics['tests_completed'] /
                         max(self.health_metrics['tests_started'], 1)) * 100
        if completion_rate < 80:
            print(f"  ⚠️  [STABILITY] Low test completion rate ({completion_rate:.1f}%)")
            print("     - System may be unstable or tests may need timeout adjustment")
        
        return {
            "timestamp": self.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_duration": total_duration,
            "memory_delta": memory_delta,
            "suite_summary": {
                "total": total_suites,
                "passed": passed_suites,
                "failed": failed_suites,
                "timeouts": timeout_suites,
                "errors": error_suites,
                "crashes": crash_suites,
                "memory_exceeded": memory_exceeded_suites,
                "critical_failures": critical_failed,
                "completion_rate": (self.health_metrics['tests_completed'] /
                                   max(self.health_metrics['tests_started'], 1)) * 100
            },
            "performance_summary": {
                "avg_test_duration": sum(r.get('duration', 0) for r in self.results.values()) / max(len(self.results), 1),
                "peak_memory_mb": max((r.get('performance', {}).get('peak_memory_mb', 0) for r in self.results.values()), default=0),
                "memory_growth_mb": memory_delta
            },
            "health_metrics": self.health_metrics,
            "results": self.results,
            "status": self._determine_final_status(critical_failed, timeout_suites, crash_suites, total_suites)
        }

    def _determine_final_status(self, critical_failed, timeout_suites, crash_suites, total_suites):
        """Determine final status based on comprehensive analysis"""
        if critical_failed > 0:
            return "CRITICAL_FAILURE"
        elif crash_suites > 0:
            return "SYSTEM_INSTABILITY"
        elif timeout_suites > total_suites // 2:  # More than half timed out
            return "TIMEOUT_ISSUES"
        elif timeout_suites > 0 or any(r.get('status') in ['FAIL', 'ERROR'] for r in self.results.values()):
            return "PARTIAL_FAILURE"
        else:
            return "PASS"
    
    def save_report(self, report):
        """Save comprehensive test report to multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"test_report_{timestamp}"

        saved_files = []

        # Save JSON report
        try:
            json_file = Path(__file__).parent / f"{base_name}.json"
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2)
            saved_files.append(json_file)
        except Exception as e:
            print(f"\n[ERROR] Failed to save JSON report: {e}")

        # Save summary text report
        try:
            txt_file = Path(__file__).parent / f"{base_name}_summary.txt"
            with open(txt_file, 'w') as f:
                f.write(f"VoiceFlow Test Report Summary\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {report['total_duration']:.1f}s\n")
                f.write(f"Status: {report['status']}\n\n")

                summary = report['suite_summary']
                f.write(f"Results: {summary['passed']}/{summary['total']} passed\n")
                f.write(f"Failures: {summary['failed']} failed, {summary['timeouts']} timeouts\n")
                f.write(f"Critical: {summary['critical_failures']} critical failures\n")
                f.write(f"Performance: {report['performance_summary']['peak_memory_mb']:.1f}MB peak memory\n")
            saved_files.append(txt_file)
        except Exception as e:
            print(f"\n[ERROR] Failed to save text report: {e}")

        if saved_files:
            print(f"\n📊 [REPORTS] Test reports saved:")
            for file in saved_files:
                file_size = file.stat().st_size if file.exists() else 0
                print(f"   📄 {file.name} ({file_size} bytes)")
            return saved_files[0]  # Return primary JSON file
        else:
            print(f"\n[ERROR] Failed to save any reports")
            return None
    
    def run_all_tests(self):
        """Run all test suites with comprehensive monitoring"""
        print("[STARTING] Comprehensive VoiceFlow Test Suite")
        print(f"Timestamp: {self.start_time}")
        print(f"Python: {sys.version}")
        print(f"Working Directory: {Path.cwd()}")
        print(f"Process ID: {os.getpid()}")
        print(f"Initial Memory: {self.start_memory:.1f}MB")

        try:
            # Validate test files exist
            missing_tests, available_tests = self._validate_test_files()

            if missing_tests:
                print(f"\n[WARNING] Missing test files ({len(missing_tests)}):")
                for missing in missing_tests[:5]:  # Show first 5
                    print(f"   [MISSING] {missing}")
                if len(missing_tests) > 5:
                    print(f"   ... and {len(missing_tests) - 5} more")

            if not available_tests:
                print("\n[ERROR] No test files available to run!")
                return False

            print(f"\n[INFO] Running {len(available_tests)} available test suites")

            # Run each available test suite
            for i, suite_info in enumerate(available_tests):
                print(f"\n[PROGRESS] Test {i+1}/{len(available_tests)}")

                try:
                    result = self.run_test_suite(suite_info)
                    self.results[suite_info['name']] = result

                    # Early termination on critical failures
                    if result['critical'] and result['status'] not in ['PASS', 'MEMORY_EXCEEDED']:
                        print(f"\n[CRITICAL] Critical test failed: {suite_info['name']}")
                        print("[INFO] Stopping test execution due to critical failure")
                        break

                except KeyboardInterrupt:
                    print(f"\n[INTERRUPTED] Test suite interrupted by user")
                    break
                except Exception as e:
                    print(f"\n[ERROR] Test suite runner error: {e}")
                    traceback.print_exc()

                # Health check between tests
                self._inter_test_health_check()

                # Brief pause for resource cleanup
                time.sleep(1.0)

            # Generate and save comprehensive report
            report = self.generate_report()
            report_file = self.save_report(report)

            # Final health summary
            self._print_health_summary()

            return self._determine_overall_success(report)

        except KeyboardInterrupt:
            print(f"\n[INTERRUPTED] Test suite interrupted")
            self._emergency_cleanup()
            return False
        except Exception as e:
            print(f"\n[CRASHED] Test suite crashed: {e}")
            traceback.print_exc()
            self._emergency_cleanup()
            return False
        finally:
            # Always cleanup
            self.process_manager.cleanup_all()
            self.performance_monitor.stop_monitoring()

    def _validate_test_files(self):
        """Validate which test files exist and are accessible"""
        missing_tests = []
        available_tests = []

        for suite in self.test_suites:
            test_path = Path(suite['script'])
            if test_path.exists() and test_path.is_file():
                available_tests.append(suite)
            else:
                missing_tests.append(suite['script'])

        return missing_tests, available_tests

    def _inter_test_health_check(self):
        """Health check between tests"""
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_growth = current_memory - self.start_memory

        if memory_growth > 500:  # More than 500MB growth
            print(f"\n[WARNING] Significant memory growth detected: {memory_growth:.1f}MB")
            print("[INFO] Forcing garbage collection")
            gc.collect()

        # Check for zombie processes
        try:
            zombie_count = 0
            for proc in psutil.process_iter(['pid', 'status']):
                if proc.info['status'] == psutil.STATUS_ZOMBIE:
                    zombie_count += 1

            if zombie_count > 5:
                print(f"[WARNING] {zombie_count} zombie processes detected")
        except Exception:
            pass

    def _determine_overall_success(self, report):
        """Determine overall test suite success"""
        if report['status'] == 'CRITICAL_FAILURE':
            return False
        elif report['suite_summary']['critical_failures'] > 0:
            return False
        elif report['suite_summary']['timeouts'] > len(self.test_suites) // 2:  # More than half timed out
            return False
        else:
            return True

    def _print_health_summary(self):
        """Print overall health summary"""
        print(f"\n[HEALTH] Test Execution Summary:")
        print(f"   Tests Started: {self.health_metrics['tests_started']}")
        print(f"   Tests Completed: {self.health_metrics['tests_completed']}")
        print(f"   Tests Timed Out: {self.health_metrics['tests_timed_out']}")
        print(f"   Tests Crashed: {self.health_metrics['tests_crashed']}")
        print(f"   Memory Leaks Detected: {self.health_metrics['memory_leaks_detected']}")

        completion_rate = (self.health_metrics['tests_completed'] /
                         max(self.health_metrics['tests_started'], 1)) * 100
        print(f"   Completion Rate: {completion_rate:.1f}%")

def main():
    """Main entry point with comprehensive error handling"""
    runner = None

    try:
        print("[INIT] Initializing VoiceFlow Comprehensive Test Suite")
        runner = ComprehensiveTestRunner()

        print("[START] Starting test execution")
        success = runner.run_all_tests()

        if success:
            print("\n[SUCCESS] ALL COMPREHENSIVE TESTS PASSED")
            print("[INFO] VoiceFlow system is stable and ready for deployment")
            sys.exit(0)
        else:
            print("\n[FAILURE] SOME TESTS FAILED OR TIMED OUT")
            print("[INFO] Check the detailed report above for specific issues")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n⚠️  [INTERRUPTED] Test run interrupted by user (Ctrl+C)")
        if runner:
            runner._emergency_cleanup()
        sys.exit(130)

    except Exception as e:
        print(f"\n[CRASHED] Test runner crashed with unexpected error: {e}")
        traceback.print_exc()

        if runner:
            try:
                runner._emergency_cleanup()
            except:
                pass

        print("\n[INFO] This indicates a serious issue with the test framework itself")
        print("[INFO] Please check the error details above and report this issue")
        sys.exit(2)

    finally:
        # Final cleanup attempt
        try:
            if runner:
                runner.process_manager.cleanup_all()
        except:
            pass

if __name__ == "__main__":
    # Set up proper signal handling for Windows
    if sys.platform == 'win32':
        import signal

        def windows_signal_handler(signal_num, frame):
            print(f"\n[SIGNAL] Received Windows signal {signal_num}")
            sys.exit(128 + signal_num)

        signal.signal(signal.SIGBREAK, windows_signal_handler)
        signal.signal(signal.SIGTERM, windows_signal_handler)

    main()