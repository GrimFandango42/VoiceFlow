#!/usr/bin/env python3
"""
VoiceFlow Parallel Test Runner
==============================
High-performance parallel test execution with intelligent categorization
"""

import sys
import time
import os
import subprocess
import json
import threading
import psutil
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class TestPriority(Enum):
    """Test priority levels for intelligent execution"""
    CRITICAL = "critical"      # Must pass - blocks development
    STANDARD = "standard"      # Should pass - important but not blocking
    OPTIONAL = "optional"      # Nice to have - performance/stress tests

@dataclass
class TestDefinition:
    """Definition of a test suite with metadata"""
    name: str
    script: str
    timeout: int
    priority: TestPriority
    can_run_parallel: bool = True
    dependencies: List[str] = None
    estimated_duration: int = 30
    description: str = ""

class ParallelTestRunner:
    """Advanced parallel test execution with intelligent scheduling"""

    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self.results: Dict[str, Dict] = {}
        self.start_time = time.perf_counter()
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024

        # Test suite definitions
        self.test_suites = self._define_test_suites()

        # Runtime tracking
        self.running_tests: Dict[str, Future] = {}
        self.completed_tests: List[str] = []
        self.failed_tests: List[str] = []
        self.lock = threading.Lock()

    def _define_test_suites(self) -> List[TestDefinition]:
        """Define all available test suites with intelligent categorization"""
        return [
            # CRITICAL: Must pass for development to continue
            TestDefinition(
                name="Smoke Test",
                script="quick_smoke_test.py",
                timeout=20,
                priority=TestPriority.CRITICAL,
                can_run_parallel=True,
                estimated_duration=5,
                description="Ultra-fast validation of core functionality"
            ),
            TestDefinition(
                name="Visual System",
                script="verify_visual_system.py",
                timeout=30,
                priority=TestPriority.CRITICAL,
                can_run_parallel=True,
                estimated_duration=10,
                description="Visual indicators and tray system verification"
            ),
            TestDefinition(
                name="Audio Validation",
                script="tests/comprehensive/test_edge_cases.py",
                timeout=60,
                priority=TestPriority.STANDARD,
                can_run_parallel=True,
                estimated_duration=45,
                description="Edge cases and audio input validation"
            ),
            TestDefinition(
                name="Integration Tests",
                script="tests/comprehensive/test_integration.py",
                timeout=90,
                priority=TestPriority.STANDARD,
                can_run_parallel=False,  # May conflict with other tests
                estimated_duration=60,
                description="Component integration validation"
            ),
            # OPTIONAL: Performance and stress tests
            TestDefinition(
                name="Stress Tests",
                script="tests/comprehensive/test_extreme_stress.py",
                timeout=180,
                priority=TestPriority.OPTIONAL,
                can_run_parallel=False,  # Resource intensive
                estimated_duration=120,
                description="System stress and endurance testing"
            ),
            TestDefinition(
                name="Performance Tests",
                script="tests/test_comprehensive_performance.py",
                timeout=120,
                priority=TestPriority.OPTIONAL,
                can_run_parallel=True,
                estimated_duration=90,
                description="Performance benchmarking and regression detection"
            ),
            TestDefinition(
                name="Memory Profiling",
                script="tests/test_memory_profiling.py",
                timeout=90,
                priority=TestPriority.OPTIONAL,
                can_run_parallel=False,  # Memory intensive
                estimated_duration=60,
                description="Memory usage analysis and leak detection"
            )
        ]

    def run_single_test(self, test_def: TestDefinition) -> Dict[str, Any]:
        """Execute a single test suite and return results"""
        start_time = time.perf_counter()

        print(f"[STARTING] {test_def.name}")

        # Check if test script exists
        if not Path(test_def.script).exists():
            return {
                'name': test_def.name,
                'status': 'SKIPPED',
                'duration': 0.0,
                'exit_code': -1,
                'stdout': '',
                'stderr': f'Test script not found: {test_def.script}',
                'priority': test_def.priority.value
            }

        try:
            # Execute test with timeout
            process = subprocess.Popen(
                [sys.executable, test_def.script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=Path(__file__).parent
            )

            try:
                stdout, stderr = process.communicate(timeout=test_def.timeout)
                exit_code = process.returncode

            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                exit_code = -999  # Timeout indicator
                stderr += f"\nTEST TIMED OUT after {test_def.timeout}s"

        except Exception as e:
            stdout, stderr = "", str(e)
            exit_code = -2

        duration = time.perf_counter() - start_time

        # Determine status
        if exit_code == 0:
            status = 'PASS'
        elif exit_code == -999:
            status = 'TIMEOUT'
        else:
            status = 'FAIL'

        result = {
            'name': test_def.name,
            'status': status,
            'duration': duration,
            'exit_code': exit_code,
            'stdout': stdout,
            'stderr': stderr,
            'priority': test_def.priority.value,
            'timeout': test_def.timeout,
            'estimated': test_def.estimated_duration,
            'description': test_def.description
        }

        print(f"[{status}] {test_def.name} ({duration:.1f}s)")

        return result

    def run_parallel_batch(self, test_batch: List[TestDefinition]) -> List[Dict[str, Any]]:
        """Run a batch of tests in parallel"""
        if not test_batch:
            return []

        print(f"\n{'='*60}")
        print(f"PARALLEL BATCH: {len(test_batch)} tests")
        print(f"{'='*60}")

        results = []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(test_batch))) as executor:
            # Submit all tests
            future_to_test = {
                executor.submit(self.run_single_test, test_def): test_def
                for test_def in test_batch
            }

            # Collect results as they complete
            for future in as_completed(future_to_test):
                result = future.result()
                results.append(result)

                with self.lock:
                    self.results[result['name']] = result
                    self.completed_tests.append(result['name'])
                    if result['status'] in ['FAIL', 'TIMEOUT']:
                        self.failed_tests.append(result['name'])

        return results

    def run_sequential_batch(self, test_batch: List[TestDefinition]) -> List[Dict[str, Any]]:
        """Run a batch of tests sequentially (for non-parallel tests)"""
        if not test_batch:
            return []

        print(f"\n{'='*60}")
        print(f"SEQUENTIAL BATCH: {len(test_batch)} tests")
        print(f"{'='*60}")

        results = []
        for test_def in test_batch:
            result = self.run_single_test(test_def)
            results.append(result)

            with self.lock:
                self.results[result['name']] = result
                self.completed_tests.append(result['name'])
                if result['status'] in ['FAIL', 'TIMEOUT']:
                    self.failed_tests.append(result['name'])

        return results

    def run_all_tests(self, priorities: List[TestPriority] = None,
                     stop_on_critical_failure: bool = True) -> Dict[str, Any]:
        """
        Run tests with intelligent parallel/sequential execution

        Args:
            priorities: Which priority levels to run (default: all)
            stop_on_critical_failure: Stop execution if critical test fails
        """
        if priorities is None:
            priorities = [TestPriority.CRITICAL, TestPriority.STANDARD, TestPriority.OPTIONAL]

        print("=" * 80)
        print("VoiceFlow Parallel Test Runner")
        print("=" * 80)
        print(f"Max Workers: {self.max_workers}")
        print(f"Priorities: {[p.value for p in priorities]}")
        print(f"Stop on Critical Failure: {stop_on_critical_failure}")
        print(f"Started: {datetime.now().strftime('%H:%M:%S')}")
        print()

        # Filter tests by priority
        selected_tests = [
            test for test in self.test_suites
            if test.priority in priorities
        ]

        print(f"Selected {len(selected_tests)} tests:")
        for test in selected_tests:
            parallel_status = "parallel" if test.can_run_parallel else "sequential"
            print(f"  - {test.name:<25} ({test.priority.value}, {parallel_status}, ~{test.estimated_duration}s)")
        print()

        # Separate parallel and sequential tests by priority
        for priority in priorities:
            priority_tests = [t for t in selected_tests if t.priority == priority]
            if not priority_tests:
                continue

            parallel_tests = [t for t in priority_tests if t.can_run_parallel]
            sequential_tests = [t for t in priority_tests if not t.can_run_parallel]

            print(f"\n[RUNNING] {priority.value.upper()} TESTS")

            # Run parallel tests first (faster)
            if parallel_tests:
                parallel_results = self.run_parallel_batch(parallel_tests)

                # Check for critical failures
                if priority == TestPriority.CRITICAL and stop_on_critical_failure:
                    critical_failures = [r for r in parallel_results if r['status'] in ['FAIL', 'TIMEOUT']]
                    if critical_failures:
                        print(f"\n[CRITICAL FAILURE] {len(critical_failures)} tests failed")
                        print("Stopping execution due to critical failures.")
                        break

            # Run sequential tests
            if sequential_tests:
                sequential_results = self.run_sequential_batch(sequential_tests)

                # Check for critical failures
                if priority == TestPriority.CRITICAL and stop_on_critical_failure:
                    critical_failures = [r for r in sequential_results if r['status'] in ['FAIL', 'TIMEOUT']]
                    if critical_failures:
                        print(f"\n[CRITICAL FAILURE] {len(critical_failures)} tests failed")
                        print("Stopping execution due to critical failures.")
                        break

        # Generate comprehensive report
        return self._generate_report()

    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test execution report"""
        total_duration = time.perf_counter() - self.start_time
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_delta = current_memory - self.start_memory

        # Calculate statistics
        total_tests = len(self.results)
        passed_tests = len([r for r in self.results.values() if r['status'] == 'PASS'])
        failed_tests = len([r for r in self.results.values() if r['status'] == 'FAIL'])
        timeout_tests = len([r for r in self.results.values() if r['status'] == 'TIMEOUT'])
        skipped_tests = len([r for r in self.results.values() if r['status'] == 'SKIPPED'])

        # Priority breakdown
        priority_stats = {}
        for priority in TestPriority:
            priority_results = [r for r in self.results.values() if r['priority'] == priority.value]
            if priority_results:
                priority_stats[priority.value] = {
                    'total': len(priority_results),
                    'passed': len([r for r in priority_results if r['status'] == 'PASS']),
                    'failed': len([r for r in priority_results if r['status'] in ['FAIL', 'TIMEOUT']])
                }

        # Performance metrics
        fastest_test = min(self.results.values(), key=lambda r: r['duration'], default={'name': 'N/A', 'duration': 0})
        slowest_test = max(self.results.values(), key=lambda r: r['duration'], default={'name': 'N/A', 'duration': 0})

        report = {
            'summary': {
                'total_duration': total_duration,
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'timeout': timeout_tests,
                'skipped': skipped_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            'memory': {
                'start_mb': self.start_memory,
                'end_mb': current_memory,
                'delta_mb': memory_delta
            },
            'performance': {
                'fastest_test': fastest_test['name'],
                'fastest_duration': fastest_test['duration'],
                'slowest_test': slowest_test['name'],
                'slowest_duration': slowest_test['duration'],
                'average_duration': sum(r['duration'] for r in self.results.values()) / len(self.results) if self.results else 0
            },
            'by_priority': priority_stats,
            'detailed_results': dict(self.results)
        }

        # Print report
        self._print_report(report)

        return report

    def _print_report(self, report: Dict[str, Any]):
        """Print formatted test execution report"""
        summary = report['summary']

        print("\n" + "=" * 80)
        print("PARALLEL TEST EXECUTION REPORT")
        print("=" * 80)

        print(f"Duration: {summary['total_duration']:.1f}s")
        print(f"Results: {summary['passed']}/{summary['total_tests']} tests passed ({summary['success_rate']:.1f}%)")

        if summary['failed'] > 0:
            print(f"Failed: {summary['failed']} tests")
        if summary['timeout'] > 0:
            print(f"Timeouts: {summary['timeout']} tests")
        if summary['skipped'] > 0:
            print(f"Skipped: {summary['skipped']} tests")

        print(f"\nMemory Usage: {report['memory']['start_mb']:.1f}MB -> {report['memory']['end_mb']:.1f}MB (+{report['memory']['delta_mb']:.1f}MB)")

        # Priority breakdown
        print(f"\nBy Priority:")
        for priority, stats in report['by_priority'].items():
            status = "[OK]" if stats['failed'] == 0 else "[FAIL]"
            print(f"  {status} {priority.upper():<10}: {stats['passed']}/{stats['total']} passed")

        # Performance summary
        perf = report['performance']
        print(f"\nPerformance:")
        print(f"  Fastest: {perf['fastest_test']} ({perf['fastest_duration']:.1f}s)")
        print(f"  Slowest: {perf['slowest_test']} ({perf['slowest_duration']:.1f}s)")
        print(f"  Average: {perf['average_duration']:.1f}s per test")

        # Detailed results
        print(f"\nDetailed Results:")
        for name, result in report['detailed_results'].items():
            status_icon = {"PASS": "[PASS]", "FAIL": "[FAIL]", "TIMEOUT": "[TIMEOUT]", "SKIPPED": "[SKIP]"}.get(result['status'], "[?]")
            print(f"  {status_icon} {name:<25} ({result['duration']:.1f}s) [{result['priority']}]")

        # Overall status
        print(f"\n" + "=" * 80)
        if summary['failed'] == 0 and summary['timeout'] == 0:
            print("[SUCCESS] ALL TESTS PASSED! System ready for development.")
        else:
            critical_failed = any(
                r['status'] in ['FAIL', 'TIMEOUT'] and r['priority'] == 'critical'
                for r in report['detailed_results'].values()
            )
            if critical_failed:
                print("[CRITICAL] CRITICAL TESTS FAILED - System needs immediate attention")
            else:
                print("[WARNING] Some tests failed but system is functional")

        print("=" * 80)

def main():
    """Entry point for parallel test runner"""
    import argparse

    parser = argparse.ArgumentParser(description="VoiceFlow Parallel Test Runner")
    parser.add_argument("--workers", "-w", type=int, default=3, help="Max parallel workers")
    parser.add_argument("--priority", "-p", choices=['critical', 'standard', 'optional'],
                       action='append', help="Test priorities to run")
    parser.add_argument("--no-stop-on-failure", action='store_true',
                       help="Continue even if critical tests fail")
    parser.add_argument("--report", "-r", help="Save detailed report to JSON file")

    args = parser.parse_args()

    # Parse priorities
    if args.priority:
        priorities = [TestPriority(p) for p in args.priority]
    else:
        priorities = [TestPriority.CRITICAL, TestPriority.STANDARD, TestPriority.OPTIONAL]

    # Run tests
    runner = ParallelTestRunner(max_workers=args.workers)
    report = runner.run_all_tests(
        priorities=priorities,
        stop_on_critical_failure=not args.no_stop_on_failure
    )

    # Save report if requested
    if args.report:
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nDetailed report saved to: {args.report}")

    # Exit with appropriate code
    success = report['summary']['failed'] == 0 and report['summary']['timeout'] == 0
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()