#!/usr/bin/env python3
"""
VoiceFlow Test Runner - Clean Version
====================================
Simplified test runner without Unicode characters for Windows compatibility
"""

import sys
import time
import os
import subprocess
import json
import traceback
from pathlib import Path
from datetime import datetime
import psutil

class SimpleTestRunner:
    """Simple test runner for VoiceFlow test suites"""

    def __init__(self):
        self.results = {}
        self.start_time = datetime.now()
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024

        self.test_suites = [
            {
                "name": "Visual System Verification",
                "script": "verify_visual_system.py",
                "timeout": 45,
                "critical": True
            },
            {
                "name": "Edge Cases",
                "script": "tests/comprehensive/test_edge_cases.py",
                "timeout": 90,
                "critical": False
            },
            {
                "name": "Integration Tests",
                "script": "tests/comprehensive/test_integration.py",
                "timeout": 120,
                "critical": True
            }
        ]

    def run_test_suite(self, suite_info):
        """Run a single test suite with timeout"""
        name = suite_info["name"]
        script = suite_info["script"]
        timeout = suite_info["timeout"]
        critical = suite_info["critical"]

        print(f"\\n{'='*60}")
        print(f"RUNNING: {name}")
        print(f"Script: {script}")
        print(f"Timeout: {timeout}s | Critical: {critical}")
        print(f"{'='*60}")

        start_time = time.perf_counter()

        try:
            # Check if script exists
            if not Path(script).exists():
                print(f"[SKIP] Script not found: {script}")
                return {
                    "name": name,
                    "status": "SKIP",
                    "duration": 0,
                    "error": "Script not found"
                }

            # Run the test script with timeout
            process = subprocess.Popen(
                [sys.executable, script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=Path(__file__).parent
            )

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                duration = time.perf_counter() - start_time

                status = "PASS" if process.returncode == 0 else "FAIL"
                print(f"RESULT: {status} ({duration:.1f}s)")

                if status == "FAIL":
                    print(f"Exit code: {process.returncode}")
                    if stderr:
                        print("STDERR:")
                        print(stderr[:500] + "..." if len(stderr) > 500 else stderr)

                return {
                    "name": name,
                    "status": status,
                    "duration": duration,
                    "exit_code": process.returncode,
                    "stdout": stdout,
                    "stderr": stderr
                }

            except subprocess.TimeoutExpired:
                duration = time.perf_counter() - start_time

                # Force kill process
                try:
                    process.kill()
                    process.wait(timeout=5)
                except:
                    pass

                print(f"RESULT: TIMEOUT ({duration:.1f}s)")

                return {
                    "name": name,
                    "status": "TIMEOUT",
                    "duration": duration,
                    "exit_code": -1,
                    "error": f"Test timed out after {timeout}s"
                }

        except Exception as e:
            duration = time.perf_counter() - start_time
            print(f"RESULT: ERROR ({duration:.1f}s) - {e}")

            return {
                "name": name,
                "status": "ERROR",
                "duration": duration,
                "exit_code": -2,
                "error": str(e)
            }

    def run_all_tests(self):
        """Run all test suites"""
        print("[STARTING] VoiceFlow Test Suite - Clean Version")
        print(f"Timestamp: {self.start_time}")
        print(f"Python: {sys.version}")
        print(f"Working Directory: {Path.cwd()}")
        print(f"Initial Memory: {self.start_memory:.1f}MB")

        # Run tests
        for suite_info in self.test_suites:
            result = self.run_test_suite(suite_info)
            self.results[suite_info['name']] = result
            time.sleep(1.0)  # Brief pause

        # Generate report
        self.generate_report()

        # Determine success
        critical_failures = sum(1 for r in self.results.values()
                              if r.get('status') not in ['PASS', 'SKIP'] and
                              any(s['critical'] for s in self.test_suites if s['name'] == r['name']))

        return critical_failures == 0

    def generate_report(self):
        """Generate test report"""
        total_duration = (datetime.now() - self.start_time).total_seconds()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024

        print(f"\\n{'='*60}")
        print("TEST REPORT")
        print(f"{'='*60}")
        print(f"Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Duration: {total_duration:.1f}s")
        print(f"Memory Usage: {self.start_memory:.1f}MB -> {final_memory:.1f}MB (Delta: {final_memory-self.start_memory:+.1f}MB)")

        # Statistics
        total_tests = len(self.results)
        passed = sum(1 for r in self.results.values() if r.get('status') == 'PASS')
        failed = sum(1 for r in self.results.values() if r.get('status') == 'FAIL')
        timeouts = sum(1 for r in self.results.values() if r.get('status') == 'TIMEOUT')
        errors = sum(1 for r in self.results.values() if r.get('status') == 'ERROR')
        skipped = sum(1 for r in self.results.values() if r.get('status') == 'SKIP')

        print(f"\\nSUMMARY:")
        print(f"  Total: {total_tests}")
        print(f"  Passed: {passed}")
        print(f"  Failed: {failed}")
        print(f"  Timeouts: {timeouts}")
        print(f"  Errors: {errors}")
        print(f"  Skipped: {skipped}")

        # Detailed results
        print(f"\\nDETAILS:")
        for result in self.results.values():
            status = result.get('status', 'UNKNOWN')
            name = result.get('name', 'Unknown')[:30]
            duration = result.get('duration', 0)
            error = result.get('error', '')

            details = f"({duration:.1f}s)"
            if error:
                details += f" - {error[:30]}..."

            print(f"  {status:<8} {name:<30} {details}")

        # Recommendations
        print(f"\\nRECOMMENDATIONS:")
        if failed > 0 or errors > 0:
            print("  [ACTION] Review and fix failed tests")
        if timeouts > 0:
            print("  [ACTION] Investigate timeout issues")
        if passed == total_tests - skipped:
            print("  [OK] All available tests passed")

def main():
    """Main entry point"""
    try:
        runner = SimpleTestRunner()
        success = runner.run_all_tests()

        if success:
            print("\\n[SUCCESS] Test execution completed successfully")
            sys.exit(0)
        else:
            print("\\n[FAILURE] Some tests failed")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\\n[INTERRUPTED] Test run interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\\n[CRASHED] Test runner crashed: {e}")
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()