#!/usr/bin/env python3
"""
VoiceFlow Stability Test Runner

Orchestrates comprehensive stability testing scenarios including:
- Quick health checks
- Extended duration tests
- Stress testing
- Edge case validation
- Memory leak detection
"""

import argparse
import sys
import time
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import psutil
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/stability_test.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class StabilityTestRunner:
    """Orchestrates comprehensive stability testing scenarios."""

    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.results_dir = self.project_root / "stability_test_results"
        self.results_dir.mkdir(exist_ok=True)

    def run_quick_check(self) -> Dict[str, Any]:
        """Run quick stability health check (15 minutes)."""
        logger.info("Starting quick stability health check")
        start_time = time.time()

        results = {
            "test_type": "quick_check",
            "start_time": start_time,
            "tests": {}
        }

        # Component import test
        try:
            logger.info("Testing component imports")
            import_result = subprocess.run([
                sys.executable, "-c",
                "import src.voiceflow.stability; print('SUCCESS: All imports working')"
            ], capture_output=True, text=True, cwd=self.project_root)

            results["tests"]["component_imports"] = {
                "success": import_result.returncode == 0,
                "output": import_result.stdout,
                "error": import_result.stderr
            }
        except Exception as e:
            results["tests"]["component_imports"] = {
                "success": False,
                "error": str(e)
            }

        # Contract test validation
        logger.info("Running contract tests")
        contract_result = subprocess.run([
            sys.executable, "-m", "pytest",
            "tests/stability/contracts/", "-v", "--tb=short"
        ], capture_output=True, text=True, cwd=self.project_root)

        results["tests"]["contract_validation"] = {
            "success": contract_result.returncode == 0,
            "output": contract_result.stdout,
            "error": contract_result.stderr
        }

        # Basic integration tests
        logger.info("Running basic integration tests")
        integration_result = subprocess.run([
            sys.executable, "-m", "pytest",
            "tests/integration/", "-v", "--tb=short", "-m", "not long_running"
        ], capture_output=True, text=True, cwd=self.project_root)

        results["tests"]["basic_integration"] = {
            "success": integration_result.returncode == 0,
            "output": integration_result.stdout,
            "error": integration_result.stderr
        }

        # Memory baseline establishment
        logger.info("Establishing memory baseline")
        process = psutil.Process()
        memory_info = process.memory_info()

        results["tests"]["memory_baseline"] = {
            "success": True,
            "memory_mb": memory_info.rss / 1024 / 1024,
            "virtual_memory_mb": memory_info.vms / 1024 / 1024
        }

        results["duration"] = time.time() - start_time
        results["overall_success"] = all(
            test.get("success", False)
            for test in results["tests"].values()
        )

        logger.info(f"Quick check completed in {results['duration']:.1f}s")
        return results

    def run_duration_test(self, duration_hours: int) -> Dict[str, Any]:
        """Run extended duration stability test."""
        logger.info(f"Starting {duration_hours}h duration test")
        start_time = time.time()

        results = {
            "test_type": "duration_test",
            "duration_hours": duration_hours,
            "start_time": start_time,
            "tests": {}
        }

        # Run long-running integration tests
        duration_result = subprocess.run([
            sys.executable, "-m", "pytest",
            "tests/stability/long_running/", "-v", "--tb=short",
            f"--timeout={duration_hours * 3600 + 300}"  # Add 5min buffer
        ], capture_output=True, text=True, cwd=self.project_root)

        results["tests"]["long_running_stability"] = {
            "success": duration_result.returncode == 0,
            "output": duration_result.stdout,
            "error": duration_result.stderr
        }

        results["duration"] = time.time() - start_time
        results["overall_success"] = all(
            test.get("success", False)
            for test in results["tests"].values()
        )

        logger.info(f"Duration test completed in {results['duration']:.1f}s")
        return results

    def run_stress_test(self, rate_per_minute: int, duration_minutes: int) -> Dict[str, Any]:
        """Run high-frequency stress test."""
        logger.info(f"Starting stress test: {rate_per_minute}/min for {duration_minutes}min")
        start_time = time.time()

        results = {
            "test_type": "stress_test",
            "rate_per_minute": rate_per_minute,
            "duration_minutes": duration_minutes,
            "start_time": start_time,
            "tests": {}
        }

        # Run stress tests
        stress_result = subprocess.run([
            sys.executable, "-m", "pytest",
            "tests/stability/stress/", "-v", "--tb=short",
            f"--timeout={duration_minutes * 60 + 300}"  # Add 5min buffer
        ], capture_output=True, text=True, cwd=self.project_root)

        results["tests"]["stress_validation"] = {
            "success": stress_result.returncode == 0,
            "output": stress_result.stdout,
            "error": stress_result.stderr
        }

        results["duration"] = time.time() - start_time
        results["overall_success"] = all(
            test.get("success", False)
            for test in results["tests"].values()
        )

        logger.info(f"Stress test completed in {results['duration']:.1f}s")
        return results

    def run_comprehensive_suite(self) -> Dict[str, Any]:
        """Run comprehensive test suite covering all scenarios."""
        logger.info("Starting comprehensive stability test suite")
        start_time = time.time()

        results = {
            "test_type": "comprehensive",
            "start_time": start_time,
            "tests": {}
        }

        # Run all stability tests
        comprehensive_result = subprocess.run([
            sys.executable, "-m", "pytest",
            "tests/stability/", "-v", "--tb=short",
            "--timeout=7200"  # 2 hour timeout
        ], capture_output=True, text=True, cwd=self.project_root)

        results["tests"]["comprehensive_stability"] = {
            "success": comprehensive_result.returncode == 0,
            "output": comprehensive_result.stdout,
            "error": comprehensive_result.stderr
        }

        results["duration"] = time.time() - start_time
        results["overall_success"] = all(
            test.get("success", False)
            for test in results["tests"].values()
        )

        logger.info(f"Comprehensive suite completed in {results['duration']:.1f}s")
        return results

    def save_results(self, results: Dict[str, Any]) -> Path:
        """Save test results to file."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{results['test_type']}_{timestamp}.json"
        filepath = self.results_dir / filename

        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"Results saved to {filepath}")
        return filepath

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="VoiceFlow Stability Test Runner")

    parser.add_argument(
        "--quick-check",
        action="store_true",
        help="Run quick 15-minute health check"
    )

    parser.add_argument(
        "--duration",
        type=str,
        help="Run duration test (e.g., '1h', '4h', '24h')"
    )

    parser.add_argument(
        "--stress-test",
        action="store_true",
        help="Run stress test with high request rate"
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=10,
        help="Request rate per minute for stress test"
    )

    parser.add_argument(
        "--stress-duration",
        type=int,
        default=30,
        help="Stress test duration in minutes"
    )

    parser.add_argument(
        "--comprehensive",
        action="store_true",
        help="Run comprehensive test suite"
    )

    parser.add_argument(
        "--scenario",
        type=str,
        choices=["mixed", "long_speech", "short_commands", "intermittent"],
        default="mixed",
        help="Test scenario type"
    )

    args = parser.parse_args()

    runner = StabilityTestRunner()
    results = None

    try:
        if args.quick_check:
            results = runner.run_quick_check()

        elif args.duration:
            # Parse duration (e.g., "1h", "4h", "24h")
            duration_str = args.duration.lower()
            if duration_str.endswith('h'):
                hours = int(duration_str[:-1])
            elif duration_str.endswith('m'):
                hours = int(duration_str[:-1]) / 60
            else:
                hours = int(duration_str)

            results = runner.run_duration_test(hours)

        elif args.stress_test:
            results = runner.run_stress_test(args.rate, args.stress_duration)

        elif args.comprehensive:
            results = runner.run_comprehensive_suite()

        else:
            # Default to quick check
            results = runner.run_quick_check()

        if results:
            # Save results
            filepath = runner.save_results(results)

            # Print summary
            print(f"\nStability Test Results:")
            print(f"Type: {results['test_type']}")
            print(f"Duration: {results['duration']:.1f}s")
            print(f"Overall Success: {results['overall_success']}")
            print(f"Results saved to: {filepath}")

            if not results['overall_success']:
                print("\nFailed tests:")
                for test_name, test_result in results['tests'].items():
                    if not test_result.get('success', False):
                        print(f"  - {test_name}: {test_result.get('error', 'Unknown error')}")
                sys.exit(1)
            else:
                print("\nAll tests passed!")

    except KeyboardInterrupt:
        logger.info("Test run interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test run failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()