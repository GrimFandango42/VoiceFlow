#!/usr/bin/env python3
"""
VoiceFlow Test Runner

This script runs different test suites with various configurations and generates reports.
"""

import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any

# Configuration
TEST_RESULTS_DIR = Path("test_results")
PERFORMANCE_THRESHOLDS = {
    "transcription_time": 3.0,  # seconds per 5s of audio
    "memory_usage": 500,  # MB
    "cpu_usage": 90.0  # %
}

class TestRunner:
    """Runs tests and generates reports."""
    
    def __init__(self, test_type: str = "all", output_dir: Path = TEST_RESULTS_DIR):
        """Initialize the test runner."""
        self.test_type = test_type
        self.output_dir = output_dir
        self.results: Dict[str, Any] = {
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "environment": self._get_environment_info(),
            "tests": {},
            "summary": {"passed": 0, "failed": 0, "skipped": 0}
        }
    
    def _get_environment_info(self) -> Dict[str, str]:
        """Get information about the test environment."""
        import platform
        try:
            import torch  # type: ignore
            torch_version = getattr(torch, "__version__", "installed")
            cuda_available = bool(getattr(torch, "cuda", None) and torch.cuda.is_available())
        except Exception:
            torch_version = "not_installed"
            cuda_available = False

        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "pytorch_version": torch_version,
            "cuda_available": cuda_available,
            "cpu_count": os.cpu_count(),
        }
    
    def run_tests(self) -> bool:
        """Run the specified tests and return overall success status."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        test_suites = []
        
        if self.test_type in ["all", "unit"]:
            test_suites.append(("Unit Tests", ["pytest", "tests/", "-k", "not integration and not performance"]))
        
        if self.test_type in ["all", "integration"]:
            test_suites.append(("Integration Tests", ["pytest", "tests/", "-k", "integration"]))
        
        if self.test_type in ["all", "performance"]:
            test_suites.append(("Performance Tests", ["pytest", "tests/", "-k", "performance", "-v"]))
        
        if not test_suites:
            print(f"No test suites found for type: {self.test_type}")
            return False
        
        overall_success = True
        
        for suite_name, cmd in test_suites:
            print(f"\n{'='*80}")
            print(f"Running {suite_name}...")
            print(f"Command: {' '.join(cmd)}")
            print("-" * 80)
            
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True)
            duration = time.time() - start_time
            
            # Parse test results
            passed = result.returncode == 0
            output = result.stdout
            error = result.stderr
            
            # Update results
            self.results["tests"][suite_name] = {
                "command": " ".join(cmd),
                "duration": round(duration, 2),
                "passed": passed,
                "output": output,
                "error": error
            }
            
            if passed:
                self.results["summary"]["passed"] += 1
                status = "PASSED"
            else:
                self.results["summary"]["failed"] += 1
                status = "FAILED"
                overall_success = False
            
            print(f"\n{suite_name} {status} in {duration:.2f}s")
            print("=" * 40)
        
        # Generate report
        self._generate_report()
        
        return overall_success
    
    def _generate_report(self) -> None:
        """Generate a test report."""
        self.results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Save JSON report
        report_path = self.output_dir / "test_report.json"
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2)
        
        # Generate summary
        summary = f"""
        VoiceFlow Test Report
        ====================
        Start Time: {self.results['start_time']}
        End Time:   {self.results['end_time']}
        
        Test Summary:
        ------------
        Passed:  {self.results['summary']['passed']}
        Failed:  {self.results['summary']['failed']}
        Skipped: {self.results['summary']['skipped']}
        
        Environment:
        -----------
        Platform: {self.results['environment']['platform']}
        Python:   {self.results['environment']['python_version']}
        PyTorch:  {self.results['environment']['pytorch_version']}
        CUDA:     {'Available' if self.results['environment']['cuda_available'] else 'Not Available'}
        CPU Cores:{self.results['environment']['cpu_count']}
        
        Detailed results saved to: {report_path}
        """
        
        # Print and save summary
        print(summary)
        with open(self.output_dir / "test_summary.txt", "w") as f:
            f.write(summary)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run VoiceFlow tests")
    parser.add_argument(
        "--type", 
        choices=["all", "unit", "integration", "performance"], 
        default="all",
        help="Type of tests to run"
    )
    parser.add_argument(
        "--output-dir", 
        type=Path, 
        default=TEST_RESULTS_DIR,
        help="Directory to save test results"
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    runner = TestRunner(test_type=args.type, output_dir=args.output_dir)
    success = runner.run_tests()
    
    # Exit with appropriate status code
    sys.exit(0 if success else 1)
