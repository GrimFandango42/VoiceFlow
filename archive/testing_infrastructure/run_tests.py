#!/usr/bin/env python3
"""
VoiceFlow Test Runner

Runs unit (default), integration, or performance tests and writes JSON/summary reports.
"""
import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any

TEST_RESULTS_DIR = Path("test_results")

class TestRunner:
    def __init__(self, test_type: str = "unit", output_dir: Path = TEST_RESULTS_DIR):
        self.test_type = test_type
        self.output_dir = output_dir
        self.results: Dict[str, Any] = {
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "environment": self._get_environment_info(),
            "tests": {},
            "summary": {"passed": 0, "failed": 0, "skipped": 0},
        }

    def _get_environment_info(self) -> Dict[str, Any]:
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
        self.output_dir.mkdir(parents=True, exist_ok=True)
        suites = []
        if self.test_type in ("all", "unit"):
            suites.append(("Unit Tests", [sys.executable, "-m", "pytest", "tests/unit", "-q"]))
        if self.test_type in ("all", "integration"):
            suites.append(("Integration Tests", [sys.executable, "-m", "pytest", "tests/integration", "-q"]))
        if self.test_type == "performance":
            suites.append(("Performance Tests", [sys.executable, "-m", "pytest", "tests", "-k", "performance", "-v"]))
        if not suites:
            print(f"Unknown test type: {self.test_type}")
            return False

        overall = True
        for name, cmd in suites:
            print("\n" + "=" * 80)
            print(f"Running {name}...")
            print("Command:", " ".join(cmd))
            start = time.time()
            proc = subprocess.run(cmd, capture_output=True, text=True)
            dur = time.time() - start
            passed = proc.returncode == 0
            self.results["tests"][name] = {
                "command": " ".join(cmd),
                "duration": round(dur, 2),
                "passed": passed,
                "output": proc.stdout,
                "error": proc.stderr,
            }
            self.results["summary"]["passed" if passed else "failed"] += 1
            overall &= passed
            print(f"\n{name} {'PASSED' if passed else 'FAILED'} in {dur:.2f}s")
        self._write_reports()
        return overall

    def _write_reports(self) -> None:
        self.results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "test_report.json").write_text(json.dumps(self.results, indent=2))
        summary = (
            f"VoiceFlow Test Report\n"
            f"======================\n"
            f"Start Time: {self.results['start_time']}\n"
            f"End Time:   {self.results['end_time']}\n\n"
            f"Passed:  {self.results['summary']['passed']}\n"
            f"Failed:  {self.results['summary']['failed']}\n"
            f"Skipped: {self.results['summary']['skipped']}\n"
        )
        print("\n" + summary)
        (self.output_dir / "test_summary.txt").write_text(summary)


def parse_args():
    p = argparse.ArgumentParser(description="Run VoiceFlow tests")
    p.add_argument("--type", choices=["unit", "integration", "performance", "all"], default="unit")
    p.add_argument("--output-dir", type=Path, default=TEST_RESULTS_DIR)
    return p.parse_args()

if __name__ == "__main__":
    a = parse_args()
    ok = TestRunner(test_type=a.type, output_dir=a.output_dir).run_tests()
    sys.exit(0 if ok else 1)
