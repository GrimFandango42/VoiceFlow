#!/usr/bin/env python3
"""
VoiceFlow Comprehensive Testing Framework - Test Orchestrator

This module provides unified test orchestration for all VoiceFlow testing needs,
coordinating test execution across unit, integration, end-to-end, performance,
and security testing suites.

Features:
- Unified test execution management
- Parallel test suite execution
- Comprehensive test result consolidation
- Advanced test configuration management
- Real-time test progress monitoring
- Automated test dependency resolution
- Performance regression detection
- Quality metrics tracking and reporting
"""

import asyncio
import json
import logging
import multiprocessing
import os
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import psutil
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TestType(Enum):
    """Test type classifications."""
    UNIT = "unit"
    INTEGRATION = "integration"
    E2E = "e2e"
    PERFORMANCE = "performance"
    SECURITY = "security"
    LOAD = "load"
    REGRESSION = "regression"
    SMOKE = "smoke"
    COMPATIBILITY = "compatibility"


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class TestResult:
    """Individual test result container."""
    name: str
    test_type: TestType
    status: TestStatus
    duration: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    output: str = ""
    error_output: str = ""
    exit_code: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'name': self.name,
            'test_type': self.test_type.value,
            'status': self.status.value,
            'duration': self.duration,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'output': self.output,
            'error_output': self.error_output,
            'exit_code': self.exit_code,
            'metadata': self.metadata
        }


@dataclass
class TestSuite:
    """Test suite configuration."""
    name: str
    test_type: TestType
    script_path: str
    description: str = ""
    timeout: int = 300  # 5 minutes default
    dependencies: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    parallel_safe: bool = True
    priority: int = 1  # 1 = highest, 5 = lowest
    tags: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate suite configuration."""
        if not Path(self.script_path).exists():
            logger.warning(f"Test script not found: {self.script_path}")


@dataclass
class OrchestrationConfig:
    """Test orchestration configuration."""
    max_parallel_tests: int = 4
    default_timeout: int = 300
    output_directory: str = "test_results"
    enable_parallel_execution: bool = True
    enable_performance_monitoring: bool = True
    enable_coverage: bool = False
    fail_fast: bool = False
    retry_failed_tests: bool = False
    max_retries: int = 2
    generate_html_report: bool = True
    enable_real_time_monitoring: bool = True
    test_data_cleanup: bool = True
    
    @classmethod
    def from_file(cls, config_path: str) -> 'OrchestrationConfig':
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f)
            return cls(**data.get('orchestration', {}))
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
            return cls()


class TestProgressMonitor:
    """Real-time test progress monitoring."""
    
    def __init__(self):
        self.start_time = None
        self.total_tests = 0
        self.completed_tests = 0
        self.running_tests = set()
        self.system_stats = {}
        self.lock = threading.Lock()
        
    def start_monitoring(self, total_tests: int):
        """Start progress monitoring."""
        self.start_time = datetime.now()
        self.total_tests = total_tests
        self.completed_tests = 0
        self.running_tests = set()
        
    def update_test_started(self, test_name: str):
        """Update when test starts."""
        with self.lock:
            self.running_tests.add(test_name)
            self._log_progress()
    
    def update_test_completed(self, test_name: str):
        """Update when test completes."""
        with self.lock:
            if test_name in self.running_tests:
                self.running_tests.remove(test_name)
            self.completed_tests += 1
            self._log_progress()
    
    def _log_progress(self):
        """Log current progress."""
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            progress = (self.completed_tests / self.total_tests) * 100 if self.total_tests > 0 else 0
            
            eta = "Unknown"
            if self.completed_tests > 0:
                avg_time_per_test = elapsed.total_seconds() / self.completed_tests
                remaining_tests = self.total_tests - self.completed_tests
                eta_seconds = avg_time_per_test * remaining_tests
                eta = str(timedelta(seconds=int(eta_seconds)))
            
            logger.info(
                f"Progress: {self.completed_tests}/{self.total_tests} ({progress:.1f}%) - "
                f"Running: {len(self.running_tests)} - ETA: {eta}"
            )
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get current system statistics."""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage_percent': psutil.disk_usage('/').percent,
                'network_io': psutil.net_io_counters()._asdict(),
                'running_processes': len(psutil.pids())
            }
        except Exception as e:
            logger.warning(f"Failed to get system stats: {e}")
            return {}


class TestOrchestrator:
    """Main test orchestration engine."""
    
    def __init__(self, config: Optional[OrchestrationConfig] = None):
        """Initialize the test orchestrator."""
        self.config = config or OrchestrationConfig()
        self.test_suites: List[TestSuite] = []
        self.results: List[TestResult] = []
        self.progress_monitor = TestProgressMonitor()
        self.output_dir = Path(self.config.output_directory)
        self.output_dir.mkdir(exist_ok=True)
        
        # Load default test suites
        self._discover_test_suites()
        
    def _discover_test_suites(self):
        """Auto-discover test suites from the project."""
        project_root = Path(__file__).parent
        
        # Define standard test suites
        suites = [
            # Core functionality tests
            TestSuite(
                name="core_unit_tests",
                test_type=TestType.UNIT,
                script_path=str(project_root / "tests" / "test_voiceflow_core.py"),
                description="Core VoiceFlow engine unit tests",
                timeout=120,
                priority=1,
                tags=["core", "unit"]
            ),
            TestSuite(
                name="ai_enhancement_tests",
                test_type=TestType.UNIT,
                script_path=str(project_root / "tests" / "test_ai_enhancement.py"),
                description="AI enhancement module tests",
                timeout=180,
                priority=1,
                tags=["ai", "unit"]
            ),
            TestSuite(
                name="config_tests",
                test_type=TestType.UNIT,
                script_path=str(project_root / "tests" / "test_config.py"),
                description="Configuration management tests",
                timeout=60,
                priority=1,
                tags=["config", "unit"]
            ),
            TestSuite(
                name="validation_tests",
                test_type=TestType.UNIT,
                script_path=str(project_root / "tests" / "test_validation.py"),
                description="Input validation tests",
                timeout=90,
                priority=1,
                tags=["validation", "unit"]
            ),
            
            # Integration tests
            TestSuite(
                name="comprehensive_integration",
                test_type=TestType.INTEGRATION,
                script_path=str(project_root / "tests" / "test_comprehensive_integration.py"),
                description="Comprehensive component integration tests",
                timeout=300,
                priority=2,
                tags=["integration", "comprehensive"]
            ),
            TestSuite(
                name="server_integration",
                test_type=TestType.INTEGRATION,
                script_path=str(project_root / "tests" / "test_server_integration.py"),
                description="Server integration tests",
                timeout=240,
                priority=2,
                tags=["integration", "server"]
            ),
            TestSuite(
                name="security_integration",
                test_type=TestType.SECURITY,
                script_path=str(project_root / "tests" / "test_security_integration.py"),
                description="Security integration tests",
                timeout=180,
                priority=2,
                tags=["security", "integration"]
            ),
            
            # End-to-end tests
            TestSuite(
                name="e2e_scenarios",
                test_type=TestType.E2E,
                script_path=str(project_root / "tests" / "test_e2e_scenarios.py"),
                description="End-to-end scenario tests",
                timeout=600,
                priority=3,
                tags=["e2e", "scenarios"]
            ),
            TestSuite(
                name="real_world_scenarios",
                test_type=TestType.E2E,
                script_path=str(project_root / "tests" / "test_real_world_scenarios.py"),
                description="Real-world usage pattern tests",
                timeout=480,
                priority=3,
                tags=["e2e", "real-world"]
            ),
            
            # Performance tests
            TestSuite(
                name="comprehensive_performance",
                test_type=TestType.PERFORMANCE,
                script_path=str(project_root / "tests" / "test_comprehensive_performance.py"),
                description="Comprehensive performance benchmarks",
                timeout=900,
                priority=4,
                parallel_safe=False,
                tags=["performance", "benchmarks"]
            ),
            TestSuite(
                name="load_testing",
                test_type=TestType.LOAD,
                script_path=str(project_root / "tests" / "test_comprehensive_load_testing.py"),
                description="Load testing and stress tests",
                timeout=1200,
                priority=4,
                parallel_safe=False,
                tags=["load", "stress"]
            ),
            
            # Security tests
            TestSuite(
                name="security_tests",
                test_type=TestType.SECURITY,
                script_path=str(project_root / "run_security_tests.py"),
                description="Security vulnerability tests",
                timeout=300,
                priority=2,
                tags=["security", "vulnerability"]
            ),
            
            # Compatibility tests
            TestSuite(
                name="accessibility_compliance",
                test_type=TestType.COMPATIBILITY,
                script_path=str(project_root / "tests" / "test_accessibility_compliance.py"),
                description="Accessibility compliance tests",
                timeout=180,
                priority=3,
                tags=["accessibility", "compliance"]
            )
        ]
        
        # Filter to only include suites with existing scripts
        self.test_suites = [suite for suite in suites if Path(suite.script_path).exists()]
        
        logger.info(f"Discovered {len(self.test_suites)} test suites")
    
    def add_test_suite(self, suite: TestSuite):
        """Add a custom test suite."""
        self.test_suites.append(suite)
        logger.info(f"Added test suite: {suite.name}")
    
    def remove_test_suite(self, suite_name: str):
        """Remove a test suite by name."""
        self.test_suites = [s for s in self.test_suites if s.name != suite_name]
        logger.info(f"Removed test suite: {suite_name}")
    
    def filter_suites(self, 
                     test_types: Optional[List[TestType]] = None,
                     tags: Optional[List[str]] = None,
                     suite_names: Optional[List[str]] = None) -> List[TestSuite]:
        """Filter test suites by criteria."""
        filtered = self.test_suites
        
        if test_types:
            filtered = [s for s in filtered if s.test_type in test_types]
        
        if tags:
            filtered = [s for s in filtered if any(tag in s.tags for tag in tags)]
        
        if suite_names:
            filtered = [s for s in filtered if s.name in suite_names]
        
        return filtered
    
    def _execute_test_suite(self, suite: TestSuite) -> TestResult:
        """Execute a single test suite."""
        result = TestResult(
            name=suite.name,
            test_type=suite.test_type,
            status=TestStatus.RUNNING,
            start_time=datetime.now()
        )
        
        self.progress_monitor.update_test_started(suite.name)
        
        try:
            # Prepare environment
            env = os.environ.copy()
            env.update(suite.environment)
            
            # Execute test
            logger.info(f"Executing test suite: {suite.name}")
            
            process = subprocess.Popen(
                [sys.executable, "-m", "pytest", suite.script_path, "-v", "--tb=short"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=Path(__file__).parent
            )
            
            try:
                stdout, stderr = process.communicate(timeout=suite.timeout)
                result.output = stdout
                result.error_output = stderr
                result.exit_code = process.returncode
                
                if process.returncode == 0:
                    result.status = TestStatus.PASSED
                else:
                    result.status = TestStatus.FAILED
                    
            except subprocess.TimeoutExpired:
                process.kill()
                result.status = TestStatus.TIMEOUT
                result.error_output = f"Test timed out after {suite.timeout} seconds"
                
        except Exception as e:
            result.status = TestStatus.ERROR
            result.error_output = str(e)
            logger.error(f"Error executing test suite {suite.name}: {e}")
        
        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
            self.progress_monitor.update_test_completed(suite.name)
        
        return result
    
    def _resolve_dependencies(self, suites: List[TestSuite]) -> List[TestSuite]:
        """Resolve test suite dependencies and return execution order."""
        # Simple topological sort for dependencies
        resolved = []
        unresolved = suites.copy()
        
        while unresolved:
            made_progress = False
            
            for suite in unresolved[:]:
                dependencies_met = all(
                    any(r.name == dep for r in resolved) 
                    for dep in suite.dependencies
                )
                
                if not suite.dependencies or dependencies_met:
                    resolved.append(suite)
                    unresolved.remove(suite)
                    made_progress = True
            
            if not made_progress:
                # Circular dependency or missing dependency
                logger.warning("Circular or missing dependencies detected, proceeding anyway")
                resolved.extend(unresolved)
                break
        
        # Sort by priority within dependency order
        return sorted(resolved, key=lambda s: s.priority)
    
    async def run_tests_async(self, 
                            test_types: Optional[List[TestType]] = None,
                            tags: Optional[List[str]] = None,
                            suite_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run tests asynchronously with parallel execution."""
        suites_to_run = self.filter_suites(test_types, tags, suite_names)
        
        if not suites_to_run:
            logger.warning("No test suites match the specified criteria")
            return {"status": "no_tests", "results": []}
        
        # Resolve dependencies
        ordered_suites = self._resolve_dependencies(suites_to_run)
        
        logger.info(f"Running {len(ordered_suites)} test suites")
        self.progress_monitor.start_monitoring(len(ordered_suites))
        
        start_time = datetime.now()
        self.results = []
        
        if self.config.enable_parallel_execution:
            # Separate parallel-safe from sequential tests
            parallel_suites = [s for s in ordered_suites if s.parallel_safe]
            sequential_suites = [s for s in ordered_suites if not s.parallel_safe]
            
            # Run parallel tests first
            if parallel_suites:
                with ThreadPoolExecutor(max_workers=self.config.max_parallel_tests) as executor:
                    futures = {executor.submit(self._execute_test_suite, suite): suite 
                             for suite in parallel_suites}
                    
                    for future in as_completed(futures):
                        result = future.result()
                        self.results.append(result)
                        
                        if self.config.fail_fast and result.status == TestStatus.FAILED:
                            logger.error(f"Failing fast due to failed test: {result.name}")
                            break
            
            # Run sequential tests
            for suite in sequential_suites:
                result = self._execute_test_suite(suite)
                self.results.append(result)
                
                if self.config.fail_fast and result.status == TestStatus.FAILED:
                    logger.error(f"Failing fast due to failed test: {result.name}")
                    break
        else:
            # Run all tests sequentially
            for suite in ordered_suites:
                result = self._execute_test_suite(suite)
                self.results.append(result)
                
                if self.config.fail_fast and result.status == TestStatus.FAILED:
                    logger.error(f"Failing fast due to failed test: {result.name}")
                    break
        
        end_time = datetime.now()
        total_duration = (end_time - start_time).total_seconds()
        
        # Generate summary
        summary = self._generate_summary(total_duration)
        
        # Save results
        await self._save_results(summary)
        
        return summary
    
    def run_tests(self, 
                 test_types: Optional[List[TestType]] = None,
                 tags: Optional[List[str]] = None,
                 suite_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run tests synchronously."""
        return asyncio.run(self.run_tests_async(test_types, tags, suite_names))
    
    def _generate_summary(self, total_duration: float) -> Dict[str, Any]:
        """Generate test execution summary."""
        total_tests = len(self.results)
        passed = len([r for r in self.results if r.status == TestStatus.PASSED])
        failed = len([r for r in self.results if r.status == TestStatus.FAILED])
        errors = len([r for r in self.results if r.status == TestStatus.ERROR])
        timeouts = len([r for r in self.results if r.status == TestStatus.TIMEOUT])
        skipped = len([r for r in self.results if r.status == TestStatus.SKIPPED])
        
        success_rate = (passed / total_tests * 100) if total_tests > 0 else 0
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_duration": total_duration,
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "timeouts": timeouts,
            "skipped": skipped,
            "success_rate": success_rate,
            "results": [result.to_dict() for result in self.results],
            "system_stats": self.progress_monitor.get_system_stats(),
            "config": {
                "max_parallel_tests": self.config.max_parallel_tests,
                "enable_parallel_execution": self.config.enable_parallel_execution,
                "fail_fast": self.config.fail_fast
            }
        }
        
        return summary
    
    async def _save_results(self, summary: Dict[str, Any]):
        """Save test results to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON report
        json_path = self.output_dir / f"test_results_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Save text summary
        text_path = self.output_dir / f"test_summary_{timestamp}.txt"
        with open(text_path, 'w') as f:
            f.write(self._format_text_summary(summary))
        
        # Generate HTML report if enabled
        if self.config.generate_html_report:
            html_path = self.output_dir / f"test_report_{timestamp}.html"
            with open(html_path, 'w') as f:
                f.write(self._generate_html_report(summary))
        
        logger.info(f"Test results saved to {self.output_dir}")
    
    def _format_text_summary(self, summary: Dict[str, Any]) -> str:
        """Format text summary of test results."""
        lines = [
            "VoiceFlow Comprehensive Test Results",
            "=" * 50,
            f"Timestamp: {summary['timestamp']}",
            f"Total Duration: {summary['total_duration']:.2f} seconds",
            f"Total Tests: {summary['total_tests']}",
            f"Passed: {summary['passed']}",
            f"Failed: {summary['failed']}",
            f"Errors: {summary['errors']}",
            f"Timeouts: {summary['timeouts']}",
            f"Skipped: {summary['skipped']}",
            f"Success Rate: {summary['success_rate']:.2f}%",
            "",
            "Test Results:",
            "-" * 30
        ]
        
        for result in summary['results']:
            status_symbol = {
                'passed': '✓',
                'failed': '✗',
                'error': '❌',
                'timeout': '⏰',
                'skipped': '⏭'
            }.get(result['status'], '?')
            
            lines.append(
                f"{status_symbol} {result['name']} ({result['test_type']}) - "
                f"{result['duration']:.2f}s"
            )
            
            if result['status'] in ['failed', 'error']:
                lines.append(f"  Error: {result['error_output'][:100]}...")
        
        return '\n'.join(lines)
    
    def _generate_html_report(self, summary: Dict[str, Any]) -> str:
        """Generate HTML test report."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VoiceFlow Test Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .test-result {{ margin: 10px 0; padding: 10px; border-radius: 3px; }}
        .passed {{ background: #d4edda; }}
        .failed {{ background: #f8d7da; }}
        .error {{ background: #fff3cd; }}
        .timeout {{ background: #e2e3e5; }}
        .skipped {{ background: #cce5ff; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }}
        .stat {{ background: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>VoiceFlow Comprehensive Test Results</h1>
        <p>Generated: {summary['timestamp']}</p>
        <p>Duration: {summary['total_duration']:.2f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="stats">
            <div class="stat">
                <h3>{summary['total_tests']}</h3>
                <p>Total Tests</p>
            </div>
            <div class="stat">
                <h3>{summary['passed']}</h3>
                <p>Passed</p>
            </div>
            <div class="stat">
                <h3>{summary['failed']}</h3>
                <p>Failed</p>
            </div>
            <div class="stat">
                <h3>{summary['success_rate']:.1f}%</h3>
                <p>Success Rate</p>
            </div>
        </div>
    </div>
    
    <div class="results">
        <h2>Test Results</h2>
"""
        
        for result in summary['results']:
            html += f"""
        <div class="test-result {result['status']}">
            <h4>{result['name']} ({result['test_type']})</h4>
            <p>Status: {result['status']} | Duration: {result['duration']:.2f}s</p>
            {f'<p>Error: {result["error_output"]}</p>' if result['error_output'] else ''}
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html


def main():
    """Main entry point for test orchestrator."""
    import argparse
    
    parser = argparse.ArgumentParser(description="VoiceFlow Test Orchestrator")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--types", nargs="+", help="Test types to run", 
                       choices=[t.value for t in TestType])
    parser.add_argument("--tags", nargs="+", help="Test tags to include")
    parser.add_argument("--suites", nargs="+", help="Specific test suites to run")
    parser.add_argument("--parallel", action="store_true", help="Enable parallel execution")
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first failure")
    parser.add_argument("--output-dir", help="Output directory for results")
    
    args = parser.parse_args()
    
    # Load configuration
    config = OrchestrationConfig()
    if args.config:
        config = OrchestrationConfig.from_file(args.config)
    
    # Override config with CLI arguments
    if args.parallel:
        config.enable_parallel_execution = True
    if args.fail_fast:
        config.fail_fast = True
    if args.output_dir:
        config.output_directory = args.output_dir
    
    # Create orchestrator
    orchestrator = TestOrchestrator(config)
    
    # Convert string types to enums
    test_types = None
    if args.types:
        test_types = [TestType(t) for t in args.types]
    
    # Run tests
    logger.info("Starting VoiceFlow comprehensive testing...")
    summary = orchestrator.run_tests(
        test_types=test_types,
        tags=args.tags,
        suite_names=args.suites
    )
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST EXECUTION SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Errors: {summary['errors']}")
    print(f"Success Rate: {summary['success_rate']:.2f}%")
    print(f"Duration: {summary['total_duration']:.2f} seconds")
    print(f"Results saved to: {config.output_directory}")
    
    # Exit with appropriate code
    exit_code = 0 if summary['failed'] == 0 and summary['errors'] == 0 else 1
    sys.exit(exit_code)


if __name__ == "__main__":
    main()