"""
Contract tests for ITestRunner interface.
Tests that any implementation of ITestRunner follows the contract specification.
"""

import pytest
from unittest.mock import Mock
from typing import List, Dict, Any, Optional

# Import the contract interfaces from the specs
import sys
from pathlib import Path
spec_contracts_path = Path(__file__).parent.parent.parent / "specs" / "clean-tray-tests-installer-enh" / "contracts"
sys.path.insert(0, str(spec_contracts_path))

from test_interface import ITestRunner, TestCase, TestCategory, TestResult, TestMetrics


class MockTestRunner(ITestRunner):
    """Mock implementation for testing contract compliance."""

    def __init__(self):
        self.discovered_tests = []
        self.execution_results = {}

    def discover_tests(self, path: str, category: Optional[TestCategory] = None) -> List[TestCase]:
        # Mock discovery of test cases
        mock_tests = [
            TestCase(
                name="test_example",
                category=TestCategory.UNIT,
                file_path=f"{path}/test_example.py",
                parallel_safe=True,
                timeout_seconds=60,
                required_resources=["filesystem"],
                dependencies=[]
            ),
            TestCase(
                name="test_integration",
                category=TestCategory.INTEGRATION,
                file_path=f"{path}/test_integration.py",
                parallel_safe=False,
                timeout_seconds=300,
                required_resources=["audio", "filesystem"],
                dependencies=["test_example"]
            )
        ]

        if category:
            mock_tests = [t for t in mock_tests if t.category == category]

        self.discovered_tests = mock_tests
        return mock_tests

    def execute_test(self, test_case: TestCase) -> Dict[str, Any]:
        # Mock test execution
        result = {
            "test_case": test_case,
            "result": TestResult.PASS,
            "metrics": TestMetrics(
                duration_seconds=1.5,
                memory_peak_mb=50.0,
                cpu_usage_percent=10.0,
                assertions_count=5,
                coverage_percent=85.0
            ),
            "output": "Test passed successfully",
            "error": None
        }
        self.execution_results[test_case.name] = result
        return result

    def execute_parallel(self, test_cases: List[TestCase], max_workers: int = 4) -> Dict[str, Any]:
        # Mock parallel execution
        results = []
        for test_case in test_cases:
            if test_case.parallel_safe:
                results.append(self.execute_test(test_case))

        return {
            "results": results,
            "summary": {
                "total": len(test_cases),
                "passed": len([r for r in results if r["result"] == TestResult.PASS]),
                "failed": len([r for r in results if r["result"] == TestResult.FAIL]),
                "skipped": len([r for r in results if r["result"] == TestResult.SKIP]),
                "errors": len([r for r in results if r["result"] == TestResult.ERROR])
            },
            "duration_seconds": 2.5,
            "max_workers_used": min(max_workers, len([tc for tc in test_cases if tc.parallel_safe]))
        }

    def validate_environment(self, required_resources: List[str]) -> bool:
        # Mock environment validation
        available_resources = ["filesystem", "memory", "audio", "display"]
        return all(resource in available_resources for resource in required_resources)


@pytest.mark.contract
class TestITestRunnerContract:
    """Test the ITestRunner interface contract."""

    @pytest.fixture
    def test_runner(self):
        """Fixture providing a mock ITestRunner implementation."""
        return MockTestRunner()

    def test_interface_compliance(self, test_runner):
        """Test that implementation properly inherits from ITestRunner."""
        assert isinstance(test_runner, ITestRunner)
        assert hasattr(test_runner, 'discover_tests')
        assert hasattr(test_runner, 'execute_test')
        assert hasattr(test_runner, 'execute_parallel')
        assert hasattr(test_runner, 'validate_environment')

    def test_discover_tests_contract(self, test_runner):
        """Test discover_tests method contract."""
        # Should accept path parameter and return list of TestCase
        tests = test_runner.discover_tests("tests/unit")
        assert isinstance(tests, list)
        assert all(isinstance(test, TestCase) for test in tests)

        # Should accept optional category filter
        unit_tests = test_runner.discover_tests("tests/unit", TestCategory.UNIT)
        assert isinstance(unit_tests, list)
        assert all(test.category == TestCategory.UNIT for test in unit_tests)

        # Should handle empty directory
        empty_tests = test_runner.discover_tests("nonexistent")
        assert isinstance(empty_tests, list)

    def test_execute_test_contract(self, test_runner):
        """Test execute_test method contract."""
        # Create a test case
        test_case = TestCase(
            name="test_sample",
            category=TestCategory.UNIT,
            file_path="tests/test_sample.py",
            parallel_safe=True,
            timeout_seconds=60,
            required_resources=["filesystem"],
            dependencies=[]
        )

        # Should return dictionary with execution results
        result = test_runner.execute_test(test_case)
        assert isinstance(result, dict)

        # Should include required fields
        assert "test_case" in result
        assert "result" in result
        assert "metrics" in result

        # Result should be TestResult enum
        assert isinstance(result["result"], TestResult)

        # Metrics should be TestMetrics instance
        assert isinstance(result["metrics"], TestMetrics)

    def test_execute_parallel_contract(self, test_runner):
        """Test execute_parallel method contract."""
        # Create test cases
        test_cases = [
            TestCase(
                name="test_parallel_1",
                category=TestCategory.UNIT,
                file_path="tests/test_parallel_1.py",
                parallel_safe=True,
                timeout_seconds=60,
                required_resources=["filesystem"],
                dependencies=[]
            ),
            TestCase(
                name="test_parallel_2",
                category=TestCategory.UNIT,
                file_path="tests/test_parallel_2.py",
                parallel_safe=True,
                timeout_seconds=60,
                required_resources=["filesystem"],
                dependencies=[]
            )
        ]

        # Should return dictionary with execution results
        result = test_runner.execute_parallel(test_cases)
        assert isinstance(result, dict)

        # Should include required fields
        assert "results" in result
        assert "summary" in result
        assert isinstance(result["results"], list)
        assert isinstance(result["summary"], dict)

        # Should respect max_workers parameter
        result_with_limit = test_runner.execute_parallel(test_cases, max_workers=1)
        assert isinstance(result_with_limit, dict)

    def test_validate_environment_contract(self, test_runner):
        """Test validate_environment method contract."""
        # Should return boolean
        result = test_runner.validate_environment(["filesystem"])
        assert isinstance(result, bool)

        # Should handle empty list
        empty_result = test_runner.validate_environment([])
        assert isinstance(empty_result, bool)

        # Should handle unknown resources
        unknown_result = test_runner.validate_environment(["nonexistent_resource"])
        assert isinstance(unknown_result, bool)

    def test_timeout_handling_contract(self, test_runner):
        """Test timeout handling according to TestCase specifications."""
        # Create test case with specific timeout
        test_case = TestCase(
            name="test_timeout",
            category=TestCategory.UNIT,
            file_path="tests/test_timeout.py",
            parallel_safe=True,
            timeout_seconds=30,
            required_resources=[],
            dependencies=[]
        )

        # Should respect timeout_seconds from TestCase
        result = test_runner.execute_test(test_case)
        assert isinstance(result, dict)

        # Execution should not exceed timeout (with reasonable margin)
        metrics = result["metrics"]
        assert metrics.duration_seconds <= test_case.timeout_seconds

    def test_parallel_safety_contract(self, test_runner):
        """Test parallel safety handling."""
        # Create mix of parallel-safe and unsafe tests
        test_cases = [
            TestCase(
                name="test_safe",
                category=TestCategory.UNIT,
                file_path="tests/test_safe.py",
                parallel_safe=True,
                timeout_seconds=60,
                required_resources=[],
                dependencies=[]
            ),
            TestCase(
                name="test_unsafe",
                category=TestCategory.INTEGRATION,
                file_path="tests/test_unsafe.py",
                parallel_safe=False,
                timeout_seconds=120,
                required_resources=["audio"],
                dependencies=[]
            )
        ]

        # Should only execute parallel-safe tests in parallel mode
        result = test_runner.execute_parallel(test_cases)

        # Should include results from parallel-safe tests
        assert isinstance(result["results"], list)

    def test_resource_validation_contract(self, test_runner):
        """Test resource validation works correctly."""
        # Should validate common resources
        common_resources = ["filesystem", "memory"]
        assert test_runner.validate_environment(common_resources) is True

        # Should handle VoiceFlow-specific resources
        voiceflow_resources = ["audio", "display"]
        result = test_runner.validate_environment(voiceflow_resources)
        assert isinstance(result, bool)

    def test_test_categories_contract(self, test_runner):
        """Test all TestCategory values are handled."""
        for category in TestCategory:
            tests = test_runner.discover_tests("tests", category)
            assert isinstance(tests, list)

    def test_dependency_awareness_contract(self, test_runner):
        """Test test runner respects dependencies."""
        # Create test with dependencies
        dependent_test = TestCase(
            name="test_dependent",
            category=TestCategory.INTEGRATION,
            file_path="tests/test_dependent.py",
            parallel_safe=False,
            timeout_seconds=120,
            required_resources=[],
            dependencies=["test_prerequisite"]
        )

        # Should handle test cases with dependencies
        result = test_runner.execute_test(dependent_test)
        assert isinstance(result, dict)

    def test_metrics_collection_contract(self, test_runner):
        """Test that metrics are properly collected."""
        test_case = TestCase(
            name="test_metrics",
            category=TestCategory.UNIT,
            file_path="tests/test_metrics.py",
            parallel_safe=True,
            timeout_seconds=60,
            required_resources=[],
            dependencies=[]
        )

        result = test_runner.execute_test(test_case)
        metrics = result["metrics"]

        # Should collect all required metrics
        assert isinstance(metrics.duration_seconds, float)
        assert metrics.duration_seconds >= 0

        assert isinstance(metrics.memory_peak_mb, float)
        assert metrics.memory_peak_mb >= 0

        assert isinstance(metrics.cpu_usage_percent, float)
        assert 0 <= metrics.cpu_usage_percent <= 100

        assert isinstance(metrics.assertions_count, int)
        assert metrics.assertions_count >= 0


@pytest.mark.contract
def test_test_case_dataclass_contract():
    """Test TestCase dataclass contract."""
    # Should create with all required fields
    test_case = TestCase(
        name="test_example",
        category=TestCategory.UNIT,
        file_path="tests/test_example.py",
        parallel_safe=True,
        timeout_seconds=60,
        required_resources=["filesystem"],
        dependencies=[]
    )

    assert test_case.name == "test_example"
    assert test_case.category == TestCategory.UNIT
    assert test_case.parallel_safe is True
    assert test_case.timeout_seconds == 60
    assert isinstance(test_case.required_resources, list)
    assert isinstance(test_case.dependencies, list)


@pytest.mark.contract
def test_test_metrics_dataclass_contract():
    """Test TestMetrics dataclass contract."""
    # Should create with required fields
    metrics = TestMetrics(
        duration_seconds=1.5,
        memory_peak_mb=50.0,
        cpu_usage_percent=10.0,
        assertions_count=5
    )

    assert metrics.duration_seconds == 1.5
    assert metrics.memory_peak_mb == 50.0
    assert metrics.cpu_usage_percent == 10.0
    assert metrics.assertions_count == 5
    assert metrics.coverage_percent is None

    # Should create with optional coverage
    metrics_with_coverage = TestMetrics(
        duration_seconds=1.5,
        memory_peak_mb=50.0,
        cpu_usage_percent=10.0,
        assertions_count=5,
        coverage_percent=85.0
    )

    assert metrics_with_coverage.coverage_percent == 85.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])