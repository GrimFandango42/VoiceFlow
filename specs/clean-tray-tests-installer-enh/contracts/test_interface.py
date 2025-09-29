"""
Contract: Test Infrastructure Interface
Defines the interface contract for enhanced test organization and execution
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime


class TestCategory(Enum):
    """Test categorization for organization"""
    UNIT = "unit"
    INTEGRATION = "integration"
    STABILITY = "stability"
    CONTRACT = "contract"


class TestResult(Enum):
    """Test execution results"""
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class TestMetrics:
    """Test execution metrics"""
    duration_seconds: float
    memory_peak_mb: float
    cpu_usage_percent: float
    assertions_count: int
    coverage_percent: Optional[float] = None


@dataclass
class TestCase:
    """Test case definition"""
    name: str
    category: TestCategory
    file_path: str
    parallel_safe: bool
    timeout_seconds: int
    required_resources: List[str]
    dependencies: List[str]


class ITestRunner(ABC):
    """Contract for test execution management"""

    @abstractmethod
    def discover_tests(self, path: str, category: Optional[TestCategory] = None) -> List[TestCase]:
        """
        Discover test cases in specified path
        Args:
            path: Directory path to scan for tests
            category: Optional category filter
        Returns: List of discovered test cases
        """
        pass

    @abstractmethod
    def execute_test(self, test_case: TestCase) -> Dict[str, Any]:
        """
        Execute a single test case
        Args:
            test_case: Test case to execute
        Returns: Test execution results and metrics
        """
        pass

    @abstractmethod
    def execute_parallel(self, test_cases: List[TestCase], max_workers: int = 4) -> Dict[str, Any]:
        """
        Execute multiple test cases in parallel
        Args:
            test_cases: List of test cases to execute
            max_workers: Maximum parallel workers
        Returns: Aggregated test results
        """
        pass

    @abstractmethod
    def validate_environment(self, required_resources: List[str]) -> bool:
        """
        Validate test environment has required resources
        Args:
            required_resources: List of required resources
        Returns: True if environment is valid
        """
        pass


class ITestOrganizer(ABC):
    """Contract for test suite organization"""

    @abstractmethod
    def organize_by_category(self, test_cases: List[TestCase]) -> Dict[TestCategory, List[TestCase]]:
        """
        Organize test cases by category
        Args:
            test_cases: List of test cases to organize
        Returns: Dictionary mapping categories to test cases
        """
        pass

    @abstractmethod
    def resolve_dependencies(self, test_cases: List[TestCase]) -> List[TestCase]:
        """
        Resolve test dependencies and return execution order
        Args:
            test_cases: List of test cases with dependencies
        Returns: Ordered list for execution
        """
        pass

    @abstractmethod
    def filter_by_criteria(self, test_cases: List[TestCase], criteria: Dict[str, Any]) -> List[TestCase]:
        """
        Filter test cases by specified criteria
        Args:
            test_cases: List of test cases to filter
            criteria: Filter criteria dictionary
        Returns: Filtered list of test cases
        """
        pass


class ITestReporter(ABC):
    """Contract for test result reporting"""

    @abstractmethod
    def generate_report(self, results: Dict[str, Any], output_format: str = "html") -> str:
        """
        Generate test report
        Args:
            results: Test execution results
            output_format: Report format (html, json, xml)
        Returns: Report content or file path
        """
        pass

    @abstractmethod
    def record_metrics(self, test_name: str, metrics: TestMetrics) -> None:
        """
        Record test metrics for trend analysis
        Args:
            test_name: Name of the test
            metrics: Test execution metrics
        """
        pass

    @abstractmethod
    def get_coverage_summary(self) -> Dict[str, float]:
        """
        Get code coverage summary
        Returns: Coverage percentages by module/package
        """
        pass


class IStabilityTester(ABC):
    """Contract for long-running stability tests"""

    @abstractmethod
    def start_stability_test(self, duration_hours: int, test_scenario: str) -> str:
        """
        Start a long-running stability test
        Args:
            duration_hours: Test duration in hours
            test_scenario: Scenario to test
        Returns: Test session ID
        """
        pass

    @abstractmethod
    def monitor_stability_test(self, session_id: str) -> Dict[str, Any]:
        """
        Get current status of stability test
        Args:
            session_id: Test session ID
        Returns: Current test status and metrics
        """
        pass

    @abstractmethod
    def stop_stability_test(self, session_id: str) -> Dict[str, Any]:
        """
        Stop stability test and get final results
        Args:
            session_id: Test session ID
        Returns: Final test results and metrics
        """
        pass


# Contract validation requirements:
# 1. ITestRunner.execute_test must timeout according to TestCase.timeout_seconds
# 2. ITestRunner.execute_parallel must respect TestCase.parallel_safe flag
# 3. ITestOrganizer.resolve_dependencies must detect circular dependencies
# 4. ITestReporter.record_metrics must persist data for trend analysis
# 5. IStabilityTester tests must run for minimum 24 hours for constitutional compliance
# 6. All test execution must handle resource cleanup on failure