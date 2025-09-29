"""
TestConfiguration model for VoiceFlow test execution management.
Defines test execution parameters and environment with constitutional compliance.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Any
import threading


class TestCategory(Enum):
    """Test category classifications."""
    UNIT = "unit"
    INTEGRATION = "integration"
    STABILITY = "stability"
    CONTRACT = "contract"


@dataclass
class TestConfiguration:
    """
    Test execution configuration with validation and constitutional compliance.
    Manages test parameters, environment settings, and execution requirements.
    """
    test_category: TestCategory = TestCategory.UNIT
    environment: str = "development"
    timeout_seconds: int = 30   # 30 seconds default
    required_resources: List[str] = None
    parallel_safe: bool = True
    cleanup_required: bool = False
    dependencies: List[str] = None

    # Thread safety
    _lock: threading.RLock = None

    def __post_init__(self):
        """Initialize TestConfiguration with validation and defaults."""
        # Initialize mutable defaults
        if self.required_resources is None:
            self.required_resources = []
        if self.dependencies is None:
            self.dependencies = []
        if self._lock is None:
            self._lock = threading.RLock()

        # Validate configuration
        self.validate()

    def validate(self) -> None:
        """
        Validate test configuration parameters.
        Raises ValueError if configuration is invalid.
        """
        if not isinstance(self.test_category, TestCategory):
            raise ValueError("test_category must be a TestCategory enum")

        if not isinstance(self.environment, str) or not self.environment.strip():
            raise ValueError("environment must be a non-empty string")

        if not (0 < self.timeout_seconds <= 3600):
            raise ValueError("timeout_seconds must be > 0 and <= 3600")

        if not isinstance(self.required_resources, list):
            raise ValueError("required_resources must be a list")

        if not isinstance(self.dependencies, list):
            raise ValueError("dependencies must be a list")

        # Validate resource identifiers
        valid_resources = {
            "audio", "display", "network", "filesystem", "registry",
            "microphone", "speakers", "gpu", "memory", "cpu"
        }
        for resource in self.required_resources:
            if resource not in valid_resources:
                raise ValueError(f"Invalid resource '{resource}'. Must be one of: {valid_resources}")

    def is_constitutional_compliant(self) -> bool:
        """
        Check if test configuration meets constitutional requirements.

        Constitutional Requirements:
        - Timeout must be reasonable for performance testing (≤600s for stability, ≤60s for others)
        - Must not require excessive resources that could impact system performance
        - Parallel execution should be preferred for faster test cycles

        Returns:
            True if configuration meets constitutional requirements
        """
        with self._lock:
            # Timeout limits based on test category
            if self.test_category == TestCategory.STABILITY:
                max_timeout = 600  # 10 minutes for stability tests
            else:
                max_timeout = 60   # 1 minute for other tests

            if self.timeout_seconds > max_timeout:
                return False

            # Resource usage limits
            if len(self.required_resources) > 5:  # Avoid excessive resource requirements
                return False

            # Encourage parallel execution for better performance
            if self.test_category in [TestCategory.UNIT, TestCategory.CONTRACT] and not self.parallel_safe:
                return False

            return True

    def get_compliance_violations(self) -> Dict[str, str]:
        """
        Get detailed constitutional compliance violations.

        Returns:
            Dictionary of violations with descriptions
        """
        violations = {}

        with self._lock:
            # Timeout violations
            if self.test_category == TestCategory.STABILITY:
                max_timeout = 600
            else:
                max_timeout = 60

            if self.timeout_seconds > max_timeout:
                violations["timeout_violation"] = (
                    f"Timeout {self.timeout_seconds}s exceeds constitutional limit of {max_timeout}s "
                    f"for {self.test_category.value} tests"
                )

            # Resource violations
            if len(self.required_resources) > 5:
                violations["resource_violation"] = (
                    f"Required resources ({len(self.required_resources)}) exceeds "
                    f"constitutional limit of 5 resources"
                )

            # Parallel execution violations
            if self.test_category in [TestCategory.UNIT, TestCategory.CONTRACT] and not self.parallel_safe:
                violations["parallel_violation"] = (
                    f"{self.test_category.value} tests should be parallel_safe=True "
                    f"for optimal performance"
                )

        return violations

    def update_configuration(self,
                           test_category: Optional[TestCategory] = None,
                           environment: Optional[str] = None,
                           timeout_seconds: Optional[int] = None,
                           required_resources: Optional[List[str]] = None,
                           parallel_safe: Optional[bool] = None,
                           cleanup_required: Optional[bool] = None,
                           dependencies: Optional[List[str]] = None) -> None:
        """
        Update test configuration parameters atomically.

        Args:
            test_category: Test category to set
            environment: Environment identifier to set
            timeout_seconds: Timeout value to set
            required_resources: Resources list to set
            parallel_safe: Parallel execution flag to set
            cleanup_required: Cleanup requirement flag to set
            dependencies: Dependencies list to set
        """
        with self._lock:
            if test_category is not None:
                self.test_category = test_category
            if environment is not None:
                self.environment = environment
            if timeout_seconds is not None:
                self.timeout_seconds = timeout_seconds
            if required_resources is not None:
                self.required_resources = required_resources.copy()
            if parallel_safe is not None:
                self.parallel_safe = parallel_safe
            if cleanup_required is not None:
                self.cleanup_required = cleanup_required
            if dependencies is not None:
                self.dependencies = dependencies.copy()

            # Re-validate after updates
            self.validate()

    def add_resource(self, resource: str) -> None:
        """
        Add a required resource to the configuration.

        Args:
            resource: Resource identifier to add
        """
        with self._lock:
            if resource not in self.required_resources:
                self.required_resources.append(resource)
                self.validate()

    def remove_resource(self, resource: str) -> None:
        """
        Remove a required resource from the configuration.

        Args:
            resource: Resource identifier to remove
        """
        with self._lock:
            if resource in self.required_resources:
                self.required_resources.remove(resource)

    def add_dependency(self, dependency: str) -> None:
        """
        Add a test dependency.

        Args:
            dependency: Test identifier that must pass first
        """
        with self._lock:
            if dependency not in self.dependencies:
                self.dependencies.append(dependency)

    def remove_dependency(self, dependency: str) -> None:
        """
        Remove a test dependency.

        Args:
            dependency: Test identifier to remove from dependencies
        """
        with self._lock:
            if dependency in self.dependencies:
                self.dependencies.remove(dependency)

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize TestConfiguration to dictionary.

        Returns:
            Dictionary representation
        """
        with self._lock:
            return {
                "test_category": self.test_category.value,
                "environment": self.environment,
                "timeout_seconds": self.timeout_seconds,
                "required_resources": self.required_resources.copy(),
                "parallel_safe": self.parallel_safe,
                "cleanup_required": self.cleanup_required,
                "dependencies": self.dependencies.copy(),
                "constitutional_compliant": self.is_constitutional_compliant(),
                "violations": self.get_compliance_violations()
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TestConfiguration':
        """
        Deserialize TestConfiguration from dictionary.

        Args:
            data: Dictionary to deserialize from

        Returns:
            TestConfiguration instance
        """
        config = cls()

        # Set test category
        if "test_category" in data:
            try:
                config.test_category = TestCategory(data["test_category"])
            except ValueError:
                config.test_category = TestCategory.UNIT

        # Set other fields
        config.environment = data.get("environment", "development")
        config.timeout_seconds = data.get("timeout_seconds", 300)
        config.required_resources = data.get("required_resources", []).copy()
        config.parallel_safe = data.get("parallel_safe", True)
        config.cleanup_required = data.get("cleanup_required", False)
        config.dependencies = data.get("dependencies", []).copy()

        return config

    def get_execution_context(self) -> Dict[str, Any]:
        """
        Get execution context for test runners.

        Returns:
            Dictionary with execution parameters
        """
        with self._lock:
            return {
                "category": self.test_category.value,
                "environment": self.environment,
                "timeout": self.timeout_seconds,
                "resources": self.required_resources.copy(),
                "parallel": self.parallel_safe,
                "cleanup": self.cleanup_required,
                "deps": self.dependencies.copy(),
                "compliant": self.is_constitutional_compliant()
            }

    def __eq__(self, other) -> bool:
        """Compare TestConfiguration instances for equality."""
        if not isinstance(other, TestConfiguration):
            return False

        return (
            self.test_category == other.test_category and
            self.environment == other.environment and
            self.timeout_seconds == other.timeout_seconds and
            self.required_resources == other.required_resources and
            self.parallel_safe == other.parallel_safe and
            self.cleanup_required == other.cleanup_required and
            self.dependencies == other.dependencies
        )

    def __str__(self) -> str:
        """String representation of TestConfiguration."""
        compliant = "✅" if self.is_constitutional_compliant() else "❌"
        parallel = "||" if self.parallel_safe else "→"
        cleanup = "🧹" if self.cleanup_required else ""

        return (
            f"TestConfig({self.test_category.value}): "
            f"{self.environment} {parallel} {self.timeout_seconds}s "
            f"[{len(self.required_resources)} resources, {len(self.dependencies)} deps] "
            f"{cleanup} {compliant}"
        )