"""
InstallerConfiguration model for VoiceFlow installation process management.
Manages installation configuration, validation, and platform compatibility.
"""

from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from typing import List, Optional, Dict, Any, Union
import threading
import os
import sys
import tempfile


class ValidationResult(Enum):
    """Installation validation result status."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


@dataclass
class Dependency:
    """System dependency definition."""
    name: str
    version_min: Optional[str] = None
    version_max: Optional[str] = None
    required: bool = True
    check_command: Optional[str] = None
    install_command: Optional[str] = None

    def __post_init__(self):
        """Validate dependency definition."""
        if not self.name or not self.name.strip():
            raise ValueError("Dependency name cannot be empty")


@dataclass
class Feature:
    """Optional installation feature."""
    name: str
    description: str
    enabled: bool = False
    dependencies: List[str] = None
    size_mb: float = 0.0

    def __post_init__(self):
        """Initialize feature with defaults."""
        if self.dependencies is None:
            self.dependencies = []
        if not self.name or not self.name.strip():
            raise ValueError("Feature name cannot be empty")


@dataclass
class ValidationCheck:
    """Pre-installation validation check."""
    name: str
    check_type: str  # "platform", "python", "disk", "permissions", "dependencies"
    result: ValidationResult = ValidationResult.SKIPPED
    message: str = ""
    required: bool = True

    def __post_init__(self):
        """Validate check definition."""
        valid_types = {"platform", "python", "disk", "permissions", "dependencies"}
        if self.check_type not in valid_types:
            raise ValueError(f"Invalid check_type '{self.check_type}'. Must be one of: {valid_types}")


@dataclass
class InstallerConfiguration:
    """
    Installation configuration with platform validation and constitutional compliance.
    Manages Windows-specific installation parameters and system requirements.
    """
    target_platform: str = "windows"
    python_version: str = "3.9+"
    install_path: Optional[Path] = None
    required_dependencies: List[Dependency] = None
    optional_features: List[Feature] = None
    validation_checks: List[ValidationCheck] = None
    rollback_enabled: bool = True

    # Thread safety
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self):
        """Initialize InstallerConfiguration with validation and defaults."""
        # Initialize mutable defaults
        if self.required_dependencies is None:
            self.required_dependencies = self._create_default_dependencies()
        if self.optional_features is None:
            self.optional_features = self._create_default_features()
        if self.validation_checks is None:
            self.validation_checks = self._create_default_validation_checks()

        # Set default install path if not provided
        if self.install_path is None:
            self.install_path = Path.home() / "AppData" / "Local" / "VoiceFlow"

        # Ensure install_path is a Path object
        if isinstance(self.install_path, str):
            self.install_path = Path(self.install_path)

        # Validate configuration
        self.validate()

    def _create_default_dependencies(self) -> List[Dependency]:
        """Create default system dependencies."""
        return [
            Dependency(
                name="python",
                version_min="3.9.0",
                version_max="3.12.99",
                check_command="python --version",
                required=True
            ),
            Dependency(
                name="pip",
                version_min="21.0",
                check_command="pip --version",
                required=True
            ),
            Dependency(
                name="pystray",
                version_min="0.19.0",
                check_command="python -c \"import pystray\"",
                install_command="pip install pystray>=0.19.0",
                required=True
            ),
            Dependency(
                name="pillow",
                version_min="8.0.0",
                check_command="python -c \"from PIL import Image\"",
                install_command="pip install Pillow>=8.0.0",
                required=True
            ),
            Dependency(
                name="faster-whisper",
                check_command="python -c \"import faster_whisper\"",
                install_command="pip install faster-whisper",
                required=True
            ),
            Dependency(
                name="sounddevice",
                check_command="python -c \"import sounddevice\"",
                install_command="pip install sounddevice",
                required=True
            )
        ]

    def _create_default_features(self) -> List[Feature]:
        """Create default optional features."""
        return [
            Feature(
                name="visual_indicators",
                description="Enhanced visual status indicators",
                enabled=True,
                size_mb=2.0
            ),
            Feature(
                name="control_center",
                description="Advanced control center interface",
                enabled=True,
                dependencies=["tkinter"],
                size_mb=5.0
            ),
            Feature(
                name="performance_monitoring",
                description="Real-time performance monitoring",
                enabled=True,
                dependencies=["psutil"],
                size_mb=1.5
            ),
            Feature(
                name="stability_testing",
                description="Built-in stability testing tools",
                enabled=False,
                dependencies=["pytest"],
                size_mb=3.0
            )
        ]

    def _create_default_validation_checks(self) -> List[ValidationCheck]:
        """Create default validation checks."""
        return [
            ValidationCheck(
                name="Platform Compatibility",
                check_type="platform",
                required=True
            ),
            ValidationCheck(
                name="Python Version",
                check_type="python",
                required=True
            ),
            ValidationCheck(
                name="Disk Space",
                check_type="disk",
                required=True
            ),
            ValidationCheck(
                name="Installation Permissions",
                check_type="permissions",
                required=True
            ),
            ValidationCheck(
                name="Dependencies",
                check_type="dependencies",
                required=True
            )
        ]

    def validate(self) -> None:
        """
        Validate installer configuration parameters.
        Raises ValueError if configuration is invalid.
        """
        # Validate platform
        supported_platforms = {"windows", "win32", "win64"}
        if self.target_platform.lower() not in supported_platforms:
            raise ValueError(f"Unsupported platform '{self.target_platform}'. Supported: {supported_platforms}")

        # Validate Python version format
        if not self._is_valid_python_version(self.python_version):
            raise ValueError(f"Invalid Python version format: {self.python_version}")

        # Validate install path
        if not isinstance(self.install_path, Path):
            raise ValueError("install_path must be a Path object")

        # Validate lists
        if not isinstance(self.required_dependencies, list):
            raise ValueError("required_dependencies must be a list")

        if not isinstance(self.optional_features, list):
            raise ValueError("optional_features must be a list")

        if not isinstance(self.validation_checks, list):
            raise ValueError("validation_checks must be a list")

    def _is_valid_python_version(self, version: str) -> bool:
        """Check if Python version string is valid."""
        if not version:
            return False

        # Handle "3.9+" format
        if version.endswith('+'):
            version = version[:-1]

        # Basic version format check
        parts = version.split('.')
        if len(parts) < 2 or len(parts) > 3:
            return False

        try:
            major = int(parts[0])
            minor = int(parts[1])
            # Python 3.9-3.12 supported
            return major == 3 and 9 <= minor <= 12
        except ValueError:
            return False

    def is_constitutional_compliant(self) -> bool:
        """
        Check if installer configuration meets constitutional requirements.

        Constitutional Requirements:
        - Must target supported Windows versions only
        - Python version must be in supported range (3.9-3.12)
        - Installation must be user-local (no admin rights required)
        - Must include rollback capability for safety
        - Resource usage must be reasonable (<100MB for base install)

        Returns:
            True if configuration meets constitutional requirements
        """
        with self._lock:
            # Platform requirement (Windows-First principle)
            if self.target_platform.lower() not in {"windows", "win32", "win64"}:
                return False

            # Python version requirement
            if not self._is_valid_python_version(self.python_version):
                return False

            # User-local installation (no admin rights)
            if self.install_path and self.install_path.is_absolute():
                # Check if path is in user directory
                try:
                    user_home = Path.home()
                    if not str(self.install_path).startswith(str(user_home)):
                        # Allow temp directory and local app data
                        temp_dir = Path(tempfile.gettempdir())
                        if not str(self.install_path).startswith(str(temp_dir)):
                            return False
                except Exception:
                    return False

            # Rollback requirement for safety
            if not self.rollback_enabled:
                return False

            # Resource usage check
            total_size = sum(feature.size_mb for feature in self.optional_features if feature.enabled)
            if total_size > 100:  # Constitutional limit: 100MB
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
            # Platform check
            if self.target_platform.lower() not in {"windows", "win32", "win64"}:
                violations["platform_violation"] = (
                    f"Platform '{self.target_platform}' violates Windows-First principle"
                )

            # Python version check
            if not self._is_valid_python_version(self.python_version):
                violations["python_violation"] = (
                    f"Python version '{self.python_version}' not in supported range (3.9-3.12)"
                )

            # Installation path check
            if self.install_path and self.install_path.is_absolute():
                try:
                    user_home = Path.home()
                    temp_dir = Path(tempfile.gettempdir())
                    if (not str(self.install_path).startswith(str(user_home)) and
                        not str(self.install_path).startswith(str(temp_dir))):
                        violations["path_violation"] = (
                            f"Install path '{self.install_path}' may require admin rights "
                            f"(should be in user directory)"
                        )
                except Exception:
                    violations["path_validation_error"] = "Unable to validate install path"

            # Rollback check
            if not self.rollback_enabled:
                violations["rollback_violation"] = (
                    "Rollback disabled violates safety requirements"
                )

            # Resource usage check
            total_size = sum(feature.size_mb for feature in self.optional_features if feature.enabled)
            if total_size > 100:
                violations["size_violation"] = (
                    f"Total installation size {total_size:.1f}MB exceeds "
                    f"constitutional limit of 100MB"
                )

        return violations

    def run_validation_checks(self) -> Dict[str, ValidationResult]:
        """
        Execute all validation checks and return results.

        Returns:
            Dictionary mapping check names to results
        """
        results = {}

        with self._lock:
            for check in self.validation_checks:
                try:
                    if check.check_type == "platform":
                        result = self._check_platform()
                    elif check.check_type == "python":
                        result = self._check_python_version()
                    elif check.check_type == "disk":
                        result = self._check_disk_space()
                    elif check.check_type == "permissions":
                        result = self._check_permissions()
                    elif check.check_type == "dependencies":
                        result = self._check_dependencies()
                    else:
                        result = ValidationResult.SKIPPED

                    check.result = result
                    results[check.name] = result

                except Exception as e:
                    check.result = ValidationResult.FAILED
                    check.message = str(e)
                    results[check.name] = ValidationResult.FAILED

        return results

    def _check_platform(self) -> ValidationResult:
        """Check platform compatibility."""
        if sys.platform.startswith('win'):
            return ValidationResult.PASSED
        return ValidationResult.FAILED

    def _check_python_version(self) -> ValidationResult:
        """Check Python version compatibility."""
        current_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        if self._is_valid_python_version(current_version):
            return ValidationResult.PASSED
        return ValidationResult.FAILED

    def _check_disk_space(self) -> ValidationResult:
        """Check available disk space."""
        try:
            if self.install_path:
                # Get parent directory that exists
                check_path = self.install_path
                while not check_path.exists() and check_path.parent != check_path:
                    check_path = check_path.parent

                # Check available space (simplified)
                total_size = sum(feature.size_mb for feature in self.optional_features if feature.enabled)
                required_mb = max(total_size * 2, 50)  # At least 50MB, double the install size

                if hasattr(os, 'statvfs'):  # Unix-like
                    stat = os.statvfs(check_path)
                    available_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
                else:  # Windows
                    import shutil
                    available_mb = shutil.disk_usage(check_path)[2] / (1024 * 1024)

                return ValidationResult.PASSED if available_mb > required_mb else ValidationResult.FAILED

        except Exception:
            return ValidationResult.WARNING

        return ValidationResult.SKIPPED

    def _check_permissions(self) -> ValidationResult:
        """Check installation permissions."""
        try:
            if self.install_path:
                parent = self.install_path.parent
                # Check if we can write to the parent directory
                if parent.exists():
                    return ValidationResult.PASSED if os.access(parent, os.W_OK) else ValidationResult.FAILED
                else:
                    # Try to create the directory structure
                    try:
                        parent.mkdir(parents=True, exist_ok=True)
                        return ValidationResult.PASSED
                    except PermissionError:
                        return ValidationResult.FAILED
        except Exception:
            return ValidationResult.WARNING

        return ValidationResult.SKIPPED

    def _check_dependencies(self) -> ValidationResult:
        """Check required dependencies."""
        failed_deps = []

        for dep in self.required_dependencies:
            if dep.required and dep.check_command:
                try:
                    result = os.system(dep.check_command + " > nul 2>&1")  # Windows null device
                    if result != 0:
                        failed_deps.append(dep.name)
                except Exception:
                    failed_deps.append(dep.name)

        return ValidationResult.PASSED if not failed_deps else ValidationResult.FAILED

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize InstallerConfiguration to dictionary.

        Returns:
            Dictionary representation
        """
        with self._lock:
            return {
                "target_platform": self.target_platform,
                "python_version": self.python_version,
                "install_path": str(self.install_path) if self.install_path else None,
                "rollback_enabled": self.rollback_enabled,
                "required_dependencies": [
                    {
                        "name": dep.name,
                        "version_min": dep.version_min,
                        "version_max": dep.version_max,
                        "required": dep.required,
                        "check_command": dep.check_command,
                        "install_command": dep.install_command
                    }
                    for dep in self.required_dependencies
                ],
                "optional_features": [
                    {
                        "name": feat.name,
                        "description": feat.description,
                        "enabled": feat.enabled,
                        "dependencies": feat.dependencies,
                        "size_mb": feat.size_mb
                    }
                    for feat in self.optional_features
                ],
                "validation_checks": [
                    {
                        "name": check.name,
                        "check_type": check.check_type,
                        "result": check.result.value,
                        "message": check.message,
                        "required": check.required
                    }
                    for check in self.validation_checks
                ],
                "constitutional_compliant": self.is_constitutional_compliant(),
                "violations": self.get_compliance_violations()
            }

    def get_installation_summary(self) -> Dict[str, Any]:
        """
        Get installation summary for display.

        Returns:
            Dictionary with installation details
        """
        enabled_features = [f for f in self.optional_features if f.enabled]
        total_size = sum(f.size_mb for f in enabled_features)

        return {
            "platform": self.target_platform,
            "python_version": self.python_version,
            "install_path": str(self.install_path),
            "rollback_enabled": self.rollback_enabled,
            "feature_count": len(enabled_features),
            "total_size_mb": round(total_size, 1),
            "dependency_count": len([d for d in self.required_dependencies if d.required]),
            "constitutional_compliant": self.is_constitutional_compliant()
        }

    def __str__(self) -> str:
        """String representation of InstallerConfiguration."""
        compliant = "✅" if self.is_constitutional_compliant() else "❌"
        rollback = "🔄" if self.rollback_enabled else ""

        enabled_features = len([f for f in self.optional_features if f.enabled])
        total_size = sum(f.size_mb for f in self.optional_features if f.enabled)

        return (
            f"InstallerConfig({self.target_platform}): "
            f"Python {self.python_version} → {self.install_path} "
            f"[{enabled_features} features, {total_size:.1f}MB] "
            f"{rollback} {compliant}"
        )