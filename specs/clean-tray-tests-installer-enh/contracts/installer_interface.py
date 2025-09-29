"""
Contract: Installer Interface
Defines the interface contract for enhanced installation and setup processes
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Optional, Callable, Any
from dataclasses import dataclass
from pathlib import Path


class InstallationStage(Enum):
    """Installation process stages"""
    VALIDATION = "validation"
    DEPENDENCIES = "dependencies"
    INSTALLATION = "installation"
    CONFIGURATION = "configuration"
    VERIFICATION = "verification"
    COMPLETE = "complete"


class ValidationResult(Enum):
    """Validation check results"""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIP = "skip"


@dataclass
class SystemRequirement:
    """System requirement definition"""
    name: str
    description: str
    required_version: Optional[str] = None
    optional: bool = False
    validation_command: Optional[str] = None


@dataclass
class ValidationCheck:
    """Validation check definition"""
    name: str
    description: str
    check_function: Callable[[], ValidationResult]
    error_message: str
    recovery_suggestion: str


@dataclass
class InstallationProgress:
    """Installation progress tracking"""
    current_stage: InstallationStage
    progress_percent: int
    current_operation: str
    estimated_remaining_seconds: int


class ISystemValidator(ABC):
    """Contract for system validation before installation"""

    @abstractmethod
    def validate_python_version(self, required_version: str) -> ValidationResult:
        """
        Validate Python version meets requirements
        Args:
            required_version: Minimum required Python version
        Returns: Validation result
        """
        pass

    @abstractmethod
    def validate_windows_version(self) -> ValidationResult:
        """
        Validate Windows version compatibility
        Returns: Validation result
        """
        pass

    @abstractmethod
    def validate_audio_devices(self) -> ValidationResult:
        """
        Validate audio input devices are available
        Returns: Validation result
        """
        pass

    @abstractmethod
    def validate_disk_space(self, required_mb: int) -> ValidationResult:
        """
        Validate sufficient disk space
        Args:
            required_mb: Required disk space in MB
        Returns: Validation result
        """
        pass

    @abstractmethod
    def validate_permissions(self, install_path: Path) -> ValidationResult:
        """
        Validate write permissions for installation
        Args:
            install_path: Target installation path
        Returns: Validation result
        """
        pass

    @abstractmethod
    def detect_gpu_acceleration(self) -> Dict[str, Any]:
        """
        Detect available GPU acceleration options
        Returns: Dictionary with GPU capabilities
        """
        pass


class IDependencyManager(ABC):
    """Contract for dependency installation and management"""

    @abstractmethod
    def resolve_dependencies(self, requirements_file: Path) -> List[str]:
        """
        Resolve dependencies from requirements file
        Args:
            requirements_file: Path to requirements file
        Returns: List of resolved package specifications
        """
        pass

    @abstractmethod
    def install_dependency(self, package: str, progress_callback: Callable[[str, int], None]) -> bool:
        """
        Install a single dependency
        Args:
            package: Package specification to install
            progress_callback: Callback for progress updates
        Returns: True if successful
        """
        pass

    @abstractmethod
    def verify_installation(self, package: str) -> bool:
        """
        Verify package is correctly installed
        Args:
            package: Package name to verify
        Returns: True if properly installed
        """
        pass

    @abstractmethod
    def create_virtual_environment(self, path: Path) -> bool:
        """
        Create Python virtual environment
        Args:
            path: Path for virtual environment
        Returns: True if successful
        """
        pass


class IInstallerCore(ABC):
    """Contract for core installation functionality"""

    @abstractmethod
    def initialize_installation(self, config: Dict[str, Any]) -> bool:
        """
        Initialize installation process
        Args:
            config: Installation configuration
        Returns: True if initialization successful
        """
        pass

    @abstractmethod
    def execute_installation(self,
                           progress_callback: Callable[[InstallationProgress], None],
                           error_callback: Callable[[str], None]) -> bool:
        """
        Execute the installation process
        Args:
            progress_callback: Callback for progress updates
            error_callback: Callback for error handling
        Returns: True if installation successful
        """
        pass

    @abstractmethod
    def create_shortcuts(self, desktop: bool = True, start_menu: bool = True) -> bool:
        """
        Create application shortcuts
        Args:
            desktop: Create desktop shortcut
            start_menu: Create start menu entry
        Returns: True if shortcuts created
        """
        pass

    @abstractmethod
    def configure_autostart(self, enabled: bool) -> bool:
        """
        Configure application autostart
        Args:
            enabled: Enable or disable autostart
        Returns: True if configuration successful
        """
        pass

    @abstractmethod
    def rollback_installation(self) -> bool:
        """
        Rollback installation on failure
        Returns: True if rollback successful
        """
        pass


class IPostInstallValidator(ABC):
    """Contract for post-installation verification"""

    @abstractmethod
    def verify_application_launch(self) -> bool:
        """
        Verify application can launch successfully
        Returns: True if application launches
        """
        pass

    @abstractmethod
    def verify_control_center(self) -> bool:
        """
        Verify Control Center GUI is functional
        Returns: True if Control Center works
        """
        pass

    @abstractmethod
    def verify_system_tray(self) -> bool:
        """
        Verify system tray integration works
        Returns: True if tray integration successful
        """
        pass

    @abstractmethod
    def verify_audio_processing(self) -> bool:
        """
        Verify audio processing pipeline works
        Returns: True if audio processing functional
        """
        pass

    @abstractmethod
    def run_health_check(self) -> Dict[str, ValidationResult]:
        """
        Run comprehensive health check
        Returns: Dictionary of check results
        """
        pass


class IUninstaller(ABC):
    """Contract for application uninstallation"""

    @abstractmethod
    def remove_application_files(self) -> bool:
        """
        Remove application files and directories
        Returns: True if removal successful
        """
        pass

    @abstractmethod
    def remove_configuration(self, preserve_user_data: bool = True) -> bool:
        """
        Remove application configuration
        Args:
            preserve_user_data: Whether to preserve user data
        Returns: True if removal successful
        """
        pass

    @abstractmethod
    def remove_shortcuts(self) -> bool:
        """
        Remove application shortcuts
        Returns: True if removal successful
        """
        pass

    @abstractmethod
    def cleanup_registry(self) -> bool:
        """
        Clean up Windows registry entries
        Returns: True if cleanup successful
        """
        pass


# Contract validation requirements:
# 1. ISystemValidator checks must complete within 30 seconds
# 2. IDependencyManager must support offline installation mode
# 3. IInstallerCore must provide accurate progress reporting
# 4. IPostInstallValidator must verify constitutional compliance
# 5. All operations must support both GUI and silent installation modes
# 6. Error messages must be user-friendly with actionable guidance
# 7. Rollback must restore system to pre-installation state