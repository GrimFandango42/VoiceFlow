"""
Contract tests for ISystemValidator interface.
Tests that any implementation of ISystemValidator follows the contract specification.
"""

import pytest
from unittest.mock import Mock
from pathlib import Path
from typing import Dict, Any

# Import the contract interfaces from the specs
import sys
from pathlib import Path
spec_contracts_path = Path(__file__).parent.parent.parent / "specs" / "clean-tray-tests-installer-enh" / "contracts"
sys.path.insert(0, str(spec_contracts_path))

from installer_interface import ISystemValidator, ValidationResult


class MockSystemValidator(ISystemValidator):
    """Mock implementation for testing contract compliance."""

    def __init__(self):
        self.system_info = {
            "python_version": "3.11.0",
            "windows_version": "Windows 11",
            "audio_devices": ["Default Audio Device"],
            "disk_space_mb": 10000,
            "has_admin_rights": True
        }

    def validate_python_version(self, required_version: str) -> ValidationResult:
        current = self.system_info["python_version"]
        # Simple version comparison for mock
        if current >= required_version:
            return ValidationResult.PASS
        return ValidationResult.FAIL

    def validate_windows_version(self) -> ValidationResult:
        windows_version = self.system_info["windows_version"]
        if "Windows 10" in windows_version or "Windows 11" in windows_version:
            return ValidationResult.PASS
        return ValidationResult.WARNING

    def validate_audio_devices(self) -> ValidationResult:
        audio_devices = self.system_info["audio_devices"]
        if len(audio_devices) > 0:
            return ValidationResult.PASS
        return ValidationResult.FAIL

    def validate_disk_space(self, required_mb: int) -> ValidationResult:
        available = self.system_info["disk_space_mb"]
        if available >= required_mb:
            return ValidationResult.PASS
        return ValidationResult.FAIL

    def validate_permissions(self, install_path: Path) -> ValidationResult:
        if self.system_info["has_admin_rights"]:
            return ValidationResult.PASS
        return ValidationResult.WARNING

    def detect_gpu_acceleration(self) -> Dict[str, Any]:
        return {
            "cuda_available": False,
            "gpu_name": None,
            "driver_version": None,
            "memory_gb": 0,
            "compute_capability": None
        }

    # Helper methods for testing
    def set_system_info(self, key: str, value: Any):
        self.system_info[key] = value


@pytest.mark.contract
class TestISystemValidatorContract:
    """Test the ISystemValidator interface contract."""

    @pytest.fixture
    def system_validator(self):
        """Fixture providing a mock ISystemValidator implementation."""
        return MockSystemValidator()

    def test_interface_compliance(self, system_validator):
        """Test that implementation properly inherits from ISystemValidator."""
        assert isinstance(system_validator, ISystemValidator)
        assert hasattr(system_validator, 'validate_python_version')
        assert hasattr(system_validator, 'validate_windows_version')
        assert hasattr(system_validator, 'validate_audio_devices')
        assert hasattr(system_validator, 'validate_disk_space')
        assert hasattr(system_validator, 'validate_permissions')
        assert hasattr(system_validator, 'detect_gpu_acceleration')

    def test_validate_python_version_contract(self, system_validator):
        """Test validate_python_version method contract."""
        # Should return ValidationResult enum
        result = system_validator.validate_python_version("3.9")
        assert isinstance(result, ValidationResult)

        # Should handle different version requirements
        result_old = system_validator.validate_python_version("3.8")
        result_new = system_validator.validate_python_version("4.0")

        assert isinstance(result_old, ValidationResult)
        assert isinstance(result_new, ValidationResult)

        # Should pass for supported versions
        result_supported = system_validator.validate_python_version("3.9")
        assert result_supported in [ValidationResult.PASS, ValidationResult.WARNING]

    def test_validate_windows_version_contract(self, system_validator):
        """Test validate_windows_version method contract."""
        # Should return ValidationResult enum
        result = system_validator.validate_windows_version()
        assert isinstance(result, ValidationResult)

        # Should identify supported Windows versions
        system_validator.set_system_info("windows_version", "Windows 11")
        result_win11 = system_validator.validate_windows_version()
        assert result_win11 == ValidationResult.PASS

        system_validator.set_system_info("windows_version", "Windows 10")
        result_win10 = system_validator.validate_windows_version()
        assert result_win10 == ValidationResult.PASS

    def test_validate_audio_devices_contract(self, system_validator):
        """Test validate_audio_devices method contract."""
        # Should return ValidationResult enum
        result = system_validator.validate_audio_devices()
        assert isinstance(result, ValidationResult)

        # Should detect when audio devices are available
        system_validator.set_system_info("audio_devices", ["Test Device"])
        result_available = system_validator.validate_audio_devices()
        assert result_available == ValidationResult.PASS

        # Should detect when no audio devices
        system_validator.set_system_info("audio_devices", [])
        result_none = system_validator.validate_audio_devices()
        assert result_none == ValidationResult.FAIL

    def test_validate_disk_space_contract(self, system_validator):
        """Test validate_disk_space method contract."""
        # Should accept required_mb parameter and return ValidationResult
        result = system_validator.validate_disk_space(1000)
        assert isinstance(result, ValidationResult)

        # Should validate sufficient space
        system_validator.set_system_info("disk_space_mb", 5000)
        result_enough = system_validator.validate_disk_space(1000)
        assert result_enough == ValidationResult.PASS

        # Should detect insufficient space
        system_validator.set_system_info("disk_space_mb", 500)
        result_not_enough = system_validator.validate_disk_space(1000)
        assert result_not_enough == ValidationResult.FAIL

    def test_validate_permissions_contract(self, system_validator):
        """Test validate_permissions method contract."""
        # Should accept Path parameter and return ValidationResult
        install_path = Path("C:/Program Files/VoiceFlow")
        result = system_validator.validate_permissions(install_path)
        assert isinstance(result, ValidationResult)

        # Should handle different permission scenarios
        system_validator.set_system_info("has_admin_rights", True)
        result_admin = system_validator.validate_permissions(install_path)
        assert result_admin == ValidationResult.PASS

        system_validator.set_system_info("has_admin_rights", False)
        result_no_admin = system_validator.validate_permissions(install_path)
        assert result_no_admin in [ValidationResult.WARNING, ValidationResult.FAIL]

    def test_detect_gpu_acceleration_contract(self, system_validator):
        """Test detect_gpu_acceleration method contract."""
        # Should return dictionary with GPU information
        result = system_validator.detect_gpu_acceleration()
        assert isinstance(result, dict)

        # Should include expected GPU information fields
        expected_fields = ["cuda_available", "gpu_name", "driver_version", "memory_gb"]
        for field in expected_fields:
            assert field in result

        # Should handle no GPU scenario
        assert isinstance(result["cuda_available"], bool)
        assert result["memory_gb"] >= 0

    def test_validation_performance_contract(self, system_validator):
        """Test that validations complete within reasonable time."""
        import time

        # All validations should complete within 30 seconds total
        start_time = time.time()

        system_validator.validate_python_version("3.9")
        system_validator.validate_windows_version()
        system_validator.validate_audio_devices()
        system_validator.validate_disk_space(1000)
        system_validator.validate_permissions(Path("/test"))

        total_time = time.time() - start_time
        assert total_time < 30, f"All validations took {total_time}s, should be < 30s"

    def test_constitutional_compliance_validation(self, system_validator):
        """Test validation supports constitutional compliance requirements."""
        # Should validate Python version meets constitutional requirements
        result = system_validator.validate_python_version("3.9")
        assert isinstance(result, ValidationResult)

        # Should validate Windows platform requirement
        result = system_validator.validate_windows_version()
        assert isinstance(result, ValidationResult)

        # Should validate audio capability for voice transcription
        result = system_validator.validate_audio_devices()
        assert isinstance(result, ValidationResult)

    def test_windows_specific_validation(self, system_validator):
        """Test Windows-specific validation capabilities."""
        # Should specifically validate Windows versions
        windows_result = system_validator.validate_windows_version()
        assert isinstance(windows_result, ValidationResult)

        # Should detect Windows audio system
        audio_result = system_validator.validate_audio_devices()
        assert isinstance(audio_result, ValidationResult)

        # Should validate Windows file system permissions
        path_result = system_validator.validate_permissions(Path("C:/Test"))
        assert isinstance(path_result, ValidationResult)

    def test_error_handling_contract(self, system_validator):
        """Test error handling in system validation."""
        # Should handle edge cases gracefully
        try:
            # Test with extreme values
            result = system_validator.validate_disk_space(999999999)
            assert isinstance(result, ValidationResult)
        except Exception as e:
            pytest.fail(f"validate_disk_space should handle large values: {e}")

        try:
            # Test with invalid paths
            result = system_validator.validate_permissions(Path(""))
            assert isinstance(result, ValidationResult)
        except Exception as e:
            pytest.fail(f"validate_permissions should handle empty paths: {e}")

    def test_comprehensive_system_check(self, system_validator):
        """Test comprehensive system validation workflow."""
        # Should be able to run all validations together
        results = {
            "python": system_validator.validate_python_version("3.9"),
            "windows": system_validator.validate_windows_version(),
            "audio": system_validator.validate_audio_devices(),
            "disk": system_validator.validate_disk_space(2000),
            "permissions": system_validator.validate_permissions(Path("C:/VoiceFlow"))
        }

        # All should return validation results
        for check_name, result in results.items():
            assert isinstance(result, ValidationResult), f"{check_name} check failed"

        # Should provide GPU information
        gpu_info = system_validator.detect_gpu_acceleration()
        assert isinstance(gpu_info, dict)


@pytest.mark.contract
def test_validation_result_enum_contract():
    """Test ValidationResult enum contract."""
    # Should have all required result values
    assert hasattr(ValidationResult, 'PASS')
    assert hasattr(ValidationResult, 'FAIL')
    assert hasattr(ValidationResult, 'WARNING')
    assert hasattr(ValidationResult, 'SKIP')

    # Should be string-valued for serialization
    assert ValidationResult.PASS.value == "pass"
    assert ValidationResult.FAIL.value == "fail"
    assert ValidationResult.WARNING.value == "warning"
    assert ValidationResult.SKIP.value == "skip"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])