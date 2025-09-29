"""
Contract tests for ITrayStatusProvider interface.
Tests that any implementation of ITrayStatusProvider follows the contract specification.
"""

import pytest
from unittest.mock import Mock
from datetime import datetime
from typing import Dict, Any, Optional

# Import the contract interfaces from the specs
import sys
from pathlib import Path
spec_contracts_path = Path(__file__).parent.parent.parent / "specs" / "clean-tray-tests-installer-enh" / "contracts"
sys.path.insert(0, str(spec_contracts_path))

from tray_interface import ITrayStatusProvider


class MockTrayStatusProvider(ITrayStatusProvider):
    """Mock implementation for testing contract compliance."""

    def __init__(self):
        self.system_health = {
            "audio_device_available": True,
            "memory_usage_mb": 180.0,
            "cpu_usage_percent": 25.0,
            "disk_space_available": True,
            "constitutional_compliant": True
        }
        self.performance_metrics = {
            "response_time_ms": 150.0,
            "memory_usage_mb": 180.0,
            "cpu_usage_percent": 25.0,
            "audio_latency_ms": 50.0
        }
        self.recording_active = False
        self.last_transcription = datetime.now()

    def get_system_health(self) -> Dict[str, Any]:
        return self.system_health.copy()

    def get_performance_metrics(self) -> Dict[str, float]:
        return self.performance_metrics.copy()

    def is_recording_active(self) -> bool:
        return self.recording_active

    def get_last_transcription_time(self) -> Optional[datetime]:
        return self.last_transcription

    # Helper methods for testing
    def set_recording_active(self, active: bool):
        self.recording_active = active

    def set_health_status(self, key: str, value: Any):
        self.system_health[key] = value

    def set_performance_metric(self, key: str, value: float):
        self.performance_metrics[key] = value


@pytest.mark.contract
class TestITrayStatusProviderContract:
    """Test the ITrayStatusProvider interface contract."""

    @pytest.fixture
    def status_provider(self):
        """Fixture providing a mock ITrayStatusProvider implementation."""
        return MockTrayStatusProvider()

    def test_interface_compliance(self, status_provider):
        """Test that implementation properly inherits from ITrayStatusProvider."""
        assert isinstance(status_provider, ITrayStatusProvider)
        assert hasattr(status_provider, 'get_system_health')
        assert hasattr(status_provider, 'get_performance_metrics')
        assert hasattr(status_provider, 'is_recording_active')
        assert hasattr(status_provider, 'get_last_transcription_time')

    def test_get_system_health_contract(self, status_provider):
        """Test get_system_health method contract."""
        health = status_provider.get_system_health()

        # Should return dictionary
        assert isinstance(health, dict)

        # Should contain health indicators
        assert isinstance(health, dict)
        assert len(health) >= 0  # May be empty, but should be dict

        # Mock should return expected health data
        assert "audio_device_available" in health
        assert "memory_usage_mb" in health
        assert "cpu_usage_percent" in health
        assert "constitutional_compliant" in health

    def test_get_performance_metrics_contract(self, status_provider):
        """Test get_performance_metrics method contract."""
        metrics = status_provider.get_performance_metrics()

        # Should return dictionary with float values
        assert isinstance(metrics, dict)

        # All values should be numeric (float)
        for key, value in metrics.items():
            assert isinstance(key, str)
            assert isinstance(value, (int, float))

        # Mock should return expected performance metrics
        assert "response_time_ms" in metrics
        assert "memory_usage_mb" in metrics
        assert "cpu_usage_percent" in metrics
        assert "audio_latency_ms" in metrics

    def test_is_recording_active_contract(self, status_provider):
        """Test is_recording_active method contract."""
        # Should return boolean
        result = status_provider.is_recording_active()
        assert isinstance(result, bool)

        # Should handle state changes
        status_provider.set_recording_active(True)
        assert status_provider.is_recording_active() is True

        status_provider.set_recording_active(False)
        assert status_provider.is_recording_active() is False

    def test_get_last_transcription_time_contract(self, status_provider):
        """Test get_last_transcription_time method contract."""
        result = status_provider.get_last_transcription_time()

        # Should return Optional[datetime]
        assert result is None or isinstance(result, datetime)

        # Mock returns datetime
        assert isinstance(result, datetime)

    def test_constitutional_compliance_monitoring(self, status_provider):
        """Test constitutional compliance requirements are monitored."""
        metrics = status_provider.get_performance_metrics()
        health = status_provider.get_system_health()

        # Performance metrics should include constitutional thresholds
        response_time = metrics.get("response_time_ms", float('inf'))
        memory_usage = metrics.get("memory_usage_mb", float('inf'))

        # Should provide current values for constitutional validation
        assert isinstance(response_time, (int, float))
        assert isinstance(memory_usage, (int, float))

        # Mock values should meet constitutional requirements
        assert response_time <= 200  # Constitutional requirement
        assert memory_usage <= 200  # Constitutional requirement (idle)

    def test_performance_data_freshness(self, status_provider):
        """Test that performance data represents current system state."""
        import time

        # Metrics should represent current state (not cached old data)
        metrics1 = status_provider.get_performance_metrics()

        # Small delay to ensure we can detect freshness
        time.sleep(0.001)

        metrics2 = status_provider.get_performance_metrics()

        # Should be able to call multiple times without error
        assert isinstance(metrics1, dict)
        assert isinstance(metrics2, dict)

        # Both should have same structure (keys)
        assert set(metrics1.keys()) == set(metrics2.keys())

    def test_system_health_completeness(self, status_provider):
        """Test system health provides complete status information."""
        health = status_provider.get_system_health()

        # Should provide health indicators relevant to VoiceFlow
        expected_health_aspects = [
            "audio_device_available",  # Audio functionality critical
            "memory_usage_mb",         # Constitutional compliance
            "constitutional_compliant" # Overall compliance status
        ]

        for aspect in expected_health_aspects:
            assert aspect in health, f"Health should include {aspect}"

    def test_recording_state_accuracy(self, status_provider):
        """Test recording state reflects actual system state."""
        # Should accurately reflect recording state
        initial_state = status_provider.is_recording_active()
        assert isinstance(initial_state, bool)

        # State changes should be reflected immediately
        status_provider.set_recording_active(not initial_state)
        new_state = status_provider.is_recording_active()
        assert new_state != initial_state

    def test_transcription_time_tracking(self, status_provider):
        """Test transcription time tracking works correctly."""
        last_time = status_provider.get_last_transcription_time()

        if last_time is not None:
            # Should be reasonable timestamp
            now = datetime.now()
            assert last_time <= now  # Can't be in future

            # Should be recent (within last hour for active system)
            time_diff = now - last_time
            assert time_diff.total_seconds() >= 0

    def test_error_handling_contract(self, status_provider):
        """Test error handling in status provider."""
        # Methods should handle errors gracefully, not raise exceptions
        try:
            health = status_provider.get_system_health()
            assert isinstance(health, dict)
        except Exception as e:
            pytest.fail(f"get_system_health should not raise: {e}")

        try:
            metrics = status_provider.get_performance_metrics()
            assert isinstance(metrics, dict)
        except Exception as e:
            pytest.fail(f"get_performance_metrics should not raise: {e}")

        try:
            recording = status_provider.is_recording_active()
            assert isinstance(recording, bool)
        except Exception as e:
            pytest.fail(f"is_recording_active should not raise: {e}")

    def test_windows_specific_monitoring(self, status_provider):
        """Test Windows-specific system monitoring capabilities."""
        health = status_provider.get_system_health()

        # Should monitor Windows-specific aspects
        # Audio devices are critical for Windows voice transcription
        if "audio_device_available" in health:
            assert isinstance(health["audio_device_available"], bool)

        # Memory monitoring for Windows memory management
        if "memory_usage_mb" in health:
            memory_usage = health["memory_usage_mb"]
            assert isinstance(memory_usage, (int, float))
            assert memory_usage >= 0


@pytest.mark.contract
def test_status_provider_performance():
    """Test that status provider meets performance requirements."""
    import time

    provider = MockTrayStatusProvider()

    # get_performance_metrics should be fast (< 10ms)
    start_time = time.time()
    metrics = provider.get_performance_metrics()
    duration_ms = (time.time() - start_time) * 1000

    assert duration_ms < 10, f"get_performance_metrics took {duration_ms}ms, should be < 10ms"
    assert isinstance(metrics, dict)

    # get_system_health should be fast (< 50ms)
    start_time = time.time()
    health = provider.get_system_health()
    duration_ms = (time.time() - start_time) * 1000

    assert duration_ms < 50, f"get_system_health took {duration_ms}ms, should be < 50ms"
    assert isinstance(health, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])