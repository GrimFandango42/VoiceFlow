"""Pytest configuration and shared fixtures for the VoiceFlow test suite.

Ensures `src/` package imports resolve correctly (`voiceflow.*`) and provides
shared fixtures for tray, installer, and stability-related tests.
"""
from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, Any
from unittest.mock import Mock, MagicMock

import pytest

def pytest_configure(config):
    """Configure pytest and add project root to Python path."""
    root = Path(__file__).resolve().parent.parent
    src = root / "src"

    # Keep src first so `import voiceflow` resolves to the package in src/,
    # not the root-level voiceflow.py launcher script.
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    if str(root) not in sys.path:
        sys.path.append(str(root))

# Test Fixtures for Enhanced Functionality

@pytest.fixture
def mock_tray_state():
    """Mock TrayState for testing tray functionality."""
    mock_state = Mock()
    mock_state.status = "IDLE"
    mock_state.icon_path = "assets/icon_idle.ico"
    mock_state.menu_items = []
    mock_state.tooltip_text = "VoiceFlow Ready"
    mock_state.last_updated = None
    mock_state.notification_queue = []
    return mock_state

@pytest.fixture
def mock_system_performance():
    """Mock SystemPerformance for constitutional compliance testing."""
    mock_perf = Mock()
    mock_perf.response_time_ms = 150.0
    mock_perf.memory_usage_mb = 180.0
    mock_perf.cpu_usage_percent = 25.0
    mock_perf.audio_latency_ms = 50.0
    mock_perf.timestamp = None
    mock_perf.component = "test"
    return mock_perf

@pytest.fixture
def mock_installer_config():
    """Mock InstallerConfiguration for installer testing."""
    mock_config = Mock()
    mock_config.target_platform = "Windows 11"
    mock_config.python_version = "3.9+"
    mock_config.install_path = Path(tempfile.gettempdir()) / "voiceflow_test"
    mock_config.required_dependencies = ["pytest", "pystray"]
    mock_config.optional_features = ["gpu_acceleration"]
    mock_config.validation_checks = []
    mock_config.rollback_enabled = True
    return mock_config

@pytest.fixture
def mock_audio_device():
    """Mock audio device for testing without hardware dependency."""
    mock_device = Mock()
    mock_device.name = "Test Audio Device"
    mock_device.channels = 1
    mock_device.sample_rate = 44100
    mock_device.available = True
    return mock_device

@pytest.fixture
def temp_config_dir(tmp_path):
    """Temporary directory for configuration files."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    return config_dir

@pytest.fixture
def mock_control_center_state():
    """Mock ControlCenterState for GUI testing."""
    mock_state = Mock()
    mock_state.active_tab = "dashboard"
    mock_state.log_filter = ""
    mock_state.monitoring_enabled = True
    mock_state.window_geometry = {"x": 100, "y": 100, "width": 800, "height": 600}
    mock_state.auto_refresh_interval = 5
    mock_state.visible = True
    return mock_state

@pytest.fixture
def mock_test_configuration():
    """Mock TestConfiguration for test infrastructure testing."""
    mock_config = Mock()
    mock_config.test_category = "UNIT"
    mock_config.environment = "test"
    mock_config.timeout_seconds = 60
    mock_config.required_resources = ["memory", "filesystem"]
    mock_config.parallel_safe = True
    mock_config.cleanup_required = False
    mock_config.dependencies = []
    return mock_config

@pytest.fixture
def performance_monitor():
    """Mock performance monitor for constitutional compliance testing."""
    mock_monitor = Mock()
    mock_monitor.start_monitoring = Mock()
    mock_monitor.stop_monitoring = Mock()
    mock_monitor.get_current_metrics = Mock(return_value={
        "response_time_ms": 150,
        "memory_usage_mb": 180,
        "cpu_usage_percent": 25,
        "constitutional_compliant": True
    })
    return mock_monitor

@pytest.fixture
def mock_windows_system():
    """Mock Windows system environment for platform-specific testing."""
    mock_system = Mock()
    mock_system.platform = "Windows"
    mock_system.version = "11"
    mock_system.has_audio_devices = Mock(return_value=True)
    mock_system.tray_supported = Mock(return_value=True)
    mock_system.permissions_check = Mock(return_value=True)
    return mock_system

@pytest.fixture
def stability_test_session():
    """Session fixture for stability testing."""
    session_data = {
        "start_time": time.time(),
        "operations_count": 0,
        "errors": [],
        "performance_samples": [],
        "active": False
    }

    def start_session():
        session_data["active"] = True
        session_data["start_time"] = time.time()

    def stop_session():
        session_data["active"] = False

    def add_operation():
        session_data["operations_count"] += 1

    def add_error(error):
        session_data["errors"].append(error)

    session_data["start"] = start_session
    session_data["stop"] = stop_session
    session_data["add_operation"] = add_operation
    session_data["add_error"] = add_error

    return session_data

# Test Markers and Configuration Helpers

def pytest_runtest_setup(item):
    """Setup for individual test items."""
    # Mark GUI tests for conditional skipping in headless environments
    if "gui" in item.keywords and not has_display():
        pytest.skip("GUI tests require display")

    # Mark audio tests for conditional skipping without audio hardware
    if "audio" in item.keywords and not has_audio_devices():
        pytest.skip("Audio tests require audio hardware")

def has_display():
    """Check if display is available for GUI tests."""
    try:
        import tkinter
        root = tkinter.Tk()
        root.destroy()
        return True
    except Exception:
        return False

def has_audio_devices():
    """Check if audio devices are available for audio tests."""
    try:
        import sounddevice as sd
        devices = sd.query_devices()
        return len(devices) > 0
    except Exception:
        return False

@pytest.fixture
def constitutional_compliance_checker():
    """Fixture for validating constitutional compliance during tests."""
    def check_compliance(metrics: Dict[str, Any]) -> bool:
        """Check if metrics meet constitutional requirements."""
        response_time = metrics.get("response_time_ms", float('inf'))
        memory_usage = metrics.get("memory_usage_mb", float('inf'))

        # Constitutional requirements
        if response_time > 200:  # Must be <= 200ms
            return False
        if memory_usage > 200:  # Must be <= 200MB idle
            return False

        return True

    return check_compliance
