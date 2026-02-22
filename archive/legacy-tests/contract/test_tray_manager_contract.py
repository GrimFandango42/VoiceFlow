"""
Contract tests for ITrayManager interface.
Tests that any implementation of ITrayManager follows the contract specification.
"""

import pytest
from unittest.mock import Mock
from abc import ABC

# Import the contract interfaces from the specs
import sys
from pathlib import Path
spec_contracts_path = Path(__file__).parent.parent.parent / "specs" / "clean-tray-tests-installer-enh" / "contracts"
sys.path.insert(0, str(spec_contracts_path))

from tray_interface import ITrayManager, TrayStatus, TrayMenuItem


class MockTrayManager(ITrayManager):
    """Mock implementation for testing contract compliance."""

    def __init__(self):
        self.initialized = False
        self.current_status = TrayStatus.IDLE
        self.current_menu = []
        self.current_tooltip = ""
        self.status_callbacks = []

    def initialize(self) -> bool:
        self.initialized = True
        return True

    def update_status(self, status: TrayStatus, message: str = "") -> None:
        self.current_status = status
        for callback in self.status_callbacks:
            callback(status)

    def update_menu(self, items):
        self.current_menu = items

    def show_notification(self, title: str, message: str, duration: int = 3000) -> None:
        # Mock implementation - would show system notification
        pass

    def set_tooltip(self, text: str) -> None:
        if len(text) > 64:
            text = text[:64]  # Windows limitation
        self.current_tooltip = text

    def get_current_status(self) -> TrayStatus:
        return self.current_status

    def register_status_callback(self, callback) -> None:
        self.status_callbacks.append(callback)

    def shutdown(self) -> None:
        self.initialized = False
        self.status_callbacks.clear()


@pytest.mark.contract
class TestITrayManagerContract:
    """Test the ITrayManager interface contract."""

    @pytest.fixture
    def tray_manager(self):
        """Fixture providing a mock ITrayManager implementation."""
        return MockTrayManager()

    def test_interface_compliance(self, tray_manager):
        """Test that implementation properly inherits from ITrayManager."""
        assert isinstance(tray_manager, ITrayManager)
        assert hasattr(tray_manager, 'initialize')
        assert hasattr(tray_manager, 'update_status')
        assert hasattr(tray_manager, 'update_menu')
        assert hasattr(tray_manager, 'show_notification')
        assert hasattr(tray_manager, 'set_tooltip')
        assert hasattr(tray_manager, 'get_current_status')
        assert hasattr(tray_manager, 'register_status_callback')
        assert hasattr(tray_manager, 'shutdown')

    def test_initialize_contract(self, tray_manager):
        """Test initialize method contract."""
        # Should return boolean
        result = tray_manager.initialize()
        assert isinstance(result, bool)
        assert result is True  # Mock always returns True

    def test_update_status_contract(self, tray_manager):
        """Test update_status method contract."""
        # Should accept TrayStatus enum
        tray_manager.update_status(TrayStatus.RECORDING)
        assert tray_manager.get_current_status() == TrayStatus.RECORDING

        # Should accept optional message parameter
        tray_manager.update_status(TrayStatus.PROCESSING, "Processing audio...")
        assert tray_manager.get_current_status() == TrayStatus.PROCESSING

        # Should handle all TrayStatus values
        for status in TrayStatus:
            tray_manager.update_status(status)
            assert tray_manager.get_current_status() == status

    def test_update_menu_contract(self, tray_manager):
        """Test update_menu method contract."""
        # Should accept list of TrayMenuItem objects
        menu_items = [
            TrayMenuItem("Test Item", lambda: None),
            TrayMenuItem("Disabled Item", lambda: None, enabled=False),
            TrayMenuItem("Separator", lambda: None, separator=True)
        ]

        # Should not raise exception
        tray_manager.update_menu(menu_items)

        # Should handle empty list
        tray_manager.update_menu([])

    def test_show_notification_contract(self, tray_manager):
        """Test show_notification method contract."""
        # Should accept title and message strings
        tray_manager.show_notification("Test Title", "Test Message")

        # Should accept optional duration parameter
        tray_manager.show_notification("Test", "Message", duration=5000)

        # Should handle empty strings
        tray_manager.show_notification("", "")

    def test_set_tooltip_contract(self, tray_manager):
        """Test set_tooltip method contract."""
        # Should accept string parameter
        tray_manager.set_tooltip("Test tooltip")
        assert tray_manager.current_tooltip == "Test tooltip"

        # Should handle Windows 64-character limitation
        long_text = "A" * 100
        tray_manager.set_tooltip(long_text)
        assert len(tray_manager.current_tooltip) <= 64

        # Should handle empty string
        tray_manager.set_tooltip("")
        assert tray_manager.current_tooltip == ""

    def test_get_current_status_contract(self, tray_manager):
        """Test get_current_status method contract."""
        # Should return TrayStatus enum
        status = tray_manager.get_current_status()
        assert isinstance(status, TrayStatus)
        assert status == TrayStatus.IDLE  # Default state

    def test_register_status_callback_contract(self, tray_manager):
        """Test register_status_callback method contract."""
        callback_called = []

        def status_callback(status):
            callback_called.append(status)

        # Should accept callable parameter
        tray_manager.register_status_callback(status_callback)

        # Callback should be called when status changes
        tray_manager.update_status(TrayStatus.RECORDING)
        assert len(callback_called) == 1
        assert callback_called[0] == TrayStatus.RECORDING

    def test_shutdown_contract(self, tray_manager):
        """Test shutdown method contract."""
        # Should properly cleanup resources
        tray_manager.initialize()
        assert tray_manager.initialized is True

        tray_manager.shutdown()
        assert tray_manager.initialized is False

    def test_performance_contract(self, tray_manager):
        """Test performance requirements from constitutional compliance."""
        import time

        tray_manager.initialize()

        # update_status should respond within 50ms (well under 200ms requirement)
        start_time = time.time()
        tray_manager.update_status(TrayStatus.RECORDING)
        duration_ms = (time.time() - start_time) * 1000
        assert duration_ms < 50, f"update_status took {duration_ms}ms, should be < 50ms"

        # show_notification should be non-blocking
        start_time = time.time()
        tray_manager.show_notification("Test", "Test notification")
        duration_ms = (time.time() - start_time) * 1000
        assert duration_ms < 10, f"show_notification took {duration_ms}ms, should be non-blocking"

    def test_windows_limitations_contract(self, tray_manager):
        """Test Windows-specific limitations are handled."""
        # Tooltip should be limited to 64 characters
        long_tooltip = "This is a very long tooltip that exceeds the Windows limit of 64 characters"
        tray_manager.set_tooltip(long_tooltip)
        assert len(tray_manager.current_tooltip) <= 64

        # Should handle all valid TrayStatus transitions
        valid_transitions = [
            (TrayStatus.IDLE, TrayStatus.RECORDING),
            (TrayStatus.RECORDING, TrayStatus.PROCESSING),
            (TrayStatus.PROCESSING, TrayStatus.IDLE),
            (TrayStatus.ERROR, TrayStatus.IDLE)
        ]

        for from_status, to_status in valid_transitions:
            tray_manager.update_status(from_status)
            tray_manager.update_status(to_status)
            assert tray_manager.get_current_status() == to_status


@pytest.mark.contract
def test_tray_menu_item_contract():
    """Test TrayMenuItem class contract."""
    # Should create with required parameters
    item = TrayMenuItem("Test", lambda: None)
    assert item.text == "Test"
    assert callable(item.action)
    assert item.enabled is True
    assert item.separator is False

    # Should create with all parameters
    item = TrayMenuItem("Disabled", lambda: None, enabled=False, separator=True)
    assert item.enabled is False
    assert item.separator is True


@pytest.mark.contract
def test_tray_status_enum_contract():
    """Test TrayStatus enum contract."""
    # Should have all required status values
    assert hasattr(TrayStatus, 'IDLE')
    assert hasattr(TrayStatus, 'RECORDING')
    assert hasattr(TrayStatus, 'PROCESSING')
    assert hasattr(TrayStatus, 'ERROR')

    # Should be string-valued for serialization
    assert TrayStatus.IDLE.value == "idle"
    assert TrayStatus.RECORDING.value == "recording"
    assert TrayStatus.PROCESSING.value == "processing"
    assert TrayStatus.ERROR.value == "error"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])