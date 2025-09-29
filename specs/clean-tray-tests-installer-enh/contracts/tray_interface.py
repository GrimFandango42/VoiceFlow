"""
Contract: System Tray Interface
Defines the interface contract for enhanced system tray functionality
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Callable, Dict
from datetime import datetime


class TrayStatus(Enum):
    """System tray status indicators"""
    IDLE = "idle"
    RECORDING = "recording"
    PROCESSING = "processing"
    ERROR = "error"


class TrayMenuItem:
    """System tray menu item definition"""
    def __init__(self, text: str, action: Callable, enabled: bool = True, separator: bool = False):
        self.text = text
        self.action = action
        self.enabled = enabled
        self.separator = separator


class ITrayManager(ABC):
    """Contract for system tray management"""

    @abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the system tray
        Returns: True if successful, False otherwise
        """
        pass

    @abstractmethod
    def update_status(self, status: TrayStatus, message: str = "") -> None:
        """
        Update tray status and icon
        Args:
            status: New status to display
            message: Optional status message for tooltip
        """
        pass

    @abstractmethod
    def update_menu(self, items: List[TrayMenuItem]) -> None:
        """
        Update tray context menu
        Args:
            items: List of menu items to display
        """
        pass

    @abstractmethod
    def show_notification(self, title: str, message: str, duration: int = 3000) -> None:
        """
        Show system notification
        Args:
            title: Notification title
            message: Notification message
            duration: Display duration in milliseconds
        """
        pass

    @abstractmethod
    def set_tooltip(self, text: str) -> None:
        """
        Set tray icon tooltip
        Args:
            text: Tooltip text (max 64 chars for Windows)
        """
        pass

    @abstractmethod
    def get_current_status(self) -> TrayStatus:
        """
        Get current tray status
        Returns: Current status enum value
        """
        pass

    @abstractmethod
    def register_status_callback(self, callback: Callable[[TrayStatus], None]) -> None:
        """
        Register callback for status changes
        Args:
            callback: Function to call when status changes
        """
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Cleanup tray resources"""
        pass


class ITrayStatusProvider(ABC):
    """Contract for providing system status to tray"""

    @abstractmethod
    def get_system_health(self) -> Dict[str, any]:
        """
        Get current system health metrics
        Returns: Dict with health indicators
        """
        pass

    @abstractmethod
    def get_performance_metrics(self) -> Dict[str, float]:
        """
        Get current performance metrics
        Returns: Dict with performance values
        """
        pass

    @abstractmethod
    def is_recording_active(self) -> bool:
        """
        Check if voice recording is currently active
        Returns: True if recording, False otherwise
        """
        pass

    @abstractmethod
    def get_last_transcription_time(self) -> Optional[datetime]:
        """
        Get timestamp of last successful transcription
        Returns: Datetime of last transcription or None
        """
        pass


# Contract validation requirements:
# 1. ITrayManager.update_status must respond within 50ms
# 2. ITrayManager.show_notification must be non-blocking
# 3. ITrayManager.set_tooltip must truncate text to 64 characters
# 4. ITrayStatusProvider.get_performance_metrics must return current values
# 5. All methods must handle Windows system tray limitations gracefully