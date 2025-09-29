"""
TrayState model for VoiceFlow system tray functionality.
Manages tray status, icons, menus, and notifications with Windows-specific optimizations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Callable, Dict, Any
import threading
import time


class TrayStatus(Enum):
    """System tray status indicators."""
    IDLE = "idle"
    RECORDING = "recording"
    PROCESSING = "processing"
    ERROR = "error"


@dataclass
class TrayMenuItem:
    """System tray menu item definition."""
    text: str
    action: Callable
    enabled: bool = True
    separator: bool = False

    def __post_init__(self):
        """Validate menu item after creation."""
        if not self.text and not self.separator:
            raise ValueError("Menu item must have text or be a separator")
        if self.separator and self.text:
            self.text = ""  # Separators don't need text


@dataclass
class Notification:
    """Tray notification definition."""
    title: str
    message: str
    duration: int = 3000  # milliseconds
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class TrayState:
    """
    System tray state management with Windows-specific optimizations.
    Manages status, icons, menus, and notifications with constitutional compliance.
    """
    status: TrayStatus = TrayStatus.IDLE
    icon_path: str = ""
    menu_items: List[TrayMenuItem] = field(default_factory=list)
    tooltip_text: str = ""
    last_updated: Optional[datetime] = None
    notification_queue: List[Notification] = field(default_factory=list)

    # Thread safety
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self):
        """Initialize TrayState with default values and validation."""
        if not self.menu_items:
            # Always include at least Settings menu item
            self.menu_items = [
                TrayMenuItem("Settings", lambda: None, enabled=True),
                TrayMenuItem("", lambda: None, separator=True),
                TrayMenuItem("Exit", lambda: None, enabled=True)
            ]

        # Ensure tooltip respects Windows 64-character limitation
        if len(self.tooltip_text) > 64:
            self.tooltip_text = self.tooltip_text[:64]

        if self.last_updated is None:
            self.last_updated = datetime.now()

    def transition_to(self, new_status: TrayStatus, message: str = "") -> bool:
        """
        Transition to new status with validation and timestamp update.

        Args:
            new_status: Target status to transition to
            message: Optional message for tooltip

        Returns:
            True if transition was successful
        """
        with self._lock:
            if not self.can_transition_to(new_status):
                return False

            old_status = self.status
            self.status = new_status
            self.last_updated = datetime.now()

            # Update tooltip with message if provided
            if message:
                self.set_tooltip(message)
            else:
                # Default status messages
                status_messages = {
                    TrayStatus.IDLE: "VoiceFlow Ready",
                    TrayStatus.RECORDING: "Recording...",
                    TrayStatus.PROCESSING: "Processing audio...",
                    TrayStatus.ERROR: "Error - Check logs"
                }
                self.set_tooltip(status_messages.get(new_status, "VoiceFlow"))

            return True

    def can_transition_to(self, target_status: TrayStatus) -> bool:
        """
        Check if transition to target status is valid.

        Args:
            target_status: Status to check transition validity for

        Returns:
            True if transition is allowed
        """
        # Valid transitions based on VoiceFlow workflow
        valid_transitions = {
            TrayStatus.IDLE: [TrayStatus.RECORDING, TrayStatus.ERROR],
            TrayStatus.RECORDING: [TrayStatus.PROCESSING, TrayStatus.ERROR, TrayStatus.IDLE],
            TrayStatus.PROCESSING: [TrayStatus.IDLE, TrayStatus.ERROR],
            TrayStatus.ERROR: [TrayStatus.IDLE]  # Error recovery always to IDLE
        }

        return target_status in valid_transitions.get(self.status, [])

    def set_tooltip(self, text: str) -> None:
        """
        Set tooltip text with Windows 64-character limitation.

        Args:
            text: Tooltip text to set
        """
        with self._lock:
            # Windows system tray tooltip limitation
            if len(text) > 64:
                text = text[:61] + "..."  # Truncate with ellipsis
            self.tooltip_text = text

    def add_notification(self, notification: Notification) -> None:
        """
        Add notification to queue.

        Args:
            notification: Notification to add
        """
        with self._lock:
            self.notification_queue.append(notification)
            # Keep queue size reasonable (max 10 notifications)
            if len(self.notification_queue) > 10:
                self.notification_queue.pop(0)

    def pop_notification(self) -> Optional[Notification]:
        """
        Remove and return next notification from queue.

        Returns:
            Next notification or None if queue is empty
        """
        with self._lock:
            if self.notification_queue:
                return self.notification_queue.pop(0)
            return None

    def update_menu_items(self, items: List[TrayMenuItem]) -> None:
        """
        Update menu items with validation.

        Args:
            items: New menu items list
        """
        with self._lock:
            # Ensure at least Settings menu exists
            has_settings = any("Settings" in item.text for item in items)
            if not has_settings:
                items.append(TrayMenuItem("Settings", lambda: None, enabled=True))

            self.menu_items = items

    def is_valid(self) -> bool:
        """
        Validate current state meets all requirements.

        Returns:
            True if state is valid
        """
        try:
            # Check basic requirements
            if not isinstance(self.status, TrayStatus):
                return False

            # Check tooltip length (Windows limitation)
            if len(self.tooltip_text) > 64:
                return False

            # Check menu items
            if not self.menu_items:
                return False

            # Must have at least Settings menu
            has_settings = any("Settings" in item.text for item in self.menu_items)
            if not has_settings:
                return False

            # Check notification queue size
            if len(self.notification_queue) > 10:
                return False

            return True

        except Exception:
            return False

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize TrayState to dictionary.

        Returns:
            Dictionary representation of TrayState
        """
        return {
            "status": self.status.value,
            "icon_path": self.icon_path,
            "tooltip_text": self.tooltip_text,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "notification_count": len(self.notification_queue),
            "menu_item_count": len(self.menu_items)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TrayState':
        """
        Deserialize TrayState from dictionary.

        Args:
            data: Dictionary to deserialize from

        Returns:
            TrayState instance
        """
        state = cls()

        # Set status
        if "status" in data:
            try:
                state.status = TrayStatus(data["status"])
            except ValueError:
                state.status = TrayStatus.IDLE

        # Set other fields
        state.icon_path = data.get("icon_path", "")
        state.tooltip_text = data.get("tooltip_text", "")

        # Parse timestamp
        if data.get("last_updated"):
            try:
                state.last_updated = datetime.fromisoformat(data["last_updated"])
            except ValueError:
                state.last_updated = datetime.now()

        return state

    def __eq__(self, other) -> bool:
        """Compare TrayState instances for equality."""
        if not isinstance(other, TrayState):
            return False

        return (
            self.status == other.status and
            self.icon_path == other.icon_path and
            self.tooltip_text == other.tooltip_text and
            len(self.menu_items) == len(other.menu_items) and
            len(self.notification_queue) == len(other.notification_queue)
        )

    def validate(self) -> None:
        """
        Validate and fix state to meet constitutional requirements.
        Raises ValueError if state cannot be fixed.
        """
        # Fix tooltip length (Windows limitation)
        if len(self.tooltip_text) > 64:
            self.tooltip_text = self.tooltip_text[:61] + "..."

        # Ensure at least Settings menu
        if not self.menu_items:
            self.menu_items = [TrayMenuItem("Settings", lambda: None)]
        else:
            has_settings = any("Settings" in item.text for item in self.menu_items)
            if not has_settings:
                self.menu_items.append(TrayMenuItem("Settings", lambda: None))

        # Limit notification queue
        if len(self.notification_queue) > 10:
            self.notification_queue = self.notification_queue[-10:]

        # Validate status
        if not isinstance(self.status, TrayStatus):
            raise ValueError("Invalid tray status")

    def get_performance_impact(self) -> Dict[str, Any]:
        """
        Get performance impact metrics for constitutional compliance.

        Returns:
            Dictionary with performance metrics
        """
        return {
            "memory_estimate_kb": (
                len(self.tooltip_text) * 2 +  # Unicode string
                len(self.menu_items) * 100 +   # Rough menu item size
                len(self.notification_queue) * 200  # Rough notification size
            ) / 1024,
            "cpu_impact": "low",  # State operations are fast
            "thread_safe": True,
            "constitutional_compliant": self.is_valid()
        }