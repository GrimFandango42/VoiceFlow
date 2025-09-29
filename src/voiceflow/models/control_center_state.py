"""
ControlCenterState model for VoiceFlow Control Center interface management.
Manages UI state, user interactions, and window behavior with constitutional compliance.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List
import threading


@dataclass
class ControlCenterState:
    """
    Control Center interface state management with constitutional compliance.
    Manages tabs, monitoring, window geometry, and user interface preferences.
    """
    active_tab: str = "overview"
    log_filter: str = ""
    monitoring_enabled: bool = True
    window_geometry: Dict[str, int] = None
    auto_refresh_interval: int = 5  # seconds
    visible: bool = False
    last_updated: Optional[datetime] = None

    # Thread safety
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self):
        """Initialize ControlCenterState with validation and defaults."""
        # Initialize mutable defaults
        if self.window_geometry is None:
            self.window_geometry = {
                "x": 100,
                "y": 100,
                "width": 800,
                "height": 600
            }

        if self.last_updated is None:
            self.last_updated = datetime.now()

        # Validate configuration
        self.validate()

    def validate(self) -> None:
        """
        Validate Control Center state parameters.
        Raises ValueError if state is invalid.
        """
        # Validate active tab
        valid_tabs = {
            "overview", "performance", "logs", "settings",
            "audio", "tray", "tests", "installer"
        }
        if self.active_tab not in valid_tabs:
            raise ValueError(f"Invalid active_tab '{self.active_tab}'. Must be one of: {valid_tabs}")

        # Validate log filter (basic string validation)
        if not isinstance(self.log_filter, str):
            raise ValueError("log_filter must be a string")

        # Validate window geometry
        if not isinstance(self.window_geometry, dict):
            raise ValueError("window_geometry must be a dictionary")

        required_geometry_keys = {"x", "y", "width", "height"}
        if not required_geometry_keys.issubset(self.window_geometry.keys()):
            raise ValueError(f"window_geometry must contain keys: {required_geometry_keys}")

        # Validate geometry values
        for key, value in self.window_geometry.items():
            if not isinstance(value, int):
                raise ValueError(f"window_geometry['{key}'] must be an integer")

        # Validate geometry constraints
        if self.window_geometry["width"] < 400 or self.window_geometry["width"] > 3840:
            raise ValueError("window width must be between 400 and 3840 pixels")

        if self.window_geometry["height"] < 300 or self.window_geometry["height"] > 2160:
            raise ValueError("window height must be between 300 and 2160 pixels")

        # Validate auto refresh interval
        if not isinstance(self.auto_refresh_interval, int):
            raise ValueError("auto_refresh_interval must be an integer")

        if self.auto_refresh_interval < 0:
            raise ValueError("auto_refresh_interval must be >= 0 (0 means disabled)")

        if self.auto_refresh_interval > 0 and self.auto_refresh_interval < 1:
            raise ValueError("auto_refresh_interval must be 0 (disabled) or >= 1 second")

    def is_constitutional_compliant(self) -> bool:
        """
        Check if Control Center state meets constitutional requirements.

        Constitutional Requirements:
        - Auto-refresh interval must not be too aggressive (>= 1 second or disabled)
        - Window size must be reasonable to not overwhelm system resources
        - Monitoring should be enabled by default for real-time feedback
        - UI updates must be efficient and not impact system performance

        Returns:
            True if state meets constitutional requirements
        """
        with self._lock:
            # Auto-refresh interval check (avoid excessive updates)
            if self.auto_refresh_interval > 0 and self.auto_refresh_interval < 1:
                return False

            # Reasonable window size (avoid excessive memory usage)
            window_area = self.window_geometry["width"] * self.window_geometry["height"]
            if window_area > 1920 * 1080:  # No larger than 1080p
                return False

            # Monitor reasonable window position (avoid off-screen)
            if (self.window_geometry["x"] < -100 or self.window_geometry["x"] > 2000 or
                self.window_geometry["y"] < -100 or self.window_geometry["y"] > 1500):
                return False

            # Performance-oriented defaults
            if self.auto_refresh_interval > 60:  # Don't refresh slower than 1 minute
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
            # Refresh interval violations
            if self.auto_refresh_interval > 0 and self.auto_refresh_interval < 1:
                violations["refresh_violation"] = (
                    f"Auto-refresh interval {self.auto_refresh_interval}s is too aggressive "
                    f"(must be 0 or >= 1 second)"
                )

            # Window size violations
            window_area = self.window_geometry["width"] * self.window_geometry["height"]
            if window_area > 1920 * 1080:
                violations["window_size_violation"] = (
                    f"Window size {self.window_geometry['width']}x{self.window_geometry['height']} "
                    f"exceeds constitutional limit (1920x1080 max)"
                )

            # Window position violations
            if (self.window_geometry["x"] < -100 or self.window_geometry["x"] > 2000 or
                self.window_geometry["y"] < -100 or self.window_geometry["y"] > 1500):
                violations["window_position_violation"] = (
                    f"Window position ({self.window_geometry['x']}, {self.window_geometry['y']}) "
                    f"may be off-screen or unreasonable"
                )

            # Performance violations
            if self.auto_refresh_interval > 60:
                violations["refresh_performance_violation"] = (
                    f"Auto-refresh interval {self.auto_refresh_interval}s too slow "
                    f"(should be <= 60s for good user experience)"
                )

        return violations

    def switch_tab(self, tab_name: str) -> bool:
        """
        Switch to a different tab.

        Args:
            tab_name: Name of tab to switch to

        Returns:
            True if switch was successful
        """
        valid_tabs = {
            "overview", "performance", "logs", "settings",
            "audio", "tray", "tests", "installer"
        }

        if tab_name not in valid_tabs:
            return False

        with self._lock:
            old_tab = self.active_tab
            self.active_tab = tab_name
            self.last_updated = datetime.now()

            # Tab-specific state adjustments
            if tab_name == "performance" and not self.monitoring_enabled:
                self.monitoring_enabled = True  # Auto-enable monitoring for performance tab

            return True

    def update_log_filter(self, filter_text: str) -> None:
        """
        Update log filtering criteria.

        Args:
            filter_text: New filter text (empty string clears filter)
        """
        with self._lock:
            self.log_filter = filter_text if filter_text else ""
            self.last_updated = datetime.now()

    def set_monitoring(self, enabled: bool) -> None:
        """
        Enable or disable real-time monitoring.

        Args:
            enabled: True to enable monitoring, False to disable
        """
        with self._lock:
            self.monitoring_enabled = enabled
            self.last_updated = datetime.now()

    def update_window_geometry(self, x: int, y: int, width: int, height: int) -> bool:
        """
        Update window geometry with validation.

        Args:
            x: Window x position
            y: Window y position
            width: Window width
            height: Window height

        Returns:
            True if update was successful
        """
        # Validate new geometry
        if width < 400 or width > 3840 or height < 300 or height > 2160:
            return False

        with self._lock:
            self.window_geometry.update({
                "x": x,
                "y": y,
                "width": width,
                "height": height
            })
            self.last_updated = datetime.now()

            # Re-validate after update
            try:
                self.validate()
                return True
            except ValueError:
                # Revert on validation failure
                return False

    def set_auto_refresh(self, interval_seconds: int) -> bool:
        """
        Set auto-refresh interval.

        Args:
            interval_seconds: Refresh interval (0 to disable, >= 1 to enable)

        Returns:
            True if update was successful
        """
        if interval_seconds < 0 or (interval_seconds > 0 and interval_seconds < 1):
            return False

        with self._lock:
            self.auto_refresh_interval = interval_seconds
            self.last_updated = datetime.now()
            return True

    def show_window(self) -> None:
        """Show Control Center window."""
        with self._lock:
            self.visible = True
            self.last_updated = datetime.now()

    def hide_window(self) -> None:
        """Hide Control Center window."""
        with self._lock:
            self.visible = False
            self.last_updated = datetime.now()

    def toggle_visibility(self) -> bool:
        """
        Toggle window visibility.

        Returns:
            New visibility state
        """
        with self._lock:
            self.visible = not self.visible
            self.last_updated = datetime.now()
            return self.visible

    def get_window_center(self) -> Dict[str, int]:
        """
        Get window center coordinates.

        Returns:
            Dictionary with center_x and center_y
        """
        with self._lock:
            return {
                "center_x": self.window_geometry["x"] + self.window_geometry["width"] // 2,
                "center_y": self.window_geometry["y"] + self.window_geometry["height"] // 2
            }

    def is_on_screen(self, screen_width: int = 1920, screen_height: int = 1080) -> bool:
        """
        Check if window is visible on screen.

        Args:
            screen_width: Screen width in pixels
            screen_height: Screen height in pixels

        Returns:
            True if window is at least partially visible
        """
        with self._lock:
            # Check if any part of window is on screen
            left = self.window_geometry["x"]
            right = left + self.window_geometry["width"]
            top = self.window_geometry["y"]
            bottom = top + self.window_geometry["height"]

            return (right > 0 and left < screen_width and
                   bottom > 0 and top < screen_height)

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize ControlCenterState to dictionary.

        Returns:
            Dictionary representation
        """
        with self._lock:
            return {
                "active_tab": self.active_tab,
                "log_filter": self.log_filter,
                "monitoring_enabled": self.monitoring_enabled,
                "window_geometry": self.window_geometry.copy(),
                "auto_refresh_interval": self.auto_refresh_interval,
                "visible": self.visible,
                "last_updated": self.last_updated.isoformat() if self.last_updated else None,
                "constitutional_compliant": self.is_constitutional_compliant(),
                "violations": self.get_compliance_violations(),
                "window_center": self.get_window_center()
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ControlCenterState':
        """
        Deserialize ControlCenterState from dictionary.

        Args:
            data: Dictionary to deserialize from

        Returns:
            ControlCenterState instance
        """
        state = cls()

        # Set fields with validation
        state.active_tab = data.get("active_tab", "overview")
        state.log_filter = data.get("log_filter", "")
        state.monitoring_enabled = data.get("monitoring_enabled", True)
        state.auto_refresh_interval = data.get("auto_refresh_interval", 5)
        state.visible = data.get("visible", False)

        # Set window geometry
        if "window_geometry" in data:
            state.window_geometry.update(data["window_geometry"])

        # Parse timestamp
        if data.get("last_updated"):
            try:
                state.last_updated = datetime.fromisoformat(data["last_updated"])
            except ValueError:
                state.last_updated = datetime.now()

        return state

    def get_ui_config(self) -> Dict[str, Any]:
        """
        Get UI configuration for interface rendering.

        Returns:
            Dictionary with UI-specific configuration
        """
        with self._lock:
            return {
                "active_tab": self.active_tab,
                "log_filter": self.log_filter,
                "monitoring": self.monitoring_enabled,
                "refresh_ms": self.auto_refresh_interval * 1000,  # Convert to milliseconds
                "geometry": self.window_geometry.copy(),
                "visible": self.visible,
                "center": self.get_window_center()
            }

    def __eq__(self, other) -> bool:
        """Compare ControlCenterState instances for equality."""
        if not isinstance(other, ControlCenterState):
            return False

        return (
            self.active_tab == other.active_tab and
            self.log_filter == other.log_filter and
            self.monitoring_enabled == other.monitoring_enabled and
            self.window_geometry == other.window_geometry and
            self.auto_refresh_interval == other.auto_refresh_interval and
            self.visible == other.visible
        )

    def __str__(self) -> str:
        """String representation of ControlCenterState."""
        compliant = "✅" if self.is_constitutional_compliant() else "❌"
        visible = "👁️" if self.visible else "🙈"
        monitoring = "📊" if self.monitoring_enabled else "📴"

        return (
            f"ControlCenter({self.active_tab}): "
            f"{self.window_geometry['width']}x{self.window_geometry['height']} "
            f"refresh={self.auto_refresh_interval}s "
            f"{visible} {monitoring} {compliant}"
        )