#!/usr/bin/env python3
"""
VoiceFlow Visual Configuration System
====================================
Configurable visual overlay positioning and accessibility options
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class OverlayPosition(Enum):
    """Predefined overlay positions"""
    BOTTOM_CENTER = "bottom_center"
    BOTTOM_LEFT = "bottom_left"
    BOTTOM_RIGHT = "bottom_right"
    TOP_CENTER = "top_center"
    TOP_LEFT = "top_left"
    TOP_RIGHT = "top_right"
    CENTER = "center"
    CUSTOM = "custom"

class OverlaySize(Enum):
    """Predefined overlay sizes"""
    SMALL = "small"      # 200x40
    MEDIUM = "medium"    # 300x60
    LARGE = "large"      # 400x80
    EXTRA_LARGE = "xl"   # 500x100

class ColorTheme(Enum):
    """Color themes for accessibility"""
    DEFAULT = "default"
    HIGH_CONTRAST = "high_contrast"
    DARK_MODE = "dark_mode"
    LIGHT_MODE = "light_mode"
    COLORBLIND_FRIENDLY = "colorblind_friendly"

@dataclass
class VisualConfig:
    """Visual overlay configuration settings"""

    # Position settings
    position: OverlayPosition = OverlayPosition.BOTTOM_CENTER
    custom_x: int = 0
    custom_y: int = 0
    offset_x: int = 0  # Additional offset from base position
    offset_y: int = 0  # Additional offset from base position

    # Size settings
    size: OverlaySize = OverlaySize.SMALL
    custom_width: int = 300
    custom_height: int = 60

    # Appearance settings
    opacity: float = 0.9
    theme: ColorTheme = ColorTheme.DEFAULT
    font_size: int = 11
    show_progress_bar: bool = True
    rounded_corners: bool = True

    # Behavior settings
    auto_hide_delay: float = 3.0  # seconds
    fade_animation: bool = True
    click_through: bool = False  # Allow clicking through overlay
    always_on_top: bool = True

    # Accessibility settings
    high_contrast_mode: bool = False
    large_font_mode: bool = False
    screen_reader_compatible: bool = False
    keyboard_navigation: bool = False

    # Multi-monitor settings
    preferred_monitor: int = 0  # Primary monitor = 0
    follow_cursor_monitor: bool = True

class VisualConfigManager:
    """Manager for visual configuration settings"""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._get_default_config_path()
        self.config = VisualConfig()
        self._load_config()

    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        config_dir = Path.home() / ".voiceflow"
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "visual_config.json")

    def _load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    data = json.load(f)

                # Convert string enums back to enum values
                if 'position' in data:
                    data['position'] = OverlayPosition(data['position'])
                if 'size' in data:
                    data['size'] = OverlaySize(data['size'])
                if 'theme' in data:
                    data['theme'] = ColorTheme(data['theme'])

                # Update config with loaded values
                for key, value in data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)

        except Exception as e:
            print(f"[VisualConfig] Error loading config: {e}")
            # Use default config

    def save_config(self):
        """Save configuration to file"""
        try:
            # Convert config to dictionary
            data = asdict(self.config)

            # Convert enums to strings for JSON serialization
            data['position'] = self.config.position.value
            data['size'] = self.config.size.value
            data['theme'] = self.config.theme.value

            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"[VisualConfig] Error saving config: {e}")

    def get_position_coordinates(self, screen_width: int, screen_height: int) -> Tuple[int, int]:
        """Calculate overlay position coordinates based on settings"""
        width, height = self.get_overlay_dimensions()

        if self.config.position == OverlayPosition.CUSTOM:
            base_x = self.config.custom_x
            base_y = self.config.custom_y
        else:
            base_x, base_y = self._calculate_base_position(
                self.config.position, screen_width, screen_height, width, height
            )

        # Apply additional offsets
        final_x = base_x + self.config.offset_x
        final_y = base_y + self.config.offset_y

        # Ensure overlay stays within screen bounds
        final_x = max(0, min(final_x, screen_width - width))
        final_y = max(0, min(final_y, screen_height - height))

        return final_x, final_y

    def _calculate_base_position(self, position: OverlayPosition,
                               screen_width: int, screen_height: int,
                               width: int, height: int) -> Tuple[int, int]:
        """Calculate base position coordinates for predefined positions"""
        positions = {
            OverlayPosition.BOTTOM_CENTER: (
                (screen_width - width) // 2,
                screen_height - height - 100
            ),
            OverlayPosition.BOTTOM_LEFT: (
                50,
                screen_height - height - 50
            ),
            OverlayPosition.BOTTOM_RIGHT: (
                screen_width - width - 50,
                screen_height - height - 50
            ),
            OverlayPosition.TOP_CENTER: (
                (screen_width - width) // 2,
                50
            ),
            OverlayPosition.TOP_LEFT: (
                50,
                50
            ),
            OverlayPosition.TOP_RIGHT: (
                screen_width - width - 50,
                50
            ),
            OverlayPosition.CENTER: (
                (screen_width - width) // 2,
                (screen_height - height) // 2
            )
        }

        return positions.get(position, positions[OverlayPosition.BOTTOM_CENTER])

    def get_overlay_dimensions(self) -> Tuple[int, int]:
        """Get overlay dimensions based on size setting"""
        if self.config.size == OverlaySize.SMALL:
            return 200, 40
        elif self.config.size == OverlaySize.MEDIUM:
            return 300, 60
        elif self.config.size == OverlaySize.LARGE:
            return 400, 80
        elif self.config.size == OverlaySize.EXTRA_LARGE:
            return 500, 100
        else:
            return self.config.custom_width, self.config.custom_height

    def get_color_scheme(self) -> Dict[str, str]:
        """Get color scheme based on theme setting"""
        themes = {
            ColorTheme.DEFAULT: {
                'bg_color': '#2d2d2d',
                'text_color': '#ffffff',
                'accent_color': '#4A9EFF',
                'error_color': '#FF4A4A',
                'success_color': '#4AFF4A',
                'warning_color': '#FFAA4A'
            },
            ColorTheme.HIGH_CONTRAST: {
                'bg_color': '#000000',
                'text_color': '#FFFFFF',
                'accent_color': '#FFFF00',
                'error_color': '#FF0000',
                'success_color': '#00FF00',
                'warning_color': '#FF8800'
            },
            ColorTheme.DARK_MODE: {
                'bg_color': '#1e1e1e',
                'text_color': '#e0e0e0',
                'accent_color': '#007ACC',
                'error_color': '#F44747',
                'success_color': '#4EC9B0',
                'warning_color': '#FFCC02'
            },
            ColorTheme.LIGHT_MODE: {
                'bg_color': '#F5F5F5',
                'text_color': '#333333',
                'accent_color': '#0078D4',
                'error_color': '#D83B01',
                'success_color': '#107C10',
                'warning_color': '#FF8C00'
            },
            ColorTheme.COLORBLIND_FRIENDLY: {
                'bg_color': '#2d2d2d',
                'text_color': '#ffffff',
                'accent_color': '#0173B2',  # Blue
                'error_color': '#CC79A7',  # Pink
                'success_color': '#009E73', # Green
                'warning_color': '#F0E442'  # Yellow
            }
        }

        return themes.get(self.config.theme, themes[ColorTheme.DEFAULT])

    def get_font_settings(self) -> Dict[str, Any]:
        """Get font settings based on accessibility options"""
        base_size = self.config.font_size

        if self.config.large_font_mode:
            base_size = max(base_size, 14)

        if self.config.high_contrast_mode:
            weight = "bold"
        else:
            weight = "normal"

        return {
            'family': 'Segoe UI',
            'size': base_size,
            'weight': weight
        }

    def update_setting(self, key: str, value: Any):
        """Update a single configuration setting"""
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            self.save_config()
        else:
            raise ValueError(f"Unknown configuration key: {key}")

    def reset_to_defaults(self):
        """Reset configuration to default values"""
        self.config = VisualConfig()
        self.save_config()

    def export_config(self, file_path: str):
        """Export configuration to a specific file"""
        data = asdict(self.config)
        data['position'] = self.config.position.value
        data['size'] = self.config.size.value
        data['theme'] = self.config.theme.value

        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)

    def import_config(self, file_path: str):
        """Import configuration from a specific file"""
        with open(file_path, 'r') as f:
            data = json.load(f)

        # Convert string enums back to enum values
        if 'position' in data:
            data['position'] = OverlayPosition(data['position'])
        if 'size' in data:
            data['size'] = OverlaySize(data['size'])
        if 'theme' in data:
            data['theme'] = ColorTheme(data['theme'])

        # Update config
        for key, value in data.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

        self.save_config()

# Global configuration instance
_config_manager = None

def get_visual_config() -> VisualConfigManager:
    """Get the global visual configuration manager"""
    global _config_manager
    if _config_manager is None:
        _config_manager = VisualConfigManager()
    return _config_manager

def update_visual_setting(key: str, value: Any):
    """Update a visual setting globally"""
    config_manager = get_visual_config()
    config_manager.update_setting(key, value)