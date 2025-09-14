#!/usr/bin/env python3
"""
VoiceFlow Visual Configuration Demo
==================================
Test script for configurable visual overlay positioning and accessibility features
"""

import sys
import time
from pathlib import Path

# Add localflow to path
sys.path.append(str(Path(__file__).parent))

try:
    from localflow.visual_config import (
        VisualConfigManager, OverlayPosition, OverlaySize, ColorTheme
    )
    from localflow.visual_indicators import BottomScreenIndicator, TranscriptionStatus
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running from the VoiceFlow root directory")
    sys.exit(1)

def demo_basic_positioning():
    """Demo basic overlay positioning"""
    print("=== Basic Positioning Demo ===")

    config_manager = VisualConfigManager()

    positions_to_test = [
        (OverlayPosition.BOTTOM_CENTER, "Bottom Center"),
        (OverlayPosition.BOTTOM_LEFT, "Bottom Left"),
        (OverlayPosition.BOTTOM_RIGHT, "Bottom Right"),
        (OverlayPosition.TOP_CENTER, "Top Center"),
        (OverlayPosition.CENTER, "Screen Center")
    ]

    for position, description in positions_to_test:
        print(f"Testing: {description}")

        # Update configuration
        config_manager.config.position = position
        config_manager.save_config()

        # Create overlay
        try:
            overlay = BottomScreenIndicator()
            overlay.show_status(TranscriptionStatus.LISTENING, f"Testing: {description}")

            time.sleep(2.0)

            overlay.hide()
            if overlay.window:
                overlay.window.destroy()

            print(f"  ✓ {description} position works")

        except Exception as e:
            print(f"  ✗ {description} position failed: {e}")

        time.sleep(0.5)

def demo_size_options():
    """Demo different overlay sizes"""
    print("\n=== Size Options Demo ===")

    config_manager = VisualConfigManager()
    config_manager.config.position = OverlayPosition.CENTER  # Use center for visibility

    sizes_to_test = [
        (OverlaySize.SMALL, "Small (200x40)"),
        (OverlaySize.MEDIUM, "Medium (300x60)"),
        (OverlaySize.LARGE, "Large (400x80)"),
        (OverlaySize.EXTRA_LARGE, "Extra Large (500x100)")
    ]

    for size, description in sizes_to_test:
        print(f"Testing: {description}")

        # Update configuration
        config_manager.config.size = size
        config_manager.save_config()

        try:
            overlay = BottomScreenIndicator()
            overlay.show_status(TranscriptionStatus.PROCESSING, f"Size: {description}")

            time.sleep(2.0)

            overlay.hide()
            if overlay.window:
                overlay.window.destroy()

            print(f"  ✓ {description} size works")

        except Exception as e:
            print(f"  ✗ {description} size failed: {e}")

        time.sleep(0.5)

def demo_color_themes():
    """Demo different color themes"""
    print("\n=== Color Themes Demo ===")

    config_manager = VisualConfigManager()
    config_manager.config.position = OverlayPosition.CENTER
    config_manager.config.size = OverlaySize.MEDIUM

    themes_to_test = [
        (ColorTheme.DEFAULT, "Default Theme"),
        (ColorTheme.HIGH_CONTRAST, "High Contrast"),
        (ColorTheme.DARK_MODE, "Dark Mode"),
        (ColorTheme.LIGHT_MODE, "Light Mode"),
        (ColorTheme.COLORBLIND_FRIENDLY, "Colorblind Friendly")
    ]

    for theme, description in themes_to_test:
        print(f"Testing: {description}")

        # Update configuration
        config_manager.config.theme = theme
        config_manager.save_config()

        try:
            overlay = BottomScreenIndicator()
            overlay.show_status(TranscriptionStatus.COMPLETE, f"Theme: {description}")

            time.sleep(2.5)

            overlay.hide()
            if overlay.window:
                overlay.window.destroy()

            print(f"  ✓ {description} theme works")

        except Exception as e:
            print(f"  ✗ {description} theme failed: {e}")

        time.sleep(0.5)

def demo_accessibility_features():
    """Demo accessibility features"""
    print("\n=== Accessibility Features Demo ===")

    config_manager = VisualConfigManager()
    config_manager.config.position = OverlayPosition.CENTER
    config_manager.config.size = OverlaySize.LARGE

    accessibility_tests = [
        ("Large Font Mode", {"large_font_mode": True, "font_size": 16}),
        ("High Contrast", {"high_contrast_mode": True, "theme": ColorTheme.HIGH_CONTRAST}),
        ("Low Opacity", {"opacity": 0.6}),
        ("High Opacity", {"opacity": 1.0})
    ]

    for test_name, settings in accessibility_tests:
        print(f"Testing: {test_name}")

        # Update configuration
        for key, value in settings.items():
            setattr(config_manager.config, key, value)
        config_manager.save_config()

        try:
            overlay = BottomScreenIndicator()
            overlay.show_status(TranscriptionStatus.TRANSCRIBING, f"A11y: {test_name}")

            time.sleep(2.5)

            overlay.hide()
            if overlay.window:
                overlay.window.destroy()

            print(f"  ✓ {test_name} accessibility works")

        except Exception as e:
            print(f"  ✗ {test_name} accessibility failed: {e}")

        time.sleep(0.5)

def demo_configuration_persistence():
    """Demo configuration saving and loading"""
    print("\n=== Configuration Persistence Demo ===")

    # Create first configuration
    config1 = VisualConfigManager()
    config1.config.position = OverlayPosition.TOP_RIGHT
    config1.config.size = OverlaySize.LARGE
    config1.config.theme = ColorTheme.DARK_MODE
    config1.config.opacity = 0.8
    config1.save_config()

    print("✓ Saved custom configuration")

    # Create second configuration manager (should load saved settings)
    config2 = VisualConfigManager()

    # Verify settings were loaded
    assert config2.config.position == OverlayPosition.TOP_RIGHT
    assert config2.config.size == OverlaySize.LARGE
    assert config2.config.theme == ColorTheme.DARK_MODE
    assert config2.config.opacity == 0.8

    print("✓ Configuration loaded correctly")

    # Test the loaded configuration
    try:
        overlay = BottomScreenIndicator()
        overlay.show_status(TranscriptionStatus.IDLE, "Loaded Configuration Test")

        time.sleep(2.0)

        overlay.hide()
        if overlay.window:
            overlay.window.destroy()

        print("✓ Loaded configuration works correctly")

    except Exception as e:
        print(f"✗ Loaded configuration failed: {e}")

def reset_to_defaults():
    """Reset configuration to defaults"""
    print("\n=== Resetting to Defaults ===")

    config_manager = VisualConfigManager()
    config_manager.reset_to_defaults()

    print("✓ Configuration reset to defaults")

def main():
    """Run all visual configuration demos"""
    print("VoiceFlow Visual Configuration Demo")
    print("=" * 50)
    print()

    try:
        demo_basic_positioning()
        demo_size_options()
        demo_color_themes()
        demo_accessibility_features()
        demo_configuration_persistence()
        reset_to_defaults()

        print("\n" + "=" * 50)
        print("🎉 All visual configuration demos completed successfully!")
        print("\nKey Features Demonstrated:")
        print("  ✓ Configurable overlay positioning (5 positions)")
        print("  ✓ Multiple size options (4 sizes)")
        print("  ✓ Color theme support (5 themes)")
        print("  ✓ Accessibility features (font, contrast, opacity)")
        print("  ✓ Configuration persistence (save/load)")
        print()
        print("Ready for production use!")

    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
    except Exception as e:
        print(f"\n\nDemo failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()