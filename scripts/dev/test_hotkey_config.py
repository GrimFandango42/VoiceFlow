#!/usr/bin/env python3
"""
Test script to verify hotkey configuration for Ctrl+Shift
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'localflow'))

from config import Config

def test_hotkey_config():
    """Test the current hotkey configuration"""
    print("Testing VoiceFlow Hotkey Configuration")
    print("=" * 50)

    # Load configuration
    cfg = Config()

    # Check current hotkey settings
    print(f"Hotkey Configuration:")
    print(f"  Ctrl Required:  {cfg.hotkey_ctrl}")
    print(f"  Shift Required: {cfg.hotkey_shift}")
    print(f"  Alt Required:   {cfg.hotkey_alt}")
    print(f"  Key Required:   '{cfg.hotkey_key}'")
    print()

    # Determine what the actual hotkey combination is
    hotkey_parts = []
    if cfg.hotkey_ctrl:
        hotkey_parts.append("Ctrl")
    if cfg.hotkey_shift:
        hotkey_parts.append("Shift")
    if cfg.hotkey_alt:
        hotkey_parts.append("Alt")
    if cfg.hotkey_key:
        hotkey_parts.append(cfg.hotkey_key.upper())

    current_hotkey = "+".join(hotkey_parts) if hotkey_parts else "None"
    print(f"Current Hotkey Combination: {current_hotkey}")
    print()

    # Check if this matches our target
    target_hotkey = "Ctrl+Shift"
    is_correct = (cfg.hotkey_ctrl and cfg.hotkey_shift and not cfg.hotkey_alt and not cfg.hotkey_key)

    print(f"Target Hotkey:  {target_hotkey}")
    print(f"Match Status:   {'[CORRECT]' if is_correct else '[NEEDS UPDATE]'}")

    if not is_correct:
        print("\nRequired Changes:")
        if not cfg.hotkey_ctrl:
            print("  - Set hotkey_ctrl = True")
        if not cfg.hotkey_shift:
            print("  - Set hotkey_shift = True")
        if cfg.hotkey_alt:
            print("  - Set hotkey_alt = False")
        if cfg.hotkey_key:
            print("  - Set hotkey_key = \"\" (empty string)")

    return is_correct

if __name__ == "__main__":
    success = test_hotkey_config()
    sys.exit(0 if success else 1)