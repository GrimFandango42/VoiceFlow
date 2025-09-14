"""
Debug script to check current VoiceFlow configuration
"""

from localflow.config import Config

def check_current_config():
    """Check what configuration VoiceFlow is actually using"""
    
    print("=" * 60)
    print("VoiceFlow Configuration Debug")
    print("=" * 60)
    
    cfg = Config()
    
    print(f"Hotkey Configuration:")
    print(f"  Ctrl: {cfg.hotkey_ctrl}")
    print(f"  Shift: {cfg.hotkey_shift}")
    print(f"  Alt: {cfg.hotkey_alt}")
    print(f"  Key: '{cfg.hotkey_key}'")
    
    # Construct hotkey string
    hotkey_parts = []
    if cfg.hotkey_ctrl:
        hotkey_parts.append("Ctrl")
    if cfg.hotkey_shift:
        hotkey_parts.append("Shift")
    if cfg.hotkey_alt:
        hotkey_parts.append("Alt")
    if cfg.hotkey_key:
        hotkey_parts.append(cfg.hotkey_key)
    
    hotkey_string = " + ".join(hotkey_parts)
    print(f"\nCombined hotkey: {hotkey_string}")
    
    # Check if this is the expected configuration
    expected_hotkey = "Ctrl + Alt + F12"
    is_correct = hotkey_string == expected_hotkey
    
    print(f"Expected: {expected_hotkey}")
    print(f"Status: {'✓ CORRECT' if is_correct else '✗ INCORRECT - Still using old config'}")
    
    if not is_correct:
        print(f"\n⚠️  WARNING: VoiceFlow is still using the OLD configuration!")
        print(f"   Current: {hotkey_string}")
        print(f"   This explains why you're still experiencing buffer issues.")
        print(f"   The new hotkey prevents accidental triggers while typing.")
        
        print(f"\n🔧 TO FIX:")
        print(f"   1. Close ALL VoiceFlow instances completely")
        print(f"   2. Restart with: python voiceflow.py --no-tray --lite")
        print(f"   3. New hotkey will be: Ctrl + Alt + F12")
    else:
        print(f"\n✅ Configuration is correct!")
        print(f"   If you're still seeing buffer issues, they may be from:")
        print(f"   1. Using an old VoiceFlow instance")
        print(f"   2. Python module caching")
        print(f"   3. Another source of duplication")
    
    print("\n" + "=" * 60)
    
    return is_correct

if __name__ == "__main__":
    check_current_config()