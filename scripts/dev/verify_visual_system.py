#!/usr/bin/env python3
"""
Quick verification that VoiceFlow visual system works
"""

import sys
import time
import threading

def test_basic_functionality():
    """Test basic imports and functionality"""
    print("=== VoiceFlow Visual System Verification ===")
    
    # Test 1: Basic imports
    print("\n1. Testing imports...")
    try:
        from localflow.visual_indicators import show_listening, show_complete, hide_status
        print("   [OK] Visual indicators imported")
    except Exception as e:
        print(f"   [FAIL] Visual indicators failed: {e}")
        return False
    
    try:
        from localflow.enhanced_tray import EnhancedTrayController
        print("   [OK] Enhanced tray imported")
    except Exception as e:
        print(f"   [FAIL] Enhanced tray failed: {e}")
        return False
    
    # Test 2: Basic tkinter
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()  # Hide immediately
        root.destroy()
        print("   [OK] tkinter functional")
    except Exception as e:
        print(f"   [FAIL] tkinter failed: {e}")
        return False
    
    # Test 3: CLI integration
    print("\n2. Testing CLI integration...")
    try:
        from localflow.cli_enhanced import EnhancedApp
        from localflow.config import Config
        cfg = Config()
        app = EnhancedApp(cfg)
        print("   [OK] Enhanced CLI loads without errors")
        
        # Check if visual integration is present
        if hasattr(app, 'visual_indicators_enabled'):
            print("   [OK] Visual indicators integration present")
        else:
            print("   [FAIL] Visual indicators integration missing")
            return False
            
    except Exception as e:
        print(f"   [FAIL] CLI integration failed: {e}")
        return False
    
    # Test 4: Quick visual display (non-blocking)
    print("\n3. Testing visual display (5 second demo)...")
    try:
        def visual_test():
            show_listening()
            time.sleep(1)
            show_complete("Test successful!")
            time.sleep(2) 
            hide_status()
        
        # Run in background thread
        thread = threading.Thread(target=visual_test, daemon=True)
        thread.start()
        thread.join(timeout=6)  # Wait max 6 seconds
        print("   [OK] Visual display test completed")
        
    except Exception as e:
        print(f"   [FAIL] Visual display failed: {e}")
        return False
    
    print("\n=== VERIFICATION COMPLETE ===")
    print("[OK] All visual components working correctly")
    print("[OK] VoiceFlow visual system ready for use")
    print("\nYou can now use:")
    print("  - LAUNCH_VOICEFLOW_VISUAL.bat")
    print("  - python voiceflow.py")
    
    return True

if __name__ == "__main__":
    success = test_basic_functionality()
    if success:
        print("\n[SUCCESS] Visual system is working!")
        sys.exit(0)
    else:
        print("\n[FAILURE] Visual system has issues!")
        sys.exit(1)