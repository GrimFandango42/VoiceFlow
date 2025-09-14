#!/usr/bin/env python3
"""
Test Visual Indicators
======================
Simple test script to validate the VoiceFlow visual indicator system
"""

import sys
import time
sys.path.append('.')

def test_bottom_overlay():
    """Test the bottom-screen overlay indicator"""
    print("Testing bottom-screen overlay...")
    
    try:
        from localflow.visual_indicators import test_visual_indicators
        test_visual_indicators()
    except Exception as e:
        print(f"Bottom overlay test failed: {e}")
        import traceback
        traceback.print_exc()

def test_tray_icons():
    """Test the enhanced tray icons"""
    print("Testing enhanced tray icons...")
    
    try:
        from localflow.enhanced_tray import _make_status_icon
        
        # Test different status icons
        statuses = ["idle", "listening", "processing", "error"]
        for status in statuses:
            icon = _make_status_icon(16, status, False)
            if icon:
                print(f"  [OK] {status} icon created successfully")
            else:
                print(f"  [FAIL] {status} icon creation failed")
        
        # Test recording state
        icon = _make_status_icon(16, "listening", True)
        if icon:
            print(f"  [OK] recording indicator created successfully")
        else:
            print(f"  [FAIL] recording indicator creation failed")
            
    except Exception as e:
        print(f"Tray icon test failed: {e}")
        import traceback
        traceback.print_exc()

def test_integration():
    """Test integration between tray and visual indicators"""
    print("Testing tray + visual integration...")
    
    try:
        from localflow.config import Config
        from localflow.enhanced_tray import EnhancedTrayController
        
        # Mock app object for testing
        class MockApp:
            def __init__(self):
                self.cfg = Config()
                self.code_mode = False
        
        app = MockApp()
        tray = EnhancedTrayController(app)
        
        print("  Testing status updates...")
        tray.update_status("listening", True, "Test listening")
        time.sleep(1)
        
        tray.update_status("processing", False, "Test processing")  
        time.sleep(1)
        
        tray.update_status("complete", False, "Test complete")
        time.sleep(2)
        
        tray.update_status("idle", False)
        
        print("  [OK] Integration test completed")
        
    except Exception as e:
        print(f"Integration test failed: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Run all visual indicator tests"""
    print("="*50)
    print("VoiceFlow Visual Indicators Test Suite")
    print("="*50)
    
    print("\n1. Testing dependencies...")
    
    try:
        import tkinter
        print("  [OK] tkinter available")
    except ImportError:
        print("  [FAIL] tkinter not available - overlay tests will fail")
    
    try:
        import pystray
        from PIL import Image
        print("  [OK] pystray + PIL available")
    except ImportError:
        print("  [FAIL] pystray/PIL not available - tray tests will fail")
    
    print("\n2. Bottom-screen overlay test:")
    test_bottom_overlay()
    
    print("\n3. Tray icon generation test:")
    test_tray_icons()
    
    print("\n4. Integration test:")
    test_integration()
    
    print("\n" + "="*50)
    print("Visual indicators test complete!")
    print("If tests passed, VoiceFlow visual system is ready.")
    print("="*50)

if __name__ == "__main__":
    main()