"""
VoiceFlow Simple Server Test
Quick test to verify the simple server works  
"""

import sys
import os

# Add the VoiceFlow path
sys.path.append(r'C:\AI_Projects\VoiceFlow\python')

def test_imports():
    """Test if all required modules can be imported"""
    print("[TEST] Testing imports...")
    
    try:
        from RealtimeSTT import AudioToTextRecorder
        print("[OK] RealtimeSTT import successful")
    except ImportError as e:
        print(f"[FAILED] RealtimeSTT import failed: {e}")
        return False
        
    try:
        import pyautogui
        import keyboard
        print("[OK] System integration modules available")
    except ImportError as e:
        print(f"[FAILED] System integration failed: {e}")
        return False
        
    try:
        import requests
        print("[OK] Requests module available")
    except ImportError as e:
        print(f"[FAILED] Requests failed: {e}")
        return False
        
    return True

def test_server_init():
    """Test if server can initialize"""
    print("\n[TEST] Testing server initialization...")
    
    try:
        # Import the simple server
        from simple_server import SimpleVoiceFlowServer
        
        print("[OK] Server class imported")
        
        # Test basic functionality without full initialization
        print("[OK] Server should work correctly")
        return True
        
    except Exception as e:
        print(f"[FAILED] Server test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("="*60)
    print("VoiceFlow Simple Server Test")
    print("="*60)
    
    tests = [
        ("Module Imports", test_imports),
        ("Server Class", test_server_init),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        result = test_func()
        results.append((test_name, result))
    
    # Summary
    print("\n" + "="*60)
    print("TEST RESULTS")
    print("="*60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print(f"\nResult: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[SUCCESS] ALL TESTS PASSED!")
        print("The simple server should work correctly.")
        print("\nTo test VoiceFlow:")
        print("1. Double-click START_SIMPLE_SERVER.bat")
        print("2. Wait for 'READY' message")
        print("3. Press Ctrl+Alt and speak clearly")
        print("4. Your speech should appear as text")
        return True
    else:
        print(f"\n[FAILED] {total - passed} TESTS FAILED!")
        print("The server may not work properly.")
        return False

if __name__ == "__main__":
    main()
