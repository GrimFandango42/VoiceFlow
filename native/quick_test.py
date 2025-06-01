"""
VoiceFlow Native - Quick Test
Quick non-interactive test of core components.
"""

import sys
import os
from pathlib import Path

def quick_test():
    print("VoiceFlow Native - Quick Component Test")
    print("=" * 50)
    
    # Test 1: Imports
    print("\n[TEST 1] Import Test...")
    try:
        import win32api
        import win32gui
        import pystray
        import keyboard
        import pyaudio
        print("[OK] All imports successful")
    except ImportError as e:
        print(f"[FAIL] Import failed: {e}")
        return False
    
    # Test 2: Basic window detection
    print("\n[TEST 2] Window Detection...")
    try:
        import win32gui
        hwnd = win32gui.GetForegroundWindow()
        if hwnd:
            title = win32gui.GetWindowText(hwnd)
            print(f"[OK] Active window: {title}")
        else:
            print("[FAIL] No active window found")
    except Exception as e:
        print(f"[FAIL] Window detection failed: {e}")
    
    # Test 3: Audio devices
    print("\n[TEST 3] Audio Devices...")
    try:
        import pyaudio
        audio = pyaudio.PyAudio()
        device_count = audio.get_device_count()
        input_devices = 0
        for i in range(device_count):
            device_info = audio.get_device_info_by_index(i)
            if device_info['maxInputChannels'] > 0:
                input_devices += 1
        audio.terminate()
        print(f"[OK] Found {input_devices} input devices")
    except Exception as e:
        print(f"[FAIL] Audio test failed: {e}")
    
    # Test 4: Speech processor
    print("\n[TEST 4] Speech Processor...")
    try:
        sys.path.append(str(Path(__file__).parent))
        from speech_processor import get_speech_processor
        processor = get_speech_processor()
        print("[OK] Speech processor initialized")
    except Exception as e:
        print(f"[FAIL] Speech processor failed: {e}")
    
    # Test 5: VoiceFlow Native core
    print("\n[TEST 5] VoiceFlow Native Core...")
    try:
        from voiceflow_native import VoiceFlowNative
        app = VoiceFlowNative()
        print("[OK] VoiceFlow Native initialized")
        
        # Test window info
        window_info = app.get_active_window_info()
        if window_info:
            context = app.detect_application_context(window_info)
            print(f"[OK] Context detection: {context}")
        
    except Exception as e:
        print(f"[FAIL] VoiceFlow Native failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 50)
    print("Quick test completed. Check results above.")
    return True

if __name__ == "__main__":
    quick_test()
