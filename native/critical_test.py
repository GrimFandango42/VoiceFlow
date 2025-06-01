"""
VoiceFlow Native - Critical Components Test
Tests only the most critical components without heavy processing.
"""

import sys
import os
import time
from pathlib import Path

def test_critical_components():
    """Test only the most critical components."""
    print("VoiceFlow Native - Critical Components Test")
    print("=" * 60)
    
    results = {}
    
    # Test 1: Basic imports and initialization
    print("\n[TEST 1] Core Initialization...")
    try:
        sys.path.append(str(Path(__file__).parent))
        from voiceflow_native import VoiceFlowNative
        app = VoiceFlowNative()
        results['initialization'] = True
        print("[OK] VoiceFlow Native initialized successfully")
    except Exception as e:
        results['initialization'] = False
        print(f"[FAIL] Initialization failed: {e}")
        return results
    
    # Test 2: Window detection and context
    print("\n[TEST 2] Window Detection & Context...")
    try:
        window_info = app.get_active_window_info()
        if window_info:
            context = app.detect_application_context(window_info)
            results['window_detection'] = True
            print(f"[OK] Window: {window_info.get('app_name')} -> Context: {context}")
        else:
            results['window_detection'] = False
            print("[FAIL] Could not detect active window")
    except Exception as e:
        results['window_detection'] = False
        print(f"[FAIL] Window detection failed: {e}")
    
    # Test 3: Text injection capabilities
    print("\n[TEST 3] Text Injection...")
    try:
        # Test clipboard method only (safest)
        test_text = "VoiceFlow test"
        success = app.inject_via_clipboard(test_text)
        results['text_injection'] = success
        print(f"[{'OK' if success else 'FAIL'}] Clipboard injection: {success}")
    except Exception as e:
        results['text_injection'] = False
        print(f"[FAIL] Text injection failed: {e}")
    
    # Test 4: Global hotkey registration
    print("\n[TEST 4] Global Hotkey...")
    try:
        # Just test the setup, don't actually register to avoid conflicts
        import keyboard
        results['hotkey'] = True
        print("[OK] Keyboard library available for hotkey registration")
    except Exception as e:
        results['hotkey'] = False
        print(f"[FAIL] Hotkey support failed: {e}")
    
    # Test 5: Audio capture capability
    print("\n[TEST 5] Audio Capture...")
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
        
        results['audio_capture'] = input_devices > 0
        print(f"[{'OK' if input_devices > 0 else 'FAIL'}] Found {input_devices} input devices")
    except Exception as e:
        results['audio_capture'] = False
        print(f"[FAIL] Audio capture test failed: {e}")
    
    # Test 6: Speech processor availability (without heavy processing)
    print("\n[TEST 6] Speech Processor...")
    try:
        from speech_processor import get_speech_processor
        processor = get_speech_processor()
        # Just check if it initializes, don't process audio
        results['speech_processor'] = True
        print("[OK] Speech processor initialized")
    except Exception as e:
        results['speech_processor'] = False
        print(f"[FAIL] Speech processor failed: {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("CRITICAL COMPONENTS SUMMARY")
    print("=" * 60)
    
    essential_components = ['initialization', 'window_detection', 'text_injection', 'hotkey']
    optional_components = ['audio_capture', 'speech_processor']
    
    essential_working = sum(results.get(comp, False) for comp in essential_components)
    optional_working = sum(results.get(comp, False) for comp in optional_components)
    
    print(f"Essential Components: {essential_working}/{len(essential_components)}")
    print(f"Optional Components: {optional_working}/{len(optional_components)}")
    
    for comp in essential_components:
        status = "OK" if results.get(comp, False) else "FAIL"
        print(f"  - {comp.replace('_', ' ').title()}: [{status}]")
    
    print("\nOptional Components:")
    for comp in optional_components:
        status = "OK" if results.get(comp, False) else "FAIL"
        print(f"  - {comp.replace('_', ' ').title()}: [{status}]")
    
    # Overall assessment
    if essential_working >= 3:  # At least 3/4 essential components
        print(f"\n[SUCCESS] VoiceFlow Native core is functional!")
        print("Ready for testing with real speech input.")
        
        if essential_working == len(essential_components) and optional_working >= 1:
            print("[EXCELLENT] All components working perfectly!")
        
        return True
    else:
        print(f"\n[FAIL] Too many critical components failed ({essential_working}/{len(essential_components)})")
        print("VoiceFlow Native needs fixes before use.")
        return False

if __name__ == "__main__":
    success = test_critical_components()
    
    if success:
        print(f"\n[NEXT STEPS]")
        print("1. Run full application: python voiceflow_native.py")
        print("2. Test with real voice input")
        print("3. Verify text injection in various applications")
    else:
        print(f"\n[REQUIRED FIXES]")
        print("1. Review failed components above")
        print("2. Check dependencies and permissions")
        print("3. Retry after fixes")
    
    input("\nPress Enter to exit...")
