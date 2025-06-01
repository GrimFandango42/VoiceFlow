"""
VoiceFlow Native - Component Tests
Tests individual components of the native application before full integration.
"""

import sys
import os
import time
import tempfile
import wave
from pathlib import Path

# Add current directory to path
sys.path.append(str(Path(__file__).parent))

def test_imports():
    """Test that all required modules can be imported."""
    print("Testing imports...")
    
    try:
        import win32api
        import win32gui
        import win32clipboard
        print("[OK] Win32 APIs available")
    except ImportError as e:
        print(f"[FAIL] Win32 APIs failed: {e}")
        return False
    
    try:
        import pystray
        from PIL import Image
        print("[OK] System tray support available")
    except ImportError as e:
        print(f"[FAIL] System tray failed: {e}")
        return False
    
    try:
        import keyboard
        print("[OK] Global hotkey support available")
    except ImportError as e:
        print(f"[FAIL] Global hotkey failed: {e}")
        return False
    
    try:
        import pyaudio
        print("[OK] Audio capture available")
    except ImportError as e:
        print(f"[FAIL] Audio capture failed: {e}")
        return False
    
    return True

def test_window_detection():
    """Test window detection and application context."""
    print("\nTesting window detection...")
    
    try:
        from voiceflow_native import VoiceFlowNative
        app = VoiceFlowNative()
        
        # Test window info
        window_info = app.get_active_window_info()
        if window_info:
            print(f"[OK] Active window: {window_info['app_name']} - {window_info['title']}")
            
            # Test context detection
            context = app.detect_application_context(window_info)
            print(f"[OK] Application context: {context}")
            return True
        else:
            print("[FAIL] Could not get active window info")
            return False
            
    except Exception as e:
        print(f"[FAIL] Window detection failed: {e}")
        return False

def test_text_injection():
    """Test text injection capabilities."""
    print("\nTesting text injection...")
    
    try:
        from voiceflow_native import VoiceFlowNative
        app = VoiceFlowNative()
        
        test_text = "Hello from VoiceFlow Native!"
        print(f"Attempting to inject: '{test_text}'")
        print("Please click in a text editor (Notepad, etc.) within 5 seconds...")
        
        time.sleep(5)
        
        success = app.inject_text_universal(test_text)
        if success:
            print("[OK] Text injection successful")
            return True
        else:
            print("[FAIL] Text injection failed")
            return False
            
    except Exception as e:
        print(f"[FAIL] Text injection test failed: {e}")
        return False

def test_audio_capture():
    """Test audio capture functionality."""
    print("\nTesting audio capture...")
    
    try:
        import pyaudio
        import wave
        
        # Test audio devices
        audio = pyaudio.PyAudio()
        device_count = audio.get_device_count()
        print(f"Found {device_count} audio devices")
        
        # Find default input device
        default_device = None
        for i in range(device_count):
            device_info = audio.get_device_info_by_index(i)
            if device_info['maxInputChannels'] > 0:
                print(f"Input device {i}: {device_info['name']}")
                if default_device is None:
                    default_device = i
        
        if default_device is not None:
            print(f"[OK] Using device {default_device} for testing")
            
            # Test recording
            print("Recording 2 seconds of audio...")
            stream = audio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=16000,
                input=True,
                input_device_index=default_device,
                frames_per_buffer=1024
            )
            
            frames = []
            for _ in range(int(16000 / 1024 * 2)):  # 2 seconds
                data = stream.read(1024, exception_on_overflow=False)
                frames.append(data)
            
            stream.stop_stream()
            stream.close()
            
            # Save test audio
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
                test_audio_path = temp_file.name
                
            wf = wave.open(test_audio_path, 'wb')
            wf.setnchannels(1)
            wf.setsampwidth(audio.get_sample_size(pyaudio.paInt16))
            wf.setframerate(16000)
            wf.writeframes(b''.join(frames))
            wf.close()
            
            audio.terminate()
            
            print(f"[OK] Audio captured successfully: {test_audio_path}")
            
            # Clean up
            try:
                os.unlink(test_audio_path)
            except:
                pass
            
            return True
        else:
            print("[FAIL] No input devices found")
            return False
            
    except Exception as e:
        print(f"[FAIL] Audio capture test failed: {e}")
        return False

def test_speech_processing():
    """Test speech processing pipeline."""
    print("\nTesting speech processing...")
    
    try:
        from speech_processor import get_speech_processor
        
        processor = get_speech_processor()
        
        # Test with mock audio file (create a dummy file)
        with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
            test_audio_path = temp_file.name
        
        # Create a minimal WAV file for testing
        import wave
        wf = wave.open(test_audio_path, 'wb')
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(16000)
        wf.writeframes(b'\x00' * 32000)  # 1 second of silence
        wf.close()
        
        # Test processing
        enhanced_text, metadata = processor.process_audio_file(test_audio_path, 'general')
        
        if enhanced_text:
            print(f"[OK] Speech processing successful: '{enhanced_text}'")
            print(f"  Processing time: {metadata.get('total_time_ms', 0):.0f}ms")
            
            # Clean up
            try:
                os.unlink(test_audio_path)
            except:
                pass
            
            return True
        else:
            print("[FAIL] Speech processing failed")
            return False
            
    except Exception as e:
        print(f"[FAIL] Speech processing test failed: {e}")
        return False

def test_hotkey_registration():
    """Test global hotkey registration (non-blocking)."""
    print("\nTesting hotkey registration...")
    
    try:
        import keyboard
        
        # Test hotkey registration
        def test_callback():
            print("Hotkey triggered!")
        
        keyboard.add_hotkey('ctrl+shift+f12', test_callback)
        print("[OK] Test hotkey registered (Ctrl+Shift+F12)")
        
        # Immediately unregister to avoid conflicts
        keyboard.remove_hotkey('ctrl+shift+f12')
        print("[OK] Test hotkey unregistered")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] Hotkey registration test failed: {e}")
        return False

def run_all_tests():
    """Run all component tests."""
    print("VoiceFlow Native - Component Tests")
    print("=" * 50)
    
    tests = [
        ("Import Test", test_imports),
        ("Window Detection", test_window_detection),
        ("Audio Capture", test_audio_capture),
        ("Speech Processing", test_speech_processing),
        ("Hotkey Registration", test_hotkey_registration),
        ("Text Injection", test_text_injection),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"[OK] {test_name} PASSED")
            else:
                print(f"[FAIL] {test_name} FAILED")
        except Exception as e:
            print(f"[FAIL] {test_name} FAILED with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("[SUCCESS] All tests passed! VoiceFlow Native is ready.")
        return True
    else:
        print(f"[WARN]  {total - passed} test(s) failed. Review issues above.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    input("\nPress Enter to exit...")
    sys.exit(0 if success else 1)
