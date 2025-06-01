"""
VoiceFlow Speech Pipeline Debugger
Tests each component of the speech recognition system
"""

import sys
import time
import threading
import queue
from pathlib import Path

def test_microphone_access():
    """Test if microphone is accessible"""
    print("\n🎤 TESTING MICROPHONE ACCESS...")
    try:
        import pyaudio
        
        # Get default input device
        p = pyaudio.PyAudio()
        default_device = p.get_default_input_device_info()
        print(f"✅ Default microphone: {default_device['name']}")
        print(f"   Max input channels: {default_device['maxInputChannels']}")
        print(f"   Default sample rate: {default_device['defaultSampleRate']}")
        
        # Test opening audio stream
        stream = p.open(
            format=pyaudio.paInt16,
            channels=1,
            rate=16000,
            input=True,
            frames_per_buffer=1024
        )
        
        print("✅ Audio stream opened successfully")
        
        # Read a small amount of audio
        data = stream.read(1024)
        print(f"✅ Audio data received: {len(data)} bytes")
        
        stream.stop_stream()
        stream.close()
        p.terminate()
        
        return True
        
    except Exception as e:
        print(f"❌ Microphone test failed: {e}")
        return False

def test_whisper_model():
    """Test if Whisper model can load"""
    print("\n🧠 TESTING WHISPER MODEL...")
    try:
        from faster_whisper import WhisperModel
        
        print("Loading Whisper base model...")
        model = WhisperModel("base", device="cpu", compute_type="int8")
        print("✅ Whisper model loaded successfully")
        
        # Test with dummy audio (silence)
        import numpy as np
        dummy_audio = np.zeros(16000, dtype=np.float32)  # 1 second of silence
        
        segments, info = model.transcribe(dummy_audio)
        segments = list(segments)
        print(f"✅ Whisper transcription test completed")
        print(f"   Language detected: {info.language} (confidence: {info.language_probability:.2f})")
        
        return True
        
    except Exception as e:
        print(f"❌ Whisper model test failed: {e}")
        return False

def test_realtimestt():
    """Test RealtimeSTT initialization"""
    print("\n🔄 TESTING REALTIMESTT...")
    try:
        from RealtimeSTT import AudioToTextRecorder
        
        # Simplified configuration for testing
        print("Initializing RealtimeSTT...")
        
        recorder = AudioToTextRecorder(
            model="base",
            language="en", 
            device="cpu",
            compute_type="int8",
            use_microphone=True,
            spinner=False,
            level=0,
            enable_realtime_transcription=False,  # Disable for testing
            post_speech_silence_duration=1.0,
            min_length_of_recording=1.0
        )
        
        print("✅ RealtimeSTT initialized successfully")
        
        # Test short recording
        print("Testing 3-second recording... Say something!")
        print("Recording starts in 3 seconds...")
        time.sleep(3)
        
        text = recorder.text(timeout=5, phrase_timeout=2)
        
        if text and text.strip():
            print(f"✅ Transcription successful: '{text}'")
            return True, text
        else:
            print("⚠️  No speech detected or transcription empty")
            return False, None
            
    except Exception as e:
        print(f"❌ RealtimeSTT test failed: {e}")
        import traceback
        traceback.print_exc()
        return False, None

def test_text_injection():
    """Test text injection capability"""
    print("\n⌨️  TESTING TEXT INJECTION...")
    try:
        import pyautogui
        import subprocess
        import time
        
        # Open notepad for testing
        print("Opening Notepad for test...")
        subprocess.Popen(["notepad.exe"])
        time.sleep(2)
        
        # Try to type test text
        test_text = f"VoiceFlow text injection test - {time.strftime('%H:%M:%S')}"
        print(f"Typing: {test_text}")
        
        pyautogui.typewrite(test_text)
        print("✅ Text injection completed - check Notepad!")
        
        return True
        
    except Exception as e:
        print(f"❌ Text injection test failed: {e}")
        return False

def test_global_hotkey():
    """Test global hotkey detection"""
    print("\n🔥 TESTING GLOBAL HOTKEY...")
    try:
        import keyboard
        
        hotkey_detected = threading.Event()
        
        def hotkey_handler():
            print("✅ Ctrl+Alt hotkey detected!")
            hotkey_detected.set()
        
        keyboard.add_hotkey('ctrl+alt', hotkey_handler)
        print("Hotkey registered. Press Ctrl+Alt within 10 seconds...")
        
        # Wait for hotkey
        if hotkey_detected.wait(timeout=10):
            keyboard.clear_all_hotkeys()
            return True
        else:
            print("⚠️  No hotkey detected within 10 seconds")
            keyboard.clear_all_hotkeys()
            return False
            
    except Exception as e:
        print(f"❌ Global hotkey test failed: {e}")
        return False

def test_ollama_connection():
    """Test Ollama AI enhancement"""
    print("\n🤖 TESTING OLLAMA AI...")
    try:
        import requests
        
        # Test connection
        response = requests.get("http://localhost:11434/api/tags", timeout=3)
        if response.status_code == 200:
            models = response.json().get('models', [])
            print(f"✅ Ollama connected with {len(models)} models")
            
            # Test text enhancement
            if models:
                model_name = models[0]['name']
                print(f"Testing enhancement with {model_name}...")
                
                enhance_response = requests.post("http://localhost:11434/api/generate", json={
                    "model": model_name,
                    "prompt": "Format this text: hello world this is a test",
                    "stream": False
                }, timeout=10)
                
                if enhance_response.status_code == 200:
                    result = enhance_response.json().get('response', '').strip()
                    print(f"✅ AI enhancement working: '{result}'")
                    return True
                    
        print("⚠️  Ollama not accessible")
        return False
        
    except Exception as e:
        print(f"❌ Ollama test failed: {e}")
        return False

def main():
    """Run comprehensive diagnostic"""
    print("="*60)
    print("🔍 VoiceFlow Speech Pipeline Diagnostic")
    print("="*60)
    
    results = {}
    
    # Test each component
    results['microphone'] = test_microphone_access()
    results['whisper'] = test_whisper_model()
    results['text_injection'] = test_text_injection()
    results['global_hotkey'] = test_global_hotkey()
    results['ollama'] = test_ollama_connection()
    
    # Test full speech pipeline
    results['realtimestt'], transcribed_text = test_realtimestt()
    
    # Generate report
    print("\n" + "="*60)
    print("📊 DIAGNOSTIC RESULTS")
    print("="*60)
    
    for component, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{component:15} {status}")
    
    # Overall assessment
    critical_components = ['microphone', 'realtimestt', 'text_injection']
    critical_failures = [comp for comp in critical_components if not results.get(comp)]
    
    print("\n" + "="*60)
    if not critical_failures:
        print("🎉 ALL CRITICAL COMPONENTS WORKING!")
        print("VoiceFlow should work properly.")
        if transcribed_text:
            print(f"Last transcription: '{transcribed_text}'")
    else:
        print("🚨 CRITICAL FAILURES DETECTED:")
        for failure in critical_failures:
            print(f"   ❌ {failure}")
        print("\nThese components must be fixed for VoiceFlow to work.")
    
    print("="*60)
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Diagnostic interrupted by user")
    except Exception as e:
        print(f"\n💥 Diagnostic crashed: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")
