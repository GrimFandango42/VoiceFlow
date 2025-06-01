"""
VoiceFlow Native - Functional Test
Tests the complete workflow without requiring user interaction.
"""

import sys
import os
import time
import tempfile
import wave
import threading
from pathlib import Path

def test_complete_workflow():
    """Test the complete voice transcription workflow."""
    print("VoiceFlow Native - Functional Test")
    print("=" * 50)
    
    try:
        # Import main components
        sys.path.append(str(Path(__file__).parent))
        from voiceflow_native import VoiceFlowNative
        from speech_processor import get_speech_processor
        
        print("\n[STEP 1] Initialize VoiceFlow Native...")
        app = VoiceFlowNative()
        print("[OK] VoiceFlow Native initialized")
        
        print("\n[STEP 2] Test application context detection...")
        window_info = app.get_active_window_info()
        if window_info:
            context = app.detect_application_context(window_info)
            print(f"[OK] Current context: {context} (App: {window_info.get('app_name')})")
        else:
            print("[WARN] Could not detect window context")
            context = 'general'
        
        print("\n[STEP 3] Test speech processing pipeline...")
        processor = get_speech_processor()
        
        # Create a test audio file (1 second of silence)
        with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
            test_audio_path = temp_file.name
        
        # Create minimal WAV file
        wf = wave.open(test_audio_path, 'wb')
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(16000)
        wf.writeframes(b'\x00' * 32000)  # 1 second of silence
        wf.close()
        
        # Process the test audio
        start_time = time.time()
        enhanced_text, metadata = processor.process_audio_file(test_audio_path, context)
        processing_time = (time.time() - start_time) * 1000
        
        if enhanced_text:
            print(f"[OK] Speech processing successful")
            print(f"     Text: '{enhanced_text}'")
            print(f"     Processing time: {processing_time:.0f}ms")
            print(f"     Context: {context}")
        else:
            print("[WARN] Speech processing returned empty result (expected with silence)")
        
        # Clean up test file
        try:
            os.unlink(test_audio_path)
        except:
            pass
        
        print("\n[STEP 4] Test text injection methods...")
        
        # Test clipboard method
        test_text = "VoiceFlow Native test message"
        clipboard_success = app.inject_via_clipboard(test_text)
        print(f"[{'OK' if clipboard_success else 'FAIL'}] Clipboard injection: {clipboard_success}")
        
        # Test SendKeys method  
        sendkeys_success = app.inject_via_sendkeys("Test")
        print(f"[{'OK' if sendkeys_success else 'FAIL'}] SendKeys injection: {sendkeys_success}")
        
        print("\n[STEP 5] Test hotkey registration...")
        hotkey_success = app.setup_global_hotkey()
        print(f"[{'OK' if hotkey_success else 'FAIL'}] Global hotkey registration: {hotkey_success}")
        
        print("\n[STEP 6] Performance summary...")
        print(f"Application context: {context}")
        print(f"Speech processing latency: {processing_time:.0f}ms")
        print(f"Text injection methods: {2 if clipboard_success and sendkeys_success else 1 if clipboard_success or sendkeys_success else 0}/2 working")
        print(f"Global hotkey: {'Working' if hotkey_success else 'Failed'}")
        
        print("\n" + "=" * 50)
        
        # Overall assessment
        critical_components = [enhanced_text is not None, clipboard_success, hotkey_success]
        working_components = sum(critical_components)
        
        if working_components >= 2:
            print("[SUCCESS] VoiceFlow Native is functional!")
            print("Key features working:")
            if enhanced_text is not None:
                print("  - Speech processing pipeline")
            if clipboard_success:
                print("  - Text injection via clipboard")
            if sendkeys_success:
                print("  - Text injection via SendKeys")
            if hotkey_success:
                print("  - Global hotkey registration")
            
            return True
        else:
            print("[FAIL] VoiceFlow Native has critical issues")
            print(f"Only {working_components}/3 critical components working")
            return False
        
    except Exception as e:
        print(f"[FAIL] Functional test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_performance_benchmarks():
    """Test performance against Whispr Flow benchmarks."""
    print("\n" + "=" * 50)
    print("Performance Benchmark Test")
    print("=" * 50)
    
    try:
        sys.path.append(str(Path(__file__).parent))
        from speech_processor import get_speech_processor
        
        processor = get_speech_processor()
        
        # Create test audio files of different lengths
        test_lengths = [1, 3, 5]  # seconds
        latencies = []
        
        for length in test_lengths:
            print(f"\n[BENCHMARK] Testing {length}s audio processing...")
            
            # Create test audio
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
                test_audio_path = temp_file.name
            
            wf = wave.open(test_audio_path, 'wb')
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(16000)
            wf.writeframes(b'\x00' * (16000 * 2 * length))  # Audio of specified length
            wf.close()
            
            # Measure processing time
            start_time = time.time()
            enhanced_text, metadata = processor.process_audio_file(test_audio_path, 'general')
            processing_time = (time.time() - start_time) * 1000
            
            latencies.append(processing_time)
            print(f"     Processing time: {processing_time:.0f}ms")
            
            # Clean up
            try:
                os.unlink(test_audio_path)
            except:
                pass
        
        # Calculate average latency
        avg_latency = sum(latencies) / len(latencies)
        print(f"\n[BENCHMARK RESULTS]")
        print(f"Average latency: {avg_latency:.0f}ms")
        print(f"Whispr Flow target: 275ms")
        
        if avg_latency <= 275:
            print("[OK] Performance meets Whispr Flow standards!")
        elif avg_latency <= 500:
            print("[OK] Performance is acceptable (under 500ms)")
        else:
            print("[WARN] Performance slower than target")
        
        return avg_latency <= 500
        
    except Exception as e:
        print(f"[FAIL] Benchmark test failed: {e}")
        return False

if __name__ == "__main__":
    print("Starting VoiceFlow Native functional testing...")
    
    # Run functional test
    functional_success = test_complete_workflow()
    
    # Run performance benchmark
    performance_success = test_performance_benchmarks()
    
    print("\n" + "=" * 60)
    print("FINAL TEST RESULTS")
    print("=" * 60)
    print(f"Functional Test: {'PASS' if functional_success else 'FAIL'}")
    print(f"Performance Test: {'PASS' if performance_success else 'FAIL'}")
    
    if functional_success and performance_success:
        print("\n[SUCCESS] VoiceFlow Native is ready for use!")
        print("\nTo run the full application:")
        print("  python voiceflow_native.py")
        print("\nOr use the launcher:")
        print("  TEST_NATIVE.bat")
    else:
        print("\n[FAIL] VoiceFlow Native needs fixes before deployment")
    
    input("\nPress Enter to exit...")
