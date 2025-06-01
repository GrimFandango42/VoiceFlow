"""
VoiceFlow Native - Minimal Test Version
Tests core functionality without system tray or blocking operations.
"""

import sys
import os
import time
import tempfile
import wave
from pathlib import Path

# Add current directory to path
sys.path.append(str(Path(__file__).parent))

def test_core_workflow():
    """Test the core voice processing workflow without UI."""
    print("VoiceFlow Native - Core Workflow Test")
    print("=" * 50)
    
    try:
        # Initialize core components
        print("\n[STEP 1] Initialize core components...")
        from voiceflow_native import VoiceFlowNative
        app = VoiceFlowNative()
        print("[OK] VoiceFlowNative initialized")
        
        # Test window detection
        print("\n[STEP 2] Test application context detection...")
        window_info = app.get_active_window_info()
        if window_info:
            context = app.detect_application_context(window_info)
            print(f"[OK] Detected context: {context}")
            print(f"     Active app: {window_info.get('app_name')}")
            print(f"     Window title: {window_info.get('title')}")
        else:
            print("[WARN] Could not detect window")
            context = 'general'
        
        # Test text formatting
        print("\n[STEP 3] Test context-aware text formatting...")
        test_cases = [
            ("hello world this is a test", "email"),
            ("hey whats up", "chat"),
            ("function calculate total", "code"),
            ("this is some text", "general")
        ]
        
        for text, test_context in test_cases:
            formatted = app.format_text_for_context(text, test_context)
            print(f"[OK] {test_context:8}: '{text}' -> '{formatted}'")
        
        # Test text injection methods
        print("\n[STEP 4] Test text injection methods...")
        
        # Test clipboard method (safest)
        test_text = "VoiceFlow Native Test Message"
        print(f"Testing clipboard injection: '{test_text}'")
        clipboard_result = app.inject_via_clipboard(test_text)
        print(f"[{'OK' if clipboard_result else 'FAIL'}] Clipboard injection: {clipboard_result}")
        
        # Test direct SendKeys
        print("Testing SendKeys injection...")
        sendkeys_result = app.inject_via_sendkeys("Test123")
        print(f"[{'OK' if sendkeys_result else 'FAIL'}] SendKeys injection: {sendkeys_result}")
        
        # Test speech processing (with mock audio)
        print("\n[STEP 5] Test speech processing pipeline...")
        
        # Create minimal test audio file
        with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
            test_audio_path = temp_file.name
        
        # Create 0.5 second WAV file
        wf = wave.open(test_audio_path, 'wb')
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(16000)
        wf.writeframes(b'\x00' * 16000)  # 0.5 seconds of silence
        wf.close()
        
        # Process audio (this tests the integration)
        print("Processing test audio...")
        start_time = time.time()
        
        try:
            result = app.process_audio_to_text(test_audio_path)
            processing_time = (time.time() - start_time) * 1000
            
            if result and len(result) == 2:
                enhanced_text, metadata = result
                print(f"[OK] Speech processing successful")
                print(f"     Result: '{enhanced_text}'")
                print(f"     Processing time: {processing_time:.0f}ms")
                speech_success = True
            else:
                print("[WARN] Speech processing returned unexpected result")
                speech_success = False
        except Exception as e:
            print(f"[FAIL] Speech processing failed: {e}")
            speech_success = False
        
        # Clean up test file
        try:
            os.unlink(test_audio_path)
        except:
            pass
        
        # Performance summary
        print("\n[STEP 6] Performance Summary...")
        
        working_components = []
        if window_info:
            working_components.append("Window detection")
        if clipboard_result:
            working_components.append("Clipboard injection")
        if sendkeys_result:
            working_components.append("SendKeys injection")
        if speech_success:
            working_components.append("Speech processing")
        
        print(f"Working components ({len(working_components)}/4):")
        for component in working_components:
            print(f"  - {component}")
        
        # Overall assessment
        print("\n" + "=" * 50)
        
        if len(working_components) >= 3:
            print("[SUCCESS] VoiceFlow Native core functionality is working!")
            print("\nKey capabilities verified:")
            for component in working_components:
                print(f"  [OK] {component}")
            
            print(f"\nDetected application context: {context}")
            if processing_time:
                print(f"Speech processing latency: {processing_time:.0f}ms")
            
            print("\n[READY] Core workflow is functional!")
            return True
        else:
            print("[FAIL] Too many critical components failed")
            print(f"Only {len(working_components)}/4 components working")
            return False
        
    except Exception as e:
        print(f"[FAIL] Core workflow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def simulate_voice_input():
    """Simulate a complete voice input workflow."""
    print("\n" + "=" * 60)
    print("VOICE INPUT WORKFLOW SIMULATION")
    print("=" * 60)
    
    try:
        from voiceflow_native import VoiceFlowNative
        app = VoiceFlowNative()
        
        # Simulate the complete workflow
        print("\n[SIMULATION] User presses Ctrl+Alt hotkey...")
        
        # Get current context
        window_info = app.get_active_window_info()
        context = app.detect_application_context(window_info)
        print(f"[CONTEXT] Detected: {context} (App: {window_info.get('app_name') if window_info else 'Unknown'})")
        
        # Simulate audio processing
        print("[PROCESSING] Simulating speech recognition...")
        simulated_speech = "hello this is a test message"
        
        # Apply context-aware formatting
        formatted_text = app.format_text_for_context(simulated_speech, context)
        print(f"[ENHANCED] '{simulated_speech}' -> '{formatted_text}'")
        
        # Inject text
        print("[INJECTION] Injecting text at cursor...")
        injection_success = app.inject_text_universal(formatted_text, window_info)
        
        if injection_success:
            print(f"[SUCCESS] Text injected: '{formatted_text}'")
            print("[COMPLETE] Voice input workflow successful!")
            return True
        else:
            print("[FAIL] Text injection failed")
            return False
        
    except Exception as e:
        print(f"[FAIL] Workflow simulation failed: {e}")
        return False

if __name__ == "__main__":
    print("VoiceFlow Native - Minimal Test Suite")
    print("=" * 60)
    
    # Run core workflow test
    print("\nRunning core workflow test...")
    core_success = test_core_workflow()
    
    # Run workflow simulation
    if core_success:
        simulation_success = simulate_voice_input()
    else:
        simulation_success = False
    
    # Final results
    print("\n" + "=" * 60)
    print("FINAL TEST RESULTS")
    print("=" * 60)
    print(f"Core Workflow Test: {'PASS' if core_success else 'FAIL'}")
    print(f"Workflow Simulation: {'PASS' if simulation_success else 'FAIL'}")
    
    if core_success and simulation_success:
        print("\n[SUCCESS] VoiceFlow Native is ready for real-world testing!")
        print("\nNext steps:")
        print("1. Test with actual voice input")
        print("2. Verify hotkey registration")
        print("3. Test across multiple applications")
        print("4. Measure real-world performance")
    else:
        print("\n[FAIL] VoiceFlow Native needs further development")
        print("Review failed components and fix issues")
    
    input("\nPress Enter to exit...")
