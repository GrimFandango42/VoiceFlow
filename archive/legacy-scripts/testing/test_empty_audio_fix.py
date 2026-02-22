#!/usr/bin/env python3
"""
Test to validate the fix for "OK OK OK" spam and stuck processing state issues.
This tests the exact scenario: Ctrl+Shift press/release without speaking.
"""

import sys
import time
import numpy as np
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

def test_empty_audio_scenarios():
    """Test that empty/silent audio doesn't cause OK spam or stuck processing"""

    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        from voiceflow.core.config import Config

        config = Config()
        asr = BufferSafeWhisperASR(config)

        print("Testing Empty Audio Scenarios")
        print("=" * 50)

        # Test 1: Completely empty audio (None)
        print("1. Testing None audio...")
        result1 = asr.transcribe(None)
        print(f"   Result: '{result1}' (expected: empty string)")
        print(f"   Processing state: {asr._is_processing} (expected: False)")
        assert result1 == "", "None audio should return empty string"
        assert not asr._is_processing, "Processing state should be False after None audio"

        # Test 2: Zero-length array
        print("2. Testing zero-length audio array...")
        empty_audio = np.array([], dtype=np.float32)
        result2 = asr.transcribe(empty_audio)
        print(f"   Result: '{result2}' (expected: empty string)")
        print(f"   Processing state: {asr._is_processing} (expected: False)")
        assert result2 == "", "Empty array should return empty string"
        assert not asr._is_processing, "Processing state should be False after empty array"

        # Test 3: Silent audio (all zeros)
        print("3. Testing silent audio (all zeros)...")
        silent_audio = np.zeros(16000, dtype=np.float32)  # 1 second of silence
        result3 = asr.transcribe(silent_audio)
        print(f"   Result: '{result3}' (expected: empty string)")
        print(f"   Processing state: {asr._is_processing} (expected: False)")
        assert result3 == "", "Silent audio should return empty string"
        assert not asr._is_processing, "Processing state should be False after silent audio"

        # Test 4: Very quiet audio (below threshold)
        print("4. Testing very quiet audio...")
        quiet_audio = np.random.normal(0, 1e-8, 16000).astype(np.float32)  # Very quiet noise
        result4 = asr.transcribe(quiet_audio)
        print(f"   Result: '{result4}' (expected: empty string)")
        print(f"   Processing state: {asr._is_processing} (expected: False)")
        assert result4 == "", "Very quiet audio should return empty string"
        assert not asr._is_processing, "Processing state should be False after quiet audio"

        # Test 5: Verify system can still transcribe real audio after empty audio
        print("5. Testing recovery - normal audio after empty audio...")
        normal_audio = np.random.normal(0, 0.01, 16000).astype(np.float32)  # Normal level audio
        result5 = asr.transcribe(normal_audio)
        print(f"   Result length: {len(result5)} chars")
        print(f"   Processing state: {asr._is_processing} (expected: False)")
        assert not asr._is_processing, "Processing state should be False after normal transcription"

        print("\nSUCCESS: All empty audio scenarios handled correctly!")
        print("- No 'OK OK OK' spam detected")
        print("- Processing state properly reset")
        print("- System ready for subsequent transcriptions")

        return True

    except Exception as e:
        print(f"\nFAILURE: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_rapid_empty_audio():
    """Test rapid empty audio requests to simulate user behavior"""

    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        from voiceflow.core.config import Config

        config = Config()
        asr = BufferSafeWhisperASR(config)

        print("\nTesting Rapid Empty Audio Requests")
        print("=" * 50)

        # Simulate rapid Ctrl+Shift press/release without speaking
        for i in range(5):
            print(f"Rapid request {i+1}...")

            # Mix of different empty audio types
            if i % 2 == 0:
                test_audio = np.zeros(8000, dtype=np.float32)  # Short silence
            else:
                test_audio = np.random.normal(0, 1e-8, 4000).astype(np.float32)  # Very quiet

            result = asr.transcribe(test_audio)
            print(f"   Result: '{result}' (length: {len(result)})")
            print(f"   Processing state: {asr._is_processing}")

            assert result == "", f"Request {i+1} should return empty string"
            assert not asr._is_processing, f"Processing state should be False after request {i+1}"

            # Small delay to simulate user timing
            time.sleep(0.1)

        print("\nSUCCESS: Rapid empty audio requests handled correctly!")
        print("- No accumulated 'OK' outputs")
        print("- Processing state consistently reset")
        print("- No system degradation")

        return True

    except Exception as e:
        print(f"\nFAILURE: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_mixed_audio_scenarios():
    """Test mixed scenarios with empty and real audio"""

    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        from voiceflow.core.config import Config

        config = Config()
        asr = BufferSafeWhisperASR(config)

        print("\nTesting Mixed Audio Scenarios")
        print("=" * 50)

        scenarios = [
            ("Empty", np.array([], dtype=np.float32)),
            ("Normal", np.random.normal(0, 0.01, 16000).astype(np.float32)),
            ("Silent", np.zeros(8000, dtype=np.float32)),
            ("Normal", np.random.normal(0, 0.01, 12000).astype(np.float32)),
            ("Quiet", np.random.normal(0, 1e-8, 6000).astype(np.float32)),
            ("Normal", np.random.normal(0, 0.01, 10000).astype(np.float32)),
        ]

        for i, (desc, audio) in enumerate(scenarios):
            print(f"Scenario {i+1}: {desc} audio...")
            result = asr.transcribe(audio)

            if desc == "Normal":
                print(f"   Result length: {len(result)} chars")
            else:
                print(f"   Result: '{result}' (expected: empty)")
                assert result == "", f"{desc} audio should return empty string"

            print(f"   Processing state: {asr._is_processing} (expected: False)")
            assert not asr._is_processing, f"Processing state should be False after {desc} audio"

        print("\nSUCCESS: Mixed audio scenarios handled correctly!")
        print("- Empty audio properly filtered out")
        print("- Normal audio still processed")
        print("- No interference between scenarios")

        return True

    except Exception as e:
        print(f"\nFAILURE: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing Empty Audio Fix for 'OK OK OK' Spam and Stuck Processing")
    print("=" * 70)

    success1 = test_empty_audio_scenarios()
    success2 = test_rapid_empty_audio()
    success3 = test_mixed_audio_scenarios()

    if success1 and success2 and success3:
        print("\nALL TESTS PASSED!")
        print("The empty audio fix is working correctly.")
        print("- No 'OK OK OK' spam from empty audio")
        print("- No stuck processing state")
        print("- System remains responsive")
        exit(0)
    else:
        print("\nSOME TESTS FAILED!")
        print("The fix needs additional work.")
        exit(1)