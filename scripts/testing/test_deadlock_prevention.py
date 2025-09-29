#!/usr/bin/env python3
"""
Quick test to verify deadlock prevention is working
"""

import sys
import time
import numpy as np
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

def test_processing_state_reset():
    """Test that _is_processing is always reset even if errors occur"""

    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        from voiceflow.core.config import Config

        config = Config()
        asr = BufferSafeWhisperASR(config)

        print(f"Initial processing state: {asr._is_processing}")
        assert asr._is_processing == False, "Should start with processing=False"

        # Test normal transcription
        test_audio = np.random.normal(0, 0.01, 16000).astype(np.float32)  # 1 second

        print("Testing normal transcription...")
        result = asr.transcribe(test_audio)

        print(f"After normal transcription: {asr._is_processing}")
        assert asr._is_processing == False, "Should reset processing=False after normal transcription"

        # Test transcription with invalid audio to trigger error
        print("Testing error handling...")
        try:
            invalid_audio = np.array([np.nan, np.inf, -np.inf], dtype=np.float32)
            result = asr.transcribe(invalid_audio)
        except:
            pass  # We expect this to fail

        print(f"After error transcription: {asr._is_processing}")
        assert asr._is_processing == False, "Should reset processing=False even after errors"

        print("SUCCESS: Deadlock prevention is working correctly!")
        print("- Processing state is properly reset after normal transcription")
        print("- Processing state is properly reset after error transcription")
        print("- No deadlock detected")

        return True

    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing Deadlock Prevention...")
    success = test_processing_state_reset()
    exit(0 if success else 1)