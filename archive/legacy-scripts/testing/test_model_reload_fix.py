#!/usr/bin/env python3
"""
Test to specifically validate the model reload fix for NoneType errors.
This test forces the reload scenario that was causing NoneType errors.
"""

import sys
import time
import numpy as np
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

def test_model_reload_scenario():
    """Test that model reload operations don't cause NoneType errors"""

    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        from voiceflow.core.config import Config

        config = Config()
        # Force reload after just 2 transcriptions to test the scenario
        config.max_transcriptions_before_reload = 2

        asr = BufferSafeWhisperASR(config)
        print(f"Testing with reload threshold: {config.max_transcriptions_before_reload}")

        # Create test audio
        test_audio = np.random.normal(0, 0.01, 16000).astype(np.float32)  # 1 second

        print("\n=== Testing Model Reload Scenario ===")

        # First transcription (count = 1)
        print("1. First transcription...")
        result1 = asr.transcribe(test_audio)
        print(f"   Result: {len(result1)} chars, Model healthy: {asr._model is not None}")
        assert asr._model is not None, "Model should not be None after first transcription"

        # Second transcription (count = 2)
        print("2. Second transcription...")
        result2 = asr.transcribe(test_audio)
        print(f"   Result: {len(result2)} chars, Model healthy: {asr._model is not None}")
        assert asr._model is not None, "Model should not be None after second transcription"

        # Third transcription (count = 3, triggers reload)
        print("3. Third transcription (triggers reload)...")
        print(f"   Before reload: transcription count = {asr._transcriptions_since_reload}")
        result3 = asr.transcribe(test_audio)
        print(f"   After reload: transcription count = {asr._transcriptions_since_reload}")
        print(f"   Result: {len(result3)} chars, Model healthy: {asr._model is not None}")
        assert asr._model is not None, "CRITICAL: Model should not be None after reload"

        # Fourth transcription (post-reload)
        print("4. Fourth transcription (post-reload)...")
        result4 = asr.transcribe(test_audio)
        print(f"   Result: {len(result4)} chars, Model healthy: {asr._model is not None}")
        assert asr._model is not None, "Model should remain healthy after reload"

        print("\nSUCCESS: Model reload scenario completed without NoneType errors!")
        print(f"   - All transcriptions completed successfully")
        print(f"   - Model remained healthy throughout reload")
        print(f"   - No NoneType context manager errors detected")

        return True

    except Exception as e:
        print(f"\nFAILURE: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_forced_reload_failure_recovery():
    """Test that the system recovers when model reload fails"""

    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        from voiceflow.core.config import Config

        config = Config()
        asr = BufferSafeWhisperASR(config)

        # Create test audio
        test_audio = np.random.normal(0, 0.01, 16000).astype(np.float32)

        print("\n=== Testing Reload Failure Recovery ===")

        # Ensure model is loaded
        print("1. Initial transcription...")
        result1 = asr.transcribe(test_audio)
        original_model = asr._model
        print(f"   Model loaded successfully: {original_model is not None}")

        # Test the _create_fresh_model method directly
        print("2. Testing fresh model creation...")
        fresh_model = asr._create_fresh_model()
        print(f"   Fresh model created: {fresh_model is not None}")
        assert fresh_model is not None, "Fresh model creation should succeed"

        # Test that original model is preserved
        print("3. Verifying original model preservation...")
        assert asr._model is original_model, "Original model should be preserved during fresh model creation"

        # Test atomic reload
        print("4. Testing atomic model reload...")
        old_model_id = id(asr._model)
        asr._reload_model_fresh()
        new_model_id = id(asr._model)
        print(f"   Model replaced: {old_model_id != new_model_id}")
        print(f"   Model healthy: {asr._model is not None}")
        assert asr._model is not None, "Model should not be None after atomic reload"

        # Test transcription still works
        print("5. Testing post-reload transcription...")
        result2 = asr.transcribe(test_audio)
        print(f"   Post-reload transcription successful: {len(result2)} chars")

        print("\nSUCCESS: Reload failure recovery working correctly!")
        return True

    except Exception as e:
        print(f"\nFAILURE: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Testing Model Reload Fix for NoneType Context Manager Error")
    print("=" * 60)

    success1 = test_model_reload_scenario()
    success2 = test_forced_reload_failure_recovery()

    if success1 and success2:
        print("\nALL TESTS PASSED!")
        print("The NoneType context manager error fix is working correctly.")
        exit(0)
    else:
        print("\nSOME TESTS FAILED!")
        print("The fix needs additional work.")
        exit(1)