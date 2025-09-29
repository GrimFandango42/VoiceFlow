#!/usr/bin/env python3
"""
Debug script to systematically reproduce and fix the NoneType context manager error.
This will help us understand exactly where and why self._model becomes None.
"""

import sys
import time
import numpy as np
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
from voiceflow.core.config import Config

def create_test_audio(duration_seconds=2.0, sample_rate=16000):
    """Create test audio - silence with small noise"""
    samples = int(duration_seconds * sample_rate)
    # Generate very quiet white noise to simulate speech
    audio = np.random.normal(0, 0.001, samples).astype(np.float32)
    return audio

def test_asr_stability():
    """Test ASR stability with multiple transcription attempts"""
    print("🔧 Debugging NoneType Context Manager Error")
    print("=" * 60)

    try:
        # Initialize ASR with config
        config = Config()
        print(f"📋 Config: max_transcriptions_before_reload = {config.max_transcriptions_before_reload}")

        asr = BufferSafeWhisperASR(config)
        print("✅ ASR initialized successfully")

        # Test multiple transcriptions to reproduce the error
        for i in range(1, 11):  # Test 10 transcriptions
            print(f"\n🎯 Test transcription #{i}")

            # Check model state before transcription
            model_state = "None" if asr._model is None else "Loaded"
            processing_state = asr._is_processing
            transcriptions_count = asr._transcriptions_since_reload

            print(f"   Model state: {model_state}")
            print(f"   Processing: {processing_state}")
            print(f"   Transcriptions since reload: {transcriptions_count}")

            # Create test audio
            test_audio = create_test_audio(duration_seconds=1.0)

            # Attempt transcription
            try:
                start_time = time.time()
                result = asr.transcribe(test_audio)
                duration = time.time() - start_time

                print(f"   ✅ Success: '{result}' ({duration:.2f}s)")

            except Exception as e:
                error_msg = str(e)
                print(f"   ❌ Error: {error_msg}")

                # Check model state after error
                model_state_after = "None" if asr._model is None else "Loaded"
                processing_state_after = asr._is_processing

                print(f"   Model state after error: {model_state_after}")
                print(f"   Processing after error: {processing_state_after}")

                if "NoneType" in error_msg and "context manager" in error_msg:
                    print("   🚨 FOUND THE NONETYPE ERROR!")

                    # Diagnostic info
                    print(f"   Transcription count when error occurred: {transcriptions_count}")
                    print(f"   Was processing flag set? {processing_state}")
                    print(f"   Model was None before transcription? {model_state == 'None'}")

                    # Try to understand what happened
                    if hasattr(asr, '_model_lock'):
                        print("   Model lock exists")
                    else:
                        print("   ⚠️ Model lock missing!")

                    break

            # Small delay between tests
            time.sleep(0.5)

        print("\n📊 Test Results Summary")
        print(f"Final model state: {'None' if asr._model is None else 'Loaded'}")
        print(f"Final processing state: {asr._is_processing}")
        print(f"Total transcriptions attempted: {asr._transcriptions_since_reload}")

    except Exception as e:
        print(f"💥 Fatal error during ASR initialization: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_asr_stability()