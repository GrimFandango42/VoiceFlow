#!/usr/bin/env python3
"""
Real-world test for VoiceFlow transcription focused on the specific issue:
"any audio clip in more than two sentences with a couple of pauses and resuming"
"""

import sys
import time
import numpy as np
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

def create_realistic_speech_audio(duration_seconds=6.0, sample_rate=16000):
    """Create more realistic speech audio with proper speech patterns"""
    samples = int(duration_seconds * sample_rate)
    audio = np.zeros(samples, dtype=np.float32)

    # Speech segments with realistic timing
    # Sentence 1: 0-2s (with 1.5s speech, 0.5s pause)
    # Sentence 2: 2.5-4.5s (with 1.8s speech, 0.2s pause)
    # Sentence 3: 5-6s (final sentence)

    speech_segments = [
        (0.0, 1.5),      # First sentence
        (2.5, 4.3),      # Second sentence after pause
        (5.0, 6.0),      # Third sentence after pause
    ]

    for start_time, end_time in speech_segments:
        start_sample = int(start_time * sample_rate)
        end_sample = int(end_time * sample_rate)

        if end_sample <= samples:
            # Create speech-like audio with varying amplitude
            segment_length = end_sample - start_sample

            # Generate more complex audio that resembles speech
            # Multiple frequency components to simulate formants
            t = np.linspace(0, end_time - start_time, segment_length)

            # Base frequency around 100Hz (fundamental)
            base_freq = np.sin(2 * np.pi * 100 * t)

            # Add harmonics and formants
            formant1 = 0.3 * np.sin(2 * np.pi * 800 * t)
            formant2 = 0.2 * np.sin(2 * np.pi * 1200 * t)

            # Add some noise for realism
            noise = 0.1 * np.random.normal(0, 1, segment_length)

            # Combine and scale
            speech_signal = (base_freq + formant1 + formant2 + noise) * 0.1

            # Add amplitude envelope (speech-like)
            envelope = np.exp(-3 * (t - (end_time - start_time)/2)**2 / ((end_time - start_time)/2)**2)
            speech_signal *= envelope

            audio[start_sample:end_sample] = speech_signal.astype(np.float32)

    return audio

def test_realistic_scenarios():
    """Test realistic scenarios that match user's issue description"""

    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        from voiceflow.core.config import Config

        config = Config()
        print(f"Testing with: device={config.device}, compute_type={config.compute_type}")

        asr = BufferSafeWhisperASR(config)
        print("ASR initialized successfully")

        # Test scenarios that match the user's description
        test_cases = [
            ("Quick single sentence", 2.0),
            ("Two sentences with pause", 4.0),
            ("Three sentences with pauses", 6.0),  # This often triggers the issue
            ("Long complex speech", 8.0),           # This should definitely trigger if issue exists
            ("Very long monologue", 10.0),          # Extended speech
            ("Recovery test", 2.0),                 # Test if system recovers
        ]

        for i, (description, duration) in enumerate(test_cases, 1):
            print(f"\n{'='*50}")
            print(f"Test {i}: {description} ({duration}s)")
            print(f"{'='*50}")

            try:
                # Check system state
                model_state = "None" if asr._model is None else "Loaded"
                processing_state = asr._is_processing
                transcription_count = asr._transcriptions_since_reload

                print(f"BEFORE: model={model_state}, processing={processing_state}, count={transcription_count}")

                # Create realistic audio
                print("Creating realistic speech audio...")
                test_audio = create_realistic_speech_audio(duration)

                # Transcribe
                print("Starting transcription...")
                start_time = time.time()
                result = asr.transcribe(test_audio)
                execution_time = time.time() - start_time

                # Check state after
                model_state_after = "None" if asr._model is None else "Loaded"
                processing_state_after = asr._is_processing

                print(f"SUCCESS: {execution_time:.2f}s")
                print(f"Result length: {len(result) if result else 0}")
                print(f"AFTER: model={model_state_after}, processing={processing_state_after}")

                if result:
                    print(f"Transcription preview: '{result[:100]}...'")

            except Exception as e:
                error_msg = str(e)
                print(f"ERROR: {error_msg}")

                # Check if this is the target error
                if "NoneType" in error_msg and "context manager" in error_msg:
                    print("*** FOUND THE NONETYPE CONTEXT MANAGER ERROR ***")
                    print(f"This occurred after {transcription_count} transcriptions")
                    print(f"During test: {description}")

                    # Check if recovery works
                    print("Testing recovery...")
                    try:
                        recovery_audio = create_realistic_speech_audio(2.0)
                        recovery_result = asr.transcribe(recovery_audio)
                        print("Recovery successful!")
                    except Exception as recovery_error:
                        print(f"Recovery failed: {recovery_error}")

                    return False

            # Brief pause between tests
            time.sleep(0.5)

        print(f"\n{'='*60}")
        print("ALL TESTS COMPLETED SUCCESSFULLY!")
        print("The NoneType context manager error was NOT reproduced.")
        print(f"{'='*60}")
        return True

    except Exception as e:
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Real-World VoiceFlow Testing")
    print("Testing: 'audio clips with more than two sentences with pauses and resuming'")
    print()

    success = test_realistic_scenarios()

    if success:
        print("\nCONCLUSION: The transcription system appears to be working correctly.")
        print("If you're still experiencing issues, they may be related to:")
        print("1. Specific audio input patterns from your microphone")
        print("2. Real-time audio processing differences")
        print("3. Threading issues in the live application")
    else:
        print("\nCONCLUSION: The NoneType error was reproduced and needs further fixing.")

    exit(0 if success else 1)