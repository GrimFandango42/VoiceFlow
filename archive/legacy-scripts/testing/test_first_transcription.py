#!/usr/bin/env python3
"""
Test First Transcription Performance
===================================
Validates that first transcription cold start issues are resolved.

Tests:
1. Model loading time
2. First transcription completeness (no cutoffs)
3. Performance comparison between first and subsequent transcriptions
"""

import sys
import time
import numpy as np
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

def test_model_loading():
    """Test ASR model loading performance"""
    print("="*60)
    print("TEST 1: Model Loading Performance")
    print("="*60)

    try:
        from voiceflow.core.config import Config
        from voiceflow.core.asr_production import ProductionWhisperASR

        cfg = Config()
        asr = ProductionWhisperASR(cfg)

        print("[TEST] Starting model loading...")
        start_time = time.time()
        asr.load()
        load_time = time.time() - start_time

        print(f"[RESULT] ✅ Models loaded in {load_time:.2f}s")

        if load_time < 10:
            print(f"[ASSESSMENT] ✅ PASS - Load time acceptable")
        else:
            print(f"[ASSESSMENT] ⚠️ SLOW - Load time may affect first transcription")

        return asr, load_time

    except Exception as e:
        print(f"[ERROR] Model loading failed: {e}")
        return None, None

def test_transcription_completeness(asr):
    """Test that transcription captures complete audio without cutoffs"""
    print("\n" + "="*60)
    print("TEST 2: Transcription Completeness")
    print("="*60)

    try:
        # Create test audio with a clear beginning and end
        sample_rate = 16000
        duration = 3.0  # 3 seconds

        # Generate audio with clear start and end markers
        # Simulate speech pattern: quiet -> loud -> quiet
        audio_samples = int(duration * sample_rate)
        audio = np.zeros(audio_samples, dtype=np.float32)

        # Add some synthetic speech-like patterns
        for i in range(audio_samples):
            t = i / sample_rate
            if 0.2 <= t <= 2.8:  # Main speech content
                # Add multiple frequency components to simulate speech
                audio[i] = (
                    0.1 * np.sin(2 * np.pi * 200 * t) +  # Low frequency
                    0.05 * np.sin(2 * np.pi * 800 * t) +  # Mid frequency
                    0.02 * np.sin(2 * np.pi * 1600 * t)   # High frequency
                ) * (0.8 + 0.2 * np.sin(2 * np.pi * 3 * t))  # Amplitude modulation

        print(f"[TEST] Created {duration}s test audio with clear start/end patterns")

        # Test transcription
        print("[TEST] Running transcription...")
        start_time = time.perf_counter()
        result = asr.transcribe(audio)
        transcription_time = time.perf_counter() - start_time

        print(f"[RESULT] Transcription completed in {transcription_time:.3f}s")
        print(f"[RESULT] Segments found: {len(result.segments) if result.segments else 0}")

        if result.segments:
            for i, segment in enumerate(result.segments):
                print(f"[SEGMENT {i+1}] {segment.start:.2f}s-{segment.end:.2f}s: '{segment.text}'")

        # Check for completeness (this is a synthetic test, so we mainly check timing)
        if result.segments:
            first_start = result.segments[0].start
            last_end = result.segments[-1].end

            print(f"[ANALYSIS] First segment starts at: {first_start:.2f}s")
            print(f"[ANALYSIS] Last segment ends at: {last_end:.2f}s")
            print(f"[ANALYSIS] Total coverage: {last_end - first_start:.2f}s of {duration:.2f}s")

            if first_start < 0.5:  # Should start within first 0.5s
                print("[ASSESSMENT] ✅ PASS - No significant audio cutoff at start")
            else:
                print("[ASSESSMENT] ⚠️ WARNING - Possible audio cutoff at start")

        return transcription_time

    except Exception as e:
        print(f"[ERROR] Transcription test failed: {e}")
        return None

def test_performance_consistency(asr):
    """Test performance consistency between first and subsequent transcriptions"""
    print("\n" + "="*60)
    print("TEST 3: Performance Consistency")
    print("="*60)

    try:
        # Create short test audio for multiple runs
        sample_rate = 16000
        duration = 1.0
        audio_samples = int(duration * sample_rate)
        audio = np.random.normal(0, 0.01, audio_samples).astype(np.float32)

        print(f"[TEST] Running 3 transcriptions to test consistency...")

        times = []
        for i in range(3):
            print(f"[TEST] Transcription {i+1}/3...")
            start_time = time.perf_counter()
            result = asr.transcribe(audio)
            transcription_time = time.perf_counter() - start_time
            times.append(transcription_time)
            print(f"[RESULT] Run {i+1}: {transcription_time:.3f}s")

        avg_time = sum(times) / len(times)
        first_time = times[0]
        subsequent_avg = sum(times[1:]) / len(times[1:]) if len(times) > 1 else times[0]

        print(f"\n[ANALYSIS] First transcription: {first_time:.3f}s")
        print(f"[ANALYSIS] Subsequent average: {subsequent_avg:.3f}s")
        print(f"[ANALYSIS] Performance ratio: {first_time/subsequent_avg:.2f}x")

        if first_time / subsequent_avg < 2.0:  # First should be less than 2x slower
            print("[ASSESSMENT] ✅ PASS - First transcription performance acceptable")
        else:
            print("[ASSESSMENT] ⚠️ WARNING - First transcription significantly slower")

        return times

    except Exception as e:
        print(f"[ERROR] Performance test failed: {e}")
        return None

def test_cold_start_simulation():
    """Test complete cold start scenario"""
    print("\n" + "="*60)
    print("TEST 4: Cold Start Simulation")
    print("="*60)

    try:
        print("[TEST] Simulating complete cold start...")

        # Import and create everything fresh
        from voiceflow.core.config import Config
        from voiceflow.core.asr_production import ProductionWhisperASR
        from voiceflow.core.self_correcting_asr import SelfCorrectingASR

        cfg = Config()
        base_asr = ProductionWhisperASR(cfg)
        asr = SelfCorrectingASR(base_asr)

        # Time the complete initialization
        print("[TEST] Loading models from scratch...")
        start_time = time.time()
        base_asr.load()
        load_time = time.time() - start_time

        # Create test audio
        sample_rate = 16000
        duration = 2.0
        audio_samples = int(duration * sample_rate)
        audio = np.random.normal(0, 0.01, audio_samples).astype(np.float32)

        # Test first transcription after cold start
        print("[TEST] Running first transcription after cold start...")
        transcription_start = time.time()
        result = asr.transcribe(audio)
        transcription_time = time.time() - transcription_start
        total_time = time.time() - start_time

        print(f"[RESULT] Model loading: {load_time:.2f}s")
        print(f"[RESULT] First transcription: {transcription_time:.2f}s")
        print(f"[RESULT] Total cold start: {total_time:.2f}s")

        if total_time < 15:  # Total cold start should be reasonable
            print("[ASSESSMENT] ✅ PASS - Cold start time acceptable")
        else:
            print("[ASSESSMENT] ⚠️ WARNING - Cold start time may impact user experience")

        return load_time, transcription_time, total_time

    except Exception as e:
        print(f"[ERROR] Cold start test failed: {e}")
        return None, None, None

def main():
    """Run all first transcription tests"""
    print("First Transcription Performance Test Suite")
    print("Testing cold start fixes and optimizations\n")

    # Test 1: Model Loading
    asr, load_time = test_model_loading()
    if asr is None:
        print("❌ Cannot continue tests without loaded model")
        return

    # Test 2: Transcription Completeness
    transcription_time = test_transcription_completeness(asr)

    # Test 3: Performance Consistency
    times = test_performance_consistency(asr)

    # Test 4: Cold Start Simulation
    cold_load, cold_transcribe, cold_total = test_cold_start_simulation()

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    if load_time is not None:
        print(f"Model Loading: {load_time:.2f}s")

    if transcription_time is not None:
        print(f"Transcription Time: {transcription_time:.3f}s")

    if times:
        print(f"Performance Consistency: {times[0]:.3f}s → {sum(times[1:])/len(times[1:]):.3f}s avg")

    if cold_total is not None:
        print(f"Cold Start Total: {cold_total:.2f}s")

    print("\n✅ First transcription tests completed!")
    print("Check results above for any performance issues.")

if __name__ == "__main__":
    main()