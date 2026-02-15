"""
Quick Transcription Test for VoiceFlow
Tests the ASR engine directly with synthetic audio.
"""

import sys
import os

# Add src to path
src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

import numpy as np
import time

from voiceflow.core.asr_engine import ASREngine, ModelTier

def main():
    print("=" * 60)
    print("VoiceFlow ASR Engine Quick Test")
    print("=" * 60)

    # Test with tiny model for speed
    print("\nInitializing tiny model...")
    engine = ASREngine(tier=ModelTier.TINY, device='cpu', compute_type='int8')
    print(f"Model: {engine.model_config.name}")
    print(f"Backend: {engine.model_config.backend}")

    print("\nLoading model...")
    start = time.time()
    engine.load()
    print(f"Loaded in {time.time() - start:.2f}s")

    # Test 1: Transcription with noise
    print("\n--- Test 1: 2 seconds of random noise ---")
    np.random.seed(42)
    audio = 0.1 * np.random.randn(32000).astype(np.float32)

    start = time.time()
    result = engine.transcribe(audio)
    elapsed = time.time() - start

    print(f"Transcription time: {elapsed:.3f}s")
    print(f"Audio duration: {result.duration:.2f}s")
    print(f"Speed: {result.duration / elapsed:.1f}x realtime")
    print(f"Result: \"{result.text}\"")

    # Test 2: Silence
    print("\n--- Test 2: 1 second of silence ---")
    silence = np.zeros(16000, dtype=np.float32)

    start = time.time()
    result = engine.transcribe(silence)
    elapsed = time.time() - start

    print(f"Transcription time: {elapsed:.3f}s")
    print(f"Result: \"{result.text if hasattr(result, 'text') else result}\"")
    print("(Should be empty or minimal hallucination)")

    # Test 3: Speech-like audio (low energy random with varying amplitude)
    print("\n--- Test 3: 3 seconds of speech-like audio ---")
    np.random.seed(123)
    # Create audio with speech-like envelope
    t = np.linspace(0, 3, 48000, dtype=np.float32)
    envelope = 0.1 * (1 + 0.5 * np.sin(2 * np.pi * 2 * t))  # ~2Hz modulation
    audio = envelope * np.random.randn(48000).astype(np.float32)

    start = time.time()
    result = engine.transcribe(audio)
    elapsed = time.time() - start

    print(f"Transcription time: {elapsed:.3f}s")
    print(f"Audio duration: {result.duration:.2f}s")
    print(f"Speed: {result.duration / elapsed:.1f}x realtime")
    print(f"Result: \"{result.text}\"")

    # Test 4: Quick/distil model
    print("\n--- Test 4: Testing with Distil Large v3 (quick tier) ---")
    engine2 = ASREngine(tier=ModelTier.QUICK, device='cpu', compute_type='int8')
    print(f"Model: {engine2.model_config.name}")

    print("Loading model...")
    start = time.time()
    engine2.load()
    load_time = time.time() - start
    print(f"Loaded in {load_time:.2f}s")

    # Same test audio
    np.random.seed(42)
    audio = 0.1 * np.random.randn(32000).astype(np.float32)

    start = time.time()
    result = engine2.transcribe(audio)
    elapsed = time.time() - start

    print(f"Transcription time: {elapsed:.3f}s")
    print(f"Speed: {result.duration / elapsed:.1f}x realtime")
    print(f"Result: \"{result.text}\"")

    # Cleanup
    engine.cleanup()
    engine2.cleanup()

    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)

if __name__ == "__main__":
    main()
