"""
ASR Performance Benchmark

Compare old buffer-safe vs new modern ASR implementation
"""

import sys
import os
import time
import numpy as np

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from voiceflow.core.config import Config
from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
from voiceflow.core.asr_modern import ModernWhisperASR

def generate_test_audio(duration_seconds=3.0, sample_rate=16000):
    """Generate test audio with some noise"""
    samples = int(duration_seconds * sample_rate)

    # Generate sine wave with noise (simulates speech-like audio)
    t = np.linspace(0, duration_seconds, samples)
    freq = 440  # A4 note
    audio = 0.1 * np.sin(2 * np.pi * freq * t)

    # Add some noise
    noise = 0.05 * np.random.randn(samples)
    audio = audio + noise

    return audio.astype(np.float32)

def benchmark_asr(asr_class, name, num_tests=5):
    """Benchmark an ASR implementation"""
    print(f"\n=== Benchmarking {name} ===")

    # Create config
    cfg = Config()
    cfg.model_name = "base"  # Use small model for faster testing
    cfg.device = "auto"
    cfg.compute_type = "float16"

    # Create ASR instance
    asr = asr_class(cfg)

    # Generate test audio
    test_audio = generate_test_audio(duration_seconds=2.0)

    # Warm up
    print("Warming up...")
    asr.transcribe(test_audio)

    # Benchmark multiple transcriptions
    total_time = 0
    results = []

    print(f"Running {num_tests} transcriptions...")
    for i in range(num_tests):
        start_time = time.time()
        result = asr.transcribe(test_audio)
        end_time = time.time()

        transcription_time = end_time - start_time
        total_time += transcription_time
        results.append((transcription_time, result))

        print(f"  Test {i+1}: {transcription_time:.3f}s - '{result[:50]}...'")

    avg_time = total_time / num_tests
    print(f"\nResults for {name}:")
    print(f"  Average time: {avg_time:.3f}s")
    print(f"  Total time: {total_time:.3f}s")
    print(f"  Min time: {min(r[0] for r in results):.3f}s")
    print(f"  Max time: {max(r[0] for r in results):.3f}s")

    # Get stats if available
    if hasattr(asr, 'get_stats'):
        stats = asr.get_stats()
        print(f"  Stats: {stats}")

    return avg_time, results

def main():
    print("ASR Performance Benchmark")
    print("=" * 50)

    try:
        # Benchmark old implementation
        old_time, old_results = benchmark_asr(BufferSafeWhisperASR, "Buffer Safe ASR (Old)")

        # Benchmark new implementation
        new_time, new_results = benchmark_asr(ModernWhisperASR, "Modern ASR (New)")

        # Compare results
        print(f"\n=== Comparison ===")
        print(f"Old implementation average: {old_time:.3f}s")
        print(f"New implementation average: {new_time:.3f}s")

        if new_time < old_time:
            speedup = old_time / new_time
            print(f"New implementation is {speedup:.2f}x FASTER")
        else:
            slowdown = new_time / old_time
            print(f"New implementation is {slowdown:.2f}x slower")

        # Check if results are similar
        old_texts = [r[1] for r in old_results if r[1]]
        new_texts = [r[1] for r in new_results if r[1]]

        print(f"\nResult quality:")
        print(f"Old implementation produced {len(old_texts)} non-empty results")
        print(f"New implementation produced {len(new_texts)} non-empty results")

    except Exception as e:
        print(f"Benchmark failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()