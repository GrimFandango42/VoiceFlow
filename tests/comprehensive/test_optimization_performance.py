#!/usr/bin/env python3
"""
Simplified Performance Testing for VoiceFlow Optimizations

Tests specific optimization functions without requiring full model initialization.
This allows us to measure the performance impact of each optimization in isolation.
"""

import os
import sys
import time
import statistics
import json
import numpy as np
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from voiceflow.core.config import Config
from voiceflow.core.audio_enhanced import audio_validation_guard, _fast_audio_validation_guard


def create_test_audio_samples():
    """Create test audio samples for performance testing"""
    samples = {}
    sample_rate = 16000

    # Various durations to test
    durations = [1.0, 3.0, 5.0, 10.0]

    for duration in durations:
        length = int(duration * sample_rate)
        # Create synthetic audio with some complexity
        t = np.linspace(0, duration, length)
        signal = (
            0.3 * np.sin(2 * np.pi * 200 * t) +
            0.2 * np.sin(2 * np.pi * 400 * t) +
            0.1 * np.random.normal(0, 0.1, length)
        ).astype(np.float32)

        samples[f"{duration}s"] = signal

    return samples


def test_audio_validation_performance():
    """Test audio validation optimization performance"""
    print("Testing Audio Validation Performance")
    print("=" * 40)

    test_samples = create_test_audio_samples()

    # Configurations to test
    configs = {
        'standard': Config(),
        'fast': Config()
    }
    configs['fast'].enable_fast_audio_validation = True
    configs['fast'].audio_validation_sample_rate = 0.05
    configs['fast'].fast_nan_inf_detection = True

    results = {}

    for config_name, cfg in configs.items():
        print(f"\nTesting {config_name} validation:")
        config_results = {}

        for sample_name, audio_sample in test_samples.items():
            times = []

            # Run multiple iterations for reliable timing
            for i in range(10):
                start_time = time.perf_counter()

                if config_name == 'fast' and cfg.enable_fast_audio_validation:
                    validated_audio = _fast_audio_validation_guard(
                        audio_sample, f"test_{sample_name}", False, cfg
                    )
                else:
                    validated_audio = audio_validation_guard(
                        audio_sample, f"test_{sample_name}", False, cfg
                    )

                elapsed = time.perf_counter() - start_time
                times.append(elapsed)

            avg_time = statistics.mean(times)
            config_results[sample_name] = avg_time
            print(f"  {sample_name}: {avg_time*1000:.2f}ms average")

        results[config_name] = config_results

    # Calculate improvements
    print(f"\nPerformance Improvements:")
    for sample_name in test_samples.keys():
        standard_time = results['standard'][sample_name]
        fast_time = results['fast'][sample_name]
        improvement = (standard_time - fast_time) / standard_time * 100
        print(f"  {sample_name}: {improvement:+.1f}% improvement")

    return results


def test_memory_pooling_simulation():
    """Simulate memory pooling optimization performance"""
    print("\n\nTesting Memory Pooling Simulation")
    print("=" * 40)

    buffer_sizes = [1000, 5000, 10000, 20000]
    iterations = 1000

    # Test standard allocation vs simulated pooling
    def standard_allocation(size):
        return np.zeros(size, dtype=np.float32)

    def simulated_pooling(size, pool):
        # Simulate pool reuse
        if pool and len(pool[0]) >= size:
            buffer = pool.pop()
            buffer[:size].fill(0.0)
            return buffer[:size]
        return np.zeros(size, dtype=np.float32)

    results = {}

    for size in buffer_sizes:
        print(f"\nTesting buffer size: {size} samples")

        # Standard allocation timing
        start_time = time.perf_counter()
        for _ in range(iterations):
            buffer = standard_allocation(size)
            del buffer
        standard_time = time.perf_counter() - start_time

        # Simulated pooling timing
        pool = [np.zeros(size*2, dtype=np.float32) for _ in range(8)]  # Pre-allocated pool
        start_time = time.perf_counter()
        for _ in range(iterations):
            buffer = simulated_pooling(size, pool)
            if len(pool) < 8:  # Return to pool
                pool.append(buffer)
        pooling_time = time.perf_counter() - start_time

        improvement = (standard_time - pooling_time) / standard_time * 100
        results[f"{size}_samples"] = {
            'standard_time': standard_time,
            'pooling_time': pooling_time,
            'improvement_percent': improvement
        }

        print(f"  Standard: {standard_time*1000:.2f}ms")
        print(f"  Pooling:  {pooling_time*1000:.2f}ms")
        print(f"  Improvement: {improvement:+.1f}%")

    return results


def test_statistical_sampling_performance():
    """Test statistical sampling vs full data validation"""
    print("\n\nTesting Statistical Sampling Performance")
    print("=" * 40)

    # Create test arrays of various sizes
    array_sizes = [1000, 10000, 50000, 100000]
    sample_rates = [0.01, 0.05, 0.1, 1.0]  # 1%, 5%, 10%, 100%

    results = {}

    for size in array_sizes:
        print(f"\nTesting array size: {size} elements")

        # Create test array with some NaN/Inf values
        test_array = np.random.normal(0, 1, size).astype(np.float32)
        test_array[size//4] = np.nan  # Add some NaN
        test_array[size//2] = np.inf  # Add some Inf

        size_results = {}

        for sample_rate in sample_rates:
            times = []

            for _ in range(20):  # Multiple runs for averaging
                start_time = time.perf_counter()

                if sample_rate < 1.0:
                    # Statistical sampling
                    step_size = max(1, int(1.0 / sample_rate))
                    sample_indices = slice(0, None, step_size)
                    sample_data = test_array[sample_indices]

                    # Quick check on sample
                    has_nan = np.any(np.isnan(sample_data))
                    has_inf = np.any(np.isinf(sample_data))
                    max_val = np.max(np.abs(sample_data))
                else:
                    # Full validation
                    has_nan = np.any(np.isnan(test_array))
                    has_inf = np.any(np.isinf(test_array))
                    max_val = np.max(np.abs(test_array))

                elapsed = time.perf_counter() - start_time
                times.append(elapsed)

            avg_time = statistics.mean(times)
            size_results[f"{sample_rate*100:.0f}%_sample"] = avg_time
            print(f"  {sample_rate*100:3.0f}% sampling: {avg_time*1000:.3f}ms")

        results[f"{size}_elements"] = size_results

        # Calculate improvement from 100% to 5% sampling
        full_time = size_results["100%_sample"]
        sample_time = size_results["5%_sample"]
        improvement = (full_time - sample_time) / full_time * 100
        print(f"  5% vs 100% improvement: {improvement:+.1f}%")

    return results


def run_comprehensive_optimization_tests():
    """Run all optimization performance tests"""
    print("VoiceFlow Optimization Performance Testing")
    print("=" * 50)
    print("Testing individual optimization components without model loading")
    print("=" * 50)

    results = {
        'test_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'audio_validation': test_audio_validation_performance(),
        'memory_pooling': test_memory_pooling_simulation(),
        'statistical_sampling': test_statistical_sampling_performance()
    }

    # Save results
    results_dir = Path("tests/performance_results")
    results_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime('%Y%m%d_%H%M%S')
    results_file = results_dir / f"optimization_performance_{timestamp}.json"

    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n\nResults saved to: {results_file}")

    # Generate summary
    print("\n" + "=" * 50)
    print("OPTIMIZATION PERFORMANCE SUMMARY")
    print("=" * 50)

    # Audio validation summary
    print("\nAudio Validation Optimization:")
    audio_results = results['audio_validation']
    if 'standard' in audio_results and 'fast' in audio_results:
        for sample in audio_results['standard'].keys():
            standard_time = audio_results['standard'][sample]
            fast_time = audio_results['fast'][sample]
            improvement = (standard_time - fast_time) / standard_time * 100
            print(f"  {sample}: {improvement:+.1f}% faster")

    # Memory pooling summary
    print("\nMemory Pooling Optimization:")
    for size_key, size_results in results['memory_pooling'].items():
        improvement = size_results['improvement_percent']
        print(f"  {size_key}: {improvement:+.1f}% faster")

    # Statistical sampling summary
    print("\nStatistical Sampling Optimization:")
    sampling_results = results['statistical_sampling']
    for size_key, size_results in sampling_results.items():
        if "100%_sample" in size_results and "5%_sample" in size_results:
            full_time = size_results["100%_sample"]
            sample_time = size_results["5%_sample"]
            improvement = (full_time - sample_time) / full_time * 100
            print(f"  {size_key}: {improvement:+.1f}% faster with 5% sampling")

    return results


if __name__ == "__main__":
    try:
        results = run_comprehensive_optimization_tests()
        print("\nOptimization testing completed successfully!")
    except Exception as e:
        print(f"\nTesting failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)