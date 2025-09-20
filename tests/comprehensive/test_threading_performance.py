#!/usr/bin/env python3
"""
Threading Performance Test for VoiceFlow Adaptive Model Access

Tests the performance impact of lockfree vs locked model access patterns
to validate the Adaptive Model Access optimization.
"""

import sys
import time
import threading
import statistics
import concurrent.futures
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))


class MockModel:
    """Mock Whisper model for testing threading performance"""

    def __init__(self):
        self.call_count = 0
        self.processing_time = 0.01  # Simulate 10ms processing

    def transcribe(self, audio_data, **kwargs):
        """Mock transcribe method"""
        self.call_count += 1
        time.sleep(self.processing_time)  # Simulate processing
        return ["Mock transcription"], {"duration": 1.0}


class LockedModelAccess:
    """Traditional locked model access pattern"""

    def __init__(self):
        self.model = MockModel()
        self.lock = threading.Lock()

    def transcribe(self, audio_data):
        with self.lock:
            return self.model.transcribe(audio_data)


class LockfreeModelAccess:
    """Lockfree model access pattern (single-threaded safe)"""

    def __init__(self):
        self.model = MockModel()

    def transcribe(self, audio_data):
        # Direct access without locking overhead
        return self.model.transcribe(audio_data)


def test_sequential_performance():
    """Test sequential performance with and without locks"""
    print("Testing Sequential Performance")
    print("=" * 30)

    iterations = 100
    audio_data = [1, 2, 3, 4, 5]  # Mock audio data

    # Test locked access
    locked_access = LockedModelAccess()
    start_time = time.perf_counter()
    for _ in range(iterations):
        locked_access.transcribe(audio_data)
    locked_time = time.perf_counter() - start_time

    # Test lockfree access
    lockfree_access = LockfreeModelAccess()
    start_time = time.perf_counter()
    for _ in range(iterations):
        lockfree_access.transcribe(audio_data)
    lockfree_time = time.perf_counter() - start_time

    improvement = (locked_time - lockfree_time) / locked_time * 100

    print(f"Locked access:   {locked_time*1000:.2f}ms total")
    print(f"Lockfree access: {lockfree_time*1000:.2f}ms total")
    print(f"Improvement:     {improvement:+.1f}%")

    return {
        'locked_time': locked_time,
        'lockfree_time': lockfree_time,
        'improvement_percent': improvement
    }


def test_concurrent_contention():
    """Test performance under thread contention scenarios"""
    print("\n\nTesting Concurrent Contention")
    print("=" * 30)

    threads_list = [1, 2, 4, 8]
    iterations_per_thread = 25
    audio_data = [1, 2, 3, 4, 5]

    results = {}

    for num_threads in threads_list:
        print(f"\nTesting with {num_threads} threads:")

        # Test locked access
        locked_access = LockedModelAccess()

        def locked_worker():
            for _ in range(iterations_per_thread):
                locked_access.transcribe(audio_data)

        start_time = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(locked_worker) for _ in range(num_threads)]
            concurrent.futures.wait(futures)
        locked_time = time.perf_counter() - start_time

        # Test lockfree access (each thread gets its own instance)
        def lockfree_worker():
            lockfree_access = LockfreeModelAccess()
            for _ in range(iterations_per_thread):
                lockfree_access.transcribe(audio_data)

        start_time = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(lockfree_worker) for _ in range(num_threads)]
            concurrent.futures.wait(futures)
        lockfree_time = time.perf_counter() - start_time

        improvement = (locked_time - lockfree_time) / locked_time * 100

        results[f"{num_threads}_threads"] = {
            'locked_time': locked_time,
            'lockfree_time': lockfree_time,
            'improvement_percent': improvement
        }

        print(f"  Locked:   {locked_time*1000:.2f}ms")
        print(f"  Lockfree: {lockfree_time*1000:.2f}ms")
        print(f"  Improvement: {improvement:+.1f}%")

    return results


def test_lock_overhead_measurement():
    """Measure pure lock acquisition overhead"""
    print("\n\nTesting Lock Overhead")
    print("=" * 20)

    iterations = 10000
    lock = threading.Lock()

    # Test lock acquisition overhead
    start_time = time.perf_counter()
    for _ in range(iterations):
        with lock:
            pass  # No work, just lock overhead
    lock_overhead_time = time.perf_counter() - start_time

    # Test no-lock baseline
    start_time = time.perf_counter()
    for _ in range(iterations):
        pass  # No work, no lock
    baseline_time = time.perf_counter() - start_time

    overhead_per_operation = (lock_overhead_time - baseline_time) / iterations * 1000000  # microseconds

    print(f"Lock overhead: {overhead_per_operation:.2f} microseconds per operation")
    print(f"Total overhead for {iterations} operations: {(lock_overhead_time - baseline_time)*1000:.2f}ms")

    return {
        'overhead_per_operation_us': overhead_per_operation,
        'total_overhead_ms': (lock_overhead_time - baseline_time) * 1000
    }


def run_threading_performance_tests():
    """Run comprehensive threading performance tests"""
    print("VoiceFlow Threading Performance Testing")
    print("=" * 45)
    print("Testing Adaptive Model Access optimization impact")
    print("=" * 45)

    results = {
        'test_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'sequential_performance': test_sequential_performance(),
        'concurrent_contention': test_concurrent_contention(),
        'lock_overhead': test_lock_overhead_measurement()
    }

    # Save results
    results_dir = Path("tests/performance_results")
    results_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime('%Y%m%d_%H%M%S')
    results_file = results_dir / f"threading_performance_{timestamp}.json"

    import json
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n\nResults saved to: {results_file}")

    # Generate summary
    print("\n" + "=" * 45)
    print("THREADING PERFORMANCE SUMMARY")
    print("=" * 45)

    seq_improvement = results['sequential_performance']['improvement_percent']
    print(f"\nSequential Performance: {seq_improvement:+.1f}% improvement")

    print(f"\nConcurrent Performance by Thread Count:")
    for thread_key, thread_results in results['concurrent_contention'].items():
        improvement = thread_results['improvement_percent']
        print(f"  {thread_key}: {improvement:+.1f}% improvement")

    overhead = results['lock_overhead']['overhead_per_operation_us']
    print(f"\nLock Overhead: {overhead:.2f} microseconds per operation")

    # Analysis
    print(f"\nANALYSIS:")
    if seq_improvement > 5:
        print(f"  ✓ Sequential performance shows significant improvement")
    else:
        print(f"  ! Sequential performance improvement is minimal")

    concurrent_improvements = [r['improvement_percent'] for r in results['concurrent_contention'].values()]
    avg_concurrent_improvement = statistics.mean(concurrent_improvements)

    if avg_concurrent_improvement > 10:
        print(f"  ✓ Concurrent performance shows excellent improvement")
    elif avg_concurrent_improvement > 5:
        print(f"  ✓ Concurrent performance shows good improvement")
    else:
        print(f"  ! Concurrent performance improvement is limited")

    print(f"\nRECOMMENDATION:")
    if seq_improvement > 3 and avg_concurrent_improvement > 5:
        print(f"  IMPLEMENT: Adaptive Model Access optimization recommended")
    elif seq_improvement > 1:
        print(f"  CONSIDER: Adaptive Model Access may provide modest benefits")
    else:
        print(f"  SKIP: Adaptive Model Access optimization not recommended")

    return results


if __name__ == "__main__":
    try:
        results = run_threading_performance_tests()
        print("\nThreading performance testing completed successfully!")
    except Exception as e:
        print(f"\nTesting failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)