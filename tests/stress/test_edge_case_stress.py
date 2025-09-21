#!/usr/bin/env python3
"""
VoiceFlow Edge Case Stress Testing
Comprehensive stress tests for production reliability validation
"""

import time
import threading
import gc
import psutil
import numpy as np
from typing import List, Dict, Any
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from voiceflow.core.config import Config
from voiceflow.core.textproc import apply_code_mode, format_transcript_text
from voiceflow.integrations.inject import ClipboardInjector


class StressTestFramework:
    """Framework for running comprehensive stress tests"""

    def __init__(self):
        self.results = []
        self.process = psutil.Process()
        self.start_memory = self.get_memory_mb()

    def get_memory_mb(self) -> float:
        """Get current memory usage in MB"""
        return self.process.memory_info().rss / 1024 / 1024

    def run_test(self, test_name: str, test_func, iterations: int = 100):
        """Run a stress test with memory monitoring"""
        print(f"\n=== Running {test_name} ({iterations} iterations) ===")

        start_memory = self.get_memory_mb()
        start_time = time.perf_counter()
        failures = 0

        for i in range(iterations):
            try:
                test_func()
                if i % 20 == 0:
                    print(f"  Progress: {i+1}/{iterations}")
            except Exception as e:
                failures += 1
                if failures == 1:  # Only log first failure
                    print(f"  Failure: {e}")

        end_time = time.perf_counter()
        end_memory = self.get_memory_mb()

        result = {
            'test_name': test_name,
            'iterations': iterations,
            'duration': end_time - start_time,
            'failures': failures,
            'success_rate': (iterations - failures) / iterations * 100,
            'memory_start_mb': start_memory,
            'memory_end_mb': end_memory,
            'memory_delta_mb': end_memory - start_memory,
            'avg_time_per_iteration': (end_time - start_time) / iterations
        }

        self.results.append(result)

        print(f"  Results: {result['success_rate']:.1f}% success, "
              f"{result['memory_delta_mb']:.1f}MB memory delta, "
              f"{result['avg_time_per_iteration']*1000:.2f}ms per iteration")

        return result


def test_rapid_text_processing():
    """Test rapid text processing under load"""
    test_texts = [
        "hello world this is a test",
        "first, make sure you do it. second, continue listening.",
        "open bracket hello close bracket equals test",
        "new line tab return semicolon",
        "",  # Empty string test
        "a" * 1000,  # Very long string test
        "unicode test: émojis 😊 and symbols •",
        "mixed content 123 ABC !@# $%^ &*(",
    ]

    def process_text():
        for text in test_texts:
            # Test both code mode and format functions
            apply_code_mode(text)
            format_transcript_text(text)

    return process_text


def test_rapid_config_creation():
    """Test rapid configuration object creation and destruction"""
    def create_config():
        cfg = Config()
        # Access some properties to ensure full initialization
        _ = cfg.model_name
        _ = cfg.paste_injection
        _ = cfg.max_inject_chars
        del cfg
        gc.collect()

    return create_config


def test_clipboard_injector_stress():
    """Test clipboard injector under rapid use"""
    cfg = Config(max_inject_chars=50, min_inject_interval_ms=1)
    injector = ClipboardInjector(cfg)

    # Mock the actual I/O operations for stress testing
    def mock_copy(s): pass
    def mock_send(s): pass
    def mock_write(s, delay=0): pass

    import voiceflow.integrations.inject as inject_module
    original_copy = inject_module.pyperclip.copy
    original_send = inject_module.keyboard.send
    original_write = inject_module.keyboard.write

    inject_module.pyperclip.copy = mock_copy
    inject_module.keyboard.send = mock_send
    inject_module.keyboard.write = mock_write

    test_payloads = [
        "short text",
        "medium length text with some symbols and numbers 123",
        "longer text that might hit character limits and need truncation",
        "",
        "unicode: émojis 😊",
    ]

    def inject_stress():
        for payload in test_payloads:
            injector.inject(payload)

    def cleanup():
        inject_module.pyperclip.copy = original_copy
        inject_module.keyboard.send = original_send
        inject_module.keyboard.write = original_write

    # Return function and cleanup
    return inject_stress, cleanup


def test_memory_pressure():
    """Test behavior under artificial memory pressure"""
    def create_memory_pressure():
        # Create large arrays to simulate memory pressure
        large_arrays = []
        try:
            for _ in range(5):
                # Create 10MB array
                arr = np.zeros(10 * 1024 * 1024 // 8, dtype=np.float64)
                large_arrays.append(arr)

            # Test basic functionality under pressure
            cfg = Config()
            text = apply_code_mode("hello world test")
            format_transcript_text(text)

        finally:
            # Cleanup memory
            large_arrays.clear()
            gc.collect()

    return create_memory_pressure


def test_concurrent_operations():
    """Test concurrent operations simulation"""
    def concurrent_simulation():
        # Simulate multiple operations happening simultaneously
        threads = []
        results = []

        def worker():
            cfg = Config()
            text = apply_code_mode("concurrent test")
            formatted = format_transcript_text(text)
            results.append(len(formatted))

        # Start multiple threads
        for _ in range(5):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        # Wait for all to complete
        for t in threads:
            t.join()

        # Verify all completed successfully
        assert len(results) == 5

    return concurrent_simulation


def run_comprehensive_stress_tests():
    """Run all stress tests and generate report"""
    framework = StressTestFramework()

    print("VoiceFlow Comprehensive Stress Testing")
    print("=" * 50)

    # Test 1: Rapid text processing
    framework.run_test(
        "Rapid Text Processing",
        test_rapid_text_processing(),
        iterations=200
    )

    # Test 2: Rapid configuration creation
    framework.run_test(
        "Rapid Config Creation",
        test_rapid_config_creation(),
        iterations=100
    )

    # Test 3: Clipboard injector stress
    inject_func, cleanup = test_clipboard_injector_stress()
    try:
        framework.run_test(
            "Clipboard Injector Stress",
            inject_func,
            iterations=150
        )
    finally:
        cleanup()

    # Test 4: Memory pressure simulation
    framework.run_test(
        "Memory Pressure Simulation",
        test_memory_pressure(),
        iterations=50
    )

    # Test 5: Concurrent operations
    framework.run_test(
        "Concurrent Operations",
        test_concurrent_operations(),
        iterations=30
    )

    # Generate summary report
    print("\n" + "=" * 50)
    print("STRESS TEST SUMMARY")
    print("=" * 50)

    total_tests = len(framework.results)
    total_iterations = sum(r['iterations'] for r in framework.results)
    total_failures = sum(r['failures'] for r in framework.results)
    total_memory_delta = framework.get_memory_mb() - framework.start_memory

    print(f"Total Tests: {total_tests}")
    print(f"Total Iterations: {total_iterations}")
    print(f"Total Failures: {total_failures}")
    print(f"Overall Success Rate: {(total_iterations - total_failures) / total_iterations * 100:.2f}%")
    print(f"Total Memory Delta: {total_memory_delta:.1f}MB")

    # Individual test results
    print("\nIndividual Test Results:")
    for result in framework.results:
        status = "PASS" if result['success_rate'] >= 95.0 else "FAIL"
        print(f"  {result['test_name']}: {status} "
              f"({result['success_rate']:.1f}% success, "
              f"{result['memory_delta_mb']:.1f}MB delta)")

    # Overall assessment
    min_success_rate = min(r['success_rate'] for r in framework.results)
    max_memory_delta = max(r['memory_delta_mb'] for r in framework.results)

    overall_pass = (
        min_success_rate >= 95.0 and
        max_memory_delta < 100.0 and  # Less than 100MB max delta
        total_memory_delta < 200.0     # Less than 200MB total delta
    )

    print(f"\nOVERALL STRESS TEST: {'PASS' if overall_pass else 'FAIL'}")

    if not overall_pass:
        print("Issues detected:")
        if min_success_rate < 95.0:
            print(f"  - Low success rate: {min_success_rate:.1f}%")
        if max_memory_delta >= 100.0:
            print(f"  - High memory usage: {max_memory_delta:.1f}MB")
        if total_memory_delta >= 200.0:
            print(f"  - High total memory delta: {total_memory_delta:.1f}MB")

    return framework.results, overall_pass


if __name__ == "__main__":
    results, success = run_comprehensive_stress_tests()
    exit(0 if success else 1)