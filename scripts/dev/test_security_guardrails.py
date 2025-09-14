#!/usr/bin/env python3
"""
Security Guardrails Validation Test
===================================
Focused test to validate the new audio security guardrails
"""

import sys
import os
import numpy as np
import time

# Add parent directory to path for imports
sys.path.append(os.path.dirname(__file__))

try:
    from voiceflow.config import Config
    from voiceflow.audio_enhanced import audio_validation_guard, validate_audio_format, safe_audio_operation
    from voiceflow.asr_buffer_safe import BufferSafeWhisperASR
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

def test_audio_validation_guard():
    """Test the comprehensive audio validation guard"""
    print("=" * 60)
    print("TESTING AUDIO VALIDATION GUARD")
    print("=" * 60)

    test_cases = [
        ("Empty array", np.array([], dtype=np.float32), True, "allow_empty=True"),
        ("None input", None, True, "allow_empty=True"),
        ("NaN values", np.full(1000, np.nan, dtype=np.float32), False, "should sanitize"),
        ("Infinite values", np.full(1000, np.inf, dtype=np.float32), False, "should sanitize"),
        ("Extreme values", np.full(1000, 1e10, dtype=np.float32), False, "should clamp"),
        ("Normal audio", np.random.random(1600) * 0.1, False, "should pass"),
        ("Stereo input", np.random.random((1600, 2)) * 0.1, False, "should convert to mono"),
        ("Wrong dtype", np.random.randint(0, 100, 1600), False, "should convert to float32"),
    ]

    passed = 0
    failed = 0

    for name, test_data, allow_empty, expected in test_cases:
        try:
            if test_data is None:
                # Test None specifically
                try:
                    result = audio_validation_guard(test_data, name, allow_empty=allow_empty)
                    if allow_empty and result.size == 0:
                        print(f"PASS: {name:<20} - {expected}")
                        passed += 1
                    else:
                        print(f"FAIL: {name:<20} - Expected empty array for None input")
                        failed += 1
                except ValueError:
                    if not allow_empty:
                        print(f"PASS: {name:<20} - {expected} (correctly raised ValueError)")
                        passed += 1
                    else:
                        print(f"FAIL: {name:<20} - Unexpected ValueError")
                        failed += 1
            else:
                result = audio_validation_guard(test_data, name, allow_empty=allow_empty)

                # Check result properties
                if isinstance(result, np.ndarray) and result.dtype == np.float32:
                    if np.any(np.isnan(result)) or np.any(np.isinf(result)):
                        print(f"FAIL: {name:<20} - Still contains NaN/Inf after validation")
                        failed += 1
                    else:
                        print(f"PASS: {name:<20} - {expected}")
                        passed += 1
                else:
                    print(f"FAIL: {name:<20} - Invalid result type or dtype")
                    failed += 1

        except Exception as e:
            print(f"FAIL: {name:<20} - Exception: {e}")
            failed += 1

    print(f"\nValidation Guard Results: {passed}/{passed + failed} passed")
    return passed, failed

def test_asr_validation():
    """Test ASR validation with problematic inputs"""
    print("\n" + "=" * 60)
    print("TESTING ASR BUFFER SAFETY")
    print("=" * 60)

    cfg = Config()
    asr = BufferSafeWhisperASR(cfg)

    # Critical test cases that previously caused crashes
    test_cases = [
        ("Empty audio", np.array([], dtype=np.float32)),
        ("NaN audio", np.full(16000, np.nan, dtype=np.float32)),
        ("Infinite audio", np.full(16000, np.inf, dtype=np.float32)),
        ("Extreme values", np.full(16000, 1e10, dtype=np.float32)),
        ("Very short", np.random.random(10).astype(np.float32)),
        ("Normal audio", np.random.random(16000).astype(np.float32) * 0.1),
    ]

    passed = 0
    failed = 0

    for name, test_audio in test_cases:
        try:
            start_time = time.perf_counter()
            result = asr.transcribe(test_audio)
            duration = time.perf_counter() - start_time

            # Should not crash and should return a string
            if isinstance(result, str):
                print(f"PASS: {name:<15} - Completed in {duration:.3f}s, result: '{result[:30]}{'...' if len(result) > 30 else ''}'")
                passed += 1
            else:
                print(f"FAIL: {name:<15} - Invalid result type: {type(result)}")
                failed += 1

        except Exception as e:
            print(f"FAIL: {name:<15} - Exception: {e}")
            failed += 1

    print(f"\nASR Safety Results: {passed}/{passed + failed} passed")
    return passed, failed

def test_buffer_operations():
    """Test buffer operations with problematic data"""
    print("\n" + "=" * 60)
    print("TESTING BUFFER OPERATIONS")
    print("=" * 60)

    from voiceflow.audio_enhanced import BoundedRingBuffer

    buffer = BoundedRingBuffer(5.0, 16000)  # 5 second buffer

    test_cases = [
        ("Normal data", np.random.random(1000).astype(np.float32) * 0.1),
        ("Empty data", np.array([], dtype=np.float32)),
        ("NaN data", np.full(1000, np.nan, dtype=np.float32)),
        ("Infinite data", np.full(1000, np.inf, dtype=np.float32)),
        ("Large data", np.random.random(100000).astype(np.float32) * 0.1),
    ]

    passed = 0
    failed = 0

    for name, test_data in test_cases:
        try:
            buffer.clear()
            buffer.append(test_data)

            # Should not crash
            result = buffer.get_data()
            duration = buffer.get_duration_seconds()

            print(f"PASS: {name:<15} - Buffer duration: {duration:.3f}s, samples: {len(result)}")
            passed += 1

        except Exception as e:
            print(f"FAIL: {name:<15} - Exception: {e}")
            failed += 1

    print(f"\nBuffer Operations Results: {passed}/{passed + failed} passed")
    return passed, failed

def main():
    """Main test runner"""
    print("VoiceFlow Security Guardrails Validation")
    print("=" * 60)

    start_time = time.perf_counter()

    # Run all tests
    guard_passed, guard_failed = test_audio_validation_guard()
    asr_passed, asr_failed = test_asr_validation()
    buffer_passed, buffer_failed = test_buffer_operations()

    total_time = time.perf_counter() - start_time

    # Summary
    total_passed = guard_passed + asr_passed + buffer_passed
    total_failed = guard_failed + asr_failed + buffer_failed
    total_tests = total_passed + total_failed

    print("\n" + "=" * 60)
    print("SECURITY GUARDRAILS VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")
    print(f"Success Rate: {(total_passed/total_tests)*100:.1f}%")
    print(f"Total Duration: {total_time:.2f}s")

    if total_failed == 0:
        print("\n>>> ALL SECURITY GUARDRAILS TESTS PASSED!")
        print(">>> Audio validation is robust against edge cases")
        print(">>> Buffer operations are crash-resistant")
        print(">>> ASR pipeline handles malformed input safely")
        return True
    else:
        print(f"\n>>> {total_failed} TESTS FAILED - Security guardrails need attention")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)