#!/usr/bin/env python3
"""
Comprehensive test suite to systematically reproduce and fix the NoneType context manager error.
This will test the exact pattern: multiple sentences with pauses and resuming.
"""

import sys
import time
import threading
import numpy as np
from pathlib import Path
from typing import List, Dict, Any
import traceback
import json

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

# Suppress CUDA warnings for testing
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

class TranscriptionTester:
    """Comprehensive transcription testing framework"""

    def __init__(self):
        self.results: List[Dict[str, Any]] = []
        self.total_tests = 0
        self.successful_tests = 0
        self.failed_tests = 0
        self.asr = None

    def setup_asr(self):
        """Setup ASR with proper error handling"""
        try:
            from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
            from voiceflow.core.config import Config

            config = Config()
            # Force CPU mode for stability
            config.device = "cpu"
            config.compute_type = "int8"

            print(f"Setting up ASR: device={config.device}, compute_type={config.compute_type}")

            self.asr = BufferSafeWhisperASR(config)
            print("ASR setup completed successfully")
            return True

        except Exception as e:
            print(f"FATAL: ASR setup failed: {e}")
            traceback.print_exc()
            return False

    def create_test_audio_sequence(self, duration_seconds: float = 2.0, sample_rate: int = 16000):
        """Create realistic test audio that simulates speech patterns"""
        samples = int(duration_seconds * sample_rate)

        # Create audio that simulates speech with pauses
        audio = np.zeros(samples, dtype=np.float32)

        # Add segments of "speech" (noise bursts) with gaps
        segment_length = int(0.3 * sample_rate)  # 300ms segments
        gap_length = int(0.1 * sample_rate)      # 100ms gaps

        pos = 0
        while pos + segment_length < samples:
            # Add speech segment
            end_pos = min(pos + segment_length, samples)
            audio[pos:end_pos] = np.random.normal(0, 0.01, end_pos - pos).astype(np.float32)
            pos = end_pos + gap_length

        return audio

    def test_single_transcription(self, test_id: int, audio_duration: float = 2.0) -> Dict[str, Any]:
        """Test a single transcription attempt"""
        print(f"\n--- Test {test_id}: {audio_duration}s audio ---")

        result = {
            "test_id": test_id,
            "audio_duration": audio_duration,
            "success": False,
            "error": None,
            "model_state_before": None,
            "model_state_after": None,
            "processing_state_before": None,
            "processing_state_after": None,
            "transcription_count": None,
            "result_length": 0,
            "execution_time": 0,
            "recovery_attempted": False
        }

        try:
            # Check state before transcription
            result["model_state_before"] = "None" if self.asr._model is None else "Loaded"
            result["processing_state_before"] = self.asr._is_processing
            result["transcription_count"] = self.asr._transcriptions_since_reload

            print(f"  Before: model={result['model_state_before']}, processing={result['processing_state_before']}, count={result['transcription_count']}")

            # Create and transcribe audio
            test_audio = self.create_test_audio_sequence(audio_duration)

            start_time = time.time()
            transcription_result = self.asr.transcribe(test_audio)
            execution_time = time.time() - start_time

            # Check state after transcription
            result["model_state_after"] = "None" if self.asr._model is None else "Loaded"
            result["processing_state_after"] = self.asr._is_processing
            result["execution_time"] = execution_time
            result["result_length"] = len(transcription_result) if transcription_result else 0
            result["success"] = True

            print(f"  Success: {execution_time:.2f}s, result_length={result['result_length']}")
            print(f"  After: model={result['model_state_after']}, processing={result['processing_state_after']}")

            self.successful_tests += 1

        except Exception as e:
            error_msg = str(e)
            result["error"] = error_msg
            result["model_state_after"] = "None" if self.asr._model is None else "Loaded"
            result["processing_state_after"] = self.asr._is_processing

            print(f"  ERROR: {error_msg}")
            print(f"  After error: model={result['model_state_after']}, processing={result['processing_state_after']}")

            # Check if this is the NoneType error we're tracking
            if "NoneType" in error_msg and "context manager" in error_msg:
                print("  *** FOUND THE NONETYPE CONTEXT MANAGER ERROR ***")
                result["recovery_attempted"] = True

            self.failed_tests += 1

        self.total_tests += 1
        self.results.append(result)
        return result

    def test_multiple_sentences_with_pauses(self):
        """Test the exact pattern that's causing issues: multiple sentences with pauses"""
        print("\n" + "="*60)
        print("TESTING: Multiple sentences with pauses and resuming")
        print("="*60)

        # Test pattern that matches user's description
        test_scenarios = [
            ("Short single sentence", 1.5),
            ("Medium sentence", 2.5),
            ("Long sentence", 4.0),
            ("Short pause", 1.0),
            ("Another medium", 2.5),
            ("Complex long sentence", 5.0),
            ("Quick pause", 0.8),
            ("Final long sentence", 4.5),
            ("Very long speech", 8.0),  # This might trigger the issue
            ("Recovery test", 2.0),
        ]

        for i, (description, duration) in enumerate(test_scenarios, 1):
            print(f"\nScenario {i}: {description} ({duration}s)")

            result = self.test_single_transcription(i, duration)

            # If we hit an error, test recovery
            if not result["success"]:
                print(f"  Error detected in scenario {i}, testing recovery...")

                # Try a simple recovery test
                recovery_result = self.test_single_transcription(f"{i}R", 1.5)
                if not recovery_result["success"]:
                    print("  CRITICAL: Recovery failed - system is broken!")
                    return False
                else:
                    print("  Recovery successful - continuing tests...")

            # Small delay between tests to simulate real usage
            time.sleep(0.3)

        return True

    def test_stress_scenario(self):
        """Stress test with rapid transcriptions"""
        print("\n" + "="*60)
        print("STRESS TEST: Rapid consecutive transcriptions")
        print("="*60)

        for i in range(15):  # 15 rapid transcriptions
            result = self.test_single_transcription(f"S{i+1}", 1.5)

            if not result["success"]:
                print(f"STRESS TEST FAILED at transcription {i+1}")
                return False

            # Very short delay to simulate rapid usage
            time.sleep(0.1)

        print("STRESS TEST PASSED!")
        return True

    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "="*60)
        print("COMPREHENSIVE TEST REPORT")
        print("="*60)

        print(f"Total Tests: {self.total_tests}")
        print(f"Successful: {self.successful_tests}")
        print(f"Failed: {self.failed_tests}")
        print(f"Success Rate: {(self.successful_tests/self.total_tests*100):.1f}%")

        # Analyze failures
        failures = [r for r in self.results if not r["success"]]
        if failures:
            print(f"\nFAILURE ANALYSIS:")
            for failure in failures:
                print(f"  Test {failure['test_id']}: {failure['error']}")

        # Check for NoneType errors
        nonetype_errors = [r for r in self.results if r.get("recovery_attempted")]
        if nonetype_errors:
            print(f"\nNONETYPE ERRORS DETECTED: {len(nonetype_errors)}")
            for error in nonetype_errors:
                print(f"  Test {error['test_id']}: occurred after {error['transcription_count']} transcriptions")

        # Save detailed results
        report_file = "transcription_test_report.json"
        with open(report_file, 'w') as f:
            json.dump({
                "summary": {
                    "total_tests": self.total_tests,
                    "successful_tests": self.successful_tests,
                    "failed_tests": self.failed_tests,
                    "success_rate": self.successful_tests/self.total_tests*100
                },
                "results": self.results
            }, f, indent=2)

        print(f"\nDetailed report saved to: {report_file}")

        return self.failed_tests == 0

def main():
    """Main testing function"""
    print("Starting Comprehensive VoiceFlow Transcription Testing")
    print("This will test the exact scenarios causing NoneType errors")

    tester = TranscriptionTester()

    # Setup phase
    if not tester.setup_asr():
        print("FATAL: Cannot proceed with testing - ASR setup failed")
        return False

    try:
        # Test 1: Multiple sentences with pauses (user's exact scenario)
        success1 = tester.test_multiple_sentences_with_pauses()

        # Test 2: Stress testing
        if success1:
            success2 = tester.test_stress_scenario()
        else:
            print("Skipping stress test due to basic test failures")
            success2 = False

        # Generate comprehensive report
        overall_success = tester.generate_report()

        if overall_success:
            print("\n🎉 ALL TESTS PASSED! The NoneType error appears to be fixed.")
            return True
        else:
            print("\n❌ TESTS FAILED! The NoneType error still exists.")
            return False

    except Exception as e:
        print(f"\n💥 TESTING FRAMEWORK ERROR: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)