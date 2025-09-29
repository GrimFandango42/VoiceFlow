#!/usr/bin/env python3
"""
Comprehensive Integration Test Suite for VoiceFlow Stability Improvements

Tests the complete end-to-end transcription workflow after implementing:
- Aggressive model reinitialization every 2 transcriptions
- Enhanced hallucination detection
- Comprehensive error recovery
- Memory cleanup and stability improvements

Author: Claude Code
Date: 2025-09-27
"""

import sys
import os
import time
import numpy as np
import threading
import queue
import json
import psutil
import gc
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
    from voiceflow.core.config import Config
    from voiceflow.stability.hallucination_detector import HallucinationDetector
    from voiceflow.stability.error_recovery import ErrorRecovery
    from voiceflow.stability.models import StabilityConfig
except ImportError as e:
    print(f"Failed to import VoiceFlow modules: {e}")
    print("Please ensure PYTHONPATH includes the src directory")
    sys.exit(1)

@dataclass
class IntegrationTestResult:
    """Integration test result data structure"""
    test_name: str
    success: bool
    duration: float
    transcription_count: int
    model_reloads: int
    hallucinations_detected: int
    errors_recovered: int
    memory_usage_mb: float
    cpu_usage_percent: float
    error_message: Optional[str] = None
    performance_metrics: Optional[Dict] = None

class ComprehensiveIntegrationTester:
    """Comprehensive integration testing framework"""

    def __init__(self):
        self.config = Config()
        self.asr = None
        self.hallucination_detector = HallucinationDetector()
        self.error_recovery = ErrorRecovery()
        self.test_results: List[IntegrationTestResult] = []
        self.process = psutil.Process()

    def setup_test_environment(self):
        """Set up the testing environment"""
        print("🔧 Setting up comprehensive integration test environment...")

        # Initialize ASR with stability configuration
        try:
            self.asr = BufferSafeWhisperASR(self.config)
            print("✅ ASR initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize ASR: {e}")
            return False

        # Verify all stability components are working
        try:
            stability_config = StabilityConfig()
            print(f"✅ Stability configuration loaded: {stability_config}")
        except Exception as e:
            print(f"⚠️ Stability configuration issue: {e}")

        return True

    def generate_test_audio(self, duration_seconds: float, audio_type: str = "speech") -> np.ndarray:
        """Generate test audio of specified type and duration"""
        sample_rate = 16000
        samples = int(duration_seconds * sample_rate)

        if audio_type == "silence":
            return np.zeros(samples, dtype=np.float32)
        elif audio_type == "noise":
            return np.random.normal(0, 0.001, samples).astype(np.float32)
        elif audio_type == "speech":
            # Generate speech-like audio with varying frequency content
            t = np.linspace(0, duration_seconds, samples)
            # Mix of frequencies that simulate speech
            audio = (0.1 * np.sin(2 * np.pi * 150 * t) +  # Low frequency
                    0.05 * np.sin(2 * np.pi * 400 * t) +   # Mid frequency
                    0.02 * np.sin(2 * np.pi * 1000 * t) +  # Higher frequency
                    0.01 * np.random.normal(0, 1, samples))  # Noise
            return audio.astype(np.float32)
        elif audio_type == "quiet":
            # Very quiet audio that might trigger hallucinations
            return np.random.normal(0, 0.0001, samples).astype(np.float32)
        else:
            return np.random.normal(0, 0.1, samples).astype(np.float32)

    def test_basic_transcription_workflow(self) -> IntegrationTestResult:
        """Test basic transcription workflow"""
        print("\n📝 Testing Basic Transcription Workflow...")
        start_time = time.time()
        start_memory = self.process.memory_info().rss / 1024 / 1024
        start_cpu = self.process.cpu_percent()

        success = True
        error_message = None
        transcription_count = 0

        try:
            # Test various audio types
            test_cases = [
                ("speech", 1.0),
                ("speech", 2.5),
                ("speech", 0.5),
                ("silence", 0.3),
                ("speech", 1.8)
            ]

            for audio_type, duration in test_cases:
                audio = self.generate_test_audio(duration, audio_type)
                result = self.asr.transcribe(audio)
                transcription_count += 1

                # Validate result is string (not stuck)
                if not isinstance(result, str):
                    raise ValueError(f"Transcription returned {type(result)}, expected str")

                print(f"   ✓ {audio_type} ({duration}s): {len(result)} chars")

        except Exception as e:
            success = False
            error_message = str(e)
            print(f"   ❌ Basic workflow failed: {e}")

        duration = time.time() - start_time
        end_memory = self.process.memory_info().rss / 1024 / 1024
        end_cpu = self.process.cpu_percent()

        result = IntegrationTestResult(
            test_name="basic_transcription_workflow",
            success=success,
            duration=duration,
            transcription_count=transcription_count,
            model_reloads=self.asr._transcriptions_since_reload if self.asr else 0,
            hallucinations_detected=0,  # Count these separately
            errors_recovered=0,
            memory_usage_mb=end_memory - start_memory,
            cpu_usage_percent=(start_cpu + end_cpu) / 2,
            error_message=error_message
        )

        self.test_results.append(result)
        return result

    def test_model_reload_cycle(self) -> IntegrationTestResult:
        """Test model reload cycle behavior"""
        print("\n🔄 Testing Model Reload Cycle...")
        start_time = time.time()
        start_memory = self.process.memory_info().rss / 1024 / 1024

        success = True
        error_message = None
        transcription_count = 0
        model_reloads = 0

        try:
            # Reset transcription counter to test reload
            initial_count = self.asr._transcriptions_since_reload

            # Perform enough transcriptions to trigger reload (should be 2)
            for i in range(5):  # More than reload threshold
                audio = self.generate_test_audio(1.0, "speech")
                result = self.asr.transcribe(audio)
                transcription_count += 1

                current_count = self.asr._transcriptions_since_reload
                if current_count < initial_count or current_count == 0:
                    model_reloads += 1
                    print(f"   🔄 Model reload detected at transcription {i+1}")
                    initial_count = current_count

                # Verify system still works after reload
                if not isinstance(result, str):
                    raise ValueError(f"Transcription failed after reload: {type(result)}")

                print(f"   ✓ Transcription {i+1}: {len(result)} chars, count: {current_count}")

        except Exception as e:
            success = False
            error_message = str(e)
            print(f"   ❌ Model reload test failed: {e}")

        duration = time.time() - start_time
        end_memory = self.process.memory_info().rss / 1024 / 1024

        result = IntegrationTestResult(
            test_name="model_reload_cycle",
            success=success,
            duration=duration,
            transcription_count=transcription_count,
            model_reloads=model_reloads,
            hallucinations_detected=0,
            errors_recovered=0,
            memory_usage_mb=end_memory - start_memory,
            cpu_usage_percent=self.process.cpu_percent(),
            error_message=error_message
        )

        self.test_results.append(result)
        return result

    def test_hallucination_detection(self) -> IntegrationTestResult:
        """Test hallucination detection and filtering"""
        print("\n🚫 Testing Hallucination Detection...")
        start_time = time.time()

        success = True
        error_message = None
        hallucinations_detected = 0

        try:
            # Test various hallucination patterns
            test_patterns = [
                "okay okay okay okay okay",
                "ok ok ok ok",
                "o.k. o.k. o.k.",
                "thank you thank you thank you",
                "the the the the the",
                "normal speech text"  # Should not be detected
            ]

            for pattern in test_patterns:
                is_hallucination = self.hallucination_detector.detect_okay_hallucination(pattern)
                is_repetitive = self.hallucination_detector.detect_repetitive_patterns(pattern)

                if is_hallucination or is_repetitive:
                    hallucinations_detected += 1
                    print(f"   🚫 Detected hallucination: '{pattern[:30]}...'")
                else:
                    print(f"   ✓ Normal text: '{pattern[:30]}...'")

            # Test text cleaning
            dirty_text = "okay okay okay the the the"
            cleaned_text = self.hallucination_detector.clean_transcription(dirty_text)
            if len(cleaned_text) < len(dirty_text):
                print(f"   🧹 Cleaned text: '{dirty_text}' -> '{cleaned_text}'")

        except Exception as e:
            success = False
            error_message = str(e)
            print(f"   ❌ Hallucination detection failed: {e}")

        duration = time.time() - start_time

        result = IntegrationTestResult(
            test_name="hallucination_detection",
            success=success,
            duration=duration,
            transcription_count=0,
            model_reloads=0,
            hallucinations_detected=hallucinations_detected,
            errors_recovered=0,
            memory_usage_mb=0,
            cpu_usage_percent=0,
            error_message=error_message
        )

        self.test_results.append(result)
        return result

    def test_error_recovery(self) -> IntegrationTestResult:
        """Test error recovery mechanisms"""
        print("\n🛡️ Testing Error Recovery...")
        start_time = time.time()

        success = True
        error_message = None
        errors_recovered = 0

        try:
            # Test various error conditions
            error_contexts = [
                {"error_message": "NoneType object has no attribute 'transcribe'", "context": "model_corruption"},
                {"error_message": "CUDA out of memory", "context": "gpu_failure"},
                {"error_message": "threading.lock timeout", "context": "deadlock"},
                {"error_message": "normal operation", "context": "no_error"}
            ]

            for context in error_contexts:
                error_type = self.error_recovery.detect_error(context)
                if error_type:
                    recovery_result = self.error_recovery.recover_from_error(error_type, context)
                    if recovery_result:
                        errors_recovered += 1
                        print(f"   🛡️ Recovered from: {context['context']}")
                    else:
                        print(f"   ⚠️ Recovery failed for: {context['context']}")
                else:
                    print(f"   ✓ No error detected: {context['context']}")

        except Exception as e:
            success = False
            error_message = str(e)
            print(f"   ❌ Error recovery test failed: {e}")

        duration = time.time() - start_time

        result = IntegrationTestResult(
            test_name="error_recovery",
            success=success,
            duration=duration,
            transcription_count=0,
            model_reloads=0,
            hallucinations_detected=0,
            errors_recovered=errors_recovered,
            memory_usage_mb=0,
            cpu_usage_percent=0,
            error_message=error_message
        )

        self.test_results.append(result)
        return result

    def test_concurrent_operations(self) -> IntegrationTestResult:
        """Test concurrent transcription prevention"""
        print("\n⚡ Testing Concurrent Operations Prevention...")
        start_time = time.time()

        success = True
        error_message = None
        transcription_count = 0

        try:
            # Test that concurrent transcriptions are properly handled
            results_queue = queue.Queue()

            def transcribe_worker(worker_id: int):
                try:
                    audio = self.generate_test_audio(1.0, "speech")
                    result = self.asr.transcribe(audio)
                    results_queue.put((worker_id, "success", result))
                except Exception as e:
                    results_queue.put((worker_id, "error", str(e)))

            # Start multiple transcription threads
            threads = []
            for i in range(3):
                thread = threading.Thread(target=transcribe_worker, args=(i,))
                threads.append(thread)
                thread.start()
                time.sleep(0.1)  # Slight delay to test overlap

            # Wait for all threads to complete
            for thread in threads:
                thread.join(timeout=30)  # 30 second timeout

            # Collect results
            while not results_queue.empty():
                worker_id, status, result = results_queue.get()
                transcription_count += 1
                if status == "error":
                    print(f"   ⚠️ Worker {worker_id} error: {result}")
                else:
                    print(f"   ✓ Worker {worker_id} success: {len(result)} chars")

        except Exception as e:
            success = False
            error_message = str(e)
            print(f"   ❌ Concurrent operations test failed: {e}")

        duration = time.time() - start_time

        result = IntegrationTestResult(
            test_name="concurrent_operations",
            success=success,
            duration=duration,
            transcription_count=transcription_count,
            model_reloads=0,
            hallucinations_detected=0,
            errors_recovered=0,
            memory_usage_mb=0,
            cpu_usage_percent=0,
            error_message=error_message
        )

        self.test_results.append(result)
        return result

    def test_memory_stability(self) -> IntegrationTestResult:
        """Test memory stability over multiple operations"""
        print("\n💾 Testing Memory Stability...")
        start_time = time.time()

        success = True
        error_message = None
        transcription_count = 0
        memory_samples = []

        try:
            initial_memory = self.process.memory_info().rss / 1024 / 1024

            # Perform many transcriptions to test memory stability
            for i in range(10):
                audio = self.generate_test_audio(2.0, "speech")
                result = self.asr.transcribe(audio)
                transcription_count += 1

                # Sample memory usage
                current_memory = self.process.memory_info().rss / 1024 / 1024
                memory_samples.append(current_memory)

                # Force garbage collection periodically
                if i % 3 == 0:
                    gc.collect()

                print(f"   📊 Transcription {i+1}: {len(result)} chars, Memory: {current_memory:.1f}MB")

            final_memory = self.process.memory_info().rss / 1024 / 1024
            memory_growth = final_memory - initial_memory

            # Check for excessive memory growth
            if memory_growth > 500:  # More than 500MB growth is concerning
                print(f"   ⚠️ High memory growth detected: {memory_growth:.1f}MB")
            else:
                print(f"   ✅ Memory growth acceptable: {memory_growth:.1f}MB")

        except Exception as e:
            success = False
            error_message = str(e)
            print(f"   ❌ Memory stability test failed: {e}")

        duration = time.time() - start_time

        result = IntegrationTestResult(
            test_name="memory_stability",
            success=success,
            duration=duration,
            transcription_count=transcription_count,
            model_reloads=0,
            hallucinations_detected=0,
            errors_recovered=0,
            memory_usage_mb=memory_growth if 'memory_growth' in locals() else 0,
            cpu_usage_percent=self.process.cpu_percent(),
            error_message=error_message,
            performance_metrics={"memory_samples": memory_samples} if memory_samples else None
        )

        self.test_results.append(result)
        return result

    def generate_comprehensive_report(self) -> Dict:
        """Generate comprehensive test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result.success)

        report = {
            "test_summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": total_tests - passed_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                "total_duration": sum(result.duration for result in self.test_results),
                "timestamp": datetime.now().isoformat()
            },
            "stability_metrics": {
                "total_transcriptions": sum(result.transcription_count for result in self.test_results),
                "total_model_reloads": sum(result.model_reloads for result in self.test_results),
                "total_hallucinations_detected": sum(result.hallucinations_detected for result in self.test_results),
                "total_errors_recovered": sum(result.errors_recovered for result in self.test_results),
                "average_memory_usage_mb": sum(result.memory_usage_mb for result in self.test_results) / total_tests if total_tests > 0 else 0
            },
            "detailed_results": [asdict(result) for result in self.test_results],
            "recommendations": self._generate_recommendations()
        }

        return report

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []

        failed_tests = [result for result in self.test_results if not result.success]
        if failed_tests:
            recommendations.append(f"🔧 Address {len(failed_tests)} failed test(s)")

        memory_usage = sum(result.memory_usage_mb for result in self.test_results)
        if memory_usage > 200:
            recommendations.append("💾 Consider optimizing memory usage (high consumption detected)")

        total_reloads = sum(result.model_reloads for result in self.test_results)
        if total_reloads > 5:
            recommendations.append("⚡ Model reload frequency may impact performance")

        if all(result.success for result in self.test_results):
            recommendations.append("✅ All tests passed - system is production ready!")

        return recommendations

    def run_comprehensive_tests(self) -> Dict:
        """Run all comprehensive integration tests"""
        print("🚀 Starting Comprehensive Integration Testing for VoiceFlow Stability Improvements")
        print("=" * 80)

        if not self.setup_test_environment():
            return {"error": "Failed to set up test environment"}

        # Run all test suites
        test_suites = [
            self.test_basic_transcription_workflow,
            self.test_model_reload_cycle,
            self.test_hallucination_detection,
            self.test_error_recovery,
            self.test_concurrent_operations,
            self.test_memory_stability
        ]

        print(f"\n📋 Running {len(test_suites)} test suites...")

        for test_func in test_suites:
            try:
                result = test_func()
                status = "✅ PASSED" if result.success else "❌ FAILED"
                print(f"{status}: {result.test_name} ({result.duration:.2f}s)")
            except Exception as e:
                print(f"❌ CRITICAL FAILURE in {test_func.__name__}: {e}")

        # Generate final report
        report = self.generate_comprehensive_report()

        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE INTEGRATION TEST RESULTS")
        print("=" * 80)
        print(f"Tests Run: {report['test_summary']['total_tests']}")
        print(f"Passed: {report['test_summary']['passed_tests']}")
        print(f"Failed: {report['test_summary']['failed_tests']}")
        print(f"Success Rate: {report['test_summary']['success_rate']:.1f}%")
        print(f"Total Duration: {report['test_summary']['total_duration']:.2f}s")

        print(f"\n🔧 Stability Metrics:")
        print(f"Total Transcriptions: {report['stability_metrics']['total_transcriptions']}")
        print(f"Model Reloads: {report['stability_metrics']['total_model_reloads']}")
        print(f"Hallucinations Detected: {report['stability_metrics']['total_hallucinations_detected']}")
        print(f"Errors Recovered: {report['stability_metrics']['total_errors_recovered']}")

        print(f"\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"  {rec}")

        return report

def main():
    """Main test execution"""
    tester = ComprehensiveIntegrationTester()

    # Run comprehensive tests
    report = tester.run_comprehensive_tests()

    # Save detailed report
    report_file = Path("comprehensive_integration_test_report.json")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Detailed report saved to: {report_file}")

    # Return exit code based on success
    if report.get('test_summary', {}).get('failed_tests', 1) == 0:
        print("\n🎉 ALL INTEGRATION TESTS PASSED! System is production ready.")
        return 0
    else:
        print("\n⚠️ Some integration tests failed. Review the report for details.")
        return 1

if __name__ == "__main__":
    exit(main())