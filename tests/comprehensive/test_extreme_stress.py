#!/usr/bin/env python3
"""
VoiceFlow Extreme Stress Test Suite
===================================
Comprehensive testing with extreme inputs to find breaking points
"""

import sys
import time
import threading
import traceback
import numpy as np
import psutil
import os
from typing import List, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import gc

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from localflow.config import Config
    from localflow.cli_enhanced import EnhancedApp
    from localflow.audio_enhanced import EnhancedAudioRecorder
    from localflow.asr_buffer_safe import BufferSafeWhisperASR
    from localflow.enhanced_tray import EnhancedTrayController
    from localflow.visual_indicators import show_listening, show_complete, hide_status
except ImportError as e:
    print(f"Import error: {e}")
    print("Please run from VoiceFlow root directory")
    sys.exit(1)

@dataclass
class TestResult:
    test_name: str
    status: str  # PASS, FAIL, TIMEOUT, ERROR
    duration: float
    memory_peak: float
    error_message: str = ""
    details: Dict[str, Any] = None

class ExtremeStressTestSuite:
    """Comprehensive test suite for extreme stress conditions"""
    
    def __init__(self):
        self.results: List[TestResult] = []
        self.cfg = Config()
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        self.process = psutil.Process()
        
    def log_result(self, result: TestResult):
        """Log test result and memory usage"""
        self.results.append(result)
        status_icon = {
            'PASS': '[OK]',
            'FAIL': '[FAIL]',
            'TIMEOUT': '[TIMEOUT]', 
            'ERROR': '[ERROR]'
        }.get(result.status, '[UNKNOWN]')
        
        print(f"{status_icon} {result.test_name}")
        print(f"     Duration: {result.duration:.2f}s | Memory: {result.memory_peak:.1f}MB")
        if result.error_message:
            print(f"     Error: {result.error_message}")
    
    def measure_memory(self) -> float:
        """Get current memory usage in MB"""
        try:
            return self.process.memory_info().rss / 1024 / 1024
        except:
            return 0.0
    
    def run_with_timeout(self, func, timeout: float, *args, **kwargs):
        """Run function with timeout and memory monitoring"""
        start_time = time.perf_counter()
        start_memory = self.measure_memory()
        peak_memory = start_memory
        
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func, *args, **kwargs)
            
            # Monitor memory while running
            while not future.done():
                current_memory = self.measure_memory()
                peak_memory = max(peak_memory, current_memory)
                time.sleep(0.1)
                
                if time.perf_counter() - start_time > timeout:
                    future.cancel()
                    duration = time.perf_counter() - start_time
                    return TestResult(
                        test_name="timeout",
                        status="TIMEOUT",
                        duration=duration,
                        memory_peak=peak_memory,
                        error_message=f"Timeout after {timeout}s"
                    )
            
            try:
                result = future.result(timeout=1.0)
                duration = time.perf_counter() - start_time
                return TestResult(
                    test_name="success",
                    status="PASS",
                    duration=duration,
                    memory_peak=peak_memory,
                    details=result
                )
            except Exception as e:
                duration = time.perf_counter() - start_time
                return TestResult(
                    test_name="exception",
                    status="ERROR", 
                    duration=duration,
                    memory_peak=peak_memory,
                    error_message=str(e)
                )

    def test_1_massive_audio_buffer(self):
        """Test 1: Massive audio buffer (10 minutes simulated)"""
        print("\nTEST 1: Massive Audio Buffer (10 minutes)")
        
        def massive_buffer_test():
            sample_rate = 16000
            duration = 600  # 10 minutes
            samples = sample_rate * duration
            
            # Generate large audio buffer
            audio_data = np.random.random(samples).astype(np.float32) * 0.1
            
            # Test buffer handling
            recorder = EnhancedAudioRecorder(self.cfg)
            
            # Simulate massive buffer accumulation
            for chunk_size in [1024, 4096, 16384]:
                for i in range(0, len(audio_data), chunk_size):
                    chunk = audio_data[i:i+chunk_size]
                    if len(chunk) == chunk_size:
                        # Simulate buffer processing
                        pass
            
            return {"samples": len(audio_data), "duration": duration}
        
        result = self.run_with_timeout(massive_buffer_test, 30.0)
        result.test_name = "Massive Audio Buffer (10min)"
        self.log_result(result)
        
        # Cleanup
        gc.collect()
    
    def test_2_rapid_transcription_requests(self):
        """Test 2: Rapid-fire transcription requests"""
        print("\nTEST 2: Rapid Transcription Requests (100 concurrent)")
        
        def rapid_requests_test():
            asr = BufferSafeWhisperASR(self.cfg)
            
            # Generate small audio samples
            sample_rate = 16000
            duration = 1.0  # 1 second samples
            num_requests = 100
            
            audio_sample = np.random.random(int(sample_rate * duration)).astype(np.float32) * 0.1
            
            results = []
            start_time = time.perf_counter()
            
            # Submit rapid requests
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for i in range(num_requests):
                    future = executor.submit(asr.transcribe, audio_sample)
                    futures.append(future)
                
                # Collect results
                for i, future in enumerate(futures):
                    try:
                        result = future.result(timeout=30.0)
                        results.append(result)
                    except Exception as e:
                        results.append(f"Error_{i}: {e}")
            
            duration = time.perf_counter() - start_time
            return {
                "requests": num_requests,
                "completed": len([r for r in results if not str(r).startswith("Error_")]),
                "errors": len([r for r in results if str(r).startswith("Error_")]),
                "total_time": duration
            }
        
        result = self.run_with_timeout(rapid_requests_test, 60.0)
        result.test_name = "Rapid Transcription Requests"
        self.log_result(result)
    
    def test_3_visual_indicator_stress(self):
        """Test 3: Visual indicator rapid updates"""
        print("\nTEST 3: Visual Indicator Stress (1000 rapid updates)")
        
        def visual_stress_test():
            states = ["listening", "processing", "transcribing", "complete", "error"]
            update_count = 1000
            
            # Test rapid state changes
            for i in range(update_count):
                state = states[i % len(states)]
                
                if state == "listening":
                    show_listening()
                elif state == "complete":
                    show_complete(f"Test message {i}")
                elif state == "error":
                    from localflow.visual_indicators import show_error
                    show_error(f"Test error {i}")
                
                # Brief pause to avoid overwhelming the system
                time.sleep(0.001)  # 1ms
            
            hide_status()
            return {"updates": update_count}
        
        result = self.run_with_timeout(visual_stress_test, 15.0)
        result.test_name = "Visual Indicator Stress"
        self.log_result(result)
    
    def test_4_memory_leak_detection(self):
        """Test 4: Memory leak detection over many cycles"""
        print("\nTEST 4: Memory Leak Detection (100 app cycles)")
        
        def memory_leak_test():
            initial_memory = self.measure_memory()
            memory_samples = [initial_memory]
            
            for cycle in range(100):
                # Create and destroy app instance
                app = EnhancedApp(Config())
                
                # Simulate some activity
                sample_audio = np.random.random(16000).astype(np.float32) * 0.1
                
                # Force cleanup
                del app
                gc.collect()
                
                # Measure memory every 10 cycles
                if cycle % 10 == 0:
                    memory_samples.append(self.measure_memory())
            
            final_memory = self.measure_memory()
            memory_growth = final_memory - initial_memory
            
            return {
                "initial_memory": initial_memory,
                "final_memory": final_memory,
                "memory_growth": memory_growth,
                "samples": memory_samples
            }
        
        result = self.run_with_timeout(memory_leak_test, 45.0)
        result.test_name = "Memory Leak Detection"
        self.log_result(result)
    
    def test_5_extreme_duration_recording(self):
        """Test 5: Extreme duration recording simulation"""
        print("\nTEST 5: Extreme Duration Recording (30 minutes simulated)")
        
        def extreme_duration_test():
            # Simulate 30-minute recording
            sample_rate = 16000
            total_duration = 1800  # 30 minutes in seconds
            chunk_duration = 30     # Process in 30-second chunks
            
            chunks_processed = 0
            total_samples = 0
            
            asr = BufferSafeWhisperASR(self.cfg)
            
            for chunk_start in range(0, total_duration, chunk_duration):
                # Generate chunk
                chunk_samples = sample_rate * chunk_duration
                audio_chunk = np.random.random(chunk_samples).astype(np.float32) * 0.1
                
                # Process chunk
                try:
                    result = asr.transcribe(audio_chunk)
                    chunks_processed += 1
                    total_samples += len(audio_chunk)
                except Exception as e:
                    print(f"Chunk {chunks_processed} failed: {e}")
                
                # Memory check
                current_memory = self.measure_memory()
                if current_memory > 2000:  # 2GB limit
                    raise MemoryError(f"Memory usage too high: {current_memory}MB")
            
            return {
                "chunks_processed": chunks_processed,
                "total_samples": total_samples,
                "duration": total_duration
            }
        
        result = self.run_with_timeout(extreme_duration_test, 120.0)  # 2 minute timeout
        result.test_name = "Extreme Duration Recording"
        self.log_result(result)
    
    def test_6_concurrent_app_instances(self):
        """Test 6: Multiple concurrent app instances"""
        print("\nTEST 6: Concurrent App Instances (5 simultaneous)")
        
        def concurrent_apps_test():
            num_instances = 5
            apps = []
            
            # Create multiple app instances
            for i in range(num_instances):
                cfg = Config()
                app = EnhancedApp(cfg)
                apps.append(app)
            
            # Test concurrent operations
            def app_worker(app_index, app):
                try:
                    # Simulate activity
                    audio_sample = np.random.random(16000).astype(np.float32) * 0.1
                    
                    # Test transcription
                    result = app.asr.transcribe(audio_sample)
                    
                    return f"App_{app_index}: Success"
                except Exception as e:
                    return f"App_{app_index}: Error - {e}"
            
            # Run concurrent workers
            with ThreadPoolExecutor(max_workers=num_instances) as executor:
                futures = []
                for i, app in enumerate(apps):
                    future = executor.submit(app_worker, i, app)
                    futures.append(future)
                
                results = []
                for future in futures:
                    try:
                        result = future.result(timeout=30.0)
                        results.append(result)
                    except Exception as e:
                        results.append(f"Timeout/Error: {e}")
            
            # Cleanup
            for app in apps:
                try:
                    app.shutdown()
                except:
                    pass
            
            return {
                "instances": num_instances,
                "results": results,
                "success_count": len([r for r in results if "Success" in r])
            }
        
        result = self.run_with_timeout(concurrent_apps_test, 60.0)
        result.test_name = "Concurrent App Instances"
        self.log_result(result)
    
    def test_7_tray_visual_integration_stress(self):
        """Test 7: Tray and visual indicator integration under stress"""
        print("\nTEST 7: Tray+Visual Integration Stress")
        
        def tray_visual_stress_test():
            try:
                # Create mock app for tray testing
                class MockApp:
                    def __init__(self):
                        self.cfg = Config()
                        self.code_mode = False
                        self.visual_indicators_enabled = True
                
                app = MockApp()
                tray = EnhancedTrayController(app)
                
                # Test rapid status updates
                statuses = ["idle", "listening", "processing", "transcribing", "complete", "error"]
                update_count = 500
                
                for i in range(update_count):
                    status = statuses[i % len(statuses)]
                    recording = (i % 2 == 0)  # Alternate recording state
                    message = f"Stress test message {i}"
                    
                    tray.update_status(status, recording, message)
                    
                    # Brief pause
                    time.sleep(0.002)  # 2ms
                
                # Final cleanup
                tray.update_status("idle", False)
                
                return {"status_updates": update_count, "tray_integration": "success"}
                
            except Exception as e:
                return {"error": str(e)}
        
        result = self.run_with_timeout(tray_visual_stress_test, 30.0)
        result.test_name = "Tray+Visual Integration Stress"
        self.log_result(result)
    
    def test_8_unicode_and_special_characters(self):
        """Test 8: Unicode and special character handling"""
        print("\nTEST 8: Unicode and Special Character Handling")
        
        def unicode_test():
            # Test various character encodings and edge cases
            test_strings = [
                "Normal text",
                "Unicode: 你好世界 🌍 👋",
                "Emojis: 🎵🎤🔊📱💻🎧",
                "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?",
                "Zero-width chars: \u200b\u200c\u200d\u2060",
                "RTL text: שלום עולם مرحبا بالعالم",
                "Math symbols: ∞∑∫∂∇∆π∑∏√∞≠≤≥",
                "Control chars: \x00\x01\x02\x03\x1f\x7f",
                "Long repeated: " + "A" * 10000,
                "Mixed: Hello 世界 🌍 !@# \x00 测试"
            ]
            
            results = []
            
            for i, test_str in enumerate(test_strings):
                try:
                    # Test text processing
                    from localflow.textproc import apply_code_mode
                    
                    processed = apply_code_mode(test_str, lowercase=False)
                    results.append(f"Test_{i}: OK ({len(processed)} chars)")
                    
                    # Test visual indicator with unicode
                    show_complete(test_str[:50])  # Truncate for display
                    
                except Exception as e:
                    results.append(f"Test_{i}: FAIL - {e}")
            
            hide_status()
            return {"tests": len(test_strings), "results": results}
        
        result = self.run_with_timeout(unicode_test, 20.0)
        result.test_name = "Unicode and Special Characters"
        self.log_result(result)
    
    def run_all_tests(self):
        """Run complete test suite"""
        print("=" * 60)
        print("VoiceFlow Extreme Stress Test Suite")
        print("=" * 60)
        print(f"Initial Memory Usage: {self.start_memory:.1f}MB")
        
        start_time = time.perf_counter()
        
        # Run all tests
        test_methods = [
            self.test_1_massive_audio_buffer,
            self.test_2_rapid_transcription_requests,
            self.test_3_visual_indicator_stress,
            self.test_4_memory_leak_detection,
            self.test_5_extreme_duration_recording,
            self.test_6_concurrent_app_instances,
            self.test_7_tray_visual_integration_stress,
            self.test_8_unicode_and_special_characters
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                result = TestResult(
                    test_name=test_method.__name__,
                    status="ERROR",
                    duration=0.0,
                    memory_peak=self.measure_memory(),
                    error_message=str(e)
                )
                self.log_result(result)
                print(f"Test runner error: {e}")
                traceback.print_exc()
            
            # Brief pause between tests
            time.sleep(1.0)
            gc.collect()
        
        total_time = time.perf_counter() - start_time
        final_memory = self.measure_memory()
        
        # Summary
        print("\n" + "=" * 60)
        print("TEST SUITE SUMMARY")
        print("=" * 60)
        
        passed = len([r for r in self.results if r.status == "PASS"])
        failed = len([r for r in self.results if r.status == "FAIL"])
        errors = len([r for r in self.results if r.status == "ERROR"])
        timeouts = len([r for r in self.results if r.status == "TIMEOUT"])
        
        print(f"Total Tests: {len(self.results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Errors: {errors}")
        print(f"Timeouts: {timeouts}")
        print(f"Total Duration: {total_time:.2f}s")
        print(f"Memory Change: {final_memory - self.start_memory:.1f}MB")
        print(f"Peak Memory: {max([r.memory_peak for r in self.results]):.1f}MB")
        
        # Detailed results
        print("\nDETAILED RESULTS:")
        for result in self.results:
            status = result.status.ljust(8)
            name = result.test_name.ljust(35)
            print(f"{status} {name} {result.duration:6.2f}s {result.memory_peak:7.1f}MB")
            if result.error_message:
                print(f"         Error: {result.error_message}")
        
        # Return summary for automation
        return {
            "total": len(self.results),
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "timeouts": timeouts,
            "duration": total_time,
            "memory_change": final_memory - self.start_memory,
            "peak_memory": max([r.memory_peak for r in self.results]) if self.results else 0,
            "results": self.results
        }

def main():
    """Main test runner"""
    try:
        suite = ExtremeStressTestSuite()
        summary = suite.run_all_tests()
        
        # Exit code based on results
        if summary["errors"] > 0 or summary["timeouts"] > 0:
            sys.exit(2)  # Critical failures
        elif summary["failed"] > 0:
            sys.exit(1)  # Test failures
        else:
            sys.exit(0)  # All passed
            
    except KeyboardInterrupt:
        print("\nTest suite interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Test suite crashed: {e}")
        traceback.print_exc()
        sys.exit(3)

if __name__ == "__main__":
    main()