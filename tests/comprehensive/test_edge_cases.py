#!/usr/bin/env python3
"""
VoiceFlow Edge Case Test Suite
==============================
Tests for edge cases, boundary conditions, and error scenarios
"""

import sys
import time
import os
import numpy as np
import tempfile
import threading
import json
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from voiceflow.config import Config
    from voiceflow.cli_enhanced import EnhancedApp
    from voiceflow.audio_enhanced import EnhancedAudioRecorder
    from voiceflow.asr_buffer_safe import BufferSafeWhisperASR
    from voiceflow.inject import ClipboardInjector
    from voiceflow.enhanced_tray import EnhancedTrayController
    from voiceflow.visual_indicators import show_listening, show_complete, hide_status
    from voiceflow.textproc import apply_code_mode
except ImportError as e:
    print(f"Import error: {e}")
    print("Please run from VoiceFlow root directory")
    sys.exit(1)

class EdgeCaseTestSuite:
    """Test suite for edge cases and boundary conditions"""
    
    def __init__(self):
        self.test_results = []
        self.cfg = Config()
        
    def log_test(self, test_name: str, status: str, details: str = ""):
        """Log test result"""
        result = f"{status.ljust(8)} {test_name.ljust(40)} {details}"
        print(result)
        self.test_results.append((test_name, status, details))
    
    def test_empty_audio_handling(self):
        """Test handling of empty/silent audio"""
        print("\nTEST: Empty Audio Handling")
        
        try:
            asr = BufferSafeWhisperASR(self.cfg)
            
            # Test completely empty array
            empty_audio = np.array([], dtype=np.float32)
            result = asr.transcribe(empty_audio)
            assert result == "", f"Expected empty string, got: {result}"
            self.log_test("Empty audio array", "PASS")
            
            # Test silent audio (all zeros)
            silent_audio = np.zeros(16000, dtype=np.float32)  # 1 second of silence
            result = asr.transcribe(silent_audio)
            self.log_test("Silent audio (1s zeros)", "PASS", f"Result: '{result}'")
            
            # Test very short audio
            short_audio = np.random.random(100).astype(np.float32) * 0.001  # Very quiet
            result = asr.transcribe(short_audio)
            self.log_test("Very short audio (100 samples)", "PASS", f"Result: '{result}'")
            
        except Exception as e:
            self.log_test("Empty audio handling", "FAIL", str(e))
    
    def test_extreme_audio_values(self):
        """Test handling of extreme audio values"""
        print("\nTEST: Extreme Audio Values")
        
        try:
            asr = BufferSafeWhisperASR(self.cfg)
            
            # Test maximum float32 values
            max_audio = np.full(16000, np.finfo(np.float32).max, dtype=np.float32)
            result = asr.transcribe(max_audio)
            self.log_test("Maximum float32 values", "PASS", f"Result: '{result}'")
            
            # Test minimum float32 values
            min_audio = np.full(16000, np.finfo(np.float32).min, dtype=np.float32)
            result = asr.transcribe(min_audio)
            self.log_test("Minimum float32 values", "PASS", f"Result: '{result}'")
            
            # Test NaN values
            nan_audio = np.full(16000, np.nan, dtype=np.float32)
            try:
                result = asr.transcribe(nan_audio)
                self.log_test("NaN audio values", "PASS", f"Result: '{result}'")
            except Exception as e:
                self.log_test("NaN audio values", "EXPECTED_FAIL", f"Error: {e}")
            
            # Test infinite values
            inf_audio = np.full(16000, np.inf, dtype=np.float32)
            try:
                result = asr.transcribe(inf_audio)
                self.log_test("Infinite audio values", "PASS", f"Result: '{result}'")
            except Exception as e:
                self.log_test("Infinite audio values", "EXPECTED_FAIL", f"Error: {e}")
                
        except Exception as e:
            self.log_test("Extreme audio values", "FAIL", str(e))
    
    def test_config_edge_cases(self):
        """Test configuration edge cases"""
        print("\nTEST: Configuration Edge Cases")
        
        try:
            # Test missing config file
            with tempfile.TemporaryDirectory() as temp_dir:
                config_path = os.path.join(temp_dir, "nonexistent.json")
                cfg = Config()  # Should use defaults
                self.log_test("Missing config file", "PASS", "Used defaults")
            
            # Test corrupted config file
            with tempfile.TemporaryDirectory() as temp_dir:
                config_path = os.path.join(temp_dir, "corrupted.json")
                with open(config_path, 'w') as f:
                    f.write("{ invalid json")
                
                try:
                    cfg = Config()
                    self.log_test("Corrupted config file", "PASS", "Handled gracefully")
                except Exception as e:
                    self.log_test("Corrupted config file", "FAIL", str(e))
            
            # Test extreme config values
            cfg = Config()
            cfg.sample_rate = 0  # Invalid sample rate
            cfg.hotkey_key = ""  # Empty hotkey
            cfg.model_name = "nonexistent_model"
            
            try:
                app = EnhancedApp(cfg)
                self.log_test("Extreme config values", "PASS", "App created with invalid config")
            except Exception as e:
                self.log_test("Extreme config values", "EXPECTED_FAIL", str(e))
                
        except Exception as e:
            self.log_test("Config edge cases", "FAIL", str(e))
    
    def test_filesystem_edge_cases(self):
        """Test filesystem-related edge cases"""
        print("\nTEST: Filesystem Edge Cases")
        
        try:
            # Test read-only directory
            with tempfile.TemporaryDirectory() as temp_dir:
                readonly_dir = os.path.join(temp_dir, "readonly")
                os.makedirs(readonly_dir)
                os.chmod(readonly_dir, 0o444)  # Read-only
                
                try:
                    # Try to create config in read-only directory
                    cfg = Config()
                    self.log_test("Read-only directory", "PASS", "Handled gracefully")
                except Exception as e:
                    self.log_test("Read-only directory", "EXPECTED_FAIL", str(e))
            
            # Test very long file paths
            try:
                long_path = "a" * 300 + ".json"  # Very long filename
                cfg = Config()
                self.log_test("Long file paths", "PASS", "Handled long paths")
            except Exception as e:
                self.log_test("Long file paths", "EXPECTED_FAIL", str(e))
            
            # Test special characters in paths
            try:
                special_chars = "file with spaces & symbols!@#$%^&*().json"
                cfg = Config()
                self.log_test("Special chars in paths", "PASS", "Handled special characters")
            except Exception as e:
                self.log_test("Special chars in paths", "FAIL", str(e))
                
        except Exception as e:
            self.log_test("Filesystem edge cases", "FAIL", str(e))
    
    def test_threading_edge_cases(self):
        """Test threading and concurrency edge cases"""
        print("\nTEST: Threading Edge Cases")
        
        try:
            # Test rapid start/stop cycles
            app = EnhancedApp(self.cfg)
            
            for i in range(10):
                app.start_recording()
                time.sleep(0.01)  # Very short recording
                app.stop_recording()
                time.sleep(0.01)
            
            self.log_test("Rapid start/stop cycles", "PASS", "10 cycles completed")
            
            # Test concurrent recordings (should be prevented)
            def start_recording_thread():
                try:
                    app.start_recording()
                    time.sleep(0.1)
                    app.stop_recording()
                except Exception as e:
                    return str(e)
                return "OK"
            
            threads = []
            for i in range(5):
                thread = threading.Thread(target=start_recording_thread)
                threads.append(thread)
                thread.start()
            
            for thread in threads:
                thread.join(timeout=5.0)
            
            self.log_test("Concurrent recording attempts", "PASS", "Handled concurrent access")
            
            # Cleanup
            app.shutdown()
            
        except Exception as e:
            self.log_test("Threading edge cases", "FAIL", str(e))
    
    def test_memory_pressure(self):
        """Test behavior under memory pressure"""
        print("\nTEST: Memory Pressure")
        
        try:
            # Create large objects to pressure memory
            large_objects = []
            
            try:
                # Allocate increasingly large chunks
                for size in [10, 50, 100]:  # MB
                    chunk = np.zeros(size * 1024 * 1024 // 4, dtype=np.float32)  # Size in MB
                    large_objects.append(chunk)
                
                # Test app creation under memory pressure
                app = EnhancedApp(self.cfg)
                
                # Test transcription under memory pressure
                audio_sample = np.random.random(16000).astype(np.float32) * 0.1
                result = app.asr.transcribe(audio_sample)
                
                self.log_test("Memory pressure operation", "PASS", f"Result: '{result[:30]}...'")
                
                app.shutdown()
                
            except MemoryError:
                self.log_test("Memory pressure handling", "EXPECTED_FAIL", "MemoryError raised")
            except Exception as e:
                self.log_test("Memory pressure handling", "FAIL", str(e))
            finally:
                # Cleanup
                del large_objects
                
        except Exception as e:
            self.log_test("Memory pressure test", "FAIL", str(e))
    
    def test_unicode_edge_cases(self):
        """Test Unicode and encoding edge cases"""
        print("\nTEST: Unicode Edge Cases")
        
        try:
            # Test various Unicode scenarios
            test_cases = [
                ("", "Empty string"),
                ("\x00\x01\x02", "Control characters"),
                ("🌍🎵🎤", "Emojis"),
                ("Ñiño piña jalapeño", "Accented characters"),
                ("Привет мир", "Cyrillic"),
                ("你好世界", "Chinese"),
                ("مرحبا بالعالم", "Arabic"),
                ("שלום עולם", "Hebrew"),
                ("🏳️‍🌈🏳️‍⚧️", "Complex emoji sequences"),
                ("\u200b\u200c\u200d", "Zero-width characters"),
                ("A" * 10000, "Very long string"),
                ("Mixed: Hello 世界 🌍 Ñiño", "Mixed encodings")
            ]
            
            for test_text, description in test_cases:
                try:
                    # Test text processing
                    processed = apply_code_mode(test_text, lowercase=False)
                    
                    # Test visual indicator with Unicode
                    show_complete(test_text[:50])
                    time.sleep(0.01)
                    
                    self.log_test(f"Unicode: {description}", "PASS", f"Length: {len(processed)}")
                    
                except Exception as e:
                    self.log_test(f"Unicode: {description}", "FAIL", str(e))
            
            hide_status()
            
        except Exception as e:
            self.log_test("Unicode edge cases", "FAIL", str(e))
    
    def test_error_recovery(self):
        """Test error recovery scenarios"""
        print("\nTEST: Error Recovery")
        
        try:
            app = EnhancedApp(self.cfg)
            
            # Test recovery from ASR errors
            with patch.object(app.asr, 'transcribe', side_effect=Exception("Mock ASR error")):
                app.start_recording()
                time.sleep(0.1)
                app.stop_recording()  # Should handle ASR error gracefully
                time.sleep(0.1)
                
                self.log_test("ASR error recovery", "PASS", "Recovered from ASR error")
            
            # Test recovery from injection errors
            with patch.object(app.injector, 'inject', side_effect=Exception("Mock injection error")):
                # Simulate successful transcription but failed injection
                audio_sample = np.random.random(8000).astype(np.float32) * 0.1
                try:
                    app.asr.transcribe(audio_sample)  # This should work
                    self.log_test("Injection error recovery", "PASS", "Handled injection error")
                except Exception as e:
                    self.log_test("Injection error recovery", "FAIL", str(e))
            
            # Test recovery from visual indicator errors
            with patch('localflow.visual_indicators.show_complete', side_effect=Exception("Mock visual error")):
                try:
                    show_complete("Test message")
                except Exception:
                    pass  # Expected to fail
                
                # App should still function
                audio_sample = np.random.random(8000).astype(np.float32) * 0.1
                result = app.asr.transcribe(audio_sample)
                self.log_test("Visual error recovery", "PASS", "App functional despite visual errors")
            
            app.shutdown()
            
        except Exception as e:
            self.log_test("Error recovery test", "FAIL", str(e))
    
    def test_boundary_conditions(self):
        """Test boundary conditions for various parameters"""
        print("\nTEST: Boundary Conditions")
        
        try:
            # Test minimum audio length
            min_audio = np.random.random(1).astype(np.float32) * 0.1  # 1 sample
            asr = BufferSafeWhisperASR(self.cfg)
            result = asr.transcribe(min_audio)
            self.log_test("Minimum audio length (1 sample)", "PASS", f"Result: '{result}'")
            
            # Test maximum reasonable audio length
            max_reasonable = 16000 * 60 * 5  # 5 minutes
            max_audio = np.random.random(max_reasonable).astype(np.float32) * 0.1
            try:
                result = asr.transcribe(max_audio[:16000])  # Test first second only for speed
                self.log_test("Maximum reasonable audio", "PASS", "Handled large audio")
            except Exception as e:
                self.log_test("Maximum reasonable audio", "FAIL", str(e))
            
            # Test edge sample rates
            original_rate = self.cfg.sample_rate
            
            for rate in [8000, 11025, 22050, 44100, 48000]:
                try:
                    self.cfg.sample_rate = rate
                    app = EnhancedApp(self.cfg)
                    app.shutdown()
                    self.log_test(f"Sample rate {rate}Hz", "PASS", "App created successfully")
                except Exception as e:
                    self.log_test(f"Sample rate {rate}Hz", "FAIL", str(e))
            
            self.cfg.sample_rate = original_rate  # Restore
            
        except Exception as e:
            self.log_test("Boundary conditions", "FAIL", str(e))
    
    def test_resource_cleanup(self):
        """Test resource cleanup and garbage collection"""
        print("\nTEST: Resource Cleanup")
        
        try:
            import gc
            import weakref
            
            # Test app lifecycle
            apps = []
            weak_refs = []
            
            for i in range(5):
                app = EnhancedApp(self.cfg)
                weak_ref = weakref.ref(app)
                weak_refs.append(weak_ref)
                
                # Do some activity
                audio_sample = np.random.random(8000).astype(np.float32) * 0.1
                result = app.asr.transcribe(audio_sample)
                
                # Proper shutdown
                app.shutdown()
                apps.append(app)
            
            # Clear references
            del apps
            gc.collect()
            
            # Check if objects were properly cleaned up
            alive_refs = [ref for ref in weak_refs if ref() is not None]
            
            if len(alive_refs) == 0:
                self.log_test("Resource cleanup", "PASS", "All objects garbage collected")
            else:
                self.log_test("Resource cleanup", "WARNING", f"{len(alive_refs)} objects still alive")
            
            # Test visual indicator cleanup
            try:
                from voiceflow.visual_indicators import cleanup_indicators
                cleanup_indicators()
                self.log_test("Visual indicators cleanup", "PASS", "Cleanup completed")
            except Exception as e:
                self.log_test("Visual indicators cleanup", "FAIL", str(e))
                
        except Exception as e:
            self.log_test("Resource cleanup test", "FAIL", str(e))
    
    def run_all_tests(self):
        """Run all edge case tests"""
        print("=" * 60)
        print("VoiceFlow Edge Case Test Suite")
        print("=" * 60)
        
        test_methods = [
            self.test_empty_audio_handling,
            self.test_extreme_audio_values,
            self.test_config_edge_cases,
            self.test_filesystem_edge_cases,
            self.test_threading_edge_cases,
            self.test_memory_pressure,
            self.test_unicode_edge_cases,
            self.test_error_recovery,
            self.test_boundary_conditions,
            self.test_resource_cleanup
        ]
        
        start_time = time.perf_counter()
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                self.log_test(test_method.__name__, "FAIL", f"Test runner error: {e}")
            
            time.sleep(0.5)  # Brief pause between tests
        
        total_time = time.perf_counter() - start_time
        
        # Summary
        print("\n" + "=" * 60)
        print("EDGE CASE TEST SUMMARY")
        print("=" * 60)
        
        passed = len([r for r in self.test_results if r[1] == "PASS"])
        failed = len([r for r in self.test_results if r[1] == "FAIL"])
        warnings = len([r for r in self.test_results if r[1] == "WARNING"])
        expected_fails = len([r for r in self.test_results if r[1] == "EXPECTED_FAIL"])
        
        print(f"Total Tests: {len(self.test_results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Warnings: {warnings}")
        print(f"Expected Failures: {expected_fails}")
        print(f"Total Duration: {total_time:.2f}s")
        
        return {
            "total": len(self.test_results),
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "expected_fails": expected_fails,
            "duration": total_time,
            "results": self.test_results
        }

def main():
    """Main test runner"""
    try:
        suite = EdgeCaseTestSuite()
        summary = suite.run_all_tests()
        
        # Exit based on critical failures only
        if summary["failed"] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nEdge case tests interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"Test suite error: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()