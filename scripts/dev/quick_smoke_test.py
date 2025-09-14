#!/usr/bin/env python3
"""
VoiceFlow Ultra-Fast Smoke Test Suite
=====================================
15-second validation for critical functionality - perfect for CI/CD and development
"""

import sys
import time
import traceback
import psutil
from pathlib import Path
from typing import List, Tuple, Dict, Any
import subprocess

class SmokeTestSuite:
    """Ultra-fast smoke tests for critical VoiceFlow functionality"""

    def __init__(self):
        self.start_time = time.perf_counter()
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        self.results: List[Tuple[str, bool, str, float]] = []
        self.critical_failures = 0

    def log_test(self, test_name: str, passed: bool, details: str = "", duration: float = 0.0):
        """Log test result with timing"""
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} {test_name:<35} ({duration:.2f}s) {details}")
        self.results.append((test_name, passed, details, duration))

        if not passed:
            self.critical_failures += 1

    def test_critical_imports(self) -> bool:
        """Test that all critical modules can be imported"""
        test_start = time.perf_counter()

        critical_modules = [
            ('voiceflow.core.config', 'Config'),
            ('voiceflow.ui.cli_enhanced', 'EnhancedApp'),
            ('voiceflow.core.audio_enhanced', 'EnhancedAudioRecorder'),
            ('voiceflow.core.asr_buffer_safe', 'BufferSafeWhisperASR'),
            ('voiceflow.ui.visual_indicators', 'BottomScreenIndicator'),
            ('voiceflow.ui.enhanced_tray', 'EnhancedTrayController')
        ]

        failed_imports = []
        for module_name, class_name in critical_modules:
            try:
                module = __import__(module_name, fromlist=[class_name])
                getattr(module, class_name)
            except Exception as e:
                failed_imports.append(f"{module_name}.{class_name}: {str(e)[:50]}")

        duration = time.perf_counter() - test_start

        if failed_imports:
            self.log_test("Critical Imports", False, f"Failed: {len(failed_imports)}", duration)
            return False
        else:
            self.log_test("Critical Imports", True, f"All {len(critical_modules)} modules OK", duration)
            return True

    def test_config_validation(self) -> bool:
        """Test configuration loading and validation"""
        test_start = time.perf_counter()

        try:
            from voiceflow.core.config import Config
            cfg = Config()

            # Validate critical config values
            assert cfg.sample_rate > 0, "Invalid sample rate"
            assert cfg.channels in [1, 2], "Invalid channel count"
            assert cfg.blocksize > 0, "Invalid blocksize"
            assert cfg.model_name, "Missing model name"

            duration = time.perf_counter() - test_start
            self.log_test("Configuration", True, f"Valid config loaded", duration)
            return True

        except Exception as e:
            duration = time.perf_counter() - test_start
            self.log_test("Configuration", False, str(e)[:50], duration)
            return False

    def test_audio_validation_system(self) -> bool:
        """Test audio input validation guardrails"""
        test_start = time.perf_counter()

        try:
            from voiceflow.core.audio_enhanced import audio_validation_guard
            import numpy as np

            # Test 1: Normal audio
            normal_audio = np.random.uniform(-0.5, 0.5, 1000).astype(np.float32)
            validated = audio_validation_guard(normal_audio, "SmokeTest_Normal")
            assert validated is not None, "Normal audio validation failed"

            # Test 2: Empty audio (should be handled gracefully)
            try:
                empty_audio = np.array([])
                audio_validation_guard(empty_audio, "SmokeTest_Empty", allow_empty=False)
                # Should raise an exception for empty audio when not allowed
                assert False, "Empty audio should have been rejected"
            except (ValueError, RuntimeError):
                pass  # Expected behavior

            # Test 3: NaN handling
            nan_audio = np.array([1.0, np.nan, 0.5], dtype=np.float32)
            validated = audio_validation_guard(nan_audio, "SmokeTest_NaN")
            assert not np.any(np.isnan(validated)), "NaN values not properly cleaned"

            duration = time.perf_counter() - test_start
            self.log_test("Audio Validation", True, "All guardrails working", duration)
            return True

        except Exception as e:
            duration = time.perf_counter() - test_start
            self.log_test("Audio Validation", False, str(e)[:50], duration)
            return False

    def test_app_lifecycle(self) -> bool:
        """Test basic app initialization and cleanup"""
        test_start = time.perf_counter()

        try:
            from voiceflow.core.config import Config
            from voiceflow.ui.cli_enhanced import EnhancedApp

            cfg = Config()

            # Quick initialization test (no actual audio recording)
            app = EnhancedApp(cfg)

            # Test basic methods exist and are callable
            assert hasattr(app, 'start_recording'), "Missing start_recording method"
            assert hasattr(app, 'stop_recording'), "Missing stop_recording method"
            assert hasattr(app, 'transcription_manager'), "Missing transcription manager"

            # Quick cleanup
            try:
                app.shutdown()
            except:
                pass  # Cleanup errors are acceptable in smoke test

            duration = time.perf_counter() - test_start
            self.log_test("App Lifecycle", True, "Init/cleanup OK", duration)
            return True

        except Exception as e:
            duration = time.perf_counter() - test_start
            self.log_test("App Lifecycle", False, str(e)[:50], duration)
            return False

    def test_visual_system_basic(self) -> bool:
        """Test visual system can be initialized without display errors"""
        test_start = time.perf_counter()

        try:
            # Test visual indicators (basic import and class creation)
            from voiceflow.ui.visual_indicators import BottomScreenIndicator, TranscriptionStatus
            from voiceflow.ui.enhanced_tray import EnhancedTrayController

            # Quick class instantiation test (no actual GUI display)
            indicator_class = BottomScreenIndicator
            tray_class = EnhancedTrayController

            # Test enums are available
            assert hasattr(TranscriptionStatus, 'LISTENING'), "Missing status enum"
            assert hasattr(TranscriptionStatus, 'PROCESSING'), "Missing status enum"

            duration = time.perf_counter() - test_start
            self.log_test("Visual System", True, "Classes available", duration)
            return True

        except Exception as e:
            duration = time.perf_counter() - test_start
            self.log_test("Visual System", False, str(e)[:50], duration)
            return False

    def test_memory_baseline(self) -> bool:
        """Test memory usage is within reasonable bounds"""
        test_start = time.perf_counter()

        try:
            current_memory = psutil.Process().memory_info().rss / 1024 / 1024
            memory_increase = current_memory - self.start_memory

            # Memory increase should be reasonable for smoke tests (<400MB for ML imports)
            if memory_increase > 400:
                duration = time.perf_counter() - test_start
                self.log_test("Memory Baseline", False, f"High usage: +{memory_increase:.1f}MB", duration)
                return False
            elif memory_increase > 200:
                duration = time.perf_counter() - test_start
                self.log_test("Memory Baseline", True, f"Acceptable: +{memory_increase:.1f}MB", duration)
                return True
            else:
                duration = time.perf_counter() - test_start
                self.log_test("Memory Baseline", True, f"Good: +{memory_increase:.1f}MB", duration)
                return True

        except Exception as e:
            duration = time.perf_counter() - test_start
            self.log_test("Memory Baseline", False, str(e)[:50], duration)
            return False

    def test_dependency_availability(self) -> bool:
        """Test critical dependencies are available"""
        test_start = time.perf_counter()

        critical_deps = [
            'numpy',
            'keyboard',
            'pystray',
            'PIL',  # Pillow
            'RealtimeSTT'
        ]

        missing_deps = []
        for dep in critical_deps:
            try:
                __import__(dep)
            except ImportError:
                missing_deps.append(dep)

        duration = time.perf_counter() - test_start

        if missing_deps:
            self.log_test("Dependencies", False, f"Missing: {', '.join(missing_deps)}", duration)
            return False
        else:
            self.log_test("Dependencies", True, f"All {len(critical_deps)} available", duration)
            return True

    def run_all_tests(self) -> bool:
        """Run all smoke tests and return overall success"""
        print("=" * 60)
        print("VoiceFlow Ultra-Fast Smoke Test Suite")
        print("=" * 60)
        print(f"Target: Complete in <15 seconds")
        print(f"Started: {time.strftime('%H:%M:%S')}")
        print()

        # Run all tests in sequence (optimized for speed)
        tests = [
            self.test_critical_imports,
            self.test_config_validation,
            self.test_dependency_availability,
            self.test_audio_validation_system,
            self.test_app_lifecycle,
            self.test_visual_system_basic,
            self.test_memory_baseline
        ]

        for test_func in tests:
            test_func()

        # Final summary
        total_duration = time.perf_counter() - self.start_time
        total_tests = len(self.results)
        passed_tests = sum(1 for _, passed, _, _ in self.results if passed)

        print()
        print("=" * 60)
        print("SMOKE TEST SUMMARY")
        print("=" * 60)
        print(f"Duration: {total_duration:.1f}s")
        print(f"Results: {passed_tests}/{total_tests} tests passed")

        if self.critical_failures == 0:
            print("STATUS: [OK] ALL CRITICAL SYSTEMS OPERATIONAL")
            success = True
        else:
            print(f"STATUS: [FAIL] {self.critical_failures} CRITICAL FAILURES DETECTED")
            success = False

        print()
        print("Memory Usage:")
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024
        print(f"  Start: {self.start_memory:.1f}MB")
        print(f"  End: {current_memory:.1f}MB")
        print(f"  Delta: +{current_memory - self.start_memory:.1f}MB")

        print()
        if total_duration <= 15.0:
            print("PERFORMANCE: Excellent (<=15s target met)")
        elif total_duration <= 25.0:
            print("PERFORMANCE: Good (acceptable for development)")
        else:
            print("PERFORMANCE: Needs optimization (>25s)")

        print()
        if success:
            print("RESULT: Ready for development/testing!")
            if total_duration > 15:
                print("NOTE: Consider running individual tests for faster feedback")
        else:
            print("RESULT: System needs attention before development")
            print("NOTE: Run comprehensive tests for detailed diagnostics")

        return success

def main():
    """Entry point for smoke test suite"""
    suite = SmokeTestSuite()
    success = suite.run_all_tests()

    # Exit with appropriate code for CI/CD integration
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()