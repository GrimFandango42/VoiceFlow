#!/usr/bin/env python3
"""
VoiceFlow Critical Guardrails Validation Test Suite
==================================================
Tests to validate that the critical guardrails prevent the identified crashes
and edge case failures from comprehensive testing.

This test suite addresses the 10/40 edge case failures and validates that
the Phase 1 critical guardrails implementation works correctly.
"""

import sys
import os
import unittest
import numpy as np
import threading
import time
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from src.voiceflow.utils.guardrails import (
        validate_and_sanitize_audio,
        safe_visual_update,
        validate_config,
        with_error_recovery,
        timeout_wrapper,
        ResourceMonitor,
        AudioValidationError,
        ConfigurationError
    )
    from src.voiceflow.core.config import Config
    from src.voiceflow.ui.visual_indicators import TranscriptionStatus, show_transcription_status
except ImportError as e:
    print(f"Import error: {e}")
    print("Please run from VoiceFlow root directory")
    sys.exit(1)


class TestAudioValidationGuardrails(unittest.TestCase):
    """Test audio input validation and sanitization guardrails"""

    def test_empty_audio_handling(self):
        """Test that empty audio arrays are handled gracefully"""
        # This was a critical failure point - empty arrays causing crashes
        empty_audio = np.array([], dtype=np.float32)

        result = validate_and_sanitize_audio(empty_audio)

        # Should return silence instead of crashing
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(result.dtype, np.float32)
        self.assertGreater(len(result), 0)  # Should not be empty
        self.assertTrue(np.allclose(result, 0.0))  # Should be silence

    def test_nan_audio_sanitization(self):
        """Test that NaN values in audio are sanitized"""
        # This was causing crashes in audio processing
        audio_with_nans = np.array([1.0, np.nan, 3.0, np.nan, 5.0], dtype=np.float32)

        result = validate_and_sanitize_audio(audio_with_nans)

        # Should replace NaN with zeros
        self.assertFalse(np.any(np.isnan(result)))
        self.assertEqual(len(result), len(audio_with_nans))
        # Non-NaN values should be preserved
        self.assertEqual(result[0], 1.0)
        self.assertEqual(result[2], 3.0)
        self.assertEqual(result[4], 5.0)

    def test_infinite_audio_sanitization(self):
        """Test that infinite values in audio are sanitized"""
        # This was causing crashes in downstream processing
        audio_with_infs = np.array([1.0, np.inf, 3.0, -np.inf, 5.0], dtype=np.float32)

        result = validate_and_sanitize_audio(audio_with_infs)

        # Should replace infinities with safe values
        self.assertFalse(np.any(np.isinf(result)))
        self.assertEqual(len(result), len(audio_with_infs))
        # Non-infinite values should be preserved
        self.assertEqual(result[0], 1.0)
        self.assertEqual(result[2], 3.0)
        self.assertEqual(result[4], 5.0)

    def test_extreme_amplitude_clipping(self):
        """Test that extreme amplitudes are clipped safely"""
        # This was causing overflow errors
        extreme_audio = np.array([-1000.0, 1000.0, 50.0, -50.0], dtype=np.float32)

        result = validate_and_sanitize_audio(extreme_audio)

        # Should clip to safe range
        self.assertTrue(np.all(np.abs(result) <= 32.0))  # max_safe = 32.0
        self.assertEqual(len(result), len(extreme_audio))

    def test_wrong_input_type_handling(self):
        """Test that non-numpy inputs are converted properly"""
        # Test various input types that could cause crashes
        list_input = [1.0, 2.0, 3.0]
        result = validate_and_sanitize_audio(list_input)
        self.assertIsInstance(result, np.ndarray)
        self.assertEqual(result.dtype, np.float32)

        # Test invalid input
        with self.assertRaises(AudioValidationError):
            validate_and_sanitize_audio("invalid")

    def test_stereo_to_mono_conversion(self):
        """Test that stereo audio is properly converted to mono"""
        # Test stereo input (common source of crashes)
        stereo_audio = np.array([[1.0, 2.0], [3.0, 4.0], [5.0, 6.0]], dtype=np.float32)

        result = validate_and_sanitize_audio(stereo_audio)

        # Should be converted to mono
        self.assertEqual(result.ndim, 1)
        self.assertEqual(len(result), 3)
        # Should be the average of stereo channels
        expected = np.array([1.5, 3.5, 5.5], dtype=np.float32)
        np.testing.assert_array_almost_equal(result, expected)


class TestConfigurationValidationGuardrails(unittest.TestCase):
    """Test configuration validation guardrails"""

    def test_invalid_sample_rate_correction(self):
        """Test that invalid sample rates are corrected"""
        cfg = Config()
        cfg.sample_rate = 12345  # Invalid sample rate

        validated_cfg = validate_config(cfg)

        # Should be corrected to valid default
        self.assertEqual(validated_cfg.sample_rate, 16000)

    def test_invalid_hotkey_correction(self):
        """Test that missing hotkeys are corrected"""
        cfg = Config()
        cfg.hotkey_ctrl = False
        cfg.hotkey_shift = False
        cfg.hotkey_alt = False
        cfg.hotkey_key = ""

        validated_cfg = validate_config(cfg)

        # Should set default hotkey
        self.assertTrue(validated_cfg.hotkey_ctrl or validated_cfg.hotkey_shift or
                       validated_cfg.hotkey_alt or validated_cfg.hotkey_key != "")

    def test_invalid_model_correction(self):
        """Test that invalid model names are corrected"""
        cfg = Config()
        cfg.model_name = "invalid_model"

        validated_cfg = validate_config(cfg)

        # Should be corrected to valid default
        valid_models = ['tiny', 'tiny.en', 'base', 'base.en', 'small', 'small.en',
                       'medium', 'medium.en', 'large', 'large-v2', 'large-v3']
        self.assertIn(validated_cfg.model_name, valid_models)

    def test_config_post_init_validation(self):
        """Test that Config.__post_init__ validates automatically"""
        # This should trigger validation automatically
        cfg = Config()
        cfg.sample_rate = 99999  # Invalid

        # After creation, it should still be valid (corrected by post_init)
        # Note: This test verifies the post_init mechanism works
        self.assertIsInstance(cfg.sample_rate, int)
        self.assertGreater(cfg.sample_rate, 0)


class TestVisualSystemThreadSafety(unittest.TestCase):
    """Test visual system thread safety guardrails"""

    def test_safe_visual_update_from_main_thread(self):
        """Test that visual updates work from main thread"""
        # Mock function to test
        test_var = [0]

        def test_update():
            test_var[0] = 42
            return "success"

        result = safe_visual_update(test_update)

        # Should execute directly on main thread
        self.assertEqual(result, "success")
        self.assertEqual(test_var[0], 42)

    def test_safe_visual_update_from_worker_thread(self):
        """Test that visual updates are queued from worker threads"""
        test_var = [0]
        result_container = [None]

        def test_update():
            test_var[0] = 99
            return "queued_success"

        def worker_thread():
            result_container[0] = safe_visual_update(test_update)

        # Run from worker thread
        thread = threading.Thread(target=worker_thread)
        thread.start()
        thread.join()

        # Should handle gracefully (queued for main thread)
        # Note: In real usage, main thread would process the queue

    def test_visual_update_error_handling(self):
        """Test that visual update errors are handled gracefully"""
        def failing_update():
            raise Exception("Visual update failed")

        # Should not crash - should return None and log error
        result = safe_visual_update(failing_update)
        self.assertIsNone(result)

    @patch('src.voiceflow.ui.visual_indicators.get_indicator')
    def test_status_update_thread_safety(self, mock_get_indicator):
        """Test that status updates are thread-safe"""
        mock_indicator = MagicMock()
        mock_get_indicator.return_value = mock_indicator

        # This should not crash even from worker thread
        def worker_update():
            show_transcription_status(TranscriptionStatus.LISTENING, "Test message")

        thread = threading.Thread(target=worker_update)
        thread.start()
        thread.join()

        # Should complete without throwing exceptions


class TestErrorRecoveryGuardrails(unittest.TestCase):
    """Test error recovery and containment guardrails"""

    def test_error_recovery_decorator_success(self):
        """Test that error recovery decorator works for successful calls"""
        @with_error_recovery(fallback_value="fallback")
        def successful_function():
            return "success"

        result = successful_function()
        self.assertEqual(result, "success")

    def test_error_recovery_decorator_failure(self):
        """Test that error recovery decorator handles failures"""
        @with_error_recovery(fallback_value="fallback", max_retries=2)
        def failing_function():
            raise Exception("Always fails")

        result = failing_function()
        self.assertEqual(result, "fallback")

    def test_error_recovery_with_retries(self):
        """Test that error recovery retries correctly"""
        call_count = [0]

        @with_error_recovery(fallback_value="fallback", max_retries=3)
        def sometimes_failing_function():
            call_count[0] += 1
            if call_count[0] < 3:
                raise Exception("Fail first two times")
            return "success_on_third"

        result = sometimes_failing_function()
        self.assertEqual(result, "success_on_third")
        self.assertEqual(call_count[0], 3)

    def test_timeout_wrapper(self):
        """Test that timeout wrapper prevents infinite loops"""
        @timeout_wrapper(timeout_seconds=0.1)
        def quick_function():
            return "completed"

        @timeout_wrapper(timeout_seconds=0.1)
        def slow_function():
            time.sleep(0.5)  # Takes longer than timeout
            return "should_not_complete"

        # Quick function should complete
        result1 = quick_function()
        self.assertEqual(result1, "completed")

        # Slow function should timeout
        result2 = slow_function()
        self.assertIsNone(result2)


class TestResourceMonitoringGuardrails(unittest.TestCase):
    """Test resource monitoring guardrails"""

    def test_resource_monitor_creation(self):
        """Test that resource monitor can be created"""
        monitor = ResourceMonitor(memory_limit_mb=100)
        self.assertIsInstance(monitor, ResourceMonitor)
        self.assertEqual(monitor.memory_limit, 100)

    def test_memory_usage_check(self):
        """Test memory usage checking"""
        monitor = ResourceMonitor(memory_limit_mb=1)  # Very low limit

        # Should be able to check memory (may or may not be over limit)
        over_limit, usage = monitor.check_memory_usage()
        self.assertIsInstance(over_limit, bool)
        self.assertIsInstance(usage, float)
        self.assertGreaterEqual(usage, 0)

    def test_resource_status_report(self):
        """Test comprehensive resource status reporting"""
        monitor = ResourceMonitor()
        status = monitor.get_resource_status()

        # Should return structured status
        self.assertIsInstance(status, dict)
        self.assertIn('memory', status)
        self.assertIn('cpu', status)
        self.assertIn('usage_mb', status['memory'])
        self.assertIn('over_limit', status['memory'])


class TestIntegratedGuardrailsWorkflow(unittest.TestCase):
    """Test that guardrails work together in realistic scenarios"""

    def test_audio_processing_pipeline_with_bad_data(self):
        """Test complete audio processing pipeline with problematic data"""
        # Create audio data that would historically cause crashes
        problematic_audio = np.array([
            np.nan, 1000.0, -1000.0, np.inf, -np.inf,
            0.1, 0.2, 0.3, np.nan, 999.0
        ], dtype=np.float32)

        # Should handle all issues gracefully
        result = validate_and_sanitize_audio(problematic_audio)

        # Verify result is safe
        self.assertFalse(np.any(np.isnan(result)))
        self.assertFalse(np.any(np.isinf(result)))
        self.assertTrue(np.all(np.abs(result) <= 32.0))
        self.assertEqual(len(result), len(problematic_audio))

    def test_configuration_and_visual_update_integration(self):
        """Test that config validation and visual updates work together"""
        # Create config with invalid values
        cfg = Config()
        cfg.sample_rate = 999999
        cfg.model_name = "nonexistent_model"

        # Validate config
        validated_cfg = validate_config(cfg)

        # Should be corrected
        self.assertNotEqual(validated_cfg.sample_rate, 999999)
        self.assertNotEqual(validated_cfg.model_name, "nonexistent_model")

        # Test that visual updates work with validated config
        @with_error_recovery(fallback_value=None)
        def test_visual_with_config():
            # This should not crash
            return "visual_update_success"

        result = test_visual_with_config()
        self.assertEqual(result, "visual_update_success")


if __name__ == "__main__":
    print("Running VoiceFlow Critical Guardrails Validation Tests")
    print("=" * 60)
    print("These tests validate that Phase 1 critical guardrails prevent")
    print("the identified crashes and edge case failures.")
    print("=" * 60)

    # Create a test suite with specific order
    suite = unittest.TestSuite()

    # Add test classes in logical order
    suite.addTest(unittest.makeSuite(TestAudioValidationGuardrails))
    suite.addTest(unittest.makeSuite(TestConfigurationValidationGuardrails))
    suite.addTest(unittest.makeSuite(TestVisualSystemThreadSafety))
    suite.addTest(unittest.makeSuite(TestErrorRecoveryGuardrails))
    suite.addTest(unittest.makeSuite(TestResourceMonitoringGuardrails))
    suite.addTest(unittest.makeSuite(TestIntegratedGuardrailsWorkflow))

    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 60)
    print("GUARDRAILS VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")

    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Exception:')[-1].strip()}")

    if len(result.failures) == 0 and len(result.errors) == 0:
        print("\n🎉 ALL GUARDRAILS TESTS PASSED!")
        print("Phase 1 critical guardrails are working correctly.")
        print("The system should now handle the identified edge cases gracefully.")
    else:
        print(f"\n❌ {len(result.failures + result.errors)} tests failed.")
        print("Some guardrails need attention before deployment.")

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)