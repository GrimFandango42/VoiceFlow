#!/usr/bin/env python3
"""
Quick Guardrails Validation Script
=================================
Validates that critical guardrails are working before user testing
"""

import sys
import os
import numpy as np
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_audio_validation():
    """Test audio validation guardrails"""
    print("🎵 Testing Audio Validation Guardrails...")

    try:
        from voiceflow.utils.guardrails import validate_and_sanitize_audio

        # Test 1: Empty audio
        empty = np.array([], dtype=np.float32)
        result = validate_and_sanitize_audio(empty)
        assert len(result) > 0, "Empty audio should return silence"
        print("   ✅ Empty audio handling: PASS")

        # Test 2: NaN values
        nan_audio = np.array([1.0, np.nan, 3.0], dtype=np.float32)
        result = validate_and_sanitize_audio(nan_audio)
        assert not np.any(np.isnan(result)), "NaN values should be removed"
        print("   ✅ NaN sanitization: PASS")

        # Test 3: Infinite values
        inf_audio = np.array([1.0, np.inf, -np.inf], dtype=np.float32)
        result = validate_and_sanitize_audio(inf_audio)
        assert not np.any(np.isinf(result)), "Infinite values should be removed"
        print("   ✅ Infinite value sanitization: PASS")

        # Test 4: Extreme amplitudes
        extreme = np.array([1000.0, -1000.0], dtype=np.float32)
        result = validate_and_sanitize_audio(extreme)
        assert np.all(np.abs(result) <= 32.0), "Extreme values should be clipped"
        print("   ✅ Amplitude clipping: PASS")

        return True

    except Exception as e:
        print(f"   ❌ Audio validation failed: {e}")
        return False

def test_config_validation():
    """Test configuration validation guardrails"""
    print("⚙️ Testing Configuration Validation Guardrails...")

    try:
        from voiceflow.core.config import Config
        from voiceflow.utils.guardrails import validate_config

        # Test 1: Invalid sample rate
        cfg = Config()
        cfg.sample_rate = 99999
        validated = validate_config(cfg)
        valid_rates = [8000, 11025, 16000, 22050, 44100, 48000]
        assert validated.sample_rate in valid_rates, "Invalid sample rate should be corrected"
        print("   ✅ Sample rate validation: PASS")

        # Test 2: Invalid model
        cfg.model_name = "nonexistent_model"
        validated = validate_config(cfg)
        valid_models = ['tiny', 'tiny.en', 'base', 'base.en', 'small', 'small.en']
        assert any(model in validated.model_name for model in valid_models), "Invalid model should be corrected"
        print("   ✅ Model validation: PASS")

        # Test 3: Missing hotkeys
        cfg.hotkey_ctrl = False
        cfg.hotkey_shift = False
        cfg.hotkey_alt = False
        cfg.hotkey_key = ""
        validated = validate_config(cfg)
        has_hotkey = validated.hotkey_ctrl or validated.hotkey_shift or validated.hotkey_alt or validated.hotkey_key
        assert has_hotkey, "Missing hotkeys should be corrected"
        print("   ✅ Hotkey validation: PASS")

        return True

    except Exception as e:
        print(f"   ❌ Config validation failed: {e}")
        return False

def test_error_recovery():
    """Test error recovery guardrails"""
    print("🛡️ Testing Error Recovery Guardrails...")

    try:
        from voiceflow.utils.guardrails import with_error_recovery

        # Test 1: Successful function
        @with_error_recovery(fallback_value="fallback")
        def success_func():
            return "success"

        result = success_func()
        assert result == "success", "Successful function should return normally"
        print("   ✅ Successful function handling: PASS")

        # Test 2: Failing function
        @with_error_recovery(fallback_value="fallback", max_retries=1)
        def fail_func():
            raise Exception("Test failure")

        result = fail_func()
        assert result == "fallback", "Failing function should return fallback"
        print("   ✅ Error recovery fallback: PASS")

        return True

    except Exception as e:
        print(f"   ❌ Error recovery failed: {e}")
        return False

def test_visual_safety():
    """Test visual system thread safety"""
    print("🎨 Testing Visual Thread Safety...")

    try:
        from voiceflow.utils.guardrails import safe_visual_update

        # Test safe visual update
        test_var = [0]

        def update_func():
            test_var[0] = 42
            return "updated"

        result = safe_visual_update(update_func)
        # Should execute on main thread and return result
        assert test_var[0] == 42, "Visual update should execute"
        print("   ✅ Safe visual update: PASS")

        # Test error handling
        def failing_update():
            raise Exception("Visual update failed")

        result = safe_visual_update(failing_update)
        # Should return None on failure, not crash
        assert result is None, "Failed visual update should return None"
        print("   ✅ Visual error handling: PASS")

        return True

    except Exception as e:
        print(f"   ❌ Visual safety failed: {e}")
        return False

def main():
    """Run all validation tests"""
    print("🛡️ VoiceFlow Guardrails Validation")
    print("=" * 50)

    tests = [
        test_audio_validation,
        test_config_validation,
        test_error_recovery,
        test_visual_safety
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"   ❌ Test failed with exception: {e}")

    print("\n" + "=" * 50)
    print("VALIDATION SUMMARY")
    print("=" * 50)
    print(f"Tests passed: {passed}/{total}")
    print(f"Success rate: {(passed/total)*100:.1f}%")

    if passed == total:
        print("\n🎉 ALL GUARDRAILS VALIDATION PASSED!")
        print("✅ Audio input sanitization working")
        print("✅ Configuration validation working")
        print("✅ Error recovery mechanisms working")
        print("✅ Visual thread safety working")
        print("\n🚀 System ready for user testing!")
        return True
    else:
        print(f"\n❌ {total - passed} validation tests failed")
        print("⚠️  Some guardrails may need attention")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)