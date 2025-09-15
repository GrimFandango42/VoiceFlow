#!/usr/bin/env python3
"""
Diagnose audio validation issues
"""

import sys
import numpy as np
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from voiceflow.core.config import Config
from voiceflow.core.audio_enhanced import audio_validation_guard
from voiceflow.utils.validation import validate_audio_data, ValidationError

def test_audio_generation():
    """Test audio generation and validation"""
    print("=== AUDIO GENERATION TEST ===")

    # Generate the same test audio as the validator
    sample_rate = 16000
    duration = 2.0
    length = int(duration * sample_rate)
    t = np.linspace(0, duration, length)

    # Create speech-like signal
    frequency_base = 150  # Human speech frequency range
    signal = (
        0.4 * np.sin(2 * np.pi * frequency_base * t) +
        0.3 * np.sin(2 * np.pi * frequency_base * 1.5 * t) +
        0.2 * np.sin(2 * np.pi * frequency_base * 2.2 * t) +
        0.1 * np.random.normal(0, 0.05, length)  # Light background noise
    )

    # Apply amplitude modulation for speech-like patterns
    modulation = 0.6 + 0.4 * np.sin(2 * np.pi * 1.5 * t)
    signal *= modulation

    # Ensure proper float32 format
    signal = signal.astype(np.float32)

    # Normalize to prevent clipping
    max_amplitude = np.max(np.abs(signal))
    if max_amplitude > 0:
        signal = signal * 0.8 / max_amplitude

    print(f"Generated audio:")
    print(f"  Length: {len(signal)} samples ({len(signal)/16000:.2f}s)")
    print(f"  Shape: {signal.shape}")
    print(f"  Dtype: {signal.dtype}")
    print(f"  Max amplitude: {np.max(np.abs(signal)):.6f}")
    print(f"  Min amplitude: {np.min(signal):.6f}")
    print(f"  Has NaN: {np.any(np.isnan(signal))}")
    print(f"  Has Inf: {np.any(np.isinf(signal))}")

    return signal

def test_validation_methods(audio):
    """Test different validation methods"""
    print("\n=== VALIDATION METHOD TEST ===")

    # Test basic validation
    try:
        validated_audio = validate_audio_data(audio, "test_audio")
        print("✓ Basic validation passed")
    except ValidationError as e:
        print(f"✗ Basic validation failed: {e}")
        return False

    # Test audio validation guard with config
    cfg = Config()

    # Test with fast validation disabled
    cfg.enable_fast_audio_validation = False
    try:
        validated_audio = audio_validation_guard(audio, "test_with_full_validation", False, cfg)
        print("✓ Full validation guard passed")
    except Exception as e:
        print(f"✗ Full validation guard failed: {e}")
        return False

    # Test with fast validation enabled
    cfg.enable_fast_audio_validation = True
    try:
        validated_audio = audio_validation_guard(audio, "test_with_fast_validation", False, cfg)
        print("✓ Fast validation guard passed")
    except Exception as e:
        print(f"✗ Fast validation guard failed: {e}")
        return False

    return True

def test_asr_directly(audio):
    """Test ASR processing directly"""
    print("\n=== ASR DIRECT TEST ===")

    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR

        cfg = Config()
        asr = BufferSafeWhisperASR(cfg)

        print("ASR instance created successfully")

        # Try transcription
        result = asr.transcribe(audio)
        print(f"Transcription result: '{result}'")
        print(f"Result length: {len(result)}")

        return result

    except Exception as e:
        print(f"ASR test failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    print("VoiceFlow Audio Diagnostic Tool")
    print("=" * 40)

    # Generate test audio
    audio = test_audio_generation()

    # Test validation methods
    validation_passed = test_validation_methods(audio)

    if validation_passed:
        # Test ASR directly
        result = test_asr_directly(audio)

        if result is not None:
            print(f"\n=== DIAGNOSIS COMPLETE ===")
            print(f"Audio generation: OK")
            print(f"Validation: OK")
            print(f"ASR transcription: {'OK' if len(result) > 0 else 'EMPTY'}")
            print(f"Result: '{result}'")
        else:
            print(f"\n=== DIAGNOSIS: ASR FAILED ===")
    else:
        print(f"\n=== DIAGNOSIS: VALIDATION FAILED ===")

if __name__ == "__main__":
    main()