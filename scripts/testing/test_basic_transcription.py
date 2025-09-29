"""
Basic Transcription Test

Test the core transcription functionality step by step
"""

import sys
import os
import time
import numpy as np

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_config():
    """Test config loading"""
    print("Testing config loading...")
    try:
        from voiceflow.core.config import Config
        cfg = Config()
        print(f"[OK] Config loaded: model={cfg.model_name}, device={cfg.device}")
        return cfg
    except Exception as e:
        print(f"[FAIL] Config failed: {e}")
        return None

def test_modern_asr(cfg):
    """Test modern ASR implementation"""
    print("\nTesting Modern ASR...")
    try:
        from voiceflow.core.asr_modern import ModernWhisperASR

        asr = ModernWhisperASR(cfg)
        print("[OK] Modern ASR created")

        # Test model loading
        start_time = time.time()
        asr.load()
        load_time = time.time() - start_time
        print(f"[OK] Model loaded in {load_time:.2f}s")

        # Test transcription with dummy audio
        test_audio = np.random.randn(16000).astype(np.float32) * 0.01  # 1 second of quiet noise

        start_time = time.time()
        result = asr.transcribe(test_audio)
        transcribe_time = time.time() - start_time

        print(f"[OK] Transcription completed in {transcribe_time:.2f}s")
        print(f"  Result: '{result}'" + (" (empty - expected for noise)" if not result else ""))

        # Get stats
        stats = asr.get_stats()
        print(f"[OK] Stats: {stats}")

        return asr

    except Exception as e:
        print(f"[FAIL] Modern ASR failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_old_asr(cfg):
    """Test old ASR implementation"""
    print("\nTesting Old ASR...")
    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR

        asr = BufferSafeWhisperASR(cfg)
        print("[OK] Old ASR created")

        # Test transcription with dummy audio
        test_audio = np.random.randn(16000).astype(np.float32) * 0.01  # 1 second of quiet noise

        start_time = time.time()
        result = asr.transcribe(test_audio)
        transcribe_time = time.time() - start_time

        print(f"[OK] Transcription completed in {transcribe_time:.2f}s")
        print(f"  Result: '{result}'" + (" (empty - expected for noise)" if not result else ""))

        return asr

    except Exception as e:
        print(f"[FAIL] Old ASR failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_multiple_transcriptions(asr, name):
    """Test multiple transcriptions to check for issues"""
    print(f"\nTesting multiple transcriptions with {name}...")

    try:
        for i in range(5):
            print(f"  Test {i+1}/5...")

            # Create slightly different audio each time
            test_audio = np.random.randn(32000).astype(np.float32) * 0.01  # 2 seconds

            start_time = time.time()
            result = asr.transcribe(test_audio)
            transcribe_time = time.time() - start_time

            print(f"    [OK] {transcribe_time:.2f}s - '{result}'" + (" (empty)" if not result else ""))

        print(f"[OK] All {name} transcriptions completed")

    except Exception as e:
        print(f"[FAIL] {name} multiple transcriptions failed: {e}")
        import traceback
        traceback.print_exc()

def main():
    print("VoiceFlow Basic Transcription Test")
    print("=" * 50)

    # Test config
    cfg = test_config()
    if not cfg:
        print("Cannot continue without config")
        return

    # Test modern ASR
    modern_asr = test_modern_asr(cfg)
    if modern_asr:
        test_multiple_transcriptions(modern_asr, "Modern ASR")

    # Test old ASR for comparison
    old_asr = test_old_asr(cfg)
    if old_asr:
        test_multiple_transcriptions(old_asr, "Old ASR")

    print("\n" + "=" * 50)
    print("Test completed!")

    if modern_asr and old_asr:
        print("[OK] Both ASR implementations working")
    elif modern_asr:
        print("[OK] Modern ASR working, Old ASR has issues")
    elif old_asr:
        print("[WARN] Old ASR working, Modern ASR has issues")
    else:
        print("[FAIL] Both ASR implementations failed")

if __name__ == "__main__":
    main()