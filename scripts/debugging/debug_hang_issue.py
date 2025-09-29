#!/usr/bin/env python3
"""
Debug script to identify where VoiceFlow is hanging during transcription.
This will test each component step-by-step to isolate the issue.
"""

import sys
import time
import threading
import numpy as np
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

def test_imports():
    """Test if imports work without hanging"""
    print("[DEBUG] Testing imports...")

    try:
        from voiceflow.core.config import Config
        print("[OK] Config imported")

        from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
        print("[OK] Audio recorder imported")

        from voiceflow.core.asr_production import ProductionWhisperASR
        print("[OK] ASR production imported")

        return True
    except Exception as e:
        print(f"[ERROR] Import failed: {e}")
        return False

def test_config():
    """Test config creation"""
    print("[DEBUG] Testing config creation...")

    try:
        from voiceflow.core.config import Config
        cfg = Config()
        print(f"[OK] Config created: {cfg.model_name} on {cfg.device}")
        return cfg
    except Exception as e:
        print(f"[ERROR] Config creation failed: {e}")
        return None

def test_asr_creation(cfg):
    """Test ASR creation (without loading models)"""
    print("[DEBUG] Testing ASR creation...")

    try:
        from voiceflow.core.asr_production import ProductionWhisperASR
        asr = ProductionWhisperASR(cfg)
        print(f"[OK] ASR created (models not loaded yet)")
        return asr
    except Exception as e:
        print(f"[ERROR] ASR creation failed: {e}")
        return None

def test_asr_loading_with_timeout(asr):
    """Test ASR model loading with timeout to catch hangs"""
    print("[DEBUG] Testing ASR model loading with 30s timeout...")

    result = {"completed": False, "error": None}

    def load_models():
        try:
            asr.load()
            result["completed"] = True
            print("[OK] ASR models loaded successfully")
        except Exception as e:
            result["error"] = e
            print(f"[ERROR] ASR loading failed: {e}")

    # Start loading in thread with timeout
    thread = threading.Thread(target=load_models)
    thread.daemon = True
    thread.start()

    # Wait with timeout
    thread.join(timeout=30)

    if thread.is_alive():
        print("[ERROR] ASR loading HUNG - this is likely the issue!")
        return False
    elif result["completed"]:
        return True
    else:
        print(f"[ERROR] ASR loading failed: {result['error']}")
        return False

def test_audio_recorder(cfg):
    """Test audio recorder creation"""
    print("[DEBUG] Testing audio recorder...")

    try:
        from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
        rec = EnhancedAudioRecorder(cfg)
        print("[OK] Audio recorder created")

        # Test that we can access microphone
        import sounddevice as sd
        devices = sd.query_devices()
        print(f"[OK] Found {len([d for d in devices if d['max_input_channels'] > 0])} input devices")

        return rec
    except Exception as e:
        print(f"[ERROR] Audio recorder creation failed: {e}")
        return None

def test_simple_transcription(asr):
    """Test simple transcription with dummy audio"""
    print("[DEBUG] Testing transcription with dummy audio...")

    try:
        # Create 1 second of dummy audio (silence)
        sample_rate = 16000
        dummy_audio = np.zeros(sample_rate, dtype=np.float32)

        print("Creating dummy audio...")
        result = asr.transcribe(dummy_audio)
        print(f"[OK] Transcription completed: {len(result.segments)} segments")
        return True
    except Exception as e:
        print(f"[ERROR] Transcription failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run diagnostic tests"""
    print("="*60)
    print("VoiceFlow Hang Diagnostic Tool")
    print("="*60)

    # Test 1: Imports
    if not test_imports():
        return

    # Test 2: Config
    cfg = test_config()
    if cfg is None:
        return

    # Test 3: ASR creation
    asr = test_asr_creation(cfg)
    if asr is None:
        return

    # Test 4: Audio recorder
    rec = test_audio_recorder(cfg)
    if rec is None:
        return

    # Test 5: ASR loading (most likely to hang)
    if not test_asr_loading_with_timeout(asr):
        print("\n" + "="*60)
        print("DIAGNOSIS: ASR model loading is hanging!")
        print("This is likely due to:")
        print("1. Network timeout downloading models")
        print("2. GPU/CUDA initialization issues")
        print("3. WhisperX or faster-whisper hanging")
        print("="*60)
        return

    # Test 6: Simple transcription
    if not test_simple_transcription(asr):
        print("\n" + "="*60)
        print("DIAGNOSIS: Transcription is hanging!")
        print("="*60)
        return

    print("\n" + "="*60)
    print("ALL TESTS PASSED - No obvious hang point found")
    print("The issue might be in the hotkey handling or UI components")
    print("="*60)

if __name__ == "__main__":
    main()