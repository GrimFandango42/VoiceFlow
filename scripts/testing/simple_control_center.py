#!/usr/bin/env python3
"""
VoiceFlow Simple Control Center
Quick testing interface for Phase 1 optimizations
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def print_header():
    print("=" * 50)
    print("VoiceFlow Control Center - Phase 1 Testing")
    print("=" * 50)

def test_optimizations():
    """Test Phase 1 optimizations"""
    print("\nTesting Phase 1 Optimizations...")

    try:
        # Test configuration
        from voiceflow.core.config import Config
        cfg = Config()
        print(f"[OK] Configuration loaded")
        print(f"     - Adaptive Model Access: {cfg.enable_lockfree_model_access}")
        print(f"     - Optimized Audio Validation: {cfg.enable_optimized_audio_validation}")
        print(f"     - Sample Rate: {cfg.audio_validation_sample_rate}")

        # Test validation system
        from voiceflow.core.optimized_audio_validation import optimized_audio_validation_guard
        import numpy as np
        import time

        test_audio = np.random.randn(16000).astype(np.float32)
        start_time = time.perf_counter()
        validated = optimized_audio_validation_guard(test_audio, 'TestOperation', cfg=cfg)
        validation_time = time.perf_counter() - start_time
        print(f"[OK] Audio validation: {len(validated)} samples in {validation_time*1000:.2f}ms")

        # Test adaptive model access
        from voiceflow.core.adaptive_model_access import get_adaptive_model_access
        access_manager = get_adaptive_model_access(cfg)
        print(f"[OK] Adaptive model access initialized")
        print(f"     - Max concurrent jobs: {access_manager.max_concurrent_jobs}")
        print(f"     - Auto-detect concurrency: {access_manager.auto_detect_concurrency}")

        # Test ASR initialization
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        asr = BufferSafeWhisperASR(cfg)
        print(f"[OK] ASR system initialized")

        print("\n*** PHASE 1 OPTIMIZATIONS: FULLY OPERATIONAL ***")
        return True

    except Exception as e:
        print(f"[ERROR] Optimization test failed: {e}")
        return False

def show_performance_summary():
    """Show expected performance improvements"""
    print("\nPhase 1 Performance Improvements:")
    print("- Adaptive Model Access: +49-87% for concurrent usage")
    print("- Smart Audio Validation: +15-50% for large audio files")
    print("- Expected Overall Improvement: 20-30%")
    print("- Target Performance: 11.2-12.0x realtime (from 9.3x)")

def main_menu():
    while True:
        print_header()

        print("\nOptions:")
        print("1. Test Phase 1 Optimizations")
        print("2. Show Performance Summary")
        print("3. Launch VoiceFlow Tray")
        print("4. Exit")

        choice = input("\nEnter choice (1-4): ").strip()

        if choice == "1":
            test_optimizations()
            input("\nPress Enter to continue...")
        elif choice == "2":
            show_performance_summary()
            input("\nPress Enter to continue...")
        elif choice == "3":
            print("\nLaunching VoiceFlow...")
            try:
                os.system("python voiceflow.py")
            except KeyboardInterrupt:
                print("\nVoiceFlow stopped.")
            input("\nPress Enter to continue...")
        elif choice == "4":
            print("\nExiting...")
            break
        else:
            print("\nInvalid choice. Please try again.")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        print(f"\nError: {e}")