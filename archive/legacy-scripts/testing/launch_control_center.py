#!/usr/bin/env python3
"""
VoiceFlow Launch Control Center
Interactive health checks and testing interface
"""

import sys
import os
import time
import subprocess
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    print("=" * 70)
    print("VoiceFlow Launch Control Center")
    print("=" * 70)

def run_health_checks():
    """Run comprehensive health checks"""
    print("\n🔍 Running Health Checks...\n")

    checks = []

    # 1. Check Python environment
    try:
        import numpy as np
        import sounddevice as sd
        checks.append(("✅ Python Environment", "OK - Core dependencies available"))
    except ImportError as e:
        checks.append(("❌ Python Environment", f"Missing: {e}"))

    # 2. Check VoiceFlow imports
    try:
        from voiceflow.core.config import Config
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        config = Config()
        checks.append(("✅ VoiceFlow Core", f"OK - Model: {config.model_name}, Device: {config.device}"))
    except ImportError as e:
        checks.append(("❌ VoiceFlow Core", f"Import error: {e}"))

    # 3. Check DeepSeek optimizations
    try:
        from voiceflow.core.config import Config
        cfg = Config()
        optimizations = [
            f"Lock-free: {cfg.enable_lockfree_model_access}",
            f"Ultra-fast: {cfg.enable_ultra_fast_mode_bypass}",
            f"Memory pool: {cfg.enable_memory_pooling}",
            f"Chunked: {cfg.enable_chunked_long_audio}"
        ]
        checks.append(("✅ DeepSeek Optimizations", " | ".join(optimizations)))
    except Exception as e:
        checks.append(("❌ DeepSeek Optimizations", f"Error: {e}"))

    # 4. Check audio system
    try:
        import sounddevice as sd
        devices = sd.query_devices()
        input_devices = [d for d in devices if d['max_input_channels'] > 0]
        checks.append(("✅ Audio System", f"OK - {len(input_devices)} input devices found"))
    except Exception as e:
        checks.append(("❌ Audio System", f"Error: {e}"))

    # 5. Check model availability
    try:
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        from voiceflow.core.config import Config
        asr = BufferSafeWhisperASR(Config())
        checks.append(("✅ Whisper Model", "Ready for loading"))
    except Exception as e:
        checks.append(("❌ Whisper Model", f"Error: {e}"))

    # Print results
    for status, message in checks:
        print(f"{status:<25} {message}")

    # Overall status
    failed_checks = [c for c in checks if c[0].startswith("❌")]
    if failed_checks:
        print(f"\n⚠️  {len(failed_checks)} issues found - VoiceFlow may not work properly")
        return False
    else:
        print(f"\n🎉 All {len(checks)} health checks passed - VoiceFlow ready!")
        return True

def run_quick_tests():
    """Run quick functionality tests"""
    print("\n🧪 Running Quick Tests...\n")

    try:
        # Test 1: Config loading
        print("1. Testing configuration loading...")
        from voiceflow.core.config import Config
        cfg = Config()
        print(f"   ✅ Config loaded - Model: {cfg.model_name}")

        # Test 2: Audio validation
        print("2. Testing audio validation...")
        import numpy as np
        test_audio = np.random.normal(0, 0.1, 16000).astype(np.float32)  # 1 second of test audio
        from voiceflow.core.audio_enhanced import audio_validation_guard
        validated = audio_validation_guard(test_audio, "test", cfg=cfg)
        print(f"   ✅ Audio validation passed - {len(validated)} samples")

        # Test 3: ASR initialization (without full model load)
        print("3. Testing ASR initialization...")
        from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
        asr = BufferSafeWhisperASR(cfg)
        print("   ✅ ASR initialized successfully")

        # Test 4: Memory pooling
        if cfg.enable_memory_pooling:
            print("4. Testing memory pooling...")
            buffer = asr._get_pooled_buffer(1000)
            asr._return_buffer_to_pool(buffer)
            print("   ✅ Memory pooling working")

        print("\n🎉 All quick tests passed!")
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return False

def show_optimization_status():
    """Show current optimization settings"""
    print("\n⚙️  Current Optimization Settings:\n")

    try:
        from voiceflow.core.config import Config
        cfg = Config()

        optimizations = [
            ("🔓 Lock-free Model Access", cfg.enable_lockfree_model_access, "20-25% speed gain"),
            ("⚡ Ultra-fast Mode Bypass", cfg.enable_ultra_fast_mode_bypass, "10-15% speed gain"),
            ("🧠 Memory Pooling", cfg.enable_memory_pooling, "5-10% speed gain"),
            ("📦 Chunked Long Audio", cfg.enable_chunked_long_audio, "30-40% gain for >10s"),
            ("🚀 Model Preloading", cfg.preload_model_on_startup, "Instant first transcription"),
        ]

        for name, enabled, benefit in optimizations:
            status = "✅ ENABLED" if enabled else "❌ DISABLED"
            print(f"{name:<25} {status:<12} ({benefit})")

        print(f"\n📊 Model: {cfg.model_name} | Device: {cfg.device}")

    except Exception as e:
        print(f"❌ Error reading config: {e}")

def launch_voiceflow(mode="enhanced"):
    """Launch VoiceFlow in specified mode"""
    print(f"\n🚀 Launching VoiceFlow ({mode} mode)...\n")

    if mode == "lite":
        cmd = [sys.executable, "voiceflow.py", "--lite", "--no-tray"]
    elif mode == "tray":
        cmd = [sys.executable, "voiceflow.py", "--tray"]
    else:  # enhanced
        cmd = [sys.executable, "voiceflow.py", "--no-tray"]

    try:
        # Launch in background
        process = subprocess.Popen(cmd, cwd=os.getcwd())
        print(f"✅ VoiceFlow launched successfully (PID: {process.pid})")
        print("🎯 Ready for voice input testing!")
        return process
    except Exception as e:
        print(f"❌ Launch failed: {e}")
        return None

def main_menu():
    """Main interactive menu"""
    while True:
        clear_screen()
        print_header()
        show_optimization_status()

        print("\n📋 Available Actions:")
        print("1. 🔍 Run Health Checks")
        print("2. 🧪 Run Quick Tests")
        print("3. 🚀 Launch VoiceFlow Enhanced")
        print("4. 💡 Launch VoiceFlow Lite")
        print("5. 🖥️  Launch VoiceFlow Tray Mode")
        print("6. ⚙️  Show Current Settings")
        print("7. 🔄 Refresh Status")
        print("8. ❌ Exit")

        choice = input("\n👉 Select option (1-8): ").strip()

        if choice == "1":
            run_health_checks()
            input("\nPress Enter to continue...")

        elif choice == "2":
            run_quick_tests()
            input("\nPress Enter to continue...")

        elif choice == "3":
            process = launch_voiceflow("enhanced")
            if process:
                input("\nPress Enter to return to menu (VoiceFlow will continue running)...")

        elif choice == "4":
            process = launch_voiceflow("lite")
            if process:
                input("\nPress Enter to return to menu (VoiceFlow will continue running)...")

        elif choice == "5":
            process = launch_voiceflow("tray")
            if process:
                input("\nPress Enter to return to menu (VoiceFlow will continue running)...")

        elif choice == "6":
            show_optimization_status()
            input("\nPress Enter to continue...")

        elif choice == "7":
            continue  # Refresh by redrawing menu

        elif choice == "8":
            print("\n👋 Goodbye!")
            break

        else:
            print("\n❌ Invalid choice. Please select 1-8.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted - Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        input("Press Enter to exit...")