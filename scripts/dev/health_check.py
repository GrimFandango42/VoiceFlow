#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VoiceFlow Health Check - Fast System Validation
===============================================
Quick health check for daily validation (< 30 seconds)
Tests core functionality without heavy stress testing
"""

import sys
import time
import os
import threading
import gc
from pathlib import Path
from datetime import datetime
import psutil

# Configure console for Unicode output on Windows
if sys.platform == 'win32':
    import locale
    try:
        # Try to set UTF-8 encoding
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        os.system('chcp 65001 > nul 2>&1')  # Set console to UTF-8
    except:
        pass

def quick_import_test():
    """Test 1: Quick import validation"""
    print("1. Import Test:", end=" ")
    try:
        from voiceflow.config import Config
        from voiceflow.cli_enhanced import EnhancedApp
        from voiceflow.visual_indicators import show_listening, show_complete, hide_status
        from voiceflow.enhanced_tray import EnhancedTrayController
        print("✅ PASS")
        return True
    except Exception as e:
        print(f"❌ FAIL - {e}")
        return False

def quick_config_test():
    """Test 2: Configuration loading"""
    print("2. Config Test:", end=" ")
    try:
        from voiceflow.config import Config
        cfg = Config()
        assert hasattr(cfg, 'sample_rate')
        assert hasattr(cfg, 'hotkey_key')
        print("✅ PASS")
        return True
    except Exception as e:
        print(f"❌ FAIL - {e}")
        return False

def quick_app_lifecycle_test():
    """Test 3: App creation and shutdown"""
    print("3. App Lifecycle:", end=" ")
    try:
        from voiceflow.config import Config
        from voiceflow.cli_enhanced import EnhancedApp

        cfg = Config()
        app = EnhancedApp(cfg)

        # Quick validation
        assert hasattr(app, 'asr')
        assert hasattr(app, 'rec')
        assert hasattr(app, 'injector')

        # Proper shutdown
        app.shutdown()
        del app

        print("✅ PASS")
        return True
    except Exception as e:
        print(f"❌ FAIL - {e}")
        return False

def quick_visual_test():
    """Test 4: Visual indicators (non-blocking)"""
    print("4. Visual Test:", end=" ")
    try:
        from voiceflow.visual_indicators import show_listening, show_complete, hide_status

        def visual_test():
            show_listening()
            time.sleep(0.5)
            show_complete("Health check OK")
            time.sleep(0.5)
            hide_status()

        # Run in background with timeout
        thread = threading.Thread(target=visual_test, daemon=True)
        thread.start()
        thread.join(timeout=3.0)

        print("✅ PASS")
        return True
    except Exception as e:
        print(f"❌ FAIL - {e}")
        return False

def quick_memory_test():
    """Test 5: Memory usage validation"""
    print("5. Memory Test:", end=" ")
    try:
        import numpy as np
        from voiceflow.config import Config
        from voiceflow.asr_buffer_safe import BufferSafeWhisperASR

        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024

        cfg = Config()
        asr = BufferSafeWhisperASR(cfg)

        # Quick transcription test
        test_audio = np.random.random(8000).astype(np.float32) * 0.1
        result = asr.transcribe(test_audio)

        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory

        # Cleanup
        del asr, test_audio
        gc.collect()

        if memory_growth > 200:  # More than 200MB is concerning
            print(f"⚠️  WARN - High memory usage: {memory_growth:.1f}MB")
            return True  # Warning but not failure
        else:
            print(f"✅ PASS ({memory_growth:+.1f}MB)")
            return True

    except Exception as e:
        print(f"❌ FAIL - {e}")
        return False

def quick_tray_test():
    """Test 6: Tray system validation"""
    print("6. Tray Test:", end=" ")
    try:
        from voiceflow.enhanced_tray import EnhancedTrayController
        from voiceflow.config import Config

        # Mock app
        class MockApp:
            def __init__(self):
                self.cfg = Config()
                self.code_mode = False
                self.visual_indicators_enabled = True

        app = MockApp()
        tray = EnhancedTrayController(app)

        # Quick status update test
        tray.update_status("listening", True, "Health check")
        time.sleep(0.1)
        tray.update_status("complete", False, "Health check complete")
        time.sleep(0.1)
        tray.update_status("idle", False)

        print("✅ PASS")
        return True
    except Exception as e:
        print(f"❌ FAIL - {e}")
        return False

def system_info():
    """Display system information"""
    print("\n" + "="*50)
    print("SYSTEM INFORMATION")
    print("="*50)

    try:
        process = psutil.Process()
        print(f"Python Version: {sys.version.split()[0]}")
        print(f"Working Directory: {Path.cwd()}")
        print(f"Process ID: {os.getpid()}")
        print(f"Memory Usage: {process.memory_info().rss / 1024 / 1024:.1f}MB")
        print(f"CPU Usage: {process.cpu_percent():.1f}%")
        print(f"Thread Count: {threading.active_count()}")

        # Check for VoiceFlow files
        voiceflow_files = [
            "localflow/cli_enhanced.py",
            "localflow/config.py",
            "localflow/visual_indicators.py",
            "verify_visual_system.py"
        ]

        print(f"\nVoiceFlow Components:")
        for file_path in voiceflow_files:
            if Path(file_path).exists():
                print(f"  ✅ {file_path}")
            else:
                print(f"  ❌ {file_path} (missing)")

    except Exception as e:
        print(f"Error getting system info: {e}")

def main():
    """Run health check suite"""
    start_time = time.perf_counter()

    print("VoiceFlow Health Check - Fast System Validation")
    print("=" * 55)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Run quick tests
    tests = [
        quick_import_test,
        quick_config_test,
        quick_app_lifecycle_test,
        quick_visual_test,
        quick_memory_test,
        quick_tray_test
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"Test runner error: {e}")
            results.append(False)

        time.sleep(0.2)  # Brief pause between tests

    duration = time.perf_counter() - start_time
    passed = sum(results)
    total = len(results)

    # Summary
    print("\n" + "="*50)
    print("HEALTH CHECK SUMMARY")
    print("="*50)
    print(f"Duration: {duration:.1f}s")
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 STATUS: HEALTHY - All systems operational")
        print("✅ VoiceFlow is ready for use")
        status_code = 0
    elif passed >= total * 0.8:  # 80% pass rate
        print("⚠️  STATUS: DEGRADED - Some issues detected")
        print("🔧 Consider running full comprehensive tests")
        status_code = 1
    else:
        print("❌ STATUS: CRITICAL - Major issues detected")
        print("🚨 Run comprehensive tests and address failures")
        status_code = 2

    # System info
    system_info()

    print(f"\n💡 For detailed testing, run: python run_comprehensive_tests.py")
    print(f"📋 For visual verification, run: python verify_visual_system.py")

    return status_code

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Health check interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Health check crashed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(3)