#!/usr/bin/env python3
"""
Test the hotkey system to see if that's where the hang occurs.
This will simulate the exact same flow as the main app.
"""

import sys
import time
import threading
import numpy as np
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

class MockApp:
    """Mock app to test hotkey integration without full CLI"""

    def __init__(self):
        self.recording_count = 0
        self.last_action = "idle"

    def start_recording(self):
        print(f"[MOCK] start_recording() called")
        self.last_action = "recording_started"
        self.recording_count += 1

    def stop_recording(self):
        print(f"[MOCK] stop_recording() called")
        self.last_action = "recording_stopped"

def test_hotkey_detection():
    """Test if hotkey detection works without hanging"""
    print("[DEBUG] Testing hotkey detection...")

    try:
        from voiceflow.core.config import Config
        from voiceflow.integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener

        cfg = Config()
        mock_app = MockApp()

        print(f"[DEBUG] Hotkey config: Ctrl={cfg.hotkey_ctrl}, Shift={cfg.hotkey_shift}, Alt={cfg.hotkey_alt}, Key='{cfg.hotkey_key}'")

        # Create hotkey listener
        listener = EnhancedPTTHotkeyListener(
            cfg,
            mock_app.start_recording,
            mock_app.stop_recording
        )

        print("[OK] Hotkey listener created")

        # Test start/stop without actually running the listener
        listener.start()
        print("[OK] Hotkey listener started")

        # Wait a short time then stop
        time.sleep(1)
        listener.stop()
        print("[OK] Hotkey listener stopped")

        return True

    except Exception as e:
        print(f"[ERROR] Hotkey test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_full_integration():
    """Test the full integration with timeout"""
    print("[DEBUG] Testing full integration with 10s timeout...")

    try:
        from voiceflow.core.config import Config
        from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
        from voiceflow.core.asr_production import ProductionWhisperASR
        from voiceflow.integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener

        cfg = Config()

        # Create components
        rec = EnhancedAudioRecorder(cfg)
        asr = ProductionWhisperASR(cfg)
        asr.load()  # Pre-load models

        class TestApp:
            def __init__(self):
                self.rec = rec
                self.asr = asr
                self.test_complete = False

            def start_recording(self):
                print("[TEST] Recording started...")
                self.rec.start()

                # Auto-stop after 1 second for testing
                def auto_stop():
                    time.sleep(1)
                    if not self.test_complete:
                        self.stop_recording()

                threading.Thread(target=auto_stop, daemon=True).start()

            def stop_recording(self):
                print("[TEST] Recording stopped...")
                try:
                    audio = self.rec.stop()
                    print(f"[TEST] Got {len(audio)} audio samples")

                    # Quick transcription test
                    if len(audio) > 0:
                        result = self.asr.transcribe(audio)
                        print(f"[TEST] Transcription: {len(result.segments)} segments")

                    self.test_complete = True

                except Exception as e:
                    print(f"[TEST] Error in stop_recording: {e}")
                    self.test_complete = True

        app = TestApp()

        # Create hotkey listener
        listener = EnhancedPTTHotkeyListener(
            cfg,
            app.start_recording,
            app.stop_recording
        )

        print("[DEBUG] Starting hotkey listener with timeout...")
        listener.start()

        # Simulate a hotkey press programmatically
        print("[DEBUG] Simulating hotkey press...")
        app.start_recording()

        # Wait for auto-stop or timeout
        start_time = time.time()
        while not app.test_complete and (time.time() - start_time) < 5:
            time.sleep(0.1)

        listener.stop()

        if app.test_complete:
            print("[OK] Full integration test completed")
            return True
        else:
            print("[ERROR] Integration test timed out")
            return False

    except Exception as e:
        print(f"[ERROR] Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run hotkey diagnostic tests"""
    print("="*60)
    print("VoiceFlow Hotkey Diagnostic Tool")
    print("="*60)

    # Test 1: Basic hotkey detection
    if not test_hotkey_detection():
        print("[ERROR] Basic hotkey test failed")
        return

    # Test 2: Full integration
    if not test_full_integration():
        print("[ERROR] Integration test failed")
        return

    print("\n" + "="*60)
    print("ALL HOTKEY TESTS PASSED")
    print("The issue might be in the actual keyboard.wait() blocking call")
    print("or in the visual indicators/tray components")
    print("="*60)

if __name__ == "__main__":
    main()