#!/usr/bin/env python3
"""
Fixed VoiceFlow CLI with proper error handling and state cleanup.
This addresses the hanging "listening" state issue.
"""

import sys
import time
import logging
import traceback
import signal
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from voiceflow.core.config import Config
from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
from voiceflow.core.asr_production import ProductionWhisperASR as WhisperASR
from voiceflow.integrations.inject import ClipboardInjector
from voiceflow.integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener
from voiceflow.utils.utils import is_admin, nvidia_smi_info
from voiceflow.core.textproc import apply_code_mode, format_transcript_text
import keyboard
from voiceflow.ui.enhanced_tray import EnhancedTrayController, update_tray_status
from voiceflow.utils.logging_setup import AsyncLogger, default_log_dir
from voiceflow.utils.settings import load_config, save_config

# Visual indicators with proper error handling
try:
    from voiceflow.ui.visual_indicators import (
        show_listening, show_processing, show_transcribing,
        show_complete, show_error, hide_status, force_cleanup_all
    )
    VISUAL_INDICATORS_AVAILABLE = True
except ImportError:
    VISUAL_INDICATORS_AVAILABLE = False

class FixedVoiceFlowApp:
    """
    Fixed VoiceFlow app with proper state management and error recovery.
    Addresses the hanging "listening" state issue.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rec = EnhancedAudioRecorder(cfg)
        self.asr = WhisperASR(cfg)
        self.injector = ClipboardInjector(cfg)

        self.code_mode = getattr(cfg, 'code_mode_default', False)
        self._log = logging.getLogger("voiceflow_fixed")

        # State tracking
        self.current_state = "idle"  # idle, listening, processing, error
        self.state_lock = False  # Prevent state changes during operations

        # Visual indicators integration
        self.tray_controller = None
        self.visual_indicators_enabled = getattr(cfg, 'visual_indicators_enabled', True)

        # Activity tracking
        self.last_activity = time.time()
        self.transcriptions_completed = 0
        self.start_time = time.time()

        print(f"[FixedApp] Initialized with proper state management")

    def _set_state(self, new_state: str, details: str = ""):
        """Thread-safe state management with proper visual indicator updates"""
        if self.state_lock:
            print(f"[STATE] State locked, skipping change to {new_state}")
            return

        old_state = self.current_state
        self.current_state = new_state
        print(f"[STATE] {old_state} -> {new_state} {details}")

        # Update visual indicators based on state
        try:
            if self.visual_indicators_enabled:
                if new_state == "listening":
                    update_tray_status(self.tray_controller, "listening", True)
                    if VISUAL_INDICATORS_AVAILABLE:
                        show_listening()
                elif new_state == "processing":
                    update_tray_status(self.tray_controller, "processing", False)
                    if VISUAL_INDICATORS_AVAILABLE:
                        show_processing()
                elif new_state == "idle":
                    update_tray_status(self.tray_controller, "idle", False)
                    if VISUAL_INDICATORS_AVAILABLE:
                        hide_status()
                elif new_state == "error":
                    update_tray_status(self.tray_controller, "error", False, details)
                    if VISUAL_INDICATORS_AVAILABLE:
                        show_error(details)
        except Exception as e:
            print(f"[STATE] Visual indicator update error: {e}")

    def _reset_to_idle(self):
        """Force reset to idle state with full cleanup"""
        print("[RESET] Forcing reset to idle state...")

        # Stop any ongoing recording
        try:
            if self.rec.is_recording():
                self.rec.stop()
        except Exception as e:
            print(f"[RESET] Error stopping recording: {e}")

        # Clear visual indicators
        try:
            if VISUAL_INDICATORS_AVAILABLE:
                hide_status()
        except Exception as e:
            print(f"[RESET] Error clearing visual indicators: {e}")

        # Reset state
        self.current_state = "idle"
        self.state_lock = False

    def start_recording(self):
        """Enhanced recording start with state management"""
        try:
            # Check if already recording or processing
            if self.current_state != "idle":
                print(f"[MIC] Already in {self.current_state} state, ignoring start request")
                return

            # Lock state during transition
            self.state_lock = True

            print("[MIC] Starting recording...")
            self.last_activity = time.time()

            # Set listening state
            self._set_state("listening", "recording started")

            # Start actual recording
            self.rec.start()

            # Unlock state
            self.state_lock = False

            print("[MIC] Recording started successfully")

        except Exception as e:
            print(f"[MIC] Audio start error: {e}")
            self._log.exception("audio_start_error: %s", e)

            # CRITICAL: Reset to idle on any error
            self._reset_to_idle()
            self._set_state("error", f"Start error: {e}")

            # Auto-recovery after 2 seconds
            def auto_recover():
                time.sleep(2)
                self._reset_to_idle()

            import threading
            threading.Thread(target=auto_recover, daemon=True).start()

    def stop_recording(self):
        """Enhanced recording stop with proper error handling"""
        try:
            # Check if we're actually recording
            if self.current_state != "listening":
                print(f"[MIC] Not in listening state (current: {self.current_state}), ignoring stop")
                return

            # Lock state during transition
            self.state_lock = True

            print("[MIC] Stopping recording...")
            audio = self.rec.stop()
            audio_duration = len(audio) / self.cfg.sample_rate if len(audio) > 0 else 0

            self.last_activity = time.time()

            if audio.size == 0:
                print("[MIC] No audio captured")
                self._reset_to_idle()
                return

            print(f"[MIC] Captured {audio_duration:.2f}s of audio")

            # Set processing state
            self._set_state("processing", f"{audio_duration:.1f}s audio")

            # Unlock for transcription
            self.state_lock = False

            # Direct transcription with timeout
            text = self._transcribe_with_timeout(audio)

            if text and text.strip():
                # Apply processing
                if self.code_mode:
                    text = apply_code_mode(text, lowercase=getattr(self.cfg, 'code_mode_lowercase', False))
                else:
                    text = format_transcript_text(text)

                print(f"[TRANSCRIPTION] => {text}")

                # Inject text
                self.injector.inject(text)
                self.transcriptions_completed += 1

                # Show completion
                self._set_state("idle")
                if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
                    show_complete()

            else:
                print("[TRANSCRIPTION] No text detected")
                self._reset_to_idle()

        except Exception as e:
            print(f"[MIC] Stop error: {e}")
            traceback.print_exc()
            self._log.exception("audio_stop_error: %s", e)

            # CRITICAL: Always reset on error
            self._reset_to_idle()
            self._set_state("error", f"Stop error: {e}")

    def _transcribe_with_timeout(self, audio_data) -> str:
        """Transcription with proper timeout and error handling"""
        try:
            import threading
            import queue

            result_queue = queue.Queue()

            def transcribe_thread():
                try:
                    result = self.asr.transcribe(audio_data)
                    text = result.segments[0].text if result.segments else ""
                    result_queue.put(('success', text))
                except Exception as e:
                    result_queue.put(('error', str(e)))

            # Start transcription thread
            thread = threading.Thread(target=transcribe_thread)
            thread.daemon = True
            thread.start()

            # Wait with timeout
            try:
                result_type, text = result_queue.get(timeout=30)  # 30 second timeout
                if result_type == 'success':
                    return text
                else:
                    print(f"[TRANSCRIPTION] Error: {text}")
                    return ""
            except queue.Empty:
                print("[TRANSCRIPTION] Timeout after 30 seconds")
                return ""

        except Exception as e:
            print(f"[TRANSCRIPTION] Unexpected error: {e}")
            return ""

    def shutdown(self):
        """Proper shutdown with cleanup"""
        print("[SHUTDOWN] Cleaning up...")
        try:
            self._reset_to_idle()
            if VISUAL_INDICATORS_AVAILABLE:
                force_cleanup_all()
        except Exception as e:
            print(f"[SHUTDOWN] Cleanup error: {e}")

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[MAIN] Shutdown requested...")
    sys.exit(0)

def main():
    """Main function with proper error handling"""

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)

    try:
        # Force cleanup any stuck indicators from previous runs
        if VISUAL_INDICATORS_AVAILABLE:
            force_cleanup_all()

        # Load configuration
        cfg = Config()

        # Create app
        app = FixedVoiceFlowApp(cfg)

        # Load ASR models
        print("[MAIN] Loading ASR models...")
        app.asr.load()

        # Create hotkey listener
        listener = EnhancedPTTHotkeyListener(
            cfg,
            app.start_recording,
            app.stop_recording
        )

        # Start listener
        listener.start()
        print("\n" + "="*70)
        print("VoiceFlow Fixed - Enhanced Error Handling")
        print("="*70)
        print(f"Hotkey: {'Ctrl+' if cfg.hotkey_ctrl else ''}"
              f"{'Shift+' if cfg.hotkey_shift else ''}"
              f"{'Alt+' if cfg.hotkey_alt else ''}"
              f"{cfg.hotkey_key.upper() if cfg.hotkey_key else '[Modifiers Only]'}")
        print("State management: Enhanced with auto-recovery")
        print("Visual feedback: Bottom-screen overlay + Dynamic tray icon")
        print("Error handling: Automatic state reset on failures")
        print("="*70)
        print("Ready for operation. Press Ctrl+C to exit.")

        # Run forever with proper error handling
        try:
            listener.run_forever()
        except KeyboardInterrupt:
            print("\n[MAIN] Keyboard interrupt received")
        except Exception as e:
            print(f"[MAIN] Runtime error: {e}")

    except Exception as e:
        print(f"[MAIN] Fatal error: {e}")
        traceback.print_exc()
    finally:
        # Graceful cleanup
        try:
            print("[MAIN] Shutting down...")
            if 'listener' in locals():
                listener.stop()
            if 'app' in locals():
                app.shutdown()
        except Exception:
            pass

if __name__ == "__main__":
    main()