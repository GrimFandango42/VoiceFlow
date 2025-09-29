#!/usr/bin/env python3
"""
Production VoiceFlow CLI with Modern AI Features
================================================
Production-quality transcription with ultra-simple architecture.
Features: WhisperX (70x realtime), Speaker Diarization, Word Timestamps
No complex thread pools, no complex monitoring - just works.
"""

import sys
import time
import logging
import traceback
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from voiceflow.core.config import Config
from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
from voiceflow.core.asr_production import ProductionWhisperASR as WhisperASR
from voiceflow.integrations.inject import ClipboardInjector
from voiceflow.integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener
from voiceflow.utils.utils import is_admin, nvidia_smi_info
from voiceflow.core.textproc import apply_code_mode, format_transcript_text
from voiceflow.core.smart_formatter import format_transcription_with_pauses, get_notification_summary
import keyboard
from voiceflow.ui.enhanced_tray import EnhancedTrayController, update_tray_status
from voiceflow.utils.logging_setup import AsyncLogger, default_log_dir
from voiceflow.utils.settings import load_config, save_config

# Visual indicators
try:
    from voiceflow.ui.visual_indicators import (
        show_listening, show_processing, show_transcribing,
        show_complete, show_error, hide_status
    )
    VISUAL_INDICATORS_AVAILABLE = True
except ImportError:
    VISUAL_INDICATORS_AVAILABLE = False


class UltraSimpleApp:
    """
    Production VoiceFlow app with modern AI features and maximum reliability.
    Features: WhisperX (70x realtime), Speaker Diarization, Word Timestamps
    No complex threading, no complex monitoring - just works.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rec = EnhancedAudioRecorder(cfg)
        self.asr = WhisperASR(cfg)
        self.injector = ClipboardInjector(cfg)

        self.code_mode = cfg.code_mode_default
        self._log = logging.getLogger("voiceflow_simple")

        # Visual indicators integration
        self.tray_controller = None
        self.visual_indicators_enabled = getattr(cfg, 'visual_indicators_enabled', True)

        # Simple activity tracking
        self.last_activity = time.time()
        self.transcriptions_completed = 0
        self.start_time = time.time()

        print(f"[ProductionApp] Initialized with modern AI features for 24/7 operation")

    def start_recording(self):
        """Simple recording start"""
        try:
            if not self.rec.is_recording():
                print("[MIC] Listening...")
                self.last_activity = time.time()

                # Update visual indicators
                if self.visual_indicators_enabled:
                    update_tray_status(self.tray_controller, "listening", True)
                    if VISUAL_INDICATORS_AVAILABLE:
                        show_listening()

                self.rec.start()

        except Exception as e:
            print(f"[MIC] Audio start error: {e}")
            self._log.exception("audio_start_error: %s", e)

            if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
                show_error(f"Audio error: {e}")

    def stop_recording(self):
        """Simple recording stop with direct transcription"""
        try:
            audio = self.rec.stop()
            audio_duration = len(audio) / self.cfg.sample_rate if len(audio) > 0 else 0

            self.last_activity = time.time()

            if audio.size == 0:
                print("[MIC] No audio captured")
                if self.visual_indicators_enabled:
                    update_tray_status(self.tray_controller, "idle", False)
                    if VISUAL_INDICATORS_AVAILABLE:
                        hide_status()
                return

            print(f"[MIC] Captured {audio_duration:.2f}s of audio")

            # Direct transcription - no complex threading
            text = self._transcribe_simple(audio)

            if text.strip():
                # Apply processing
                if self.code_mode:
                    text = apply_code_mode(text, lowercase=self.cfg.code_mode_lowercase)
                else:
                    text = format_transcript_text(text)

                print(f"[TRANSCRIPTION] => {text}")

                # Inject text
                self.injector.inject(text)
                self.transcriptions_completed += 1

                # Update visual indicators
                if self.visual_indicators_enabled:
                    # Use smart summary for better notification text
                    summary_text = get_notification_summary(text, 45)  # Leave room for "Transcribed: "
                    update_tray_status(self.tray_controller, "complete", False, f"Transcribed: {summary_text}")

                    if VISUAL_INDICATORS_AVAILABLE:
                        # Adaptive notification timing based on text length
                        word_count = len(text.split())
                        if word_count <= 3:
                            duration = 1.5  # Short phrases
                        elif word_count <= 10:
                            duration = 2.5  # Medium sentences
                        elif word_count <= 25:
                            duration = 3.5  # Longer sentences
                        else:
                            duration = 5.0  # Long conversations

                        from voiceflow.ui.visual_indicators import show_transcription_status, TranscriptionStatus
                        show_transcription_status(TranscriptionStatus.COMPLETE, "Complete", duration=duration)
            else:
                if self.visual_indicators_enabled:
                    update_tray_status(self.tray_controller, "idle", False)
                    if VISUAL_INDICATORS_AVAILABLE:
                        hide_status()

        except Exception as e:
            print(f"[MIC] Stop error: {e}")
            traceback.print_exc()
            self._log.exception("audio_stop_error: %s", e)

            if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
                show_error(f"Stop error: {e}")

    def _transcribe_simple(self, audio_data) -> str:
        """Simple, direct transcription with timeout"""
        try:
            start_time = time.perf_counter()

            # Update visual indicators
            if self.visual_indicators_enabled:
                update_tray_status(self.tray_controller, "transcribing", False)
                if VISUAL_INDICATORS_AVAILABLE:
                    show_transcribing()

            # Simple timeout using signal (Unix) or thread (Windows)
            import threading
            import queue

            result_queue = queue.Queue()

            def transcribe_thread():
                try:
                    # Use production ASR with rich results
                    result = self.asr.transcribe(audio_data)

                    # Use smart formatter for pause-based formatting
                    if result.segments:
                        text = format_transcription_with_pauses(result)
                    else:
                        text = ""

                    result_queue.put(('success', text, result))
                except Exception as e:
                    result_queue.put(('error', str(e), None))

            # Start transcription thread
            thread = threading.Thread(target=transcribe_thread)
            thread.daemon = True
            thread.start()

            # Wait with timeout
            try:
                result_type, text, asr_result = result_queue.get(timeout=60)  # 60 second timeout
                if result_type == 'success':
                    transcription_time = time.perf_counter() - start_time

                    # Display performance stats
                    if asr_result:
                        rtf = transcription_time / asr_result.duration if asr_result.duration > 0 else 0
                        print(f"[TRANSCRIPTION] Completed in {transcription_time:.2f}s (RTF: {rtf:.2f}x)")

                        # Display advanced features
                        if asr_result.speaker_count > 1:
                            print(f"[SPEAKERS] {asr_result.speaker_count} speakers detected")

                        if any(seg.words for seg in asr_result.segments):
                            print(f"[TIMESTAMPS] Word-level timing available")

                        # Show ASR stats
                        stats = self.asr.get_stats()
                        features = []
                        if stats.get('whisperx_enabled'):
                            features.append("WhisperX")
                        if stats.get('diarization_enabled'):
                            features.append("Diarization")
                        if stats.get('word_timestamps_enabled'):
                            features.append("Word-Timestamps")
                        if features:
                            print(f"[FEATURES] {', '.join(features)}")
                    else:
                        print(f"[TRANSCRIPTION] Completed in {transcription_time:.2f}s")

                    return text
                else:
                    print(f"[TRANSCRIPTION] Error: {text}")
                    return ""
            except queue.Empty:
                print("[TRANSCRIPTION] Timeout after 60 seconds")
                return ""

        except Exception as e:
            print(f"[TRANSCRIPTION] Error: {e}")
            traceback.print_exc()
            return ""

    def get_status(self):
        """Get simple status info"""
        uptime = time.time() - self.start_time
        return {
            'uptime_minutes': uptime / 60,
            'transcriptions': self.transcriptions_completed,
            'last_activity': time.time() - self.last_activity
        }

    def shutdown(self):
        """Simple shutdown"""
        print("[UltraSimpleApp] Shutting down...")
        if self.rec.is_recording():
            try:
                self.rec.stop()
            except:
                pass


def main():
    """Ultra-simple main function"""
    cfg = load_config(Config())

    # Initialize logging
    _alog = AsyncLogger(default_log_dir())

    if not is_admin():
        print("Warning: Not running as Administrator. Global hotkeys may be limited.")

    info = nvidia_smi_info()
    if info:
        print(f"GPU: {info}")

    app = UltraSimpleApp(cfg)

    # Simple tray support
    tray = None
    if cfg.use_tray:
        try:
            from voiceflow.ui.enhanced_tray import EnhancedTrayController
            tray = EnhancedTrayController(app)
            app.tray_controller = tray
            tray.start()
            print("Enhanced tray started.")
        except Exception as e:
            print(f"Tray failed: {e}")

    # Simple hotkey toggles
    def toggle_code_mode():
        app.code_mode = not app.code_mode
        print(f"[CONFIG] Code mode: {'ON' if app.code_mode else 'OFF'}")
        save_config(app.cfg)

    def toggle_injection():
        app.cfg.paste_injection = not app.cfg.paste_injection
        print(f"[CONFIG] Injection: {'Paste' if app.cfg.paste_injection else 'Type'}")
        save_config(app.cfg)

    keyboard.add_hotkey('ctrl+alt+c', toggle_code_mode, suppress=False)
    keyboard.add_hotkey('ctrl+alt+p', toggle_injection, suppress=False)

    # Simple PTT listener
    listener = EnhancedPTTHotkeyListener(
        cfg,
        on_start=app.start_recording,
        on_stop=app.stop_recording,
    )

    # Simple status reporter
    def status_thread():
        """Report status every 10 minutes"""
        while True:
            try:
                time.sleep(600)  # 10 minutes
                status = app.get_status()
                if status['uptime_minutes'] > 1:  # Only report after 1 minute
                    print(f"[STATUS] Uptime: {status['uptime_minutes']:.1f}min, "
                          f"Transcriptions: {status['transcriptions']}, "
                          f"Idle: {status['last_activity']:.1f}s")
            except:
                break

    import threading
    status_reporter = threading.Thread(target=status_thread, daemon=True)
    status_reporter.start()

    try:
        listener.start()
        print("\n" + "="*70)
        print("VoiceFlow Production - Modern AI Transcription")
        print("="*70)
        print(f"Hotkey: {'Ctrl+' if cfg.hotkey_ctrl else ''}"
              f"{'Shift+' if cfg.hotkey_shift else ''}"
              f"{'Alt+' if cfg.hotkey_alt else ''}"
              f"{cfg.hotkey_key.upper() if cfg.hotkey_key else '[Modifiers Only]'}")
        print("Features: WhisperX (70x realtime), Speaker Diarization, Word Timestamps")
        print("Mode: Production-quality with ultra-simple architecture")
        print("Timeouts: 60s transcription, no activity timeouts")
        print("Status: Reports every 10 minutes")
        print("="*70)
        print("Ready for 24/7 operation with modern AI capabilities...")

        listener.run_forever()

    except KeyboardInterrupt:
        print("\n[MAIN] Shutdown requested...")
    except Exception as e:
        print(f"[MAIN] Fatal error: {e}")
        traceback.print_exc()
    finally:
        try:
            listener.stop()
            app.shutdown()
        except:
            pass


if __name__ == "__main__":
    sys.exit(main())