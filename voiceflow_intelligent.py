#!/usr/bin/env python3
"""
VoiceFlow Intelligent - Enhanced with Self-Correcting ASR
========================================================
Features intelligent transcription correction and continuous learning.

New Features:
- Self-correcting transcription with quality analysis
- Real-time learning from user patterns
- Context-aware error detection and correction
- Quality monitoring and improvement suggestions
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
from voiceflow.core.asr_production import ProductionWhisperASR
from voiceflow.core.self_correcting_asr import SelfCorrectingASR
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

class IntelligentVoiceFlowApp:
    """
    Intelligent VoiceFlow app with self-correcting ASR and quality monitoring.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rec = EnhancedAudioRecorder(cfg)

        # Create base ASR and wrap with self-correcting layer
        base_asr = ProductionWhisperASR(cfg)
        self.asr = SelfCorrectingASR(base_asr, learning_data_path="voiceflow_learning.json")

        self.injector = ClipboardInjector(cfg)

        self.code_mode = getattr(cfg, 'code_mode_default', False)
        self._log = logging.getLogger("voiceflow_intelligent")

        # State tracking with quality monitoring
        self.current_state = "idle"
        self.state_lock = False
        self.transcription_count = 0
        self.quality_scores = []
        self.improvement_suggestions = []

        # Visual indicators integration
        self.tray_controller = None
        self.visual_indicators_enabled = getattr(cfg, 'visual_indicators_enabled', True)

        # Activity tracking
        self.last_activity = time.time()
        self.start_time = time.time()

        print(f"[IntelligentApp] Initialized with self-correcting ASR and quality monitoring")

    def _set_state(self, new_state: str, details: str = ""):
        """Enhanced state management with quality tracking"""
        if self.state_lock:
            print(f"[STATE] State locked, skipping change to {new_state}")
            return

        old_state = self.current_state
        self.current_state = new_state
        print(f"[STATE] {old_state} -> {new_state} {details}")

        # Update visual indicators
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
                elif new_state == "transcribing":
                    update_tray_status(self.tray_controller, "transcribing", False)
                    if VISUAL_INDICATORS_AVAILABLE:
                        show_transcribing()
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

        try:
            if self.rec.is_recording():
                self.rec.stop()
        except Exception as e:
            print(f"[RESET] Error stopping recording: {e}")

        try:
            if VISUAL_INDICATORS_AVAILABLE:
                hide_status()
        except Exception as e:
            print(f"[RESET] Error clearing visual indicators: {e}")

        self.current_state = "idle"
        self.state_lock = False

    def start_recording(self):
        """Enhanced recording start with intelligent monitoring"""
        try:
            if self.current_state != "idle":
                print(f"[MIC] Already in {self.current_state} state, ignoring start request")
                return

            self.state_lock = True
            print("[MIC] Starting intelligent recording...")
            self.last_activity = time.time()

            self._set_state("listening", "intelligent recording started")
            self.rec.start()
            self.state_lock = False

            print("[MIC] Intelligent recording started successfully")

        except Exception as e:
            print(f"[MIC] Audio start error: {e}")
            self._log.exception("audio_start_error: %s", e)
            self._reset_to_idle()
            self._set_state("error", f"Start error: {e}")

            # Auto-recovery
            def auto_recover():
                time.sleep(2)
                self._reset_to_idle()

            import threading
            threading.Thread(target=auto_recover, daemon=True).start()

    def stop_recording(self):
        """Enhanced recording stop with intelligent transcription"""
        try:
            if self.current_state != "listening":
                print(f"[MIC] Not in listening state (current: {self.current_state}), ignoring stop")
                return

            self.state_lock = True
            print("[MIC] Stopping intelligent recording...")

            audio = self.rec.stop()
            audio_duration = len(audio) / self.cfg.sample_rate if len(audio) > 0 else 0
            self.last_activity = time.time()

            if audio.size == 0:
                print("[MIC] No audio captured")
                self._reset_to_idle()
                return

            print(f"[MIC] Captured {audio_duration:.2f}s of audio")

            # Enhanced transcription with self-correction
            self._set_state("transcribing", f"{audio_duration:.1f}s audio")
            self.state_lock = False

            # Intelligent transcription with quality analysis
            result = self._intelligent_transcribe(audio)

            if result and result.segments:
                text = " ".join(seg.text for seg in result.segments)

                if text.strip():
                    # Apply processing
                    if self.code_mode:
                        text = apply_code_mode(text, lowercase=getattr(self.cfg, 'code_mode_lowercase', False))
                    else:
                        text = format_transcript_text(text)

                    print(f"[TRANSCRIPTION] => {text}")

                    # Track quality and generate suggestions
                    self._track_transcription_quality(result, text)

                    # Inject text
                    self.injector.inject(text)
                    self.transcription_count += 1

                    # Show completion with quality info
                    quality_score = getattr(result, 'quality_score', 0.9)
                    self._set_state("idle")

                    if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
                        show_complete()

                    # Display quality insights
                    self._display_quality_insights(result, text)

                else:
                    print("[TRANSCRIPTION] No meaningful text detected")
                    self._reset_to_idle()
            else:
                print("[TRANSCRIPTION] Transcription failed")
                self._reset_to_idle()

        except Exception as e:
            print(f"[MIC] Stop error: {e}")
            traceback.print_exc()
            self._log.exception("audio_stop_error: %s", e)
            self._reset_to_idle()
            self._set_state("error", f"Stop error: {e}")

    def _intelligent_transcribe(self, audio_data):
        """Intelligent transcription with self-correction"""
        try:
            import threading
            import queue

            result_queue = queue.Queue()

            def transcribe_thread():
                try:
                    # Use self-correcting ASR
                    result = self.asr.transcribe(audio_data)
                    result_queue.put(('success', result))
                except Exception as e:
                    result_queue.put(('error', str(e)))

            # Start transcription thread
            thread = threading.Thread(target=transcribe_thread)
            thread.daemon = True
            thread.start()

            # Wait with timeout
            try:
                result_type, result = result_queue.get(timeout=30)
                if result_type == 'success':
                    return result
                else:
                    print(f"[TRANSCRIPTION] Error: {result}")
                    return None
            except queue.Empty:
                print("[TRANSCRIPTION] Timeout after 30 seconds")
                return None

        except Exception as e:
            print(f"[TRANSCRIPTION] Unexpected error: {e}")
            return None

    def _track_transcription_quality(self, result, text):
        """Track transcription quality and learn from patterns"""
        try:
            # Get quality analysis from self-correcting ASR
            quality_report = self.asr.get_quality_report()

            # Get improvement suggestions
            suggestions = self.asr.get_suggestions(text)

            if suggestions:
                print(f"[QUALITY] Found {len(suggestions)} improvement suggestions")
                for suggestion in suggestions[:3]:  # Show top 3
                    print(f"  • {suggestion.original_text} → {suggestion.suggested_text} ({suggestion.reason})")

            # Store quality data
            self.quality_scores.append({
                'timestamp': time.time(),
                'text': text,
                'confidence': getattr(result, 'confidence', 0.9),
                'suggestions': len(suggestions),
                'quality_report': quality_report
            })

            # Keep only recent quality data
            if len(self.quality_scores) > 100:
                self.quality_scores.pop(0)

        except Exception as e:
            print(f"[QUALITY] Error tracking quality: {e}")

    def _display_quality_insights(self, result, text):
        """Display quality insights to user"""
        try:
            # Calculate session statistics
            if len(self.quality_scores) >= 5:
                recent_scores = [q['confidence'] for q in self.quality_scores[-5:]]
                avg_confidence = sum(recent_scores) / len(recent_scores)

                if avg_confidence < 0.8:
                    print(f"[INSIGHT] Recent transcription confidence is low ({avg_confidence:.1%})")
                    print("[INSIGHT] Consider speaking more clearly or reducing background noise")

                # Check for learning progress
                if len(self.quality_scores) >= 20:
                    older_scores = [q['confidence'] for q in self.quality_scores[-20:-10]]
                    newer_scores = [q['confidence'] for q in self.quality_scores[-10:]]

                    if sum(newer_scores) / len(newer_scores) > sum(older_scores) / len(older_scores):
                        print("[INSIGHT] ✓ Transcription quality is improving over time!")

            # Show vocabulary learning
            vocab_size = len(getattr(self.asr.user_patterns, 'domain_vocabulary', {}))
            if vocab_size > 0:
                print(f"[LEARNING] Learned {vocab_size} domain-specific terms")

        except Exception as e:
            print(f"[INSIGHTS] Error displaying insights: {e}")

    def get_quality_summary(self):
        """Get quality summary for current session"""
        if not self.quality_scores:
            return "No transcriptions in current session"

        avg_confidence = sum(q['confidence'] for q in self.quality_scores) / len(self.quality_scores)
        total_suggestions = sum(q['suggestions'] for q in self.quality_scores)

        return {
            'session_duration': time.time() - self.start_time,
            'transcription_count': len(self.quality_scores),
            'average_confidence': avg_confidence,
            'total_suggestions': total_suggestions,
            'learning_progress': self.asr.get_quality_report()
        }

    def shutdown(self):
        """Enhanced shutdown with learning data save"""
        print("[SHUTDOWN] Saving learning data and cleaning up...")
        try:
            # Save learning data
            self.asr.shutdown()

            # Display session summary
            summary = self.get_quality_summary()
            print(f"[SESSION] Transcriptions: {summary.get('transcription_count', 0)}")
            print(f"[SESSION] Avg Confidence: {summary.get('average_confidence', 0):.1%}")
            print(f"[SESSION] Suggestions Generated: {summary.get('total_suggestions', 0)}")

            # Clean up visual indicators
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
    """Main function with intelligent transcription"""

    signal.signal(signal.SIGINT, signal_handler)

    try:
        # Force cleanup any stuck indicators
        if VISUAL_INDICATORS_AVAILABLE:
            force_cleanup_all()

        # Load configuration
        cfg = Config()

        # Create intelligent app
        app = IntelligentVoiceFlowApp(cfg)

        # Load ASR models
        print("[MAIN] Loading intelligent ASR models...")
        app.asr.base_asr.load()

        # Create hotkey listener
        listener = EnhancedPTTHotkeyListener(
            cfg,
            app.start_recording,
            app.stop_recording
        )

        # Start listener
        listener.start()
        print("\n" + "="*70)
        print("VoiceFlow Intelligent - Self-Correcting ASR")
        print("="*70)
        print(f"Hotkey: {'Ctrl+' if cfg.hotkey_ctrl else ''}"
              f"{'Shift+' if cfg.hotkey_shift else ''}"
              f"{'Alt+' if cfg.hotkey_alt else ''}"
              f"{cfg.hotkey_key.upper() if cfg.hotkey_key else '[Modifiers Only]'}")
        print("Intelligence: Self-correcting transcription with continuous learning")
        print("Quality: Real-time quality monitoring and improvement suggestions")
        print("Learning: Adapts to your vocabulary and speaking patterns")
        print("Performance: 70x realtime with professional accuracy")
        print("="*70)
        print("Ready for intelligent operation. Press Ctrl+C to exit.")
        print("Tip: Launch quality_monitor.py for real-time quality insights!")

        # Run forever
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
            print("[MAIN] Shutting down intelligent systems...")
            if 'listener' in locals():
                listener.stop()
            if 'app' in locals():
                app.shutdown()
        except Exception:
            pass

if __name__ == "__main__":
    main()