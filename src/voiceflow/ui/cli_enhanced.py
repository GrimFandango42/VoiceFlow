from __future__ import annotations

import threading
import traceback
import sys
from typing import Optional, Dict, Any
import logging
import time
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, Future

import numpy as np

from voiceflow.core.config import Config
from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
from voiceflow.core.asr_modern import ModernWhisperASR as WhisperASR
from voiceflow.integrations.inject import ClipboardInjector
from voiceflow.integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener
from voiceflow.utils.utils import is_admin, nvidia_smi_info
from voiceflow.core.textproc import apply_code_mode, format_transcript_text
import keyboard
from voiceflow.ui.tray import TrayController
from voiceflow.ui.enhanced_tray import EnhancedTrayController, update_tray_status
from voiceflow.utils.logging_setup import AsyncLogger, default_log_dir
from voiceflow.utils.settings import load_config, save_config
from voiceflow.utils.idle_aware_monitor import (
    start_idle_monitoring, stop_idle_monitoring, record_heartbeat,
    mark_idle, mark_recording, mark_processing, mark_injecting, mark_error,
    ProcessState
)
from voiceflow.utils.process_monitor import OperationTimeout

# Initialize logger for the module
logger = logging.getLogger(__name__)

# Visual indicators integration
try:
    from voiceflow.ui.visual_indicators import (
        show_listening, show_processing, show_transcribing, 
        show_complete, show_error, hide_status
    )
    VISUAL_INDICATORS_AVAILABLE = True
except ImportError:
    VISUAL_INDICATORS_AVAILABLE = False


class EnhancedTranscriptionManager:
    """Enhanced thread-safe transcription manager for long conversations"""
    
    def __init__(self, max_concurrent_jobs: int = 2):
        self.executor = ThreadPoolExecutor(
            max_workers=max_concurrent_jobs,
            thread_name_prefix="Transcriber"
        )
        self.active_jobs: Dict[str, Future] = {}
        self.job_counter = 0
        self.lock = threading.Lock()
        
        print(f"[TranscriptionManager] Initialized with {max_concurrent_jobs} worker threads")
    
    def submit_transcription(self, audio_data: np.ndarray, callback: callable) -> str:
        """Submit transcription job with proper thread management"""
        with self.lock:
            self.job_counter += 1
            job_id = f"job_{self.job_counter}"
        
        # Clean up completed jobs
        self._cleanup_completed_jobs()
        
        # Submit new job
        future = self.executor.submit(self._transcription_worker, audio_data, callback, job_id)
        
        with self.lock:
            self.active_jobs[job_id] = future
        
        print(f"[TranscriptionManager] Started {job_id} (active jobs: {len(self.active_jobs)})")
        return job_id
    
    def _transcription_worker(self, audio_data: np.ndarray, callback: callable, job_id: str):
        """Enhanced transcription worker with error handling"""
        try:
            start_time = time.perf_counter()
            duration = len(audio_data) / 16000.0  # Assuming 16kHz

            print(f"[TranscriptionManager] {job_id}: Processing {duration:.2f}s of audio...")

            # Perform transcription with timeout
            import signal
            import threading
            result = None
            error = None

            def transcription_thread():
                nonlocal result, error
                try:
                    result = callback(audio_data)
                except Exception as e:
                    error = e

            # Start transcription in separate thread
            thread = threading.Thread(target=transcription_thread)
            thread.daemon = True
            thread.start()

            # Wait with timeout
            thread.join(timeout=90)  # 90 second timeout

            if thread.is_alive():
                print(f"[TranscriptionManager] {job_id}: Thread timeout - transcription hung")
                # Force return to idle state
                from voiceflow.utils.idle_aware_monitor import mark_idle
                mark_idle()
                return ""

            if error:
                raise error

            if result is None:
                print(f"[TranscriptionManager] {job_id}: No result returned")
                return ""

            # Performance metrics
            processing_time = time.perf_counter() - start_time
            speed_factor = duration / processing_time if processing_time > 0 else 0

            print(f"[TranscriptionManager] {job_id}: Completed in {processing_time:.2f}s "
                  f"({speed_factor:.1f}x realtime)")

            return result

        except Exception as e:
            print(f"[TranscriptionManager] {job_id}: Error - {e}")
            traceback.print_exc()
            # Make sure we return to idle state on error
            from voiceflow.utils.idle_aware_monitor import mark_idle
            mark_idle()
            return ""
        finally:
            # Remove from active jobs
            with self.lock:
                if job_id in self.active_jobs:
                    del self.active_jobs[job_id]
    
    def _cleanup_completed_jobs(self):
        """Clean up completed jobs to prevent memory leaks"""
        with self.lock:
            completed_jobs = [
                job_id for job_id, future in self.active_jobs.items()
                if future.done()
            ]
            for job_id in completed_jobs:
                del self.active_jobs[job_id]
    
    def shutdown(self):
        """Shutdown the transcription manager gracefully"""
        print("[TranscriptionManager] Shutting down...")
        self.executor.shutdown(wait=True)
        print("[TranscriptionManager] Shutdown complete")


class EnhancedApp:
    """Enhanced VoiceFlow app with better thread management and long conversation support"""
    
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.rec = EnhancedAudioRecorder(cfg)
        self.asr = WhisperASR(cfg)
        self.injector = ClipboardInjector(cfg)
        
        # Enhanced thread management
        self.transcription_manager = EnhancedTranscriptionManager(max_concurrent_jobs=1)
        
        self.code_mode = cfg.code_mode_default
        self._log = logging.getLogger("localflow")
        
        # Visual indicators integration
        self.tray_controller: Optional[EnhancedTrayController] = None
        self.visual_indicators_enabled = getattr(cfg, 'visual_indicators_enabled', True)
        
        # Long conversation tracking
        self._session_start_time = time.time()
        self._total_transcription_time = 0.0
        self._session_word_count = 0
        
        print(f"[EnhancedApp] Initialized with enhanced thread management and visual indicators {'enabled' if self.visual_indicators_enabled else 'disabled'}")

    def start_recording(self):
        """Enhanced recording start with better error handling"""
        try:
            if not self.rec.is_recording():
                print("[MIC] Listening...")
                self._log.info("recording_started")

                # Mark state as recording for idle-aware monitoring
                mark_recording()

                # Update visual indicators - listening status
                if self.visual_indicators_enabled:
                    update_tray_status(self.tray_controller, "listening", True)
                    if VISUAL_INDICATORS_AVAILABLE:
                        show_listening()

                self.rec.start()

                # Monitor for very long recordings
                current_duration = self.rec.get_current_duration()
                if current_duration > 0:
                    print(f"[MIC] Resuming recording ({current_duration:.1f}s elapsed)")
                    
        except Exception as e:
            print(f"[MIC] Audio start error: {e}")
            traceback.print_exc()
            self._log.exception("audio_start_error: %s", e)

            # Mark error state
            mark_error(f"Audio start error: {e}")

            # Update visual indicators - error status
            if self.visual_indicators_enabled:
                update_tray_status(self.tray_controller, "error", False, f"Audio error: {e}")
                if VISUAL_INDICATORS_AVAILABLE:
                    show_error(f"Audio error: {e}")

    def stop_recording(self):
        """Enhanced recording stop with improved transcription handling"""
        try:
            audio = self.rec.stop()
            audio_duration = len(audio) / self.cfg.sample_rate if len(audio) > 0 else 0

            # State will be marked as processing only after validation passes

            self._log.info("recording_stopped duration=%.2f samples=%d",
                          audio_duration, len(audio))

            if audio.size == 0:
                print("[MIC] No audio captured")
                # Return to idle state
                mark_idle()
                # Update visual indicators - back to idle
                if self.visual_indicators_enabled:
                    update_tray_status(self.tray_controller, "idle", False)
                    if VISUAL_INDICATORS_AVAILABLE:
                        hide_status()
                return

            # CRITICAL FIX: Enhanced silence detection for background noise
            # This prevents "OK OK OK" spam from background noise/room tone
            try:
                # Calculate audio energy (RMS)
                audio_energy = np.sqrt(np.mean(audio ** 2)) if audio.size > 0 else 0

                # More sophisticated silence detection
                silence_threshold = 0.01  # Higher threshold for background noise
                max_amplitude = np.max(np.abs(audio)) if audio.size > 0 else 0

                # Check if audio is essentially silent (background noise only)
                if audio_energy < silence_threshold and max_amplitude < 0.05:
                    print(f"[MIC] Silent audio detected (energy: {audio_energy:.6f}, max: {max_amplitude:.6f}) - skipping transcription")
                    # Return to idle state
                    mark_idle()
                    # Update visual indicators - back to idle
                    if self.visual_indicators_enabled:
                        update_tray_status(self.tray_controller, "idle", False)
                        if VISUAL_INDICATORS_AVAILABLE:
                            hide_status()
                    return

            except Exception as silence_error:
                print(f"[MIC] Silence detection error: {silence_error}")
                # Continue with transcription if silence detection fails
            
            print(f"[MIC] Captured {audio_duration:.2f}s of audio ({len(audio)} samples)")

            # CRITICAL FIX: Mark as processing ONLY after validation passes
            # This prevents stuck state when early validation fails
            mark_processing()

            # Update visual indicators - processing status
            if self.visual_indicators_enabled:
                update_tray_status(self.tray_controller, "processing", False)
                if VISUAL_INDICATORS_AVAILABLE:
                    show_processing()

            # Enhanced transcription with proper thread management
            def transcription_callback(audio_data: np.ndarray) -> str:
                return self._perform_transcription(audio_data)

            # Submit to thread pool instead of creating ad-hoc threads
            job_id = self.transcription_manager.submit_transcription(
                audio, transcription_callback
            )
            
        except Exception as e:
            print(f"[MIC] Audio stop error: {e}")
            traceback.print_exc()
            self._log.exception("audio_stop_error: %s", e)
            
            # Update visual indicators - error status
            if self.visual_indicators_enabled:
                update_tray_status(self.tray_controller, "error", False, f"Stop error: {e}")
                if VISUAL_INDICATORS_AVAILABLE:
                    show_error(f"Stop error: {e}")

    def _perform_transcription(self, audio_data: np.ndarray) -> str:
        """Perform actual transcription with enhanced error handling and timeout protection"""
        # Ensure logger is available (fix for scoping issue)
        logger = logging.getLogger(__name__)

        try:
            start_time = time.perf_counter()

            # Already in processing state from stop_recording

            # Update visual indicators - transcribing status
            if self.visual_indicators_enabled:
                update_tray_status(self.tray_controller, "transcribing", False)
                if VISUAL_INDICATORS_AVAILABLE:
                    show_transcribing()

            # Transcribe with timeout protection (60 seconds max)
            audio_duration = len(audio_data) / self.cfg.sample_rate
            timeout_seconds = max(60, audio_duration * 3)  # 3x audio duration or 60s minimum

            try:
                with OperationTimeout(timeout_seconds, f"transcription_{audio_duration:.1f}s"):
                    text = self.asr.transcribe(audio_data)

                # Simple hallucination detection - fast and reliable
                if text and len(text.strip()) > 0:
                    # Basic pattern detection for common hallucinations
                    text_lower = text.lower().strip()

                    # Common Whisper hallucination patterns
                    hallucinations = [
                        'okay' * 3,  # "okay okay okay"
                        'thank you' * 2,  # "thank you thank you"
                        'you' * 4,  # "you you you you"
                    ]

                    is_hallucination = any(pattern in text_lower for pattern in hallucinations)

                    if is_hallucination:
                        print(f"[TRANSCRIPTION] Filtered hallucination pattern: {text[:50]}...")
                        mark_idle()
                        update_tray_status(self.tray_controller, "idle", False)
                        return ""

                    # Check for very short or repetitive content
                    if len(text.strip()) < 3:
                        print(f"[TRANSCRIPTION] Content too short - skipping")
                        mark_idle()
                        update_tray_status(self.tray_controller, "idle", False)
                        return ""

            except TimeoutError as e:
                logger.error(f"Transcription timeout: {e}")
                print(f"[TRANSCRIPTION] Timeout after {timeout_seconds}s - skipping")
                # Return to idle state after timeout
                mark_idle()
                return ""
            
            # Apply processing
            if self.code_mode:
                text = apply_code_mode(text, lowercase=self.cfg.code_mode_lowercase)
            else:
                # Apply improved text formatting for better readability
                text = format_transcript_text(text)
            
            # Performance tracking
            transcription_time = time.perf_counter() - start_time
            self._total_transcription_time += transcription_time
            self._session_word_count += len(text.split())

            # Session stats
            session_duration = time.time() - self._session_start_time
            avg_transcription_time = self._total_transcription_time / max(1, session_duration / 60)

            print(f"[TRANSCRIPTION] => {text}")
            print(f"[STATS] Words: {len(text.split())}, "
                  f"Time: {transcription_time:.2f}s, "
                  f"Session: {self._session_word_count} words")

            # Inject text
            if text.strip():
                # Mark as injecting
                mark_injecting()

                self.injector.inject(text)
                self._log.info("transcribed chars=%d words=%d seconds=%.3f",
                             len(text), len(text.split()), transcription_time)

                # Update visual indicators - completion with transcription result
                if self.visual_indicators_enabled:
                    truncated_text = text[:50] + "..." if len(text) > 50 else text
                    update_tray_status(self.tray_controller, "complete", False, f"Transcribed: {truncated_text}")
                    if VISUAL_INDICATORS_AVAILABLE:
                        show_complete("Complete")

                    # CRITICAL: Schedule delayed reset to idle via tray auto-reset timer
                    # Don't immediately go to idle - let the tray controller handle the 2s auto-reset

            # Return to idle state after completion (for non-UI state)
            mark_idle()

            # Update visual indicators - only if empty result (no auto-reset needed)
            if not text.strip() and self.visual_indicators_enabled:
                update_tray_status(self.tray_controller, "idle", False)
                if VISUAL_INDICATORS_AVAILABLE:
                    hide_status()

            return text
            
        except Exception as e:
            print(f"[TRANSCRIPTION] Error: {e}")
            traceback.print_exc()
            self._log.exception("transcription_error: %s", e)

            # Mark error state
            mark_error(f"Transcription error: {e}")

            # Update visual indicators - transcription error
            if self.visual_indicators_enabled:
                update_tray_status(self.tray_controller, "error", False, f"Transcription error: {e}")
                if VISUAL_INDICATORS_AVAILABLE:
                    show_error(f"Transcription error: {e}")

            # Return to idle after error
            time.sleep(2)  # Brief pause before returning to idle
            mark_idle()

            return ""
    
    def shutdown(self):
        """Graceful shutdown with cleanup"""
        print("[EnhancedApp] Shutting down...")
        
        # Stop recording if active
        if self.rec.is_recording():
            try:
                self.rec.stop()
            except Exception:
                pass
        
        # Shutdown transcription manager
        self.transcription_manager.shutdown()
        
        # Session summary with ASR statistics
        session_duration = time.time() - self._session_start_time
        asr_stats = self.asr.get_clean_statistics()
        
        print(f"[SESSION] Duration: {session_duration:.1f}s, "
              f"Words: {self._session_word_count}, "
              f"Transcription time: {self._total_transcription_time:.1f}s")
        print(f"[ASR STATS] Recordings: {asr_stats['transcription_count']}, "
              f"Avg Speed: {asr_stats['average_speed_factor']:.1f}x, "
              f"VAD Fallback: {asr_stats['vad_fallback_triggered']}")
        
        print("[EnhancedApp] Shutdown complete")


def main(argv=None):
    """Enhanced main with better error handling and monitoring"""
    cfg = load_config(Config())

    # Initialize async logging to a rotating file
    _alog = AsyncLogger(default_log_dir())

    # Start idle-aware monitoring for long-running operation
    print("[MONITOR] Starting idle-aware monitoring for 24/7 operation...")
    monitor = start_idle_monitoring(
        operation_timeout=120.0,        # 2 minutes max for active operations
        memory_warning_mb=1024.0,       # Warn at 1GB
        memory_critical_mb=2048.0,      # Critical at 2GB
        check_interval=10.0             # Check every 10 seconds
    )

    # Set up monitoring callbacks
    def on_hang_detected(reason: str):
        print(f"[MONITOR] HANG DETECTED: {reason}")
        # Could trigger restart here if desired
        # For now, just log it

    def on_memory_warning(memory_mb: float):
        print(f"[MONITOR] Memory warning: {memory_mb:.1f}MB")

    monitor.on_hang_detected = on_hang_detected
    monitor.on_memory_warning = on_memory_warning

    # Mark initial state as idle
    mark_idle()

    if not is_admin():
        print("Warning: Not running as Administrator. Global hotkeys and key injection may be limited in elevated apps.")
    info = nvidia_smi_info()
    if info:
        print(f"GPU: {info}")

    app = EnhancedApp(cfg)

    # Enhanced tray support with visual indicators
    tray = None
    if cfg.use_tray:
        try:
            tray = EnhancedTrayController(app)
            app.tray_controller = tray  # Connect to app for status updates
            tray.start()
            print("Enhanced tray with visual indicators started.")
        except Exception as e:
            print(f"Enhanced tray failed to start: {e}")
            # Fallback to basic tray
            try:
                tray = TrayController(app)
                tray.start()
                print("Basic tray started.")
            except Exception as e2:
                print(f"Basic tray also failed: {e2}")

    # Enhanced hotkey toggles with better feedback
    def toggle_code_mode():
        app.code_mode = not app.code_mode
        state = "ON" if app.code_mode else "OFF"
        print(f"[CONFIG] Code mode: {state}")
        save_config(app.cfg)

    def toggle_injection():
        app.cfg.paste_injection = not app.cfg.paste_injection
        state = "Paste" if app.cfg.paste_injection else "Type"
        print(f"[CONFIG] Injection: {state}")
        save_config(app.cfg)

    def toggle_enter():
        app.cfg.press_enter_after_paste = not app.cfg.press_enter_after_paste
        state = "ON" if app.cfg.press_enter_after_paste else "OFF"
        print(f"[CONFIG] After-paste Enter: {state}")
        save_config(app.cfg)

    # Register hotkeys
    keyboard.add_hotkey('ctrl+alt+c', toggle_code_mode, suppress=False)
    keyboard.add_hotkey('ctrl+alt+p', toggle_injection, suppress=False)
    keyboard.add_hotkey('ctrl+alt+enter', toggle_enter, suppress=False)

    # Enhanced PTT listener with tail-end buffer
    listener = EnhancedPTTHotkeyListener(
        cfg,
        on_start=app.start_recording,
        on_stop=app.stop_recording,
    )
    
    try:
        listener.start()
        print("\n" + "="*70)
        print("VoiceFlow Enhanced - 24/7 Idle-Aware Operation")
        print("="*70)
        print(f"Hotkey: {'Ctrl+' if cfg.hotkey_ctrl else ''}"
              f"{'Shift+' if cfg.hotkey_shift else ''}"
              f"{'Alt+' if cfg.hotkey_alt else ''}"
              f"{cfg.hotkey_key.upper() if cfg.hotkey_key else '[Modifiers Only]'}")
        print("Visual Feedback: Bottom-screen overlay + Dynamic tray icon")
        print("Monitoring: Idle-aware (supports hours/days of inactivity)")
        print("Max recording: 5 minutes")
        print("Operation timeout: 2 minutes")
        print("Memory limit: 2GB")
        print(f"Visual indicators: {'Enabled' if app.visual_indicators_enabled else 'Disabled'}")
        print("="*70)
        print("Ready for 24/7 background operation. Waiting for hotkey...")

        # Add heartbeat to main loop to prove we're alive
        def heartbeat_thread():
            """Send periodic heartbeats while idle"""
            while True:
                try:
                    record_heartbeat()
                    time.sleep(30)  # Heartbeat every 30 seconds
                except:
                    break

        heartbeat = threading.Thread(target=heartbeat_thread, daemon=True)
        heartbeat.start()

        listener.run_forever()
        
    except KeyboardInterrupt:
        print("\n[MAIN] Shutdown requested...")
    except Exception as e:
        print(f"[MAIN] Fatal error: {e}")
        traceback.print_exc()
    finally:
        # Graceful cleanup
        try:
            print("[MAIN] Stopping idle-aware monitoring...")
            stop_idle_monitoring()
            listener.stop()
            app.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())