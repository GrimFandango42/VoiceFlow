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

from .config import Config
from .audio_enhanced import EnhancedAudioRecorder
from .asr_buffer_safe import BufferSafeWhisperASR as WhisperASR
from .inject import ClipboardInjector
from .hotkeys_enhanced import EnhancedPTTHotkeyListener
from .utils import is_admin, nvidia_smi_info
from .textproc import apply_code_mode
import keyboard
from .tray import TrayController
from .logging_setup import AsyncLogger, default_log_dir
from .settings import load_config, save_config


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
            
            # Perform transcription
            result = callback(audio_data)
            
            # Performance metrics
            processing_time = time.perf_counter() - start_time
            speed_factor = duration / processing_time if processing_time > 0 else 0
            
            print(f"[TranscriptionManager] {job_id}: Completed in {processing_time:.2f}s "
                  f"({speed_factor:.1f}x realtime)")
            
            return result
            
        except Exception as e:
            print(f"[TranscriptionManager] {job_id}: Error - {e}")
            traceback.print_exc()
            raise
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
        
        # Long conversation tracking
        self._session_start_time = time.time()
        self._total_transcription_time = 0.0
        self._session_word_count = 0
        
        print("[EnhancedApp] Initialized with enhanced thread management")

    def start_recording(self):
        """Enhanced recording start with better error handling"""
        try:
            if not self.rec.is_recording():
                print("[MIC] Listening...")
                self._log.info("recording_started")
                self.rec.start()
                
                # Monitor for very long recordings
                current_duration = self.rec.get_current_duration()
                if current_duration > 0:
                    print(f"[MIC] Resuming recording ({current_duration:.1f}s elapsed)")
                    
        except Exception as e:
            print(f"[MIC] Audio start error: {e}")
            traceback.print_exc()
            self._log.exception("audio_start_error: %s", e)

    def stop_recording(self):
        """Enhanced recording stop with improved transcription handling"""
        try:
            audio = self.rec.stop()
            audio_duration = len(audio) / self.cfg.sample_rate if len(audio) > 0 else 0
            
            self._log.info("recording_stopped duration=%.2f samples=%d", 
                          audio_duration, len(audio))
            
            if audio.size == 0:
                print("[MIC] No audio captured")
                return
            
            print(f"[MIC] Captured {audio_duration:.2f}s of audio ({len(audio)} samples)")
            
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

    def _perform_transcription(self, audio_data: np.ndarray) -> str:
        """Perform actual transcription with enhanced error handling"""
        try:
            start_time = time.perf_counter()
            
            # Transcribe
            text = self.asr.transcribe(audio_data)
            
            # Apply processing
            if self.code_mode:
                text = apply_code_mode(text, lowercase=self.cfg.code_mode_lowercase)
            
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
                self.injector.inject(text)
                self._log.info("transcribed chars=%d words=%d seconds=%.3f", 
                             len(text), len(text.split()), transcription_time)
            
            return text
            
        except Exception as e:
            print(f"[TRANSCRIPTION] Error: {e}")
            traceback.print_exc()
            self._log.exception("transcription_error: %s", e)
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

    if not is_admin():
        print("Warning: Not running as Administrator. Global hotkeys and key injection may be limited in elevated apps.")
    info = nvidia_smi_info()
    if info:
        print(f"GPU: {info}")

    app = EnhancedApp(cfg)

    # Enhanced tray support
    tray = None
    if cfg.use_tray:
        try:
            tray = TrayController(app)
            tray.start()
            print("Enhanced tray started.")
        except Exception as e:
            print(f"Tray failed to start: {e}")

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
        print("\n" + "="*60)
        print("VoiceFlow Enhanced - Long Conversation Support")
        print("="*60)
        print(f"Hotkey: {'Ctrl+' if cfg.hotkey_ctrl else ''}"
              f"{'Shift+' if cfg.hotkey_shift else ''}"
              f"{'Alt+' if cfg.hotkey_alt else ''}"
              f"{cfg.hotkey_key.upper() if cfg.hotkey_key else '[Modifiers Only]'}")
        print("Tail buffer: 1.0s (continues after key release)")
        print("Max recording: 5 minutes")
        print("Thread management: Enhanced")
        print("Memory: Bounded ring buffer")
        print("="*60)
        
        listener.run_forever()
        
    except KeyboardInterrupt:
        print("\n[MAIN] Shutdown requested...")
    except Exception as e:
        print(f"[MAIN] Fatal error: {e}")
        traceback.print_exc()
    finally:
        # Graceful cleanup
        try:
            listener.stop()
            app.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())