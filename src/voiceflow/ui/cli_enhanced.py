from __future__ import annotations

import threading
import traceback
import sys
import os
import re
from typing import Optional, Dict, Any, Deque, Tuple
import logging
import time
import ctypes
from types import SimpleNamespace
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, Future
from collections import deque

import numpy as np

from voiceflow.core.config import Config
from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
# Use new unified ASR engine with model tier support
from voiceflow.core.asr_engine import ModernWhisperASR as WhisperASR
# Cold start elimination
from voiceflow.core.preloader import ModelPreloader, PreloadState
# Streaming preview
from voiceflow.core.streaming import StreamingTranscriber, StreamingResult
from voiceflow.integrations.inject import ClipboardInjector
from voiceflow.integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener
from voiceflow.utils.utils import is_admin, nvidia_smi_info
from voiceflow.core.textproc import apply_code_mode, format_transcript_text, normalize_context_terms
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
_SINGLE_INSTANCE_MUTEX = None


def _acquire_single_instance_mutex() -> bool:
    """
    Prevent duplicate VoiceFlow CLI instances.
    Duplicate listeners race on global hotkeys and cause random start/stop behavior.
    """
    global _SINGLE_INSTANCE_MUTEX
    try:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexW(None, False, "Local\\VoiceFlow_CLI_Enhanced")
        if not mutex:
            return True
        _SINGLE_INSTANCE_MUTEX = mutex
        ERROR_ALREADY_EXISTS = 183
        if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
            print("[MAIN] Another VoiceFlow instance is already running. Exiting duplicate process.")
            return False
        return True
    except Exception:
        # Non-Windows or mutex failure: do not block startup.
        return True


def _is_primary_cli_process() -> bool:
    """
    Extra duplicate-instance guard.
    Keep only the oldest running `-m voiceflow.ui.cli_enhanced` process.
    """
    try:
        import psutil  # type: ignore
    except Exception:
        return True

    me = os.getpid()
    matches: list[tuple[int, float, int]] = []
    for proc in psutil.process_iter(["pid", "create_time", "cmdline", "name", "ppid"]):
        try:
            name = str(proc.info.get("name") or "").lower()
            if name not in {"python.exe", "pythonw.exe", "python"}:
                continue
            cmd_list = [str(part).strip() for part in (proc.info.get("cmdline") or []) if str(part).strip()]
            cmdline = " ".join(cmd_list)
            if "-m voiceflow.ui.cli_enhanced" in cmdline:
                matches.append(
                    (
                        int(proc.info["pid"]),
                        float(proc.info.get("create_time") or 0.0),
                        int(proc.info.get("ppid") or 0),
                    )
                )
        except Exception:
            continue

    if not matches:
        return True
    pids = {pid for pid, _, _ in matches}
    parent_refs = {ppid for _, _, ppid in matches}
    leaf_pids = [pid for pid, _, _ in matches if pid not in parent_refs]

    if leaf_pids:
        # Prefer the newest leaf process so parent bootstrap duplicates self-exit.
        by_pid = {pid: (ts, ppid) for pid, ts, ppid in matches}
        primary_pid = sorted(leaf_pids, key=lambda pid: (by_pid[pid][0], pid))[-1]
    else:
        # Fallback: oldest process wins; break ties by lowest pid.
        primary_pid = sorted(matches, key=lambda item: (item[1], item[0]))[0][0]

    if me != primary_pid:
        print(
            f"[MAIN] Duplicate VoiceFlow process detected (pid={me}, primary={primary_pid}). "
            "Exiting duplicate process."
        )
        return False
    return True


def _list_cli_processes() -> list[tuple[int, float]]:
    """Return running VoiceFlow CLI process tuples as (pid, create_time)."""
    try:
        import psutil  # type: ignore
    except Exception:
        return []

    matches: list[tuple[int, float]] = []
    for proc in psutil.process_iter(["pid", "create_time", "cmdline", "name"]):
        try:
            name = str(proc.info.get("name") or "").lower()
            if name not in {"python.exe", "pythonw.exe", "python"}:
                continue
            cmd_list = [str(part).strip() for part in (proc.info.get("cmdline") or []) if str(part).strip()]
            if "-m" not in cmd_list:
                continue
            # Strict module match to avoid false positives from arbitrary command text.
            if "voiceflow.ui.cli_enhanced" not in cmd_list:
                continue
            matches.append((int(proc.info["pid"]), float(proc.info.get("create_time") or 0.0)))
        except Exception:
            continue
    return matches


def _enforce_single_instance() -> bool:
    """
    Keep only one `voiceflow.ui.cli_enhanced` process.
    Chooses the newest process (ties: highest PID), terminates the others.
    """
    try:
        import psutil  # type: ignore
    except Exception:
        return True

    me = os.getpid()
    processes = _list_cli_processes()
    if not processes:
        return True

    keep_pid = sorted(processes, key=lambda item: (item[1], item[0]))[-1][0]
    for pid, _ in processes:
        if pid == keep_pid:
            continue
        try:
            psutil.Process(pid).terminate()
        except Exception:
            continue

    if me != keep_pid:
        print(f"[MAIN] Exiting duplicate VoiceFlow process (pid={me}, active={keep_pid}).")
        return False
    return True


def _terminate_duplicate_parent() -> None:
    """If parent is another VoiceFlow Python instance, terminate it to avoid dual listeners."""
    try:
        import psutil  # type: ignore
        me = psutil.Process(os.getpid())
        parent = me.parent()
        if not parent:
            return
        pname = str(parent.name() or "").lower()
        if pname not in {"python.exe", "pythonw.exe", "python"}:
            return
        cmd = " ".join(parent.cmdline() or [])
        if (
            "voiceflow.ui.cli_enhanced" in cmd
            or "from voiceflow.ui.cli_enhanced import main" in cmd
        ):
            try:
                parent.terminate()
            except Exception:
                pass
    except Exception:
        pass


def _yield_if_bootstrap_parent(wait_seconds: float = 1.2) -> bool:
    """
    Some environments bootstrap a child python process with the same VoiceFlow entrypoint.
    If this process spawned such a child, parent should exit early to avoid duplicate listeners/UI.
    Returns True when caller should exit.
    """
    try:
        import psutil  # type: ignore
        me = psutil.Process(os.getpid())
        time.sleep(max(0.2, float(wait_seconds)))
        for child in me.children(recursive=False):
            try:
                name = str(child.name() or "").lower()
                if name not in {"python.exe", "pythonw.exe", "python"}:
                    continue
                cmd = " ".join(child.cmdline() or [])
                if (
                    "-m voiceflow.ui.cli_enhanced" in cmd
                    or "from voiceflow.ui.cli_enhanced import main" in cmd
                ):
                    print(
                        f"[MAIN] Bootstrap parent detected (pid={os.getpid()}) "
                        f"-> child pid={child.pid}. Parent exiting."
                    )
                    return True
            except Exception:
                continue
    except Exception:
        return False
    return False


def _start_bootstrap_parent_watchdog(window_seconds: float = 10.0) -> None:
    """
    During startup, periodically check whether this process spawned a same-entrypoint child.
    If yes, exit parent to avoid duplicate listeners.
    """
    def _worker() -> None:
        deadline = time.time() + max(2.0, float(window_seconds))
        while time.time() < deadline:
            if _yield_if_bootstrap_parent(wait_seconds=0.0):
                os._exit(0)
            time.sleep(0.8)

    threading.Thread(target=_worker, name="BootstrapParentWatchdog", daemon=True).start()


def _has_same_entry_child() -> bool:
    try:
        import psutil  # type: ignore
        me = psutil.Process(os.getpid())
        for child in me.children(recursive=False):
            try:
                name = str(child.name() or "").lower()
                if name not in {"python.exe", "pythonw.exe", "python"}:
                    continue
                cmd = " ".join(child.cmdline() or [])
                if (
                    "-m voiceflow.ui.cli_enhanced" in cmd
                    or "from voiceflow.ui.cli_enhanced import main" in cmd
                ):
                    return True
            except Exception:
                continue
    except Exception:
        return False
    return False


def _start_single_instance_watchdog(interval_seconds: float = 2.0) -> threading.Thread:
    """Continuously enforce single-instance behavior after startup races."""
    def _worker() -> None:
        while True:
            time.sleep(max(0.5, float(interval_seconds)))
            try:
                if not _enforce_single_instance():
                    os._exit(0)
            except Exception:
                # Never crash watchdog caller due diagnostic failures.
                continue

    thread = threading.Thread(target=_worker, name="SingleInstanceWatchdog", daemon=True)
    thread.start()
    return thread

# Visual indicators integration
try:
    from voiceflow.ui.visual_indicators import (
        show_listening, show_processing, show_transcribing,
        show_complete, show_error, hide_status,
        show_preview as visual_show_preview, clear_preview as visual_clear_preview,
        record_transcription_event as visual_record_transcription_event,
        update_audio_level as visual_update_audio_level,
    )
    VISUAL_INDICATORS_AVAILABLE = True
except ImportError:
    VISUAL_INDICATORS_AVAILABLE = False
    def visual_show_preview(text): pass
    def visual_clear_preview(): pass
    def visual_record_transcription_event(text, audio_duration, processing_time): pass
    def visual_update_audio_level(level): pass


class EnhancedTranscriptionManager:
    """Enhanced thread-safe transcription manager for long conversations"""
    
    def __init__(self, max_concurrent_jobs: int = 2, worker_timeout_seconds: float = 45.0):
        self.executor = ThreadPoolExecutor(
            max_workers=max_concurrent_jobs,
            thread_name_prefix="Transcriber"
        )
        self.worker_timeout_seconds = max(5.0, float(worker_timeout_seconds))
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

            # Wait with timeout to keep app responsive even if backend hangs.
            timeout_seconds = max(5.0, min(self.worker_timeout_seconds, max(15.0, duration * 3.0)))
            thread.join(timeout=timeout_seconds)

            if thread.is_alive():
                print(f"[TranscriptionManager] {job_id}: Thread timeout ({timeout_seconds:.1f}s) - transcription hung")
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
        self.injector = ClipboardInjector(cfg)

        # Cold start elimination: Create ASR and start background preloading
        print("[STARTUP] Creating ASR engine...")
        self.asr = WhisperASR(cfg)
        self._preloader = ModelPreloader(self.asr, on_progress=self._on_preload_progress)
        self._model_ready = False
        self.asr_fast: Optional[WhisperASR] = None
        self._fast_preloader: Optional[ModelPreloader] = None
        self._fast_model_ready = False

        # Start background preloading immediately
        print("[STARTUP] Starting background model preload...")
        self._preloader.start_preload()
        self._init_fast_asr_path()

        # Enhanced thread management
        self.transcription_manager = EnhancedTranscriptionManager(
            max_concurrent_jobs=1,
            worker_timeout_seconds=getattr(cfg, "transcription_worker_timeout_seconds", 45.0),
        )
        self.postprocess_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="PostProcess")
        self.checkpoint_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="LiveCheckpoint")

        self.code_mode = cfg.code_mode_default
        self._log = logging.getLogger("localflow")

        # Visual indicators integration
        self.tray_controller: Optional[EnhancedTrayController] = None
        self.visual_indicators_enabled = getattr(cfg, 'visual_indicators_enabled', True)

        # AI Enhancement Layer (VoiceFlow 3.0)
        self.ai_enabled = getattr(cfg, 'enable_ai_enhancement', True)
        self.course_corrector = None
        self.command_mode = None
        self.adaptive_learning = None

        if self.ai_enabled:
            try:
                from voiceflow.ai.course_corrector import CourseCorrector
                from voiceflow.ai.command_mode import CommandMode

                use_correction = getattr(cfg, 'enable_course_correction', True)
                use_commands = getattr(cfg, 'enable_command_mode', True)

                if use_correction:
                    self.course_corrector = CourseCorrector(use_llm=True)
                if use_commands:
                    self.command_mode = CommandMode(
                        use_llm=True,
                        requires_prefix=getattr(cfg, "command_mode_requires_prefix", True),
                        prefix=getattr(cfg, "command_mode_prefix", "command"),
                    )

                print(f"[AI] Enhancement layer enabled (correction: {use_correction}, commands: {use_commands})")
            except Exception as e:
                print(f"[AI] Enhancement layer not available: {e}")
                self.ai_enabled = False

        if getattr(cfg, 'adaptive_learning_enabled', True):
            try:
                from voiceflow.ai.adaptive_memory import AdaptiveLearningManager
                self.adaptive_learning = AdaptiveLearningManager(cfg)
                print("[AI] Adaptive learning enabled (local temp audit log)")
            except Exception as e:
                print(f"[AI] Adaptive learning unavailable: {e}")
                self.adaptive_learning = None

        # Long conversation tracking
        self._session_start_time = time.time()
        self._total_transcription_time = 0.0
        self._session_word_count = 0
        self._perf_window: Deque[Tuple[float, float]] = deque(maxlen=20)  # (audio_s, processing_s)
        self._perf_total_audio = 0.0
        self._perf_total_processing = 0.0
        self._perf_total_count = 0

        # Streaming preview (VoiceFlow 3.0)
        self.live_caption_enabled = bool(getattr(cfg, "live_caption_enabled", True))
        self.streaming_enabled = bool(getattr(cfg, 'enable_streaming', True)) and self.live_caption_enabled
        self._streaming_transcriber: Optional[StreamingTranscriber] = None
        self._streaming_start_timer: Optional[threading.Timer] = None
        self._last_preview_text = ""
        self._audio_visual_thread: Optional[threading.Thread] = None
        self._audio_visual_stop = threading.Event()
        self._audio_noise_floor = 0.0
        self._live_checkpoint_thread: Optional[threading.Thread] = None
        self._live_checkpoint_stop = threading.Event()
        self._checkpoint_lock = threading.Lock()
        self._checkpoint_next_seconds = max(3.0, float(getattr(cfg, "live_checkpoint_seconds", 10.0)))
        self._checkpoint_last_sample_idx = 0
        self._checkpoint_in_flight = False
        self._checkpoint_preview_parts: Deque[str] = deque(maxlen=24)
        self._checkpoint_last_text = ""
        self._checkpoint_committed_sample_idx = 0
        self._checkpoint_live_injected = False
        self.ptt_listener: Optional[EnhancedPTTHotkeyListener] = None

        print(f"[EnhancedApp] Initialized with enhanced thread management and visual indicators {'enabled' if self.visual_indicators_enabled else 'disabled'}")
        print(f"[EnhancedApp] Streaming preview: {'Enabled' if self.streaming_enabled else 'Disabled'}")

    def _on_preload_progress(self, progress):
        """Handle preload progress updates"""
        if progress.state == PreloadState.LOADING:
            print(f"[MODEL] Loading: {progress.message}")
        elif progress.state == PreloadState.WARMING_UP:
            print(f"[MODEL] Warming up: {progress.message}")
        elif progress.state == PreloadState.READY:
            self._model_ready = True
            print(f"[MODEL] Ready! {progress.message}")
        elif progress.state == PreloadState.FAILED:
            print(f"[MODEL] FAILED: {progress.message}")

    def _on_fast_preload_progress(self, progress):
        if progress.state == PreloadState.READY:
            self._fast_model_ready = True
            print(f"[MODEL] Fast path ready ({getattr(self.cfg, 'latency_boost_model_tier', 'tiny')})")

    def _init_fast_asr_path(self) -> None:
        """Optional low-latency ASR path for short utterances."""
        if not getattr(self.cfg, "latency_boost_enabled", True):
            return

        fast_tier = str(getattr(self.cfg, "latency_boost_model_tier", "tiny")).strip().lower()
        base_tier = str(getattr(self.cfg, "model_tier", "quick")).strip().lower()
        if fast_tier == base_tier:
            return

        try:
            fast_cfg = SimpleNamespace(**self.cfg.__dict__)
            fast_cfg.model_tier = fast_tier
            if fast_tier == "tiny":
                fast_cfg.model_name = "tiny.en"
            self.asr_fast = WhisperASR(fast_cfg)
            self._fast_preloader = ModelPreloader(self.asr_fast, on_progress=self._on_fast_preload_progress)
            self._fast_preloader.start_preload()
        except Exception as e:
            logger.warning(f"Fast ASR path unavailable: {e}")
            self.asr_fast = None
            self._fast_preloader = None
            self._fast_model_ready = False

    def _pick_asr_engine(self, audio_duration: float):
        """Pick fast engine for short audio to reduce perceived latency."""
        if not self.asr_fast:
            return self.asr, "primary"
        threshold = float(getattr(self.cfg, "latency_boost_max_audio_seconds", 12.0))
        if 0.0 < audio_duration <= threshold:
            return self.asr_fast, "fast"
        return self.asr, "primary"

    def _compact_pauses(self, audio_data: np.ndarray) -> np.ndarray:
        """
        Remove long silence spans from lengthy recordings to reduce inference time.
        Keeps a small silence margin around detected speech to preserve phrase boundaries.
        """
        if not getattr(self.cfg, "enable_pause_compaction", True):
            return audio_data
        if audio_data is None or len(audio_data) == 0:
            return audio_data

        sample_rate = int(getattr(self.cfg, "sample_rate", 16000))
        audio_duration = len(audio_data) / float(sample_rate)
        min_duration = float(getattr(self.cfg, "pause_compaction_min_audio_seconds", 14.0))
        if audio_duration < min_duration:
            return audio_data

        frame_ms = max(10, int(getattr(self.cfg, "pause_compaction_frame_ms", 30)))
        frame_len = max(160, int(sample_rate * frame_ms / 1000.0))
        keep_ms = max(50, int(getattr(self.cfg, "pause_compaction_keep_silence_ms", 180)))
        keep_frames = max(1, int(keep_ms / frame_ms))

        # Align to whole frames for vectorized RMS estimation.
        usable = (len(audio_data) // frame_len) * frame_len
        if usable <= 0:
            return audio_data
        framed = audio_data[:usable].reshape(-1, frame_len)
        rms = np.sqrt(np.mean(framed * framed, axis=1))

        base_thr = float(getattr(self.cfg, "min_rms_amplitude", 5e-4))
        noise_floor = float(np.percentile(rms, 20))
        if audio_duration >= 10.0:
            dyn_thr = max(base_thr * 1.6, noise_floor * 2.6)
        else:
            dyn_thr = max(base_thr * 1.3, noise_floor * 2.0)
        speech = rms >= dyn_thr
        speech_ratio = float(np.mean(speech)) if speech.size > 0 else 1.0
        if audio_duration >= 10.0 and speech_ratio > 0.92:
            # Fallback for "always speech" masks caused by room noise in long dictation.
            dyn_thr_alt = max(base_thr * 2.0, float(np.percentile(rms, 55)) * 1.1)
            speech = rms >= dyn_thr_alt

        # Remove tiny speech blips so long pauses are compacted more effectively.
        min_speech_frames = max(1, int(120 / frame_ms))
        if np.any(speech) and min_speech_frames > 1:
            filtered = speech.copy()
            i = 0
            n = len(filtered)
            while i < n:
                if filtered[i]:
                    j = i + 1
                    while j < n and filtered[j]:
                        j += 1
                    if (j - i) < min_speech_frames:
                        filtered[i:j] = False
                    i = j
                else:
                    i += 1
            speech = filtered
        if not np.any(speech):
            return audio_data

        # Dilate speech mask to preserve short pauses near speech.
        dilated = speech.copy()
        for shift in range(1, keep_frames + 1):
            dilated[:-shift] |= speech[shift:]
            dilated[shift:] |= speech[:-shift]

        kept_frames = framed[dilated]
        if kept_frames.size == 0:
            return audio_data

        compacted = kept_frames.reshape(-1)
        max_reduction_pct = float(getattr(self.cfg, "pause_compaction_max_reduction_pct", 60.0))
        min_keep_ratio = max(0.2, 1.0 - max(0.0, min(95.0, max_reduction_pct)) / 100.0)
        if (len(compacted) / len(audio_data)) < min_keep_ratio:
            # Over-compaction guardrail: preserve more context for recognition quality.
            return audio_data
        # Keep any tail samples if original ends with speech-like energy.
        tail = audio_data[usable:]
        if tail.size > 0 and np.sqrt(np.mean(tail * tail)) >= dyn_thr:
            compacted = np.concatenate((compacted, tail))
        return compacted

    def wait_for_model(self, timeout: float = 60.0) -> bool:
        """Wait for model to be ready"""
        if self._model_ready:
            return True
        return self._preloader.wait_for_ready(timeout)

    def is_model_ready(self) -> bool:
        """Check if model is ready for transcription"""
        return self._model_ready or self._preloader.is_ready

    def _reset_checkpoint_state(self) -> None:
        with self._checkpoint_lock:
            self._checkpoint_next_seconds = max(3.0, float(getattr(self.cfg, "live_checkpoint_seconds", 10.0)))
            self._checkpoint_last_sample_idx = 0
            self._checkpoint_in_flight = False
            self._checkpoint_preview_parts.clear()
            self._checkpoint_last_text = ""
            self._checkpoint_committed_sample_idx = 0
            self._checkpoint_live_injected = False

    def _queue_checkpoint_preview(self, audio_snapshot: np.ndarray, current_duration: float) -> None:
        """Run a lightweight checkpoint transcript every N seconds while recording."""
        if not getattr(self.cfg, "live_flush_during_hold", False):
            return
        if not getattr(self.cfg, "live_checkpoint_enabled", True):
            return
        if audio_snapshot is None or len(audio_snapshot) == 0:
            return

        sample_rate = int(getattr(self.cfg, "sample_rate", 16000))
        chunk_seconds = max(3.0, float(getattr(self.cfg, "live_checkpoint_seconds", 10.0)))
        min_chunk_seconds = max(2.0, float(getattr(self.cfg, "live_checkpoint_min_audio_seconds", 6.0)))

        inject_mode = bool(getattr(self.cfg, "live_checkpoint_inject", True))
        with self._checkpoint_lock:
            if self._checkpoint_in_flight:
                return
            if current_duration < self._checkpoint_next_seconds:
                return

            start_idx = int(self._checkpoint_committed_sample_idx if inject_mode else self._checkpoint_last_sample_idx)
            end_idx = int(len(audio_snapshot))
            if end_idx <= start_idx:
                return

            segment_duration = (end_idx - start_idx) / float(sample_rate)
            if segment_duration < min_chunk_seconds:
                return

            segment = audio_snapshot[start_idx:end_idx].copy()
            if not inject_mode:
                # Preview-only mode can advance by queued segment.
                self._checkpoint_last_sample_idx = end_idx
            while self._checkpoint_next_seconds <= current_duration:
                self._checkpoint_next_seconds += chunk_seconds
            self._checkpoint_in_flight = True

        print(f"[LIVE] checkpoint queued dur={segment_duration:.1f}s total={current_duration:.1f}s")
        self.checkpoint_executor.submit(self._run_checkpoint_preview, segment, segment_duration, end_idx)

    def _run_checkpoint_preview(self, segment: np.ndarray, segment_duration: float, end_sample_idx: int) -> None:
        try:
            # Prefer fast ASR path, but always fallback so live flush does not silently skip.
            engine = self.asr_fast if (self.asr_fast and self._fast_model_ready) else self.asr
            text = engine.transcribe(segment)
            text = normalize_context_terms(text)
            if self.code_mode:
                text = apply_code_mode(text, lowercase=self.cfg.code_mode_lowercase)
            else:
                text = format_transcript_text(text)
            text = (text or "").strip()
            if not text:
                return

            with self._checkpoint_lock:
                duplicate = (text == self._checkpoint_last_text)
                self._checkpoint_last_text = text
                if not duplicate:
                    self._checkpoint_preview_parts.append(text)
                preview_full = " ".join(self._checkpoint_preview_parts).strip()

            max_chars = max(120, int(getattr(self.cfg, "live_checkpoint_preview_chars", 260)))
            preview_tail = preview_full[-max_chars:]
            print(f"[LIVE {segment_duration:.1f}s] {text}")
            if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
                visual_show_preview(preview_tail)

            injected_ok = False
            inject_mode = bool(getattr(self.cfg, "live_checkpoint_inject", True))
            if inject_mode:
                listener = self.ptt_listener
                if listener is not None:
                    # Keyboard injection can emit synthetic key transitions; suppress their stop side-effects.
                    suppress_for = min(2.0, max(0.35, 0.2 + (len(text) / 120.0)))
                    try:
                        listener.suppress_event_side_effects(suppress_for)
                    except Exception:
                        pass
                injected_ok = bool(self.injector.inject_live_checkpoint(text + " "))
                if injected_ok:
                    with self._checkpoint_lock:
                        self._checkpoint_committed_sample_idx = max(
                            self._checkpoint_committed_sample_idx, int(end_sample_idx)
                        )
                        self._checkpoint_last_sample_idx = max(
                            self._checkpoint_last_sample_idx, int(end_sample_idx)
                        )
                        self._checkpoint_live_injected = True
                else:
                    self._log.warning(
                        "live_checkpoint_inject_failed segment_duration=%.2f end_sample_idx=%d",
                        segment_duration,
                        int(end_sample_idx),
                    )
            else:
                # Preview-only mode should not retry duplicate text endlessly.
                with self._checkpoint_lock:
                    self._checkpoint_last_sample_idx = max(
                        self._checkpoint_last_sample_idx, int(end_sample_idx)
                    )
        except Exception as e:
            logger.debug(f"Live checkpoint preview failed: {e}")
        finally:
            with self._checkpoint_lock:
                self._checkpoint_in_flight = False

    def _on_streaming_preview(self, result: StreamingResult) -> None:
        """Handle streaming preview update"""
        if result.text and result.text != self._last_preview_text:
            self._last_preview_text = result.text
            # Caption-style preview: keep latest 1-2 words for large, readable live feedback.
            words = re.findall(r"\S+", result.text.strip())
            keep_words = max(1, int(getattr(self.cfg, "live_caption_words", 2)))
            caption_text = " ".join(words[-keep_words:]) if words else result.text.strip()
            preview_display = caption_text[:60] + "..." if len(caption_text) > 60 else caption_text
            print(f"[PREVIEW] {preview_display}")

            # Update visual overlay preview
            if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
                # Send full partial text to UI so it can render flowing word bubbles.
                visual_show_preview(result.text)

    def _start_streaming_preview(self) -> None:
        """Start streaming preview for real-time transcription feedback"""
        try:
            if self._streaming_transcriber is not None:
                return
            self._last_preview_text = ""
            self._streaming_transcriber = StreamingTranscriber(
                self.asr_fast if self.asr_fast else self.asr,
                sample_rate=self.cfg.sample_rate,
                chunk_duration=0.70,
                min_audio_duration=0.40,
                on_partial=self._on_streaming_preview,
            )
            self._streaming_transcriber.start()

            # Start a thread to periodically feed audio to the streamer
            self._streaming_thread = threading.Thread(
                target=self._streaming_feed_loop,
                daemon=True,
                name="StreamingFeed",
            )
            self._streaming_thread.start()
            logger.debug("Streaming preview started")
        except Exception as e:
            logger.warning(f"Failed to start streaming preview: {e}")
            self._streaming_transcriber = None

    def _schedule_streaming_preview(self) -> None:
        """Delay caption ASR startup so short utterances stay ultra-fast."""
        if not self.streaming_enabled or not self._model_ready:
            return
        delay = max(0.0, float(getattr(self.cfg, "live_caption_start_delay_seconds", 1.8)))
        if delay <= 0.0:
            self._start_streaming_preview()
            return
        if self._streaming_start_timer and self._streaming_start_timer.is_alive():
            return

        def _delayed_start() -> None:
            if self.rec.is_recording():
                self._start_streaming_preview()

        self._streaming_start_timer = threading.Timer(delay, _delayed_start)
        self._streaming_start_timer.daemon = True
        self._streaming_start_timer.start()

    def _streaming_feed_loop(self) -> None:
        """Feed audio to streaming transcriber while recording"""
        last_sample_count = 0

        while self.rec.is_recording() and self._streaming_transcriber:
            try:
                # Get current audio buffer
                audio = self.rec._ring_buffer.get_samples()
                current_count = len(audio)

                # Only add new audio
                if current_count > last_sample_count:
                    new_audio = audio[last_sample_count:]
                    self._streaming_transcriber.add_audio(new_audio)
                    last_sample_count = current_count
                    if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE and len(new_audio) > 0:
                        # Lightweight amplitude estimate for visual waveform (no ASR impact).
                        rms = float(np.sqrt(np.mean(np.square(new_audio))))
                        denom = max(1e-6, float(getattr(self.cfg, "min_rms_amplitude", 5e-4)) * 12.0)
                        level = min(1.0, (rms / denom) ** 0.7)
                        visual_update_audio_level(level)

                time.sleep(0.5)  # Check every 500ms

            except Exception as e:
                logger.warning(f"Streaming feed error: {e}")
                break

    def _start_audio_visual_monitor(self) -> None:
        """Always-on (during recording) amplitude sampler for waveform visuals."""
        if not (self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE):
            return
        if self._audio_visual_thread and self._audio_visual_thread.is_alive():
            return
        self._audio_visual_stop.clear()
        self._audio_visual_thread = threading.Thread(
            target=self._audio_visual_loop,
            daemon=True,
            name="AudioVisualLevel",
        )
        self._audio_visual_thread.start()

    def _start_live_checkpoint_monitor(self) -> None:
        """Dedicated checkpoint scheduler independent from visual update loop."""
        if not getattr(self.cfg, "live_checkpoint_enabled", True):
            return
        if self._live_checkpoint_thread and self._live_checkpoint_thread.is_alive():
            return
        self._live_checkpoint_stop.clear()
        self._live_checkpoint_thread = threading.Thread(
            target=self._live_checkpoint_loop,
            daemon=True,
            name="LiveCheckpointLoop",
        )
        self._live_checkpoint_thread.start()

    def _stop_live_checkpoint_monitor(self) -> None:
        self._live_checkpoint_stop.set()

    def _live_checkpoint_loop(self) -> None:
        while self.rec.is_recording() and not self._live_checkpoint_stop.is_set():
            try:
                current_duration = float(self.rec.get_current_duration())
                if current_duration <= 0:
                    time.sleep(0.15)
                    continue
                audio = self.rec._ring_buffer.get_data()
                if len(audio) > 0:
                    self._queue_checkpoint_preview(audio, current_duration)
                time.sleep(0.18)
            except Exception as e:
                logger.debug(f"Live checkpoint loop error: {e}")
                time.sleep(0.25)

    def _stop_audio_visual_monitor(self) -> None:
        self._audio_visual_stop.set()
        if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
            visual_update_audio_level(0.0)

    def _audio_visual_loop(self) -> None:
        while self.rec.is_recording() and not self._audio_visual_stop.is_set():
            try:
                audio = self.rec._ring_buffer.get_samples()
                if len(audio) > 0:
                    window = audio[-min(len(audio), 3200):]  # ~200ms at 16kHz
                    rms = float(np.sqrt(np.mean(np.square(window))))
                    # Adaptive floor to suppress constant movement from room noise.
                    if self._audio_noise_floor <= 0.0:
                        self._audio_noise_floor = rms
                    if rms < self._audio_noise_floor * 1.8:
                        self._audio_noise_floor = (self._audio_noise_floor * 0.96) + (rms * 0.04)

                    signal = max(0.0, rms - (self._audio_noise_floor * 1.15))
                    min_rms = float(getattr(self.cfg, "min_rms_amplitude", 5e-4))
                    denom = max(1e-6, min_rms * 4.5, self._audio_noise_floor * 3.0)
                    level_signal = min(1.0, (signal / denom) ** 0.75)
                    level_raw = min(1.0, (rms / max(1e-6, min_rms * 8.0)) ** 0.55)
                    # Keep a clear zero-state when quiet, but react strongly when speech starts.
                    if signal < max(min_rms * 0.35, self._audio_noise_floor * 0.22):
                        level = 0.0
                    else:
                        level = max(level_signal, level_raw * 0.45)
                    visual_update_audio_level(level)
                time.sleep(0.06)
            except Exception:
                break

    def _stop_streaming_preview(self) -> None:
        """Stop streaming preview"""
        if self._streaming_start_timer and self._streaming_start_timer.is_alive():
            self._streaming_start_timer.cancel()
        self._streaming_start_timer = None

        if self._streaming_transcriber:
            try:
                self._streaming_transcriber.stop()
            except Exception as e:
                logger.warning(f"Error stopping streaming preview: {e}")
            finally:
                self._streaming_transcriber = None

        # Clear visual preview
        if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
            visual_clear_preview()

    def _observe_adaptive_async(
        self,
        raw_transcript: str,
        final_text: str,
        metadata: Dict[str, Any],
    ) -> None:
        """Persist adaptive learning data without blocking text injection."""
        if not self.adaptive_learning:
            return

        def _task() -> None:
            try:
                self.adaptive_learning.observe(
                    raw_text=raw_transcript,
                    final_text=final_text,
                    metadata=metadata,
                )
            except Exception as learning_error:
                logger.debug(f"Adaptive learning observe failed: {learning_error}")

        self.postprocess_executor.submit(_task)

    def start_recording(self):
        """Enhanced recording start with better error handling"""
        try:
            if not self.rec.is_recording():
                print("[MIC] Listening...")
                self._log.info("recording_started")
                self._reset_checkpoint_state()
                self.injector.capture_target_window()

                # Mark state as recording for idle-aware monitoring
                mark_recording()

                # Update visual indicators - listening status
                if self.visual_indicators_enabled:
                    update_tray_status(self.tray_controller, "listening", True)
                    if VISUAL_INDICATORS_AVAILABLE:
                        show_listening()

                self.rec.start()
                self._start_audio_visual_monitor()
                if getattr(self.cfg, "live_flush_during_hold", False):
                    self._start_live_checkpoint_monitor()

                # Start caption preview only after sustained hold to protect short-dictation latency.
                self._schedule_streaming_preview()

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
            # Stop streaming preview first
            self._stop_streaming_preview()
            self._stop_audio_visual_monitor()
            self._stop_live_checkpoint_monitor()

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
                max_amplitude = np.max(np.abs(audio)) if audio.size > 0 else 0

                # Use config values for silence detection thresholds
                # These are intentionally LOW to avoid rejecting quiet speech
                silence_threshold = getattr(self.cfg, 'min_audio_energy', 1e-8)
                peak_threshold = getattr(self.cfg, 'min_peak_amplitude', 1e-4)

                # Check if audio is essentially silent (background noise only)
                # Both conditions must be true - energy AND peak must be below thresholds
                if audio_energy < silence_threshold and max_amplitude < peak_threshold:
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
            original_samples = len(audio_data)
            if getattr(self.cfg, "live_checkpoint_enabled", True) and getattr(self.cfg, "live_checkpoint_inject", True):
                with self._checkpoint_lock:
                    committed_idx = int(self._checkpoint_committed_sample_idx)
                    live_injected = bool(self._checkpoint_live_injected)
                if live_injected and committed_idx > 0:
                    committed_idx = min(committed_idx, len(audio_data))
                    audio_data = audio_data[committed_idx:]
                    self._log.info(
                        "live_checkpoint_tail_only committed_samples=%d total_samples=%d tail_samples=%d",
                        committed_idx,
                        original_samples,
                        len(audio_data),
                    )
                    if len(audio_data) == 0:
                        mark_idle()
                        if self.visual_indicators_enabled:
                            update_tray_status(self.tray_controller, "idle", False)
                            if VISUAL_INDICATORS_AVAILABLE:
                                hide_status()
                        return ""

            start_time = time.perf_counter()
            raw_audio_duration = len(audio_data) / self.cfg.sample_rate if len(audio_data) > 0 else 0.0
            compacted_audio = self._compact_pauses(audio_data)
            audio_duration = len(compacted_audio) / self.cfg.sample_rate if len(compacted_audio) > 0 else 0.0
            if len(compacted_audio) != len(audio_data):
                reduction_pct = 100.0 * (1.0 - (len(compacted_audio) / max(1, len(audio_data))))
                self._log.info(
                    "pause_compaction raw_duration=%.2f compacted_duration=%.2f reduction=%.1f%%",
                    raw_audio_duration,
                    audio_duration,
                    reduction_pct,
                )
            self._log.info(
                "transcription_started duration=%.2f raw_duration=%.2f samples=%d compacted_samples=%d",
                audio_duration,
                raw_audio_duration,
                len(audio_data),
                len(compacted_audio),
            )

            # Already in processing state from stop_recording

            # Update visual indicators - transcribing status
            if self.visual_indicators_enabled:
                update_tray_status(self.tray_controller, "transcribing", False)
                if VISUAL_INDICATORS_AVAILABLE:
                    show_transcribing()

            # Transcribe with timeout protection (60 seconds max)
            timeout_seconds = max(60, audio_duration * 3)  # 3x audio duration or 60s minimum

            try:
                with OperationTimeout(timeout_seconds, f"transcription_{audio_duration:.1f}s"):
                    active_asr, asr_path = self._pick_asr_engine(audio_duration)
                    self._log.info("transcription_path path=%s duration=%.2f", asr_path, audio_duration)
                    text = active_asr.transcribe(compacted_audio)
                raw_transcript = text

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
                        self._log.info("transcription_filtered reason=hallucination")
                        mark_idle()
                        update_tray_status(self.tray_controller, "idle", False)
                        return ""

                    # Check for very short or repetitive content
                    if len(text.strip()) < 3:
                        print(f"[TRANSCRIPTION] Content too short - skipping")
                        self._log.info("transcription_filtered reason=too_short")
                        mark_idle()
                        update_tray_status(self.tray_controller, "idle", False)
                        return ""

            except TimeoutError as e:
                logger.error(f"Transcription timeout: {e}")
                print(f"[TRANSCRIPTION] Timeout after {timeout_seconds}s - skipping")
                self._log.error("transcription_timeout duration=%.2f timeout=%.2f", audio_duration, timeout_seconds)
                # Return to idle state after timeout
                mark_idle()
                return ""
            
            # Apply basic processing
            text = normalize_context_terms(text)
            if self.code_mode:
                text = apply_code_mode(text, lowercase=self.cfg.code_mode_lowercase)
            else:
                if self.adaptive_learning and text.strip():
                    text = self.adaptive_learning.apply(text)
                # Apply improved text formatting for better readability
                text = format_transcript_text(text)

            # AI Enhancement Layer (VoiceFlow 3.0)
            course_corrected = False
            correction_type = ""
            ai_runtime_enabled = self.ai_enabled
            ai_skip_threshold = float(getattr(self.cfg, "ai_disable_above_audio_seconds", 20.0))
            if ai_runtime_enabled and audio_duration >= ai_skip_threshold:
                ai_runtime_enabled = False
                self._log.info(
                    "ai_enhancement_skipped reason=long_audio duration=%.2f threshold=%.2f",
                    audio_duration,
                    ai_skip_threshold,
                )

            if ai_runtime_enabled and text.strip():
                original_text = text

                # Check for command mode first
                if self.command_mode:
                    is_command, cmd_type = self.command_mode.detect_command(text)
                    if is_command:
                        print(f"[AI] Detected command: {cmd_type.value}")
                        # For now, commands need selected text which we don't have
                        # Just log it - full command mode needs clipboard integration
                        text = ""  # Don't inject command text
                        print(f"[AI] Command mode triggered - say command after selecting text")

                # Apply course correction (remove false starts, filler words)
                if text and self.course_corrector:
                    try:
                        result = self.course_corrector.correct(text)
                        if result.was_corrected:
                            print(f"[AI] Course correction: '{original_text}' -> '{result.text}'")
                            text = result.text
                            course_corrected = True
                            correction_type = result.correction_type
                    except Exception as e:
                        print(f"[AI] Course correction error: {e}")

            # Performance tracking
            transcription_time = time.perf_counter() - start_time
            self._total_transcription_time += transcription_time
            self._session_word_count += len(text.split())
            perf_snapshot = self._record_performance(audio_duration, transcription_time)

            # Session stats
            session_duration = time.time() - self._session_start_time
            avg_transcription_time = self._total_transcription_time / max(1, session_duration / 60)

            print(f"[TRANSCRIPTION] => {text}")
            print(f"[STATS] Words: {len(text.split())}, "
                  f"Time: {transcription_time:.2f}s, "
                  f"Session: {self._session_word_count} words")
            print(
                "[PERF] audio={audio:.2f}s proc={proc:.2f}s rtf={rtf:.2f}x "
                "window_avg={wavg:.2f}x session_avg={savg:.2f}x status={status}".format(
                    audio=audio_duration,
                    proc=transcription_time,
                    rtf=perf_snapshot["rtf"],
                    wavg=perf_snapshot["window_rtf_avg"],
                    savg=perf_snapshot["session_rtf_avg"],
                    status=perf_snapshot["status"],
                )
            )
            self._log.info(
                "transcription_finished duration=%.2f seconds=%.3f chars=%d words=%d",
                audio_duration,
                transcription_time,
                len(text),
                len(text.split()),
            )
            self._log.info(
                "performance_metrics audio=%.2f processing=%.2f rtf=%.2fx window_rtf=%.2fx session_rtf=%.2fx status=%s",
                audio_duration,
                transcription_time,
                perf_snapshot["rtf"],
                perf_snapshot["window_rtf_avg"],
                perf_snapshot["session_rtf_avg"],
                perf_snapshot["status"],
            )
            if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE and text.strip():
                visual_record_transcription_event(text, audio_duration, transcription_time)

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

            if text.strip():
                self._observe_adaptive_async(
                    raw_transcript if 'raw_transcript' in locals() else text,
                    text,
                    {
                        "model_tier": getattr(self.cfg, "model_tier", ""),
                        "code_mode": bool(self.code_mode),
                        "course_corrected": course_corrected,
                        "correction_type": correction_type,
                        "audio_duration": round(audio_duration, 3),
                        "processing_time": round(transcription_time, 3),
                    },
                )

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

    def _record_performance(self, audio_duration: float, processing_time: float) -> Dict[str, float | str]:
        """Track per-transcription performance and return a compact snapshot."""
        safe_processing = max(0.001, float(processing_time))
        safe_audio = max(0.0, float(audio_duration))
        rtf = safe_audio / safe_processing if safe_audio > 0 else 0.0

        self._perf_window.append((safe_audio, safe_processing))
        self._perf_total_audio += safe_audio
        self._perf_total_processing += safe_processing
        self._perf_total_count += 1

        window_audio = sum(a for a, _ in self._perf_window)
        window_processing = sum(p for _, p in self._perf_window)
        window_rtf_avg = (window_audio / window_processing) if window_processing > 0 else 0.0
        session_rtf_avg = (
            self._perf_total_audio / self._perf_total_processing
            if self._perf_total_processing > 0
            else 0.0
        )

        # Fast heuristic for live guidance in terminal output.
        if rtf >= 3.0:
            status = "excellent"
        elif rtf >= 1.2:
            status = "good"
        elif rtf >= 0.9:
            status = "near-realtime"
        else:
            status = "slow"

        return {
            "rtf": rtf,
            "window_rtf_avg": window_rtf_avg,
            "session_rtf_avg": session_rtf_avg,
            "status": status,
        }
    
    def shutdown(self):
        """Graceful shutdown with cleanup"""
        print("[EnhancedApp] Shutting down...")
        
        # Stop recording if active
        if self.rec.is_recording():
            try:
                self.rec.stop()
            except Exception:
                pass
        self._stop_live_checkpoint_monitor()
        
        # Shutdown transcription manager
        self.transcription_manager.shutdown()
        self.postprocess_executor.shutdown(wait=False)
        self.checkpoint_executor.shutdown(wait=False)
        self.injector.clear_target_window()
        
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
    # Single-instance enforcement temporarily disabled: it caused startup exits
    # before tray/dock initialization in this environment.
    if _yield_if_bootstrap_parent():
        return 0
    _start_bootstrap_parent_watchdog()

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
    app.ptt_listener = listener

    # Final bootstrap guard: if this process spawned an identical child, yield to child.
    # This avoids dual hotkey listeners in parent+child launch environments.
    time.sleep(1.0)
    if _has_same_entry_child():
        print(f"[MAIN] Parent process yielding to child runtime (pid={os.getpid()}).")
        try:
            app.shutdown()
        except Exception:
            pass
        return 0
    
    try:
        listener.start()
        print("\n" + "="*70)
        print("VoiceFlow 3.0 - Cold Start Elimination Enabled")
        print("="*70)
        # Show actual model from ASR engine (more accurate than config)
        actual_model = getattr(app.asr, 'model_config', None)
        if actual_model:
            print(f"Model: {actual_model.name} ({actual_model.model_id})")
        else:
            print(f"Model: {getattr(cfg, 'model_tier', 'quick')} tier ({cfg.model_name})")
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
        print(f"AI Enhancement: {'Enabled' if app.ai_enabled else 'Disabled'}")
        print("="*70)

        # Wait for model to be ready (cold start elimination)
        if not app.is_model_ready():
            print("[STARTUP] Waiting for model preload to complete...")
            if app.wait_for_model(timeout=120.0):
                print("[STARTUP] Model preloaded successfully - zero cold start!")
            else:
                print("[STARTUP] Warning: Model preload incomplete, first transcription may be slower")

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
