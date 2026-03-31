from __future__ import annotations

import threading
import traceback
import sys
import os
import subprocess
import gc
import re
import json
import wave
from datetime import datetime, timedelta
from pathlib import Path
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
# Use new unified ASR engine with model tier support.
# When VOICEFLOW_MODEL_SERVER_ENABLED=1 (set by the two-process dev launcher),
# delegate to the model server instead so hot-reloads skip model loading.
if os.environ.get("VOICEFLOW_MODEL_SERVER_ENABLED") == "1":
    from voiceflow.core.model_server_client import ModelServerASR as WhisperASR  # type: ignore[assignment]
else:
    from voiceflow.core.asr_engine import ModernWhisperASR as WhisperASR  # type: ignore[assignment]
# Cold start elimination
from voiceflow.core.preloader import ModelPreloader, PreloadState
# Streaming preview
from voiceflow.core.streaming import StreamingTranscriber, StreamingResult
from voiceflow.platform.factory import (
    create_hotkey_backend,
    create_injector_backend,
    create_tray_backend,
    runtime_platform_name,
)
from voiceflow.utils.utils import is_admin, nvidia_smi_info
from voiceflow.core.textproc import (
    apply_code_mode,
    apply_second_pass_cleanup,
    format_transcript_text,
    format_transcript_for_destination,
    infer_destination_profile,
    normalize_context_terms,
)
import keyboard
from voiceflow.ui.enhanced_tray import update_tray_status
from voiceflow.ui.setup_wizard import maybe_run_startup_setup
from voiceflow.utils.logging_setup import AsyncLogger, default_log_dir
from voiceflow.utils.settings import config_dir, load_config, save_config, append_jsonl_bounded
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
            if (
                "voiceflow.ui.cli_enhanced" in cmdline
                and ("-m" in cmdline or "from voiceflow.ui.cli_enhanced import main" in cmdline)
            ):
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


def _list_cli_processes() -> list[tuple[int, float, int]]:
    """Return running VoiceFlow CLI process tuples as (pid, create_time, ppid)."""
    try:
        import psutil  # type: ignore
    except Exception:
        return []

    matches: list[tuple[int, float, int]] = []
    for proc in psutil.process_iter(["pid", "create_time", "cmdline", "name", "ppid"]):
        try:
            name = str(proc.info.get("name") or "").lower()
            if name not in {"python.exe", "pythonw.exe", "python"}:
                continue
            cmd_list = [str(part).strip() for part in (proc.info.get("cmdline") or []) if str(part).strip()]
            cmdline = " ".join(cmd_list)
            # Accept both tokenized and collapsed command-line variants.
            if "voiceflow.ui.cli_enhanced" not in cmdline:
                continue
            if "-m" not in cmdline and "from voiceflow.ui.cli_enhanced import main" not in cmdline:
                continue
            matches.append(
                (
                    int(proc.info["pid"]),
                    float(proc.info.get("create_time") or 0.0),
                    int(proc.info.get("ppid") or 0),
                )
            )
        except Exception:
            continue
    return matches


def _enforce_single_instance() -> bool:
    """
    Keep only one `voiceflow.ui.cli_enhanced` process.
    Prefer the oldest leaf process to avoid churn from short-lived bootstrap helpers.
    """
    try:
        import psutil  # type: ignore
    except Exception:
        return True

    me = os.getpid()
    processes = _list_cli_processes()
    if not processes:
        return True

    parent_refs = {ppid for _, _, ppid in processes}
    leaf_processes = [proc for proc in processes if proc[0] not in parent_refs]
    target_pool = leaf_processes if leaf_processes else processes
    keep_pid = sorted(target_pool, key=lambda item: (item[1], item[0]))[0][0]

    for pid, _, _ in processes:
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
        update_audio_features as visual_update_audio_features,
        get_indicator as visual_get_indicator,
        set_dock_enabled as visual_set_dock_enabled,
        set_animation_preferences as visual_set_animation_preferences,
        set_correction_feedback_handler as visual_set_correction_feedback_handler,
    )
    VISUAL_INDICATORS_AVAILABLE = True
except ImportError:
    VISUAL_INDICATORS_AVAILABLE = False
    def visual_show_preview(text): pass
    def visual_clear_preview(): pass
    def visual_record_transcription_event(text, audio_duration, processing_time, metadata=None):
        # Late-bind fallback: import can fail early during startup races.
        try:
            from voiceflow.ui.visual_indicators import record_transcription_event as _record_event
            _record_event(text, audio_duration, processing_time, metadata=metadata)
        except Exception:
            pass
    def visual_update_audio_level(level): pass
    def visual_update_audio_features(features): pass
    def visual_get_indicator(): return None
    def visual_set_dock_enabled(enabled): pass
    def visual_set_animation_preferences(quality="auto", reduced_motion=False, target_fps=28): pass
    def visual_set_correction_feedback_handler(handler): pass


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
        submitted_at = time.perf_counter()
        
        # Clean up completed jobs
        self._cleanup_completed_jobs()
        
        # Submit new job
        future = self.executor.submit(self._transcription_worker, audio_data, callback, job_id, submitted_at)
        
        with self.lock:
            self.active_jobs[job_id] = future
        
        print(f"[TranscriptionManager] Started {job_id} (active jobs: {len(self.active_jobs)})")
        return job_id
    
    def _transcription_worker(
        self,
        audio_data: np.ndarray,
        callback: callable,
        job_id: str,
        submitted_at: float,
    ):
        """Enhanced transcription worker with error handling"""
        try:
            start_time = time.perf_counter()
            duration = len(audio_data) / 16000.0  # Assuming 16kHz
            queue_wait_ms = max(0.0, (start_time - float(submitted_at)) * 1000.0)

            print(
                f"[TranscriptionManager] {job_id}: Processing {duration:.2f}s of audio... "
                f"(queue_wait={queue_wait_ms:.1f}ms)"
            )

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
            # Keep a generous floor for first-run model warmup/download paths.
            expected_timeout = max(15.0, duration * 3.0)
            timeout_seconds = max(float(self.worker_timeout_seconds), min(180.0, expected_timeout))
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

    def __init__(self, cfg: Config, injector_backend: Optional[Any] = None):
        self.cfg = cfg
        self.rec = EnhancedAudioRecorder(cfg)
        self.injector = injector_backend or create_injector_backend(cfg)

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
        if self.code_mode and str(os.environ.get("VOICEFLOW_KEEP_CODE_MODE_DEFAULT", "")).strip().lower() not in {
            "1",
            "true",
            "yes",
            "on",
        }:
            # Default to natural-language dictation unless explicitly opted into persistent code mode.
            self.code_mode = False
            try:
                self.cfg.code_mode_default = False
                save_config(self.cfg)
            except Exception:
                pass
        self._log = logging.getLogger("localflow")

        # Visual indicators integration
        self.tray_controller: Optional[Any] = None
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
        self._last_transcription_completed_at = 0.0

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
        self._idle_resume_warmup_lock = threading.Lock()
        self._idle_resume_last_warmup_at = 0.0
        self.ptt_listener: Optional[Any] = None
        self._feedback_audio_enabled = str(os.environ.get("VOICEFLOW_FEEDBACK_AUDIO", "")).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        self._feedback_audio_max_seconds = max(
            1.0,
            float(os.environ.get("VOICEFLOW_FEEDBACK_AUDIO_MAX_SECONDS", "12.0") or 12.0),
        )
        self._feedback_audio_retention_minutes = max(
            1,
            int(os.environ.get("VOICEFLOW_FEEDBACK_AUDIO_RETENTION_MINUTES", "30") or 30),
        )
        self._housekeeping_stop = threading.Event()
        self._housekeeping_thread: Optional[threading.Thread] = None
        self._background_services_started = False

        print(f"[EnhancedApp] Initialized with enhanced thread management and visual indicators {'enabled' if self.visual_indicators_enabled else 'disabled'}")
        print(f"[EnhancedApp] Streaming preview: {'Enabled' if self.streaming_enabled else 'Disabled'}")
        if self._feedback_audio_enabled:
            print(
                "[EnhancedApp] Feedback audio capture: ON "
                f"(max={self._feedback_audio_max_seconds:.1f}s, retention={self._feedback_audio_retention_minutes}m)"
            )

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
        elif progress.state == PreloadState.FAILED:
            self._fast_model_ready = False
            self._fast_preloader = None
            self.asr_fast = None
            logger.warning("Fast ASR preload failed; falling back to primary model path: %s", progress.message)
            print("[MODEL] Fast path unavailable; using primary model only")

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
            # Tell ModelServerASR (used in two-process dev mode) to route
            # requests to the fast model loaded on the server.
            fast_cfg._model_server_path = "fast"
            self.asr_fast = WhisperASR(fast_cfg)
            self._fast_preloader = ModelPreloader(self.asr_fast, on_progress=self._on_fast_preload_progress)
            self._fast_preloader.start_preload()
        except Exception as e:
            logger.warning(f"Fast ASR path unavailable: {e}")
            self.asr_fast = None
            self._fast_preloader = None
            self._fast_model_ready = False

    def _daily_learning_report_exists(self, target_date_text: str) -> bool:
        if not target_date_text:
            return False
        report_dir = config_dir() / "daily_learning_reports"
        if not report_dir.exists():
            return False
        pattern = f"daily_learning_{target_date_text}_*.json"
        try:
            return any(report_dir.glob(pattern))
        except Exception:
            return False

    def _is_daily_learning_task_registered(self) -> bool:
        if os.name != "nt":
            return True
        task_name = str(getattr(self.cfg, "daily_learning_task_name", "VoiceFlow-DailyLearning") or "").strip()
        if not task_name:
            task_name = "VoiceFlow-DailyLearning"
        try:
            result = subprocess.run(
                ["schtasks", "/Query", "/TN", task_name],
                capture_output=True,
                text=True,
                timeout=6,
            )
            return int(result.returncode) == 0
        except Exception:
            return False

    def _start_daily_learning_guardrail(self) -> None:
        """Run a bounded startup catch-up daily-learning pass when needed."""
        if not bool(getattr(self.cfg, "daily_learning_autorun_enabled", True)):
            return

        def _worker() -> None:
            try:
                delay = max(0.0, float(getattr(self.cfg, "daily_learning_autorun_startup_delay_seconds", 22.0)))
                if delay > 0:
                    time.sleep(delay)

                if not self._is_daily_learning_task_registered():
                    self._log.warning(
                        "daily_learning_task_missing task=%s action=startup_autorun",
                        str(getattr(self.cfg, "daily_learning_task_name", "VoiceFlow-DailyLearning")),
                    )

                days_back = max(1, int(getattr(self.cfg, "daily_learning_autorun_days_back", 1)))
                target_date_text = (datetime.now().date() - timedelta(days=days_back)).isoformat()
                if self._daily_learning_report_exists(target_date_text):
                    self._log.info(
                        "daily_learning_autorun_skipped reason=report_exists target_date=%s",
                        target_date_text,
                    )
                    return

                from voiceflow.ai.daily_learning import run_daily_learning_job

                report = run_daily_learning_job(
                    days_back=days_back,
                    dry_run=False,
                    max_history_items=max(50, int(getattr(self.cfg, "daily_learning_max_history_items", 400))),
                    max_correction_items=max(50, int(getattr(self.cfg, "daily_learning_max_correction_items", 400))),
                )
                stats = report.get("stats", {})
                self._log.info(
                    "daily_learning_autorun_complete target_date=%s corrections=%s/%s history=%s/%s instr=%s/%s report=%s",
                    str(report.get("target_date", "")),
                    int(stats.get("correction_items_used", 0)),
                    int(stats.get("correction_items_total", 0)),
                    int(stats.get("history_items_used", 0)),
                    int(stats.get("history_items_total", 0)),
                    int(stats.get("instructional_items_used", 0)),
                    int(stats.get("instructional_items_total", 0)),
                    str(stats.get("report_path", "")),
                )
            except Exception as exc:
                self._log.warning("daily_learning_autorun_failed error=%s", exc)

        thread = threading.Thread(
            target=_worker,
            name="DailyLearningGuardrail",
            daemon=True,
        )
        thread.start()

    def _start_longrun_housekeeping_thread(self) -> None:
        """Background long-run health telemetry + bounded cleanup hooks."""
        if not bool(getattr(self.cfg, "longrun_housekeeping_enabled", True)):
            return
        if self._housekeeping_thread and self._housekeeping_thread.is_alive():
            return

        self._housekeeping_stop.clear()
        self._housekeeping_thread = threading.Thread(
            target=self._longrun_housekeeping_loop,
            name="LongRunHousekeeping",
            daemon=True,
        )
        self._housekeeping_thread.start()

    def start_background_services(self) -> None:
        """Defer opportunistic background work until runtime surfaces are ready."""
        if bool(getattr(self, "_background_services_started", False)):
            return
        self._background_services_started = True
        self._start_daily_learning_guardrail()
        self._start_longrun_housekeeping_thread()
        self._log.info(
            "background_services_started daily_learning=%s housekeeping=%s",
            bool(getattr(self.cfg, "daily_learning_autorun_enabled", True)),
            bool(getattr(self.cfg, "longrun_housekeeping_enabled", True)),
        )

    def _recommended_soft_gc_threshold_mb(self) -> float:
        """Adaptive threshold used when config keeps soft GC on auto (0)."""
        gpu_mode = (
            str(getattr(self.cfg, "device", "")).strip().lower() == "cuda"
            or bool(getattr(self.cfg, "enable_gpu_acceleration", False))
        )
        model_tier = str(getattr(self.cfg, "model_tier", "quick")).strip().lower()
        if gpu_mode:
            if model_tier in {"quality", "voxtral"}:
                return 1728.0
            return 960.0
        return 768.0

    @staticmethod
    def _make_warmup_speech_audio(sample_rate: int, duration: float) -> np.ndarray:
        """Generate bandlimited speech-like noise for ASR warm-up.

        Pure silence is discarded by Silero VAD before CTranslate2 is ever
        invoked, so the CUDA decode path never runs and the GPU stays cold.
        This function produces amplitude-modulated bandlimited noise (80–3400 Hz)
        that passes the VAD gate and forces a full decode, priming CUDA kernels
        and eliminating the cold-start stall on the first real utterance.
        """
        n = max(1, int(sample_rate * duration))
        rng = np.random.default_rng(seed=42)
        half = n // 2 + 1
        freqs = np.fft.rfftfreq(n, d=1.0 / sample_rate)
        # Speech band: 80–3400 Hz
        in_band = (freqs >= 80) & (freqs <= 3400)
        spectrum = np.zeros(half, dtype=complex)
        n_in_band = int(in_band.sum())
        spectrum[in_band] = (
            rng.standard_normal(n_in_band) + 1j * rng.standard_normal(n_in_band)
        )
        signal = np.fft.irfft(spectrum, n=n).astype(np.float32)
        # Syllabic amplitude modulation at ~4 Hz increases speech-likeness
        t = np.arange(n, dtype=np.float32) / sample_rate
        signal *= 0.5 + 0.5 * np.sin(2.0 * np.pi * 4.0 * t)
        # Normalise to -18 dBFS (RMS ≈ 0.126) — loud enough for VAD detection
        rms = float(np.sqrt(np.mean(signal ** 2)))
        if rms > 1e-9:
            signal *= 0.126 / rms
        return np.clip(signal, -1.0, 1.0)

    def _run_idle_resume_warmup(self) -> float:
        """Warm ASR runtime once after long idle to reduce first-utterance quality dips."""
        if not bool(getattr(self.cfg, "idle_resume_warmup_enabled", True)):
            return 0.0

        # Default raised from 0.45 s to 1.5 s: the speech sample must be long
        # enough that Silero VAD's minimum speech duration gate doesn't reject it.
        warmup_seconds = max(0.5, float(getattr(self.cfg, "idle_resume_warmup_audio_seconds", 1.5)))
        cooldown_seconds = 300.0
        now = time.time()
        with self._idle_resume_warmup_lock:
            if now - float(self._idle_resume_last_warmup_at or 0.0) < cooldown_seconds:
                return 0.0
            self._idle_resume_last_warmup_at = now

        sample_rate = max(8000, int(getattr(self.cfg, "sample_rate", 16000)))
        warmup_audio = self._make_warmup_speech_audio(sample_rate, warmup_seconds)
        started = time.perf_counter()
        try:
            # Warm both paths when available; keep this short and bounded.
            self.asr.transcribe(warmup_audio)
            if self.asr_fast and self._fast_model_ready:
                self.asr_fast.transcribe(warmup_audio)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            self._log.info(
                "idle_resume_warmup_complete audio_seconds=%.2f elapsed_ms=%.1f",
                warmup_seconds,
                elapsed_ms,
            )
            return elapsed_ms
        except Exception as exc:
            self._log.debug("idle_resume_warmup_failed error=%s", exc)
            return 0.0

    def _evaluate_compaction_retry_signal(
        self,
        *,
        raw_audio_duration: float,
        compaction_reduction_pct: float,
        initial_words: int,
        initial_chars: int,
        idle_resume_active: bool,
    ) -> Dict[str, Any]:
        """Decide whether a compacted decode is suspicious enough to retry on raw audio."""
        retry_min_reduction = float(getattr(self.cfg, "pause_compaction_retry_min_reduction_pct", 38.0))
        retry_max_words = int(getattr(self.cfg, "pause_compaction_retry_max_words", 8))
        min_words_per_second = float(getattr(self.cfg, "pause_compaction_retry_min_words_per_second", 1.15))
        min_chars_per_second = float(getattr(self.cfg, "pause_compaction_retry_min_chars_per_second", 5.0))

        words_per_second = initial_words / max(0.1, raw_audio_duration)
        chars_per_second = initial_chars / max(0.1, raw_audio_duration)
        retry_due_to_short = initial_words <= retry_max_words
        retry_due_to_sparse = (
            words_per_second < min_words_per_second
            and chars_per_second < min_chars_per_second
        )
        idle_resume_retry_due_to_compaction = (
            idle_resume_active
            and bool(getattr(self.cfg, "idle_resume_retry_on_compaction", True))
            and compaction_reduction_pct >= float(getattr(self.cfg, "idle_resume_retry_min_reduction_pct", 55.0))
            and raw_audio_duration >= float(getattr(self.cfg, "idle_resume_retry_min_raw_audio_seconds", 12.0))
        )

        reasons: list[str] = []
        if retry_due_to_short:
            reasons.append("short_output")
        if retry_due_to_sparse:
            reasons.append("sparse_output")
        if idle_resume_retry_due_to_compaction:
            reasons.append("idle_resume_compaction")

        retry_triggered = (
            compaction_reduction_pct >= retry_min_reduction
            and bool(reasons)
        )

        return {
            "retry_triggered": bool(retry_triggered),
            "retry_due_to_short": bool(retry_due_to_short),
            "retry_due_to_sparse": bool(retry_due_to_sparse),
            "idle_resume_retry_due_to_compaction": bool(idle_resume_retry_due_to_compaction),
            "retry_min_reduction": retry_min_reduction,
            "words_per_second": words_per_second,
            "chars_per_second": chars_per_second,
            "reasons": reasons,
        }

    def _should_skip_pause_compaction_on_idle_resume(
        self,
        *,
        raw_audio_duration: float,
        idle_resume_active: bool,
    ) -> bool:
        if not idle_resume_active:
            return False
        if not bool(getattr(self.cfg, "idle_resume_skip_pause_compaction", True)):
            return False
        min_seconds = float(
            getattr(self.cfg, "idle_resume_skip_pause_compaction_min_audio_seconds", 18.0)
        )
        return raw_audio_duration >= min_seconds

    def _longrun_housekeeping_loop(self) -> None:
        interval_s = max(30.0, float(getattr(self.cfg, "longrun_health_log_interval_seconds", 900.0)))
        configured_soft_gc_mb = float(getattr(self.cfg, "longrun_soft_gc_memory_mb", 0.0) or 0.0)
        soft_gc_mb = configured_soft_gc_mb if configured_soft_gc_mb > 0.0 else self._recommended_soft_gc_threshold_mb()
        while not self._housekeeping_stop.wait(interval_s):
            try:
                rss_mb = 0.0
                try:
                    import psutil  # type: ignore

                    rss_mb = float(psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024))
                except Exception:
                    rss_mb = 0.0

                ring_capacity_mb = float(getattr(self.rec, "get_memory_usage_mb", lambda: 0.0)() or 0.0)
                live_audio_s = float(getattr(self.rec, "get_current_duration", lambda: 0.0)() or 0.0)
                self._log.info(
                    "longrun_health rss_mb=%.1f ring_capacity_mb=%.2f live_audio_s=%.2f perf_window=%d checkpoint_parts=%d",
                    rss_mb,
                    ring_capacity_mb,
                    live_audio_s,
                    len(self._perf_window),
                    len(self._checkpoint_preview_parts),
                )

                if self.adaptive_learning and hasattr(self.adaptive_learning, "_purge_expired"):
                    try:
                        self.adaptive_learning._purge_expired()
                    except Exception as purge_exc:
                        self._log.debug("longrun_adaptive_purge_failed error=%s", purge_exc)

                if self._feedback_audio_enabled:
                    folder = self._feedback_audio_dir()
                    if folder is not None:
                        self._purge_feedback_audio(folder)

                if soft_gc_mb > 0.0 and rss_mb >= soft_gc_mb:
                    collected = gc.collect()
                    self._log.warning(
                        "longrun_soft_gc_triggered rss_mb=%.1f threshold_mb=%.1f collected=%d",
                        rss_mb,
                        soft_gc_mb,
                        int(collected),
                    )
            except Exception as exc:
                self._log.debug("longrun_housekeeping_error error=%s", exc)

    def _pick_asr_engine(self, audio_duration: float, *, force_primary: bool = False):
        """Pick fast engine for short audio to reduce perceived latency."""
        if force_primary:
            return self.asr, "primary-forced"
        # Only route to fast path after successful preload.
        # Fresh installs may still be downloading tiny model assets.
        if not self.asr_fast or not self._fast_model_ready:
            return self.asr, "primary"
        threshold = float(getattr(self.cfg, "latency_boost_max_audio_seconds", 12.0))
        fast_tier = str(getattr(self.cfg, "latency_boost_model_tier", "tiny")).strip().lower()
        if fast_tier == "tiny":
            tiny_cap = float(getattr(self.cfg, "latency_boost_tiny_max_audio_seconds", 3.0))
            threshold = min(threshold, tiny_cap)
        if 0.0 < audio_duration <= threshold:
            return self.asr_fast, "fast"
        return self.asr, "primary"

    def _should_retry_blank_fast_path(
        self,
        *,
        asr_path: str,
        text: str,
        audio_duration: float,
        raw_audio_duration: float,
        is_non_speech: bool,
        non_speech_metrics: Dict[str, float],
    ) -> bool:
        """Retry empty fast-path decodes on the primary model for speech-like clips."""
        if str(asr_path or "").strip().lower() != "fast":
            return False
        if str(text or "").strip():
            return False
        if is_non_speech:
            return False
        if self.asr is None or self.asr is self.asr_fast:
            return False

        effective_duration = max(float(audio_duration or 0.0), float(raw_audio_duration or 0.0))
        if effective_duration < 0.75:
            return False

        # The non-speech guard has already had a chance to reject obvious bursts/silence.
        # At this point, a blank fast-model decode is more expensive in UX than a single
        # retry on the primary model, so prefer correctness over saving ~tens of ms.
        return True

    def _transcribe_with_fast_path_fallback(
        self,
        active_asr: Any,
        asr_path: str,
        audio_data: np.ndarray,
        *,
        audio_duration: float,
        raw_audio_duration: float,
        is_non_speech: bool,
        non_speech_reason: str,
        non_speech_metrics: Dict[str, float],
    ) -> tuple[str, Any, bool, str, float, float]:
        """Decode with the selected engine, retrying blank fast-path results on primary."""
        decode_start = time.perf_counter()
        text = active_asr.transcribe(audio_data)
        decode_ms = (time.perf_counter() - decode_start) * 1000.0

        retry_used = False
        retry_path = "none"
        retry_ms = 0.0
        final_asr = active_asr

        if not self._should_retry_blank_fast_path(
            asr_path=asr_path,
            text=str(text or ""),
            audio_duration=audio_duration,
            raw_audio_duration=raw_audio_duration,
            is_non_speech=is_non_speech,
            non_speech_metrics=non_speech_metrics,
        ):
            return text, final_asr, retry_used, retry_path, decode_ms, retry_ms

        self._log.info(
            "blank_fast_retry_candidate duration=%.2f raw_duration=%.2f reason=%s peak=%.3f rms=%.5f voiced=%.3f voiced_run=%.3f",
            audio_duration,
            raw_audio_duration,
            non_speech_reason,
            float(non_speech_metrics.get("peak", 0.0) or 0.0),
            float(non_speech_metrics.get("rms", 0.0) or 0.0),
            float(non_speech_metrics.get("voiced_ratio", 0.0) or 0.0),
            float(non_speech_metrics.get("longest_voiced_seconds", 0.0) or 0.0),
        )

        retry_start = time.perf_counter()
        retry_text = self.asr.transcribe(audio_data)
        retry_ms = (time.perf_counter() - retry_start) * 1000.0
        retry_chars = len(str(retry_text or "").strip())
        retry_words = len(str(retry_text or "").split())

        if retry_chars > 0:
            retry_used = True
            retry_path = "fast-empty-primary-retry"
            final_asr = self.asr
            text = retry_text
            self._log.info(
                "blank_fast_retry_applied chars=%d words=%d path=%s",
                retry_chars,
                retry_words,
                retry_path,
            )
        else:
            self._log.info("blank_fast_retry_empty path=primary chars=0 words=0")

        return text, final_asr, retry_used, retry_path, decode_ms, retry_ms

    def _transcribe_raw_in_chunks(
        self,
        audio_data: np.ndarray,
        *,
        force_primary: bool = False,
    ) -> tuple[str, int]:
        """
        Bounded long-clip retry path when single-pass raw decode would be too expensive.
        Returns (stitched_text, chunks_used).
        """
        sample_rate = max(8000, int(getattr(self.cfg, "sample_rate", 16000)))
        audio_duration = len(audio_data) / float(sample_rate)
        chunk_seconds = max(6.0, float(getattr(self.cfg, "pause_compaction_retry_chunk_seconds", 32.0)))
        overlap_seconds = max(
            0.05,
            min(chunk_seconds * 0.4, float(getattr(self.cfg, "pause_compaction_retry_chunk_overlap_seconds", 0.35))),
        )
        max_chunks = max(2, int(getattr(self.cfg, "pause_compaction_retry_chunk_max_chunks", 8)))

        chunk_samples = max(1, int(chunk_seconds * sample_rate))
        overlap_samples = max(1, int(overlap_seconds * sample_rate))
        step_samples = max(1, chunk_samples - overlap_samples)

        chunks: list[np.ndarray] = []
        start = 0
        while start < len(audio_data):
            end = min(len(audio_data), start + chunk_samples)
            chunk = audio_data[start:end]
            if len(chunk) > 0:
                chunks.append(chunk)
            if end >= len(audio_data):
                break
            start += step_samples
            if len(chunks) > max_chunks:
                self._log.info(
                    "pause_compaction_chunked_retry_skipped reason=max_chunks raw_duration=%.2f chunks=%d max_chunks=%d",
                    audio_duration,
                    len(chunks),
                    max_chunks,
                )
                return "", len(chunks)

        merged_words: list[str] = []
        chunks_used = 0
        overlap_token_cap = 12

        for idx, chunk in enumerate(chunks):
            chunk_duration = len(chunk) / float(sample_rate)
            retry_asr, retry_path = self._pick_asr_engine(chunk_duration, force_primary=force_primary)
            piece = str(retry_asr.transcribe(chunk) or "").strip()
            chunks_used += 1
            if not piece:
                continue

            piece_words = piece.split()
            if merged_words and piece_words:
                max_overlap = min(overlap_token_cap, len(merged_words), len(piece_words))
                trim = 0
                for overlap in range(max_overlap, 2, -1):
                    prev_slice = [w.lower() for w in merged_words[-overlap:]]
                    next_slice = [w.lower() for w in piece_words[:overlap]]
                    if prev_slice == next_slice:
                        trim = overlap
                        break
                if trim > 0:
                    piece_words = piece_words[trim:]

            if piece_words:
                merged_words.extend(piece_words)

            self._log.info(
                "pause_compaction_chunked_retry_piece idx=%d/%d duration=%.2f words=%d path=%s",
                idx + 1,
                len(chunks),
                chunk_duration,
                len(piece_words),
                retry_path,
            )

        return " ".join(merged_words).strip(), chunks_used

    def _compact_pauses(self, audio_data: np.ndarray, overrides: Optional[Dict[str, float]] = None) -> np.ndarray:
        """
        Remove long silence spans from lengthy recordings to reduce inference time.
        Keeps a small silence margin around detected speech to preserve phrase boundaries.
        """
        options: Dict[str, float] = dict(overrides or {})
        if not getattr(self.cfg, "enable_pause_compaction", True):
            return audio_data
        if audio_data is None or len(audio_data) == 0:
            return audio_data

        sample_rate = int(options.get("sample_rate", getattr(self.cfg, "sample_rate", 16000)))
        audio_duration = len(audio_data) / float(sample_rate)
        min_duration = float(options.get("min_duration", getattr(self.cfg, "pause_compaction_min_audio_seconds", 14.0)))
        if audio_duration < min_duration:
            return audio_data

        frame_ms = max(10, int(options.get("frame_ms", getattr(self.cfg, "pause_compaction_frame_ms", 30))))
        frame_len = max(160, int(sample_rate * frame_ms / 1000.0))
        keep_ms = max(
            50,
            int(options.get("keep_ms", getattr(self.cfg, "pause_compaction_keep_silence_ms", 180))),
        )
        keep_frames = max(1, int(keep_ms / frame_ms))

        # Align to whole frames for vectorized RMS estimation.
        usable = (len(audio_data) // frame_len) * frame_len
        if usable <= 0:
            return audio_data
        framed = audio_data[:usable].reshape(-1, frame_len)
        rms = np.sqrt(np.mean(framed * framed, axis=1))

        base_thr = float(options.get("min_rms_amplitude", getattr(self.cfg, "min_rms_amplitude", 5e-4)))
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
        max_reduction_pct = float(
            options.get("max_reduction_pct", getattr(self.cfg, "pause_compaction_max_reduction_pct", 60.0))
        )
        min_keep_ratio = max(0.2, 1.0 - max(0.0, min(95.0, max_reduction_pct)) / 100.0)
        if (len(compacted) / len(audio_data)) < min_keep_ratio:
            # Over-compaction guardrail: preserve more context for recognition quality.
            return audio_data
        # Keep any tail samples if original ends with speech-like energy.
        tail = audio_data[usable:]
        if tail.size > 0 and np.sqrt(np.mean(tail * tail)) >= dyn_thr:
            compacted = np.concatenate((compacted, tail))
        return compacted

    def _detect_likely_non_speech(self, audio_data: np.ndarray) -> tuple[bool, str, Dict[str, float]]:
        """
        Conservative short-audio detector for sneeze/cough/throat-clear bursts.
        Returns (is_non_speech, reason, metrics).
        """
        metrics: Dict[str, float] = {}
        if not getattr(self.cfg, "enable_non_speech_guard", True):
            return False, "disabled", metrics
        if audio_data is None or len(audio_data) == 0:
            return False, "empty", metrics

        sample_rate = max(8000, int(getattr(self.cfg, "sample_rate", 16000)))
        duration = len(audio_data) / float(sample_rate)
        max_duration = float(getattr(self.cfg, "non_speech_max_audio_seconds", 1.25))
        metrics["duration"] = float(duration)
        if duration <= 0.0 or duration > max_duration:
            return False, "duration_out_of_scope", metrics

        audio = np.asarray(audio_data, dtype=np.float32)
        peak = float(np.max(np.abs(audio)))
        rms = float(np.sqrt(np.mean(audio * audio)) + 1e-9)
        crest_factor = peak / max(rms, 1e-7)
        metrics["peak"] = peak
        metrics["rms"] = rms
        metrics["crest_factor"] = crest_factor

        frame_len = max(64, int(sample_rate * 0.02))
        usable = (len(audio) // frame_len) * frame_len
        if usable < frame_len:
            return False, "insufficient_frames", metrics
        framed = audio[:usable].reshape(-1, frame_len)
        frame_rms = np.sqrt(np.mean(framed * framed, axis=1) + 1e-12)

        activity_floor = max(float(getattr(self.cfg, "min_rms_amplitude", 5e-4)) * 3.0, 0.006)
        voiced_frames = frame_rms > activity_floor
        voiced_ratio = float(np.mean(voiced_frames))
        metrics["voiced_ratio"] = voiced_ratio

        # Longest sustained voiced run helps avoid filtering short spoken words like "yes/no/hi".
        run = 0
        max_run = 0
        for active in voiced_frames:
            if bool(active):
                run += 1
                if run > max_run:
                    max_run = run
            else:
                run = 0
        longest_voiced_seconds = (max_run * frame_len) / float(sample_rate)
        metrics["longest_voiced_seconds"] = float(longest_voiced_seconds)

        signs = np.sign(audio)
        zcr = float(np.mean(signs[1:] != signs[:-1])) if len(signs) > 1 else 0.0
        metrics["zcr"] = zcr

        flatness = 0.0
        n_fft = min(len(audio), 2048)
        if n_fft >= 64:
            segment = audio[-n_fft:].astype(np.float32)
            windowed = segment * np.hanning(len(segment))
            spectrum = np.abs(np.fft.rfft(windowed)) + 1e-9
            flatness = float(np.exp(np.mean(np.log(spectrum))) / np.mean(spectrum))
        metrics["flatness"] = flatness

        min_peak = float(getattr(self.cfg, "non_speech_min_peak", 0.16))
        min_crest = float(getattr(self.cfg, "non_speech_min_crest_factor", 9.0))
        max_voiced = float(getattr(self.cfg, "non_speech_max_voiced_ratio", 0.24))
        min_flatness = float(getattr(self.cfg, "non_speech_min_flatness", 0.50))
        min_zcr = float(getattr(self.cfg, "non_speech_min_zcr", 0.10))
        speech_hint_min_voiced_seconds = float(
            getattr(self.cfg, "non_speech_speech_hint_min_voiced_seconds", 0.20)
        )
        speech_hint_min_voiced_ratio = float(
            getattr(self.cfg, "non_speech_speech_hint_min_voiced_ratio", 0.20)
        )
        max_voiced_run_seconds = float(getattr(self.cfg, "non_speech_max_voiced_run_seconds", 0.16))

        impulsive = peak >= min_peak and crest_factor >= min_crest
        noise_like = flatness >= min_flatness and zcr >= min_zcr
        short_burst = duration <= 0.55 and peak >= min_peak and zcr >= min_zcr
        speech_hint = (
            longest_voiced_seconds >= speech_hint_min_voiced_seconds
            or voiced_ratio >= speech_hint_min_voiced_ratio
        )
        low_voicing = voiced_ratio <= max_voiced and longest_voiced_seconds <= max_voiced_run_seconds
        metrics["speech_hint"] = 1.0 if speech_hint else 0.0

        if speech_hint:
            return False, "speech_hint_present", metrics
        if (impulsive and noise_like and low_voicing) or (short_burst and low_voicing):
            return True, "likely_non_speech_burst", metrics
        return False, "speech_like", metrics

    def _feedback_audio_dir(self) -> Optional[Path]:
        if not self._feedback_audio_enabled:
            return None
        override = str(os.environ.get("VOICEFLOW_FEEDBACK_AUDIO_DIR", "")).strip()
        if override:
            base = Path(override).expanduser()
            if not base.is_absolute():
                base = config_dir() / base
        else:
            base = config_dir() / "feedback_audio"
        try:
            base.mkdir(parents=True, exist_ok=True)
            return base
        except Exception:
            return None

    def _purge_feedback_audio(self, folder: Path) -> None:
        if not folder.exists():
            return
        cutoff = time.time() - (self._feedback_audio_retention_minutes * 60.0)
        for candidate in folder.glob("*"):
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() not in {".wav", ".json"}:
                continue
            try:
                if candidate.stat().st_mtime < cutoff:
                    candidate.unlink(missing_ok=True)
            except Exception:
                continue

    def _maybe_capture_feedback_audio(self, audio_data: np.ndarray, metadata: Dict[str, Any]) -> None:
        if not self._feedback_audio_enabled:
            return
        if audio_data is None or len(audio_data) == 0:
            return
        sample_rate = max(8000, int(getattr(self.cfg, "sample_rate", 16000)))
        duration = len(audio_data) / float(sample_rate)
        if duration <= 0.0 or duration > self._feedback_audio_max_seconds:
            return
        folder = self._feedback_audio_dir()
        if folder is None:
            return

        self._purge_feedback_audio(folder)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        suffix = f"{int(time.time_ns()) % 1000000:06d}"
        base_name = f"{stamp}_{suffix}"
        wav_path = folder / f"{base_name}.wav"
        meta_path = folder / f"{base_name}.json"

        try:
            # Store as 16-bit PCM WAV for portable offline analysis.
            clipped = np.clip(np.asarray(audio_data, dtype=np.float32), -1.0, 1.0)
            pcm16 = (clipped * 32767.0).astype(np.int16)
            with wave.open(str(wav_path), "wb") as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(sample_rate)
                wf.writeframes(pcm16.tobytes())

            payload = {
                "timestamp": time.time(),
                "sample_rate": sample_rate,
                "duration_seconds": round(duration, 3),
                "samples": int(len(audio_data)),
                "metadata": metadata,
            }
            meta_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
            self._log.info("feedback_audio_saved path=%s duration=%.2f", str(wav_path), duration)
        except Exception as e:
            self._log.warning("feedback_audio_save_failed error=%s", e)

    def _destination_format_context(self) -> Dict[str, Any]:
        context = self.injector.get_target_context()
        context["destination_aware_formatting"] = bool(getattr(self.cfg, "destination_aware_formatting", True))
        context["destination_wrap_enabled"] = bool(getattr(self.cfg, "destination_wrap_enabled", True))
        context["destination_default_chars"] = int(getattr(self.cfg, "destination_default_chars", 84))
        context["destination_terminal_chars"] = int(getattr(self.cfg, "destination_terminal_chars", 104))
        context["destination_chat_chars"] = int(getattr(self.cfg, "destination_chat_chars", 68))
        context["destination_editor_chars"] = int(getattr(self.cfg, "destination_editor_chars", 94))
        return context

    def _normalize_context_terms_runtime(self, text: str) -> str:
        return normalize_context_terms(
            text,
            aggressive=bool(getattr(self.cfg, "enable_aggressive_context_corrections", False)),
            light=bool(getattr(self.cfg, "enable_light_typo_correction", True)),
        )

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
            text = self._normalize_context_terms_runtime(text)
            destination_context = self._destination_format_context()
            destination_profile = infer_destination_profile(destination_context)
            effective_code_mode = bool(self.code_mode and destination_profile in {"editor", "terminal"})
            if effective_code_mode:
                text = apply_code_mode(text, lowercase=self.cfg.code_mode_lowercase)
            else:
                text = format_transcript_for_destination(
                    text,
                    destination=destination_context,
                    audio_duration=segment_duration,
                )
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
            # Caption-style preview: keep latest N words for readable live feedback.
            words = re.findall(r"\S+", result.text.strip())
            keep_words = max(1, int(getattr(self.cfg, "live_caption_words", 6)))
            caption_text = " ".join(words[-keep_words:]) if words else result.text.strip()
            display_cap = max(40, int(getattr(self.cfg, "live_caption_max_chars", 110)))
            preview_display = caption_text[:display_cap] + "..." if len(caption_text) > display_cap else caption_text
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
                chunk_duration=0.85,
                min_audio_duration=0.55,
                partial_max_audio_seconds=6.0,
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
                # Pull only new samples since last poll; avoids O(n) full-buffer copies on long dictation.
                new_audio, current_total = self.rec._ring_buffer.get_samples_since(last_sample_count)
                if len(new_audio) > 0:
                    self._streaming_transcriber.add_audio(new_audio)
                    last_sample_count = current_total
                    if self.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE and len(new_audio) > 0:
                        # Lightweight amplitude estimate for visual waveform (no ASR impact).
                        rms = float(np.sqrt(np.mean(np.square(new_audio))))
                        denom = max(1e-6, float(getattr(self.cfg, "min_rms_amplitude", 5e-4)) * 12.0)
                        level = min(1.0, (rms / denom) ** 0.7)
                        visual_update_audio_level(level)
                else:
                    last_sample_count = current_total

                time.sleep(0.18)  # Lower-latency feed without high CPU usage.

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
            visual_update_audio_features({"level": 0.0, "low": 0.0, "mid": 0.0, "high": 0.0, "centroid": 0.0})

    def _audio_visual_loop(self) -> None:
        while self.rec.is_recording() and not self._audio_visual_stop.is_set():
            try:
                audio = self.rec._ring_buffer.get_latest_samples(4096)
                if len(audio) > 0:
                    window = audio
                    rms = float(np.sqrt(np.mean(np.square(window))))
                    # Adaptive floor to suppress constant movement from room noise.
                    if self._audio_noise_floor <= 0.0:
                        self._audio_noise_floor = rms
                    if rms < self._audio_noise_floor * 1.8:
                        self._audio_noise_floor = (self._audio_noise_floor * 0.96) + (rms * 0.04)

                    min_rms = float(getattr(self.cfg, "min_rms_amplitude", 5e-4))
                    noise_ref = max(min_rms * 0.8, self._audio_noise_floor)
                    signal = max(0.0, rms - noise_ref)
                    speech_gate = max(min_rms * 0.15, noise_ref * 0.08)
                    if signal <= speech_gate:
                        level = 0.0
                    else:
                        denom = max(1e-6, (noise_ref * 2.2) + (min_rms * 1.5))
                        level = min(1.0, (signal / denom) ** 0.62)
                    visual_update_audio_level(level)

                    # Frequency profile for animation (UI-only; no ASR dependency).
                    n = min(len(window), 2048)
                    if n >= 256:
                        seg = window[-n:].astype(np.float32)
                        hann = np.hanning(n).astype(np.float32)
                        spectrum = np.abs(np.fft.rfft(seg * hann))
                        freqs = np.fft.rfftfreq(n, d=1.0 / float(self.cfg.sample_rate))

                        def _band(lo: float, hi: float) -> float:
                            m = (freqs >= lo) & (freqs < hi)
                            if not np.any(m):
                                return 0.0
                            return float(np.mean(spectrum[m]))

                        low_e = _band(70.0, 280.0)
                        mid_e = _band(280.0, 1800.0)
                        high_e = _band(1800.0, 6000.0)
                        total = max(1e-8, low_e + mid_e + high_e)

                        spec_sum = float(np.sum(spectrum))
                        centroid_hz = (
                            float(np.sum(freqs * spectrum)) / max(1e-8, spec_sum)
                            if spec_sum > 0.0
                            else 0.0
                        )
                        centroid_norm = max(0.0, min(1.0, centroid_hz / 5000.0))

                        visual_update_audio_features(
                            {
                                "level": float(level),
                                "low": float(low_e / total),
                                "mid": float(mid_e / total),
                                "high": float(high_e / total),
                                "centroid": float(centroid_norm),
                            }
                        )
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
                # Preview stream only; skip expensive final pass to protect long-utterance latency.
                self._streaming_transcriber.stop(discard_final=True, join_timeout=0.2)
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

    def handle_manual_correction_feedback(
        self,
        original_text: str,
        corrected_text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        raw = str(original_text or "").strip()
        corrected = str(corrected_text or "").strip()
        if not raw or not corrected or raw == corrected:
            return
        meta = dict(metadata or {})
        meta["source"] = "manual_correction"

        # Persist to transcription_corrections.jsonl for the daily learning job.
        # Skip if "local_ts" is already in metadata — that means visual_indicators.py
        # already wrote this correction to the file via _save_history_correction.
        if not meta.get("local_ts"):
            try:
                payload = {
                    "ts": time.time(),
                    "local_ts": datetime.now().isoformat(timespec="seconds"),
                    "original_text": raw,
                    "corrected_text": corrected,
                    "source": "manual_correction",
                }
                append_jsonl_bounded(
                    config_dir() / "transcription_corrections.jsonl",
                    payload,
                    max_file_bytes=786432,
                    keep_lines=1000,
                    max_line_chars=8192,
                )
            except Exception as exc:
                self._log.warning("correction_persist_failed error=%s", exc)

        if not self.adaptive_learning:
            return
        self._observe_adaptive_async(raw, corrected, meta)

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
        stage_ms: Dict[str, float] = {}
        asr_model_id = ""
        asr_model_name = ""
        asr_device = ""
        asr_compute = ""
        asr_path = "primary"
        retry_used = False
        retry_strategy = "none"
        retry_chunks_used = 0
        second_pass_mode = "none"
        second_pass_chars_delta = 0
        idle_resume_force_primary = False

        def _capture_model_metadata(engine: Any) -> None:
            nonlocal asr_model_id, asr_model_name, asr_device, asr_compute
            model_cfg = getattr(engine, "model_config", None)
            if model_cfg is None:
                return
            asr_model_name = str(getattr(model_cfg, "name", "") or "")
            asr_model_id = str(getattr(model_cfg, "model_id", "") or "")
            asr_device = str(getattr(model_cfg, "device", "") or "")
            asr_compute = str(getattr(model_cfg, "compute_type", "") or "")

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
                        self._last_transcription_completed_at = time.time()
                        return ""

            start_time = time.perf_counter()
            raw_audio_duration = len(audio_data) / self.cfg.sample_rate if len(audio_data) > 0 else 0.0
            idle_resume_active = False
            idle_gap_seconds = 0.0
            last_completed = float(getattr(self, "_last_transcription_completed_at", 0.0) or 0.0)
            if bool(getattr(self.cfg, "idle_resume_guard_enabled", True)) and last_completed > 0.0:
                idle_gap_seconds = max(0.0, time.time() - last_completed)
                idle_resume_threshold = max(30.0, float(getattr(self.cfg, "idle_resume_threshold_seconds", 1200.0)))
                idle_resume_active = idle_gap_seconds >= idle_resume_threshold
                if idle_resume_active:
                    self._log.info(
                        "transcription_idle_resume_guard gap_seconds=%.1f threshold_seconds=%.1f",
                        idle_gap_seconds,
                        idle_resume_threshold,
                    )
                    stage_start = time.perf_counter()
                    warmup_ms = self._run_idle_resume_warmup()
                    stage_ms["idle_resume_warmup"] = warmup_ms or ((time.perf_counter() - stage_start) * 1000.0)

            if idle_resume_active and bool(getattr(self.cfg, "idle_resume_force_primary_model", True)):
                idle_resume_force_primary = raw_audio_duration >= float(
                    getattr(self.cfg, "idle_resume_force_primary_min_audio_seconds", 1.8)
                )
                if idle_resume_force_primary:
                    self._log.info(
                        "idle_resume_force_primary_enabled raw_duration=%.2f min_seconds=%.2f",
                        raw_audio_duration,
                        float(getattr(self.cfg, "idle_resume_force_primary_min_audio_seconds", 1.8)),
                    )

            skip_pause_compaction = self._should_skip_pause_compaction_on_idle_resume(
                raw_audio_duration=raw_audio_duration,
                idle_resume_active=idle_resume_active,
            )
            compaction_overrides: Dict[str, float] = {}
            if idle_resume_active and not skip_pause_compaction:
                compaction_overrides["keep_ms"] = float(
                    getattr(self.cfg, "idle_resume_compaction_keep_silence_ms", 140)
                )
                compaction_overrides["max_reduction_pct"] = float(
                    getattr(self.cfg, "idle_resume_compaction_max_reduction_pct", 68.0)
                )
            if skip_pause_compaction:
                compacted_audio = audio_data
                stage_ms["pause_compaction"] = 0.0
                self._log.info(
                    "idle_resume_pause_compaction_bypassed raw_duration=%.2f min_seconds=%.2f",
                    raw_audio_duration,
                    float(getattr(self.cfg, "idle_resume_skip_pause_compaction_min_audio_seconds", 18.0)),
                )
            else:
                stage_start = time.perf_counter()
                compacted_audio = self._compact_pauses(audio_data, overrides=compaction_overrides)
                stage_ms["pause_compaction"] = (time.perf_counter() - stage_start) * 1000.0
            audio_duration = len(compacted_audio) / self.cfg.sample_rate if len(compacted_audio) > 0 else 0.0
            compacted_audio_duration = audio_duration
            compaction_reduction_pct = 0.0
            if len(compacted_audio) != len(audio_data):
                compaction_reduction_pct = 100.0 * (1.0 - (len(compacted_audio) / max(1, len(audio_data))))
                self._log.info(
                    "pause_compaction raw_duration=%.2f compacted_duration=%.2f reduction=%.1f%%",
                    raw_audio_duration,
                    audio_duration,
                    compaction_reduction_pct,
                )
            self._log.info(
                "transcription_started duration=%.2f raw_duration=%.2f samples=%d compacted_samples=%d",
                audio_duration,
                raw_audio_duration,
                len(audio_data),
                len(compacted_audio),
            )

            non_speech_soft_trigger = False
            non_speech_reason = ""
            non_speech_metrics: Dict[str, float] = {}
            stage_start = time.perf_counter()
            is_non_speech, non_speech_reason, non_speech_metrics = self._detect_likely_non_speech(compacted_audio)
            stage_ms["non_speech_guard"] = (time.perf_counter() - stage_start) * 1000.0
            if is_non_speech:
                self._log.info(
                    "transcription_filtered reason=%s duration=%.2f peak=%.3f rms=%.5f crest=%.2f voiced=%.3f zcr=%.3f flatness=%.3f",
                    non_speech_reason,
                    non_speech_metrics.get("duration", 0.0),
                    non_speech_metrics.get("peak", 0.0),
                    non_speech_metrics.get("rms", 0.0),
                    non_speech_metrics.get("crest_factor", 0.0),
                    non_speech_metrics.get("voiced_ratio", 0.0),
                    non_speech_metrics.get("zcr", 0.0),
                    non_speech_metrics.get("flatness", 0.0),
                )
                if not bool(getattr(self.cfg, "non_speech_guard_soft_mode", True)):
                    print("[TRANSCRIPTION] Filtered likely non-speech audio burst.")
                    mark_idle()
                    if self.visual_indicators_enabled:
                        update_tray_status(self.tray_controller, "idle", False)
                        if VISUAL_INDICATORS_AVAILABLE:
                            hide_status()
                    self._last_transcription_completed_at = time.time()
                    return ""

                non_speech_soft_trigger = True
                self._log.info(
                    "transcription_guard_soft_trigger reason=%s action=retry_asr",
                    non_speech_reason,
                )
                # Avoid losing speech around cough/sneeze by retrying on raw (uncompacted) audio.
                if len(audio_data) > len(compacted_audio):
                    previous_compacted_duration = audio_duration
                    compacted_audio = audio_data
                    audio_duration = raw_audio_duration
                    self._log.info(
                        "transcription_guard_retry_raw raw_duration=%.2f compacted_duration=%.2f",
                        raw_audio_duration,
                        previous_compacted_duration,
                    )
                    self._maybe_capture_feedback_audio(
                        compacted_audio,
                        {
                            "stage": "non_speech_guard_soft_trigger",
                            "reason": non_speech_reason,
                            "metrics": non_speech_metrics,
                        },
                    )

            # Already in processing state from stop_recording

            # Update visual indicators - transcribing status
            if self.visual_indicators_enabled:
                update_tray_status(self.tray_controller, "transcribing", False)
                if VISUAL_INDICATORS_AVAILABLE:
                    show_transcribing()

            # Transcribe with timeout protection (60 seconds max)
            timeout_seconds = max(60, max(audio_duration, raw_audio_duration) * 3)  # 3x audio duration or 60s minimum

            try:
                active_asr = self.asr
                asr_path = "primary"
                with OperationTimeout(timeout_seconds, f"transcription_{audio_duration:.1f}s"):
                    engine_pick_duration = audio_duration
                    if bool(getattr(self.cfg, "pause_compaction_engine_guard_enabled", True)):
                        guard_min_reduction = float(
                            getattr(self.cfg, "pause_compaction_engine_guard_min_reduction_pct", 45.0)
                        )
                        guard_min_raw = float(
                            getattr(self.cfg, "pause_compaction_engine_guard_min_raw_audio_seconds", 6.0)
                        )
                        if compaction_reduction_pct >= guard_min_reduction and raw_audio_duration >= guard_min_raw:
                            engine_pick_duration = max(audio_duration, raw_audio_duration)
                            self._log.info(
                                "pause_compaction_engine_guard reduction=%.1f%% pick_duration=%.2f raw_duration=%.2f compacted_duration=%.2f",
                                compaction_reduction_pct,
                                engine_pick_duration,
                                raw_audio_duration,
                                audio_duration,
                            )

                    active_asr, asr_path = self._pick_asr_engine(
                        engine_pick_duration,
                        force_primary=idle_resume_force_primary,
                    )
                    _capture_model_metadata(active_asr)
                    self._log.info(
                        "transcription_engine path=%s model=%s model_id=%s device=%s compute=%s",
                        asr_path,
                        asr_model_name,
                        asr_model_id,
                        asr_device,
                        asr_compute,
                    )
                    self._log.info("transcription_path path=%s duration=%.2f", asr_path, audio_duration)
                    (
                        text,
                        active_asr,
                        blank_fast_retry_used,
                        blank_fast_retry_path,
                        stage_ms["asr_decode"],
                        blank_fast_retry_ms,
                    ) = self._transcribe_with_fast_path_fallback(
                        active_asr,
                        asr_path,
                        compacted_audio,
                        audio_duration=audio_duration,
                        raw_audio_duration=raw_audio_duration,
                        is_non_speech=is_non_speech,
                        non_speech_reason=non_speech_reason,
                        non_speech_metrics=non_speech_metrics,
                    )
                    if blank_fast_retry_ms > 0.0:
                        stage_ms["asr_retry"] = stage_ms.get("asr_retry", 0.0) + blank_fast_retry_ms
                    if blank_fast_retry_used:
                        retry_used = True
                        retry_strategy = blank_fast_retry_path
                        _capture_model_metadata(active_asr)
                raw_transcript = text

                # Quality fallback: if compaction removed a lot and transcript looks sparse/short,
                # retry on raw audio. For long clips above hard max, use bounded chunked retry.
                retry_max_raw_seconds = float(getattr(self.cfg, "pause_compaction_retry_max_raw_audio_seconds", 20.0))
                retry_hard_max_raw_seconds = float(
                    getattr(self.cfg, "pause_compaction_retry_hard_max_raw_audio_seconds", 75.0)
                )
                retry_chunked_long_enabled = bool(
                    getattr(self.cfg, "pause_compaction_retry_chunked_long_enabled", True)
                )
                retry_chunked_max_raw_seconds = float(
                    getattr(self.cfg, "pause_compaction_retry_chunked_max_raw_audio_seconds", 210.0)
                )
                if (
                    bool(getattr(self.cfg, "pause_compaction_retry_on_short_output", True))
                    and len(audio_data) > len(compacted_audio)
                    and raw_audio_duration >= float(getattr(self.cfg, "pause_compaction_retry_min_raw_audio_seconds", 4.0))
                ):
                    initial_words = len((text or "").split())
                    initial_chars = len((text or "").strip())
                    retry_eval = self._evaluate_compaction_retry_signal(
                        raw_audio_duration=raw_audio_duration,
                        compaction_reduction_pct=compaction_reduction_pct,
                        initial_words=initial_words,
                        initial_chars=initial_chars,
                        idle_resume_active=idle_resume_active,
                    )
                    retry_due_to_short = bool(retry_eval["retry_due_to_short"])
                    retry_due_to_sparse = bool(retry_eval["retry_due_to_sparse"])
                    idle_resume_retry_due_to_compaction = bool(
                        retry_eval["idle_resume_retry_due_to_compaction"]
                    )
                    retry_min_reduction = float(retry_eval["retry_min_reduction"])
                    words_per_second = float(retry_eval["words_per_second"])
                    chars_per_second = float(retry_eval["chars_per_second"])
                    retry_reasons = ",".join(retry_eval["reasons"]) or "none"
                    within_primary_window = raw_audio_duration <= retry_max_raw_seconds
                    within_extended_window = (
                        raw_audio_duration > retry_max_raw_seconds
                        and raw_audio_duration <= retry_hard_max_raw_seconds
                        and (retry_due_to_sparse or idle_resume_retry_due_to_compaction)
                    )
                    within_chunked_window = (
                        retry_chunked_long_enabled
                        and raw_audio_duration > retry_hard_max_raw_seconds
                        and raw_audio_duration <= retry_chunked_max_raw_seconds
                        and (retry_due_to_sparse or idle_resume_retry_due_to_compaction)
                    )
                    retry_triggered = bool(retry_eval["retry_triggered"]) and (
                        within_primary_window or within_extended_window or within_chunked_window
                    )
                    if retry_triggered:
                        self._log.info(
                            "pause_compaction_retry_candidate words=%d chars=%d wps=%.2f cps=%.2f reduction=%.1f%% raw_duration=%.2f window=%s reasons=%s idle_resume=%s",
                            initial_words,
                            initial_chars,
                            words_per_second,
                            chars_per_second,
                            compaction_reduction_pct,
                            raw_audio_duration,
                            (
                                "primary"
                                if within_primary_window
                                else ("extended" if within_extended_window else "chunked")
                            ),
                            retry_reasons,
                            str(idle_resume_active),
                        )
                        stage_start = time.perf_counter()
                        retry_path = "primary-retry"
                        retry_text = ""
                        if within_chunked_window:
                            retry_text, retry_chunks_used = self._transcribe_raw_in_chunks(
                                audio_data,
                                force_primary=idle_resume_force_primary,
                            )
                            retry_path = "chunked-raw-retry"
                        else:
                            fast_retry_max_raw = float(
                                getattr(self.cfg, "pause_compaction_retry_fast_path_max_raw_audio_seconds", 18.0)
                            )
                            if asr_path == "fast" and raw_audio_duration <= fast_retry_max_raw:
                                retry_asr = active_asr
                                retry_path = "fast-retry"
                            else:
                                retry_asr, retry_path = self._pick_asr_engine(
                                    raw_audio_duration,
                                    force_primary=idle_resume_force_primary,
                                )
                            retry_text = retry_asr.transcribe(audio_data)

                        stage_ms["asr_retry"] = (time.perf_counter() - stage_start) * 1000.0
                        retry_words = len((retry_text or "").split())
                        retry_chars = len((retry_text or "").strip())
                        retry_wps = retry_words / max(0.1, raw_audio_duration)
                        retry_cps = retry_chars / max(0.1, raw_audio_duration)
                        improved_density = retry_wps >= (words_per_second * 1.2) or retry_cps >= (chars_per_second * 1.18)
                        improved_volume = retry_words >= (initial_words + 2) or retry_chars >= (initial_chars + 12)
                        retry_accept = (retry_words > 0 and retry_chars > 0) and (
                            improved_volume or improved_density
                        )

                        if retry_accept:
                            retry_used = True
                            retry_strategy = retry_path
                            self._log.info(
                                "pause_compaction_retry_applied initial_words=%d retry_words=%d reduction=%.1f%% path=%s chunks=%d reasons=%s",
                                initial_words,
                                retry_words,
                                compaction_reduction_pct,
                                retry_path,
                                int(retry_chunks_used),
                                retry_reasons,
                            )
                            text = retry_text
                            raw_transcript = retry_text
                            if not within_chunked_window:
                                _capture_model_metadata(retry_asr)
                            compacted_audio = audio_data
                            audio_duration = raw_audio_duration
                        else:
                            self._log.info(
                                "pause_compaction_retry_rejected initial_words=%d retry_words=%d reduction=%.1f%% path=%s chunks=%d reasons=%s",
                                initial_words,
                                retry_words,
                                compaction_reduction_pct,
                                retry_path,
                                int(retry_chunks_used),
                                retry_reasons,
                            )
                    elif raw_audio_duration > retry_chunked_max_raw_seconds:
                        self._log.info(
                            "pause_compaction_retry_skipped raw_duration=%.2f max_raw=%.2f",
                            raw_audio_duration,
                            retry_chunked_max_raw_seconds,
                        )
                    elif (
                        raw_audio_duration > retry_max_raw_seconds
                        and compaction_reduction_pct >= retry_min_reduction
                    ):
                        self._log.info(
                            "pause_compaction_retry_not_sparse words=%d chars=%d wps=%.2f cps=%.2f raw_duration=%.2f max_raw=%.2f reasons=%s idle_resume=%s",
                            initial_words,
                            initial_chars,
                            words_per_second,
                            chars_per_second,
                            raw_audio_duration,
                            retry_max_raw_seconds,
                            retry_reasons,
                            str(idle_resume_active),
                        )

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
                        self._last_transcription_completed_at = time.time()
                        return ""

                    # Check for very short or repetitive content
                    if len(text.strip()) < 3:
                        print(f"[TRANSCRIPTION] Content too short - skipping")
                        self._log.info("transcription_filtered reason=too_short")
                        mark_idle()
                        update_tray_status(self.tray_controller, "idle", False)
                        self._last_transcription_completed_at = time.time()
                        return ""

            except TimeoutError as e:
                logger.error(f"Transcription timeout: {e}")
                print(f"[TRANSCRIPTION] Timeout after {timeout_seconds}s - skipping")
                self._log.error("transcription_timeout duration=%.2f timeout=%.2f", audio_duration, timeout_seconds)
                # Return to idle state after timeout
                mark_idle()
                self._last_transcription_completed_at = time.time()
                return ""

            # Apply basic processing
            postprocess_start = time.perf_counter()
            text = self._normalize_context_terms_runtime(text)
            destination_context = self._destination_format_context()
            destination_profile = infer_destination_profile(destination_context)
            effective_code_mode = bool(self.code_mode and destination_profile in {"editor", "terminal"})
            if effective_code_mode:
                text = apply_code_mode(text, lowercase=self.cfg.code_mode_lowercase)
            else:
                if self.adaptive_learning and text.strip():
                    text = self.adaptive_learning.apply(text)
                text = format_transcript_for_destination(
                    text,
                    destination=destination_context,
                    audio_duration=audio_duration,
                )
                self._log.info(
                    "format_profile profile=%s process=%s width=%s",
                    destination_profile,
                    str(destination_context.get("process_name", "") or ""),
                    int(destination_context.get("window_width", 0) or 0),
                )
                if non_speech_soft_trigger:
                    self._log.info(
                        "transcription_guard_soft_result reason=%s words=%d chars=%d",
                        non_speech_reason,
                        len(text.split()),
                        len(text),
                    )
                    self._maybe_capture_feedback_audio(
                        compacted_audio,
                        {
                            "stage": "non_speech_guard_soft_result",
                            "reason": non_speech_reason,
                            "metrics": non_speech_metrics,
                            "raw_transcript": str(raw_transcript or "")[:240],
                            "final_transcript": str(text or "")[:240],
                        },
                    )

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

            # Keep capitalization/paragraph structure after AI edits.
            if text and not effective_code_mode:
                try:
                    final_destination = destination_context or self._destination_format_context()
                    text = format_transcript_for_destination(
                        text,
                        destination=final_destination,
                        audio_duration=audio_duration,
                    )
                except Exception:
                    text = format_transcript_text(text)

                # Optional low-latency second-pass cleanup stage.
                base_before_second_pass = text
                if bool(getattr(self.cfg, "enable_safe_second_pass_cleanup", True)):
                    stage_start = time.perf_counter()
                    text = apply_second_pass_cleanup(text, heavy=False)
                    stage_ms["second_pass_safe"] = (time.perf_counter() - stage_start) * 1000.0
                    second_pass_mode = "safe"
                if bool(getattr(self.cfg, "enable_heavy_second_pass_cleanup", False)):
                    heavy_threshold = max(64, int(getattr(self.cfg, "heavy_second_pass_min_chars", 180)))
                    if len(text or "") >= heavy_threshold:
                        stage_start = time.perf_counter()
                        text = apply_second_pass_cleanup(text, heavy=True)
                        stage_ms["second_pass_heavy"] = (time.perf_counter() - stage_start) * 1000.0
                        second_pass_mode = "safe+heavy" if second_pass_mode == "safe" else "heavy"
                second_pass_chars_delta = len(text) - len(base_before_second_pass)
                self._log.info(
                    "second_pass_cleanup mode=%s delta_chars=%d safe_ms=%.2f heavy_ms=%.2f",
                    second_pass_mode,
                    second_pass_chars_delta,
                    stage_ms.get("second_pass_safe", 0.0),
                    stage_ms.get("second_pass_heavy", 0.0),
                )
            stage_ms["postprocess"] = (time.perf_counter() - postprocess_start) * 1000.0

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
            final_transcription_path = retry_strategy if retry_used else asr_path
            if self.visual_indicators_enabled and text.strip():
                visual_record_transcription_event(
                    text,
                    audio_duration,
                    transcription_time,
                    metadata={
                        "raw_audio_duration": round(raw_audio_duration, 3),
                        "compacted_audio_duration": round(compacted_audio_duration, 3),
                        "compaction_reduction_pct": round(compaction_reduction_pct, 2),
                        "retry_used": bool(retry_used),
                        "transcription_path": str(final_transcription_path),
                        "idle_resume_active": bool(idle_resume_active),
                    },
                )

            # Inject text
            inject_start = time.perf_counter()
            if text.strip():
                # Mark as injecting
                mark_injecting()

                inject_ok = bool(self.injector.inject(text))
                if not inject_ok:
                    clipboard_ok = bool(self.injector.copy_text_to_clipboard(text))
                    target_context = self.injector.get_target_context()
                    target_name = (
                        str(target_context.get("process_name", "") or "").strip()
                        or str(target_context.get("window_title", "") or "").strip()
                        or "target window"
                    )
                    if clipboard_ok:
                        print(
                            f"[INJECT] Focus changed before paste. Transcript copied to clipboard for manual paste in {target_name}."
                        )
                    else:
                        print(
                            f"[INJECT] Focus changed before paste and clipboard fallback failed. Verify focus and retry in {target_name}."
                        )
                    self._log.warning(
                        "inject_failed clipboard_fallback=%s target=%s chars=%d",
                        str(clipboard_ok),
                        target_name,
                        len(text),
                    )
                    if self.visual_indicators_enabled:
                        update_tray_status(
                            self.tray_controller,
                            "error",
                            False,
                            "Focus changed; transcript copied to clipboard" if clipboard_ok else "Focus changed; injection failed",
                        )
                        if VISUAL_INDICATORS_AVAILABLE:
                            if clipboard_ok:
                                show_error("Focus changed; copied to clipboard")
                            else:
                                show_error("Focus changed; injection failed")

                self._log.info("transcribed chars=%d words=%d seconds=%.3f",
                             len(text), len(text.split()), transcription_time)

                # Update visual indicators - completion with transcription result
                if self.visual_indicators_enabled and inject_ok:
                    truncated_text = text[:50] + "..." if len(text) > 50 else text
                    update_tray_status(self.tray_controller, "complete", False, f"Transcribed: {truncated_text}")
                    if VISUAL_INDICATORS_AVAILABLE:
                        show_complete("Complete")

                    # CRITICAL: Schedule delayed reset to idle via tray auto-reset timer
                    # Don't immediately go to idle - let the tray controller handle the 2s auto-reset
            stage_ms["inject"] = (time.perf_counter() - inject_start) * 1000.0

            self._log.info(
                (
                    "transcription_timing total_ms=%.1f path=%s model_id=%s device=%s compute=%s "
                    "retry_used=%s compaction_ms=%.1f guard_ms=%.1f asr_ms=%.1f retry_ms=%.1f "
                    "post_ms=%.1f safe2_ms=%.1f heavy2_ms=%.1f second_pass=%s delta_chars=%d inject_ms=%.1f "
                    "raw_dur=%.2f compacted_dur=%.2f reduction=%.1f retry_strategy=%s retry_chunks=%d "
                    "idle_resume=%s idle_resume_force_primary=%s warmup_ms=%.1f"
                ),
                transcription_time * 1000.0,
                asr_path,
                asr_model_id,
                asr_device,
                asr_compute,
                str(retry_used),
                stage_ms.get("pause_compaction", 0.0),
                stage_ms.get("non_speech_guard", 0.0),
                stage_ms.get("asr_decode", 0.0),
                stage_ms.get("asr_retry", 0.0),
                stage_ms.get("postprocess", 0.0),
                stage_ms.get("second_pass_safe", 0.0),
                stage_ms.get("second_pass_heavy", 0.0),
                second_pass_mode,
                int(second_pass_chars_delta),
                stage_ms.get("inject", 0.0),
                raw_audio_duration,
                compacted_audio_duration,
                compaction_reduction_pct,
                retry_strategy,
                int(retry_chunks_used),
                str(idle_resume_active),
                str(idle_resume_force_primary),
                stage_ms.get("idle_resume_warmup", 0.0),
            )

            if text.strip():
                self._observe_adaptive_async(
                    raw_transcript if 'raw_transcript' in locals() else text,
                    text,
                    {
                        "source": "runtime_transcription",
                        "model_tier": getattr(self.cfg, "model_tier", ""),
                        "code_mode": bool(self.code_mode),
                        "course_corrected": course_corrected,
                        "correction_type": correction_type,
                        "audio_duration": round(audio_duration, 3),
                        "raw_audio_duration": round(raw_audio_duration, 3),
                        "compacted_audio_duration": round(compacted_audio_duration, 3),
                        "compaction_reduction_pct": round(compaction_reduction_pct, 2),
                        "retry_used": bool(retry_used),
                        "retry_strategy": retry_strategy,
                        "retry_chunks_used": int(retry_chunks_used),
                        "idle_resume_active": bool(idle_resume_active),
                        "idle_resume_force_primary": bool(idle_resume_force_primary),
                        "transcription_path": final_transcription_path,
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

            self._last_transcription_completed_at = time.time()
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

            self._last_transcription_completed_at = time.time()
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
        self._housekeeping_stop.set()
        if self._housekeeping_thread and self._housekeeping_thread.is_alive():
            self._housekeeping_thread.join(timeout=1.5)
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
    if not _acquire_single_instance_mutex():
        return 0
    if not _is_primary_cli_process():
        return 0
    if not _enforce_single_instance():
        return 0
    if _yield_if_bootstrap_parent():
        return 0
    _start_bootstrap_parent_watchdog()
    _start_single_instance_watchdog(interval_seconds=2.0)

    cfg = load_config(Config())
    setup_saved, _setup_restart_required = maybe_run_startup_setup(cfg)
    if setup_saved:
        print("[SETUP] Saved startup defaults from setup wizard.")
    else:
        skip_setup_env = str(os.environ.get("VOICEFLOW_SKIP_SETUP_UI", "")).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        setup_incomplete = not bool(getattr(cfg, "setup_completed", False))
        startup_prompt_enabled = bool(getattr(cfg, "show_setup_on_startup", True))
        if setup_incomplete and startup_prompt_enabled and not skip_setup_env:
            print("[SETUP] Startup setup was not completed. Exiting before runtime launch.")
            return 0

    gpu_mode = (
        str(getattr(cfg, "device", "")).strip().lower() == "cuda"
        or bool(getattr(cfg, "enable_gpu_acceleration", False))
    )
    model_tier = str(getattr(cfg, "model_tier", "quick")).strip().lower()
    if gpu_mode:
        if model_tier in {"quality", "voxtral"}:
            monitor_memory_warning_mb = 2048.0
            monitor_memory_critical_mb = 4096.0
        else:
            monitor_memory_warning_mb = 1536.0
            monitor_memory_critical_mb = 3072.0
    else:
        monitor_memory_warning_mb = 1024.0
        monitor_memory_critical_mb = 2048.0

    # Initialize async logging to a rotating file
    _alog = AsyncLogger(default_log_dir())
    runtime_log = _alog.get()
    runtime_log.info("single_instance_ok pid=%d", os.getpid())
    runtime_log.info("single_instance_watchdog_started interval_s=2.0")

    # Start idle-aware monitoring for long-running operation
    print(
        "[MONITOR] Starting idle-aware monitoring for 24/7 operation "
        f"(warn={monitor_memory_warning_mb:.0f}MB, critical={monitor_memory_critical_mb:.0f}MB)..."
    )
    monitor = start_idle_monitoring(
        operation_timeout=120.0,        # 2 minutes max for active operations
        memory_warning_mb=monitor_memory_warning_mb,
        memory_critical_mb=monitor_memory_critical_mb,
        check_interval=10.0             # Check every 10 seconds
    )
    app_ref: Dict[str, Any] = {"instance": None}

    # Set up monitoring callbacks
    def on_hang_detected(reason: str):
        print(f"[MONITOR] HANG DETECTED: {reason}")
        # Could trigger restart here if desired
        # For now, just log it

    def on_memory_warning(memory_mb: float):
        print(f"[MONITOR] Memory warning: {memory_mb:.1f}MB")
        runtime_log.warning("monitor_memory_warning usage_mb=%.1f", float(memory_mb))
        instance = app_ref.get("instance")
        if instance is not None:
            try:
                if getattr(instance, "adaptive_learning", None) and hasattr(instance.adaptive_learning, "_purge_expired"):
                    instance.adaptive_learning._purge_expired()
            except Exception:
                runtime_log.exception("monitor_memory_warning adaptive_purge_failed")
        try:
            collected = gc.collect()
            runtime_log.info("monitor_memory_warning gc_collected=%d", int(collected))
        except Exception:
            runtime_log.exception("monitor_memory_warning gc_failed")

    monitor.on_hang_detected = on_hang_detected
    monitor.on_memory_warning = on_memory_warning

    # Mark initial state as idle
    mark_idle()

    if VISUAL_INDICATORS_AVAILABLE:
        try:
            visual_set_animation_preferences(
                quality=str(getattr(cfg, "visual_animation_quality", "auto") or "auto"),
                reduced_motion=bool(getattr(cfg, "visual_reduced_motion", False)),
                target_fps=int(getattr(cfg, "visual_target_fps", 28) or 28),
            )
        except Exception:
            runtime_log.exception("visual_animation_pref_apply_failed")

    if not is_admin():
        print("Warning: Not running as Administrator. Global hotkeys and key injection may be limited in elevated apps.")
    info = nvidia_smi_info()
    if info:
        print(f"GPU: {info}")

    current_platform = runtime_platform_name()
    injector_backend = create_injector_backend(cfg, platform_name=current_platform)
    app = EnhancedApp(cfg, injector_backend=injector_backend)
    app_ref["instance"] = app
    if VISUAL_INDICATORS_AVAILABLE:
        try:
            visual_set_correction_feedback_handler(app.handle_manual_correction_feedback)
        except Exception:
            runtime_log.exception("visual_correction_feedback_handler_register_failed")

    # Enhanced tray support with visual indicators
    tray = None
    if cfg.use_tray:
        runtime_log.info("tray_start_attempt controller=platform platform=%s", current_platform)
        try:
            tray = create_tray_backend(app, platform_name=current_platform, prefer_enhanced=True)
            app.tray_controller = tray
            tray.start()
            print(f"Tray backend started ({current_platform}).")
            runtime_log.info("tray_started controller=platform platform=%s", current_platform)
        except Exception as e:
            print(f"Primary tray backend failed: {e}")
            runtime_log.exception("tray_start_failed controller=platform platform=%s", current_platform)
            if current_platform == "windows":
                try:
                    tray = create_tray_backend(app, platform_name=current_platform, prefer_enhanced=False)
                    app.tray_controller = tray
                    tray.start()
                    print("Fallback tray backend started.")
                    runtime_log.info("tray_started controller=fallback platform=%s", current_platform)
                except Exception as e2:
                    print(f"Fallback tray backend also failed: {e2}")
                    runtime_log.exception("tray_start_failed controller=fallback platform=%s", current_platform)
    else:
        runtime_log.info("tray_disabled_by_config")

    # Keep dock feedback alive even if tray startup fails.
    if not tray and app.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
        try:
            from voiceflow.ui.visual_indicators import set_dock_enabled

            dock_enabled = bool(getattr(cfg, "visual_dock_enabled", True))
            set_dock_enabled(dock_enabled)
            runtime_log.info("dock_started_without_tray enabled=%s", dock_enabled)
        except Exception:
            runtime_log.exception("dock_start_without_tray_failed")

    if app.visual_indicators_enabled and VISUAL_INDICATORS_AVAILABLE:
        try:
            indicator = visual_get_indicator()
            dock_enabled = bool(getattr(cfg, "visual_dock_enabled", True))
            if indicator:
                visual_set_dock_enabled(dock_enabled)
            runtime_log.info("visual_indicator_prewarmed dock_enabled=%s ready=%s", dock_enabled, bool(indicator))
        except Exception:
            runtime_log.exception("visual_indicator_prewarm_failed")

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

    def _register_hotkey(chord: str, callback: callable, label: str) -> bool:
        try:
            keyboard.add_hotkey(chord, callback, suppress=False)
            runtime_log.info("hotkey_registered chord=%s label=%s", chord, label)
            return True
        except Exception:
            runtime_log.exception("hotkey_register_failed chord=%s label=%s", chord, label)
            return False

    # Register config hotkeys (best-effort; failures should not block app startup).
    _register_hotkey('ctrl+alt+c', toggle_code_mode, "toggle_code_mode")
    _register_hotkey('ctrl+alt+p', toggle_injection, "toggle_injection")
    _register_hotkey('ctrl+alt+enter', toggle_enter, "toggle_enter")

    # Enhanced PTT listener with tail-end buffer
    listener = create_hotkey_backend(
        cfg=cfg,
        on_start=app.start_recording,
        on_stop=app.stop_recording,
        platform_name=current_platform,
    )
    app.ptt_listener = listener

    # Final bootstrap guard: if this process spawned an identical child, yield to child.
    # This avoids dual hotkey listeners in parent+child launch environments.
    time.sleep(1.0)
    if _has_same_entry_child():
        print(f"[MAIN] Parent process yielding to child runtime (pid={os.getpid()}).")
        try:
            if tray:
                tray.stop()
        except Exception:
            pass
        try:
            app.shutdown()
        except Exception:
            pass
        try:
            visual_set_correction_feedback_handler(None)
        except Exception:
            pass
        return 0
    
    try:
        listener.start()
        runtime_log.info("hotkey_listener_started backend=%s", type(listener).__name__)
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
        app.start_background_services()

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
        try:
            visual_set_correction_feedback_handler(None)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
