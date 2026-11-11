"""Unified ASR Engine - VoiceFlow 3.2

Speech recognition engine built on faster-whisper (CTranslate2 backend).

Model Tiers:
- Quick: adaptive low-latency tier (small.en on CPU, distil-large-v3 on CUDA)
- Balanced: distil-large-v3 weights (best speed/quality ratio)
- Quality: large-v3 (highest accuracy)
- Tiny: tiny.en (fastest, lower accuracy — good for testing)
"""

import dataclasses
import logging
import os
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Process-wide model construction (VF-18)
#
# Two preloader threads (main model and, on CPU setups that opt in to the
# fast path, tiny.en) start in the same second and both end up in
# huggingface_hub.snapshot_download. Its disabled_tqdm class
# keeps a class-level ``_lock`` that concurrent calls create and delete under
# each other, so one of them dies with "type object 'disabled_tqdm' has no
# attribute '_lock'". That was misread as a CUDA failure and silently demoted
# the main model to CPU for the life of the process (warmup 4.6s instead of
# 0.1s). Each FasterWhisperBackend has its own RLock, which is why a per-backend
# lock never helped: the lock has to be shared by every backend in the process.
# ---------------------------------------------------------------------------
_MODEL_INIT_LOCK = threading.Lock()

# Seconds to wait before the one same-device retry of a non-CUDA init failure.
_CUDA_INIT_RETRY_DELAY_S = 0.25
# Minimum gap between attempts to move a CPU-fallback model back to the GPU.
_CUDA_RESTORE_MIN_INTERVAL_S = 120.0

# Failures that retrying on CUDA cannot fix: the card is full, or the runtime
# libraries are not there. Anything else (a race in a download helper, a
# transient driver hiccup) is not evidence that CUDA is unusable.
_CUDA_OUT_OF_MEMORY_MARKERS = (
    "out of memory",
    "cudaerrormemoryallocation",
    "memory allocation",
    "failed to allocate",
    "cuda_error_out_of_memory",
)
_CUDA_MISSING_RUNTIME_MARKERS = (
    "cublas",
    "cudnn",
    "cudart",
    "cannot load symbol",
    "could not load library",
    "cannot be loaded",
    "library cu",
    "no cuda-capable device",
    "cuda driver version is insufficient",
    "unsupported device cuda",
    "cuda support",
    "not compiled with cuda",
    "dll load failed",
)

#: ``(event, detail)`` -> None. Events: ``cpu_fallback`` and ``cuda_restored``.
DeviceEventListener = Callable[[str, str], None]
_device_listeners: List[DeviceEventListener] = []
_device_listeners_lock = threading.Lock()


def add_device_listener(listener: DeviceEventListener) -> None:
    """Register a callback told when an engine drops to CPU or gets CUDA back."""
    with _device_listeners_lock:
        if listener not in _device_listeners:
            _device_listeners.append(listener)


def remove_device_listener(listener: DeviceEventListener) -> None:
    with _device_listeners_lock:
        if listener in _device_listeners:
            _device_listeners.remove(listener)


def _notify_device_event(event: str, detail: str) -> None:
    with _device_listeners_lock:
        listeners = list(_device_listeners)
    for listener in listeners:
        try:
            listener(event, detail)
        except Exception:
            logger.exception("device event listener failed")


def classify_cuda_init_failure(exc: BaseException) -> str:
    """Say whether a CUDA init failure is one retrying on CUDA can fix.

    Returns ``"out_of_memory"`` or ``"missing_runtime"`` (both persistent: go
    straight to CPU) or ``"transient"`` (anything else: try CUDA once more
    before concluding CUDA is unusable).
    """
    message = f"{type(exc).__name__}: {exc}".lower()
    if any(marker in message for marker in _CUDA_OUT_OF_MEMORY_MARKERS):
        return "out_of_memory"
    if any(marker in message for marker in _CUDA_MISSING_RUNTIME_MARKERS):
        return "missing_runtime"
    return "transient"


def _is_missing_local_files(exc: BaseException) -> bool:
    """True when a ``local_files_only`` load failed only because the model is not cached."""
    for cls in type(exc).__mro__:
        if cls.__name__ in {"LocalEntryNotFoundError", "OfflineModeIsEnabled"}:
            return True
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "cannot find an appropriate cached snapshot",
            "outgoing traffic has been disabled",
            "couldn't find the requested files in the local cache",
            "not found in the local cache",
        )
    )


def _find_dll_in_path(dll_name: str) -> bool:
    path_var = os.environ.get("PATH", "")
    for entry in path_var.split(os.pathsep):
        if not entry:
            continue
        candidate = Path(entry) / dll_name
        if candidate.exists():
            return True
    return False


def _add_dll_search_path(path: Path) -> None:
    lib_path = str(path)
    path_entries = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    if lib_path not in path_entries:
        os.environ["PATH"] = lib_path + os.pathsep + os.environ.get("PATH", "")

    add_dll_directory = getattr(os, "add_dll_directory", None)
    if add_dll_directory is not None:
        try:
            add_dll_directory(lib_path)
        except Exception:
            # PATH fallback above is usually sufficient.
            pass


def _probe_external_torch_lib_dirs() -> list[Path]:
    """Find torch/lib candidates without importing torch (safe for packaged builds)."""
    candidates: list[Path] = []

    env_dir = os.environ.get("VOICEFLOW_TORCH_LIB_DIR", "").strip()
    if env_dir:
        candidates.append(Path(env_dir))

    if getattr(sys, "frozen", False):
        # PyInstaller one-dir layout.
        try:
            exe_dir = Path(sys.executable).resolve().parent
            candidates.extend(
                [
                    exe_dir / "_internal" / "torch" / "lib",
                    exe_dir / "torch" / "lib",
                    exe_dir / "_internal",
                    exe_dir,
                ]
            )
        except Exception:
            pass

        # PyInstaller one-file layout extracts binaries into sys._MEIPASS at runtime.
        # Include this explicitly so CUDA DLL probing works for released one-file EXEs.
        try:
            meipass = getattr(sys, "_MEIPASS", None)
            if meipass:
                meipass_dir = Path(str(meipass))
                candidates.extend(
                    [
                        meipass_dir / "torch" / "lib",
                        meipass_dir / "_internal" / "torch" / "lib",
                        meipass_dir,
                    ]
                )
        except Exception:
            pass

    # Active interpreter environment (source mode).
    candidates.append(Path(sys.prefix) / "Lib" / "site-packages" / "torch" / "lib")

    probe_roots: list[Path] = []
    try:
        exe_dir = Path(sys.executable).resolve().parent
        probe_roots.extend([exe_dir, exe_dir.parent, exe_dir.parent.parent])
    except Exception:
        pass

    try:
        repo_root = Path(__file__).resolve().parents[3]
        probe_roots.append(repo_root)
    except Exception:
        pass

    probe_roots.append(Path.cwd())

    for root in probe_roots:
        for venv_name in (".venv-gpu", "venv", ".venv"):
            candidates.append(root / venv_name / "Lib" / "site-packages" / "torch" / "lib")

    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _register_external_cuda_runtime_path(required_dlls: list[str]) -> bool:
    """Register CUDA runtime DLL directory without importing torch.
    Returns True if a suitable directory was found and registered.
    """
    for candidate in _probe_external_torch_lib_dirs():
        try:
            if not candidate.exists():
                continue
            if not all((candidate / dll).exists() for dll in required_dlls):
                continue
            _add_dll_search_path(candidate)
            return True
        except Exception:
            continue
    return False


def _register_torch_cuda_path(required_dlls: list[str]) -> None:
    """Expose torch CUDA DLLs to PATH/on-dll search when using venv installs on Windows."""
    try:
        import torch
    except Exception:
        return

    torch_lib = Path(torch.__file__).resolve().parent / "lib"
    if not torch_lib.exists():
        return

    if not all((torch_lib / dll).exists() for dll in required_dlls):
        return

    _add_dll_search_path(torch_lib)


def _missing_cuda_dlls(required_dlls: list[str]) -> list[str]:
    return [dll for dll in required_dlls if not _find_dll_in_path(dll)]


# DLLs ctranslate2 needs for CUDA float16 on Windows. The build verifier
# (scripts/setup/verify_bundle.py) checks the same list, so "bundle passed" and
# "runtime found CUDA" cannot disagree.
CUDA_REQUIRED_DLLS = ("cudnn_ops64_9.dll", "cublas64_12.dll")


def _cuda_runtime_ready() -> bool:
    """Best-effort CUDA runtime check for faster-whisper/ctranslate2 on Windows."""
    required_dlls = list(CUDA_REQUIRED_DLLS)
    _register_external_cuda_runtime_path(required_dlls)

    # Source/venv fallback path: keep torch probing for environments that depend on
    # torch-provided CUDA runtime DLL discovery.
    try:
        import torch
        if torch.cuda.is_available():
            _register_torch_cuda_path(required_dlls)
    except Exception:
        # torch is optional for packaged runtime checks.
        pass

    missing = _missing_cuda_dlls(required_dlls)
    if missing:
        logging.getLogger("voiceflow").info(
            "cuda_runtime_unavailable missing_dlls=%s",
            ",".join(missing),
        )
        return False

    # Prefer ctranslate2 capability checks because packaged builds may intentionally
    # exclude torch to avoid DLL init crashes.
    try:
        import ctranslate2

        get_cuda_device_count = getattr(ctranslate2, "get_cuda_device_count", None)
        if callable(get_cuda_device_count):
            try:
                if int(get_cuda_device_count()) <= 0:
                    return False
            except Exception:
                return False

        get_supported_compute_types = getattr(ctranslate2, "get_supported_compute_types", None)
        if callable(get_supported_compute_types):
            try:
                supported = get_supported_compute_types("cuda")
                if not supported:
                    return False
                return True
            except Exception:
                return False
    except Exception:
        # Fall back to torch probing when ctranslate2 probing is unavailable.
        pass

    try:
        import torch
        return bool(torch.cuda.is_available())
    except Exception:
        return False


class ModelTier(Enum):
    """Model tiers for easy selection"""
    TINY = "tiny"           # Fastest, lowest accuracy
    QUICK = "quick"         # Fast with good accuracy (adaptive by hardware)
    BALANCED = "balanced"   # Best ratio (distil-large-v3 weights)
    QUALITY = "quality"     # Highest accuracy (large-v3)
    VOXTRAL = "voxtral"     # Mistral's new model


@dataclass
class ModelConfig:
    """Configuration for a specific model"""
    name: str
    model_id: str
    backend: str  # "faster-whisper", "whisperx", "voxtral"
    compute_type: str = "int8"
    device: str = "cpu"
    description: str = ""
    size_mb: int = 0
    languages: List[str] = field(default_factory=lambda: ["en"])
    supports_diarization: bool = False
    supports_word_timestamps: bool = True
    vad_filter: bool = True
    cpu_threads: int = 0
    asr_num_workers: int = 1
    beam_size: int = 1
    best_of: int = 1
    temperature: float = 0.0
    condition_on_previous_text: bool = False


# Predefined model configurations
MODEL_CONFIGS: Dict[str, ModelConfig] = {
    # Tiny models - for testing and low-resource systems
    "tiny.en": ModelConfig(
        name="Tiny English",
        model_id="tiny.en",
        backend="faster-whisper",
        description="Fastest model, good for testing",
        size_mb=75,
        languages=["en"],
    ),
    "tiny": ModelConfig(
        name="Tiny Multilingual",
        model_id="tiny",
        backend="faster-whisper",
        description="Fastest multilingual model",
        size_mb=75,
    ),

    # Distil-Whisper models - best speed/accuracy ratio (2025)
    "distil-large-v3": ModelConfig(
        name="Distil Large v3",
        model_id="Systran/faster-distil-whisper-large-v3",
        backend="faster-whisper",
        description="6x faster than large-v3, within 1% WER",
        size_mb=1500,
        languages=["en"],
    ),
    # Legacy label. No CTranslate2 export of v3.5 was published when this key was
    # added, so it has always loaded the distil-large-v3 weights. The name now
    # says so; MODEL_KEY_ALIASES maps it to the key that matches what runs.
    # VF-18 measured the real v3.5 export ("distil-large-v3.5-ct2" below) at the
    # same speed as v3 but only a few words better on a small synthetic set, not
    # enough to change what the default loads.
    "distil-large-v3.5": ModelConfig(
        name="Distil Large v3 (legacy 'v3.5' label)",
        model_id="Systran/faster-distil-whisper-large-v3",
        backend="faster-whisper",
        description="Legacy alias: loads the distil-large-v3 weights",
        size_mb=1500,
        languages=["en"],
    ),
    # Opt-in: the real v3.5 weights (CTranslate2 export from distil-whisper).
    "distil-large-v3.5-ct2": ModelConfig(
        name="Distil Large v3.5",
        model_id="distil-whisper/distil-large-v3.5-ct2",
        backend="faster-whisper",
        description="Distil-Whisper large-v3.5, CTranslate2 export (opt-in)",
        size_mb=1500,
        languages=["en"],
    ),

    # Standard Whisper models
    "small.en": ModelConfig(
        name="Small English",
        model_id="small.en",
        backend="faster-whisper",
        description="Good balance for English only",
        size_mb=500,
        languages=["en"],
    ),
    "medium.en": ModelConfig(
        name="Medium English",
        model_id="medium.en",
        backend="faster-whisper",
        description="High accuracy English model",
        size_mb=1500,
        languages=["en"],
    ),
    "large-v3": ModelConfig(
        name="Large v3",
        model_id="large-v3",
        backend="faster-whisper",
        description="Highest accuracy, slower",
        size_mb=3000,
        supports_diarization=True,
    ),

    # WhisperX models (with advanced features)
    "whisperx-large-v3": ModelConfig(
        name="WhisperX Large v3",
        model_id="large-v3",
        backend="whisperx",
        description="Large-v3 with word timestamps and diarization",
        size_mb=3000,
        supports_diarization=True,
        supports_word_timestamps=True,
    ),

    # Voxtral models (Mistral AI - July 2025)
    "voxtral-3b": ModelConfig(
        name="Voxtral 3B",
        model_id="mistralai/Voxtral-Mini-3B-2507",
        backend="voxtral",
        description="Mistral's edge model - beats Whisper large-v3",
        size_mb=2000,
        languages=["en", "es", "fr", "de", "pt", "hi", "nl", "it"],
    ),
}

# Tier to model mapping
TIER_MODELS: Dict[ModelTier, str] = {
    ModelTier.TINY: "tiny.en",
    # QUICK is resolved dynamically per hardware in resolve_tier_model_key().
    ModelTier.QUICK: "distil-large-v3",
    ModelTier.BALANCED: "distil-large-v3",
    ModelTier.QUALITY: "large-v3",
    ModelTier.VOXTRAL: "voxtral-3b",
}

# Config keys that load the same weights as another key. The label in config,
# the log line and the weights actually loaded must name the same model (VF-18).
MODEL_KEY_ALIASES: Dict[str, str] = {
    "distil-large-v3.5": "distil-large-v3",
}


def canonical_model_key(name: str) -> str:
    """The key whose weights ``name`` actually loads."""
    return MODEL_KEY_ALIASES.get(name, name)

# Compatibility aliases for model IDs configured before runtime backend constraints changed.
# faster-whisper requires a CTranslate2 model directory containing model.bin.
FASTER_WHISPER_MODEL_ALIASES: Dict[str, str] = {
    "distil-whisper/distil-large-v3.5": "Systran/faster-distil-whisper-large-v3",
}


def resolve_tier_model_key(tier: ModelTier, device: str = "cpu") -> str:
    """Resolve model key for a tier using hardware-aware routing.

    QUICK tier is intentionally adaptive:
    - CPU: `small.en` for lower end-to-end dictation latency
    - CUDA: `distil-large-v3` for stronger accuracy with good speed
    """
    if tier == ModelTier.QUICK:
        device_norm = str(device or "cpu").strip().lower()
        if device_norm == "auto":
            device_norm = "cuda" if _cuda_runtime_ready() else "cpu"
        if device_norm != "cuda":
            return "small.en"
        return "distil-large-v3"
    return TIER_MODELS.get(tier, "tiny.en")


@dataclass
class TranscriptionSegment:
    """Rich transcription segment with metadata"""
    text: str
    start: float
    end: float
    speaker: Optional[str] = None
    confidence: float = 1.0
    words: Optional[List[Dict[str, Any]]] = None
    no_speech_prob: float = 0.0


@dataclass
class TranscriptionResult:
    """Result from transcription"""
    text: str
    segments: List[TranscriptionSegment] = field(default_factory=list)
    language: str = "en"
    duration: float = 0.0
    processing_time: float = 0.0
    confidence: float = 1.0
    words: Optional[List[Dict[str, Any]]] = None
    speaker_count: int = 0
    #: Highest per-segment no-speech probability the decoder reported. Used to
    #: tell a dictated "Thank you." from silence that decoded as one.
    max_no_speech_prob: float = 0.0


class ASRBackend(ABC):
    """Abstract base class for ASR backends"""

    @abstractmethod
    def load(self) -> None:
        """Load the model"""
        pass

    @abstractmethod
    def transcribe(self, audio: np.ndarray, initial_prompt: Optional[str] = None, beam_size_override: Optional[int] = None, vad_filter_override: Optional[bool] = None) -> TranscriptionResult:
        """Transcribe audio"""
        pass

    @abstractmethod
    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Clean up resources"""
        pass


class FasterWhisperBackend(ASRBackend):
    """Backend using faster-whisper (Distil-Whisper, standard Whisper)"""

    def __init__(self, config: ModelConfig, sample_rate: int = 16000):
        self.config = config
        self.sample_rate = sample_rate
        self._model = None
        self._lock = threading.RLock()
        self._retried_cpu_fallback = False
        # Set when this engine wanted CUDA and is running on CPU instead. The
        # fallback is announced and retried; it is never silent or permanent.
        self._cuda_wanted_compute: Optional[str] = None
        self._cpu_fallback_reason = ""
        self._next_cuda_restore_at = 0.0
        self._restore_lock = threading.Lock()

    def load(self) -> None:
        with self._lock:
            if self._model is not None:
                return

            model_ref = self._resolve_model_ref(self.config.model_id)
            logger.info(f"Loading faster-whisper model: {model_ref}")
            start_time = time.time()

            try:
                from faster_whisper import WhisperModel

                self._model = self._create_model(WhisperModel, model_ref)

                # Warmup with minimal audio
                warmup_audio = np.zeros(1600, dtype=np.float32)
                list(self._model.transcribe(warmup_audio, language="en"))

                load_time = time.time() - start_time
                logger.info(f"Model loaded in {load_time:.2f}s")
                logging.getLogger("voiceflow").info(
                    "asr_model_loaded model_id=%s ref=%s device=%s compute=%s load_s=%.2f",
                    self.config.model_id,
                    model_ref,
                    self.config.device,
                    self.config.compute_type,
                    load_time,
                )

            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self._model = None
                raise

    @property
    def fell_back_to_cpu(self) -> bool:
        """True while a model that was meant for CUDA is running on CPU."""
        return self._cuda_wanted_compute is not None

    @property
    def cpu_fallback_reason(self) -> str:
        return self._cpu_fallback_reason

    def _cpu_thread_count(self) -> int:
        cpu_threads = int(self.config.cpu_threads or 0)
        if cpu_threads <= 0:
            # Keep one core free for UI/hotkeys; cap to avoid diminishing returns.
            cpu_threads = max(4, min(12, max(1, (os.cpu_count() or 4) - 1)))
        return cpu_threads

    def _construct(self, model_cls, model_ref: str, device: str, compute_type: str):
        """Build one WhisperModel under the process-wide lock, cache first.

        A cached model is loaded with ``local_files_only=True`` so a normal
        start never touches the network or huggingface_hub's download path. The
        network is used only when the model is not on disk. A local directory
        (prefetched model) needs neither.
        """
        kwargs = dict(
            device=device,
            compute_type=compute_type,
            cpu_threads=self._cpu_thread_count(),
            num_workers=max(1, int(self.config.asr_num_workers or 1)),
        )
        with _MODEL_INIT_LOCK:
            if Path(model_ref).is_dir():
                return model_cls(model_ref, **kwargs)
            try:
                return model_cls(model_ref, local_files_only=True, **kwargs)
            except Exception as exc:
                if not _is_missing_local_files(exc):
                    raise
                logger.info("Model %s not in the local cache; downloading", model_ref)
                return model_cls(model_ref, local_files_only=False, **kwargs)

    def _create_model(self, model_cls, model_ref: str):
        """Create the model on the configured device.

        A CUDA init failure that is not a CUDA problem is retried on CUDA once.
        Only a persistent failure (out of memory, missing runtime) or a second
        failure drops to CPU, and that drop is announced and later retried.
        """
        device = str(self.config.device).lower()
        compute = self.config.compute_type
        if device != "cuda":
            return self._construct(model_cls, model_ref, device, compute)

        last_exc: Optional[BaseException] = None
        for attempt in (1, 2):
            try:
                model = self._construct(model_cls, model_ref, "cuda", compute)
                if attempt > 1:
                    logger.warning("CUDA model init succeeded on retry (first failure: %s)", last_exc)
                    logging.getLogger("voiceflow").warning(
                        "asr_cuda_init_retry_ok model=%s first_error=%s", model_ref, last_exc
                    )
                return model
            except Exception as exc:
                last_exc = exc
                kind = classify_cuda_init_failure(exc)
                if kind == "transient" and attempt == 1:
                    logger.warning(
                        "Model init failed with a non-CUDA error (%s: %s); retrying on CUDA once",
                        type(exc).__name__,
                        exc,
                    )
                    time.sleep(_CUDA_INIT_RETRY_DELAY_S)
                    continue
                break

        assert last_exc is not None
        reason = f"{classify_cuda_init_failure(last_exc)}: {type(last_exc).__name__}: {last_exc}"
        logger.warning("CUDA model init failed (%s). Falling back to CPU int8.", reason)
        logging.getLogger("voiceflow").warning(
            "asr_cuda_init_failed error=%s fallback=cpu_int8 model=%s", reason, model_ref
        )
        model = self._construct(model_cls, model_ref, "cpu", "int8")
        self._enter_cpu_fallback(compute, reason)
        return model

    def _enter_cpu_fallback(self, wanted_compute: str, reason: str) -> None:
        """Record and announce that this engine is now running on CPU."""
        self.config.device = "cpu"
        self.config.compute_type = "int8"
        self._cuda_wanted_compute = wanted_compute or "float16"
        self._cpu_fallback_reason = reason
        self._next_cuda_restore_at = time.monotonic() + _CUDA_RESTORE_MIN_INTERVAL_S
        logging.getLogger("voiceflow").warning(
            "asr_cpu_fallback_active model=%s reason=%s restore_retry_s=%.0f",
            self.config.model_id,
            reason,
            _CUDA_RESTORE_MIN_INTERVAL_S,
        )
        _notify_device_event("cpu_fallback", f"{self.config.model_id}: {reason}")

    def retry_cuda_if_fallen_back(self, force: bool = False) -> bool:
        """Try to move a CPU-fallback model back onto the GPU.

        Meant to be called from an idle period. Builds the CUDA model first and
        swaps it in only if that worked, so a failed attempt costs nothing and
        dictation keeps running on the CPU model. Returns True when CUDA was
        restored.
        """
        if not self.fell_back_to_cpu:
            return False
        if not force and time.monotonic() < self._next_cuda_restore_at:
            return False
        if not self._restore_lock.acquire(blocking=False):
            return False
        try:
            wanted = self._cuda_wanted_compute or "float16"
            model_ref = self._resolve_model_ref(self.config.model_id)
            try:
                from faster_whisper import WhisperModel

                model = self._construct(WhisperModel, model_ref, "cuda", wanted)
                list(model.transcribe(np.zeros(1600, dtype=np.float32), language="en"))
            except Exception as exc:
                self._next_cuda_restore_at = time.monotonic() + _CUDA_RESTORE_MIN_INTERVAL_S
                logging.getLogger("voiceflow").info(
                    "asr_cuda_restore_failed kind=%s error=%s next_try_s=%.0f",
                    classify_cuda_init_failure(exc),
                    exc,
                    _CUDA_RESTORE_MIN_INTERVAL_S,
                )
                return False
            with self._lock:
                self._model = model
                self.config.device = "cuda"
                self.config.compute_type = wanted
                self._cuda_wanted_compute = None
                self._cpu_fallback_reason = ""
                self._retried_cpu_fallback = False
            logging.getLogger("voiceflow").warning(
                "asr_cuda_restored model=%s compute=%s", self.config.model_id, wanted
            )
            _notify_device_event("cuda_restored", self.config.model_id)
            return True
        finally:
            self._restore_lock.release()

    @staticmethod
    def _resolve_model_ref(model_id: str) -> str:
        """Prefer pre-fetched local model directory when available."""
        resolved_id = FASTER_WHISPER_MODEL_ALIASES.get(model_id, model_id)
        candidate_ids = [resolved_id]
        if resolved_id != model_id:
            candidate_ids.append(model_id)

        for candidate_id in candidate_ids:
            local_prefetch = Path.home() / ".voiceflow" / "models" / candidate_id.replace("/", "__")
            if local_prefetch.exists():
                return str(local_prefetch)
        return resolved_id

    def transcribe(self, audio: np.ndarray, initial_prompt: Optional[str] = None, beam_size_override: Optional[int] = None, vad_filter_override: Optional[bool] = None) -> TranscriptionResult:
        if not self.is_loaded():
            self.load()

        start_time = time.time()
        audio_duration = len(audio) / self.sample_rate

        try:
            with self._lock:
                cfg_beam = max(1, int(getattr(self.config, "beam_size", 1)))
                beam_size = max(1, int(beam_size_override)) if beam_size_override else cfg_beam
                # Final-pass long-form lift: callers that don't pass overrides
                # are using config defaults (the legacy/main transcribe path).
                # For ≥ 12s clips on that path, force beam=2 and cross-segment
                # context — accuracy gain is worth the latency cost on CUDA.
                # The streaming preview path passes overrides so it stays fast;
                # otherwise growing previews past 12s would re-decode with
                # conditioning every cycle and feel sluggish.
                is_final_pass = beam_size_override is None and vad_filter_override is None
                long_form = audio_duration >= 12.0 and is_final_pass
                if long_form:
                    beam_size = max(beam_size, 2)
                best_of = max(1, int(getattr(self.config, "best_of", 1)))
                use_vad = vad_filter_override if vad_filter_override is not None else self.config.vad_filter
                cfg_condition = bool(getattr(self.config, "condition_on_previous_text", False))
                # The beam lift applies to every long clip. The conditioning
                # lift does not: feeding Whisper its own previous output back
                # in helps a 15s clip and degrades a 90s one, because an early
                # error propagates forward and the decode drifts, repeats, or
                # drops words. Reported as "the longer I talk the worse it
                # gets". Bound it to a window instead of applying it forever.
                condition_ceiling = float(
                    getattr(self.config, "long_form_condition_max_seconds", 30.0)
                )
                long_form_condition = (
                    long_form
                    and condition_ceiling > 0
                    and audio_duration <= condition_ceiling
                )
                use_condition = cfg_condition or long_form_condition
                kwargs: Dict[str, Any] = {
                    "language": "en",
                    "beam_size": beam_size,
                    "best_of": max(best_of, beam_size),
                    "temperature": float(getattr(self.config, "temperature", 0.0)),
                    "condition_on_previous_text": use_condition,
                    "without_timestamps": True,
                    "vad_filter": use_vad,
                }
                if use_vad:
                    kwargs["vad_parameters"] = {
                        "threshold": 0.35,
                        "min_speech_duration_ms": 150,
                        "max_speech_duration_s": 300,
                    }
                if initial_prompt:
                    kwargs["initial_prompt"] = initial_prompt
                segments_iter, info = self._model.transcribe(audio, **kwargs)

            # faster-whisper decodes lazily: transcribe() only returns a
            # generator, and the real CUDA work (and any CUDA out-of-memory)
            # happens while it is consumed. Consume it inside this guard, or a
            # decode-time failure escapes with the engine still marked CUDA.
            # (Not under self._lock: the generator holds its own model reference.)
            segments = []
            text_parts = []
            max_no_speech_prob = 0.0

            for seg in segments_iter:
                seg_no_speech = float(getattr(seg, 'no_speech_prob', 0.0) or 0.0)
                if seg.text and seg.text.strip():
                    text_parts.append(seg.text.strip())
                    segments.append(TranscriptionSegment(
                        text=seg.text.strip(),
                        start=seg.start,
                        end=seg.end,
                        confidence=getattr(seg, 'avg_logprob', 1.0),
                        no_speech_prob=seg_no_speech,
                    ))
                # Track silence evidence from every segment, including ones whose
                # text was empty -- those are the strongest signal of all.
                if seg_no_speech > max_no_speech_prob:
                    max_no_speech_prob = seg_no_speech
        except Exception as exc:
            if self._should_fallback_to_cpu(exc):
                logger.warning("CUDA runtime failure detected (%s). Falling back to CPU and retrying once.", exc)
                self._fallback_to_cpu(f"{classify_cuda_init_failure(exc)}: {type(exc).__name__}: {exc}")
                return self.transcribe(audio, initial_prompt=initial_prompt, beam_size_override=beam_size_override, vad_filter_override=vad_filter_override)
            raise

        processing_time = time.time() - start_time

        return TranscriptionResult(
            text=" ".join(text_parts).strip(),
            segments=segments,
            language=info.language,
            duration=audio_duration,
            processing_time=processing_time,
            max_no_speech_prob=max_no_speech_prob,
        )

    def is_loaded(self) -> bool:
        return self._model is not None

    def cleanup(self) -> None:
        with self._lock:
            self._model = None
            logger.info("faster-whisper model cleaned up")
            self._retried_cpu_fallback = False

    def _should_fallback_to_cpu(self, exc: Exception) -> bool:
        if self._retried_cpu_fallback:
            return False
        if str(self.config.device).lower() != "cuda":
            return False
        message = str(exc).lower()
        runtime_markers = [
            "cuda",
            "cudnn",
            "cublas",
            "invalid handle",
            "driver",
            "cannot load symbol",
            "out of memory",
        ]
        return any(marker in message for marker in runtime_markers)

    def _fallback_to_cpu(self, reason: str = "runtime CUDA failure") -> None:
        with self._lock:
            wanted = self.config.compute_type
            self._model = None
            self._retried_cpu_fallback = True
            logging.getLogger("voiceflow").warning("asr_runtime_fallback device=cpu compute=int8")
            self._enter_cpu_fallback(wanted, reason)
        self.load()


class WhisperXBackend(ASRBackend):
    """Backend using WhisperX (advanced features)"""

    def __init__(self, config: ModelConfig, sample_rate: int = 16000,
                 enable_diarization: bool = False, enable_word_timestamps: bool = True):
        self.config = config
        self.sample_rate = sample_rate
        self.enable_diarization = enable_diarization and config.supports_diarization
        self.enable_word_timestamps = enable_word_timestamps and config.supports_word_timestamps
        self._model = None
        self._align_model = None
        self._diarize_model = None
        self._lock = threading.RLock()

    def load(self) -> None:
        with self._lock:
            if self._model is not None:
                return

            logger.info(f"Loading WhisperX model: {self.config.model_id}")
            start_time = time.time()

            try:
                import whisperx

                # Main transcription model
                self._model = whisperx.load_model(
                    self.config.model_id,
                    device=self.config.device,
                    compute_type=self.config.compute_type,
                    language="en",
                )

                # Alignment model for word-level timestamps
                if self.enable_word_timestamps:
                    try:
                        self._align_model, self._align_metadata = whisperx.load_align_model(
                            language_code="en",
                            device=self.config.device,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to load alignment model: {e}")
                        self._align_model = None

                # Diarization model
                if self.enable_diarization:
                    try:
                        self._diarize_model = whisperx.DiarizationPipeline(
                            device=self.config.device,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to load diarization model: {e}")
                        self._diarize_model = None

                load_time = time.time() - start_time
                logger.info(f"WhisperX models loaded in {load_time:.2f}s")

            except ImportError:
                logger.error("WhisperX not installed. Install with: pip install whisperx")
                raise
            except Exception as e:
                logger.error(f"Failed to load WhisperX: {e}")
                self._model = None
                raise

    def transcribe(self, audio: np.ndarray, initial_prompt: Optional[str] = None, beam_size_override: Optional[int] = None, vad_filter_override: Optional[bool] = None) -> TranscriptionResult:
        if not self.is_loaded():
            self.load()

        start_time = time.time()
        audio_duration = len(audio) / self.sample_rate

        import whisperx

        with self._lock:
            # Basic transcription
            result = self._model.transcribe(audio, batch_size=16, language="en")

            # Word-level alignment
            if self.enable_word_timestamps and self._align_model and result.get("segments"):
                try:
                    result = whisperx.align(
                        result["segments"],
                        self._align_model,
                        self._align_metadata,
                        audio,
                        self.config.device,
                        return_char_alignments=False,
                    )
                except Exception as e:
                    logger.warning(f"Alignment failed: {e}")

            # Speaker diarization
            speaker_count = 0
            if self.enable_diarization and self._diarize_model and result.get("segments"):
                try:
                    diarize_segments = self._diarize_model(audio)
                    result = whisperx.assign_word_speakers(diarize_segments, result)
                    speakers = set()
                    for seg in result.get("segments", []):
                        if seg.get("speaker"):
                            speakers.add(seg["speaker"])
                    speaker_count = len(speakers)
                except Exception as e:
                    logger.warning(f"Diarization failed: {e}")

        # Convert to our format
        segments = []
        text_parts = []
        all_words = []

        for seg in result.get("segments", []):
            if seg.get("text", "").strip():
                text_parts.append(seg["text"].strip())

                # Collect words for this segment
                seg_words = None
                if seg.get("words"):
                    seg_words = [
                        {
                            "text": word.get("word", ""),
                            "start": word.get("start", 0.0),
                            "end": word.get("end", 0.0),
                            "confidence": word.get("score", 1.0),
                        }
                        for word in seg["words"]
                    ]
                    all_words.extend(seg_words)

                segments.append(TranscriptionSegment(
                    text=seg["text"].strip(),
                    start=seg.get("start", 0.0),
                    end=seg.get("end", audio_duration),
                    speaker=seg.get("speaker"),
                    confidence=seg.get("score", 1.0),
                    words=seg_words,
                ))

        # Note: all_words collection removed from inner loop (handled above)
        # Remove old word collection code that followed
        processing_time = time.time() - start_time

        return TranscriptionResult(
            text=" ".join(text_parts).strip(),
            segments=segments,
            language=result.get("language", "en"),
            duration=audio_duration,
            processing_time=processing_time,
            words=all_words if all_words else None,
            speaker_count=speaker_count,
        )

    def is_loaded(self) -> bool:
        return self._model is not None

    def cleanup(self) -> None:
        with self._lock:
            self._model = None
            self._align_model = None
            self._diarize_model = None
            logger.info("WhisperX models cleaned up")


class VoxtralBackend(ASRBackend):
    """Backend using Voxtral (Mistral AI's speech model)"""

    def __init__(self, config: ModelConfig, sample_rate: int = 16000):
        self.config = config
        self.sample_rate = sample_rate
        self._model = None
        self._processor = None
        self._lock = threading.RLock()

    def load(self) -> None:
        with self._lock:
            if self._model is not None:
                return

            logger.info(f"Loading Voxtral model: {self.config.model_id}")
            start_time = time.time()

            try:
                import torch
                from transformers import AutoModelForSpeechSeq2Seq, AutoProcessor

                # Determine device and dtype
                device = self.config.device
                if device == "cpu":
                    torch_dtype = torch.float32
                else:
                    torch_dtype = torch.float16 if torch.cuda.is_available() else torch.float32
                    device = "cuda" if torch.cuda.is_available() else "cpu"

                # Load processor
                self._processor = AutoProcessor.from_pretrained(self.config.model_id)

                # Load model
                self._model = AutoModelForSpeechSeq2Seq.from_pretrained(
                    self.config.model_id,
                    torch_dtype=torch_dtype,
                    low_cpu_mem_usage=True,
                    use_safetensors=True,
                )
                self._model.to(device)
                self._device = device
                self._torch_dtype = torch_dtype

                load_time = time.time() - start_time
                logger.info(f"Voxtral model loaded in {load_time:.2f}s on {device}")

            except ImportError:
                logger.error("transformers not installed. Install with: pip install transformers accelerate")
                raise
            except Exception as e:
                logger.error(f"Failed to load Voxtral: {e}")
                self._model = None
                raise

    def transcribe(self, audio: np.ndarray, initial_prompt: Optional[str] = None, beam_size_override: Optional[int] = None, vad_filter_override: Optional[bool] = None) -> TranscriptionResult:
        if not self.is_loaded():
            self.load()

        import torch

        start_time = time.time()
        audio_duration = len(audio) / self.sample_rate

        with self._lock:
            # Prepare input
            input_features = self._processor(
                audio,
                sampling_rate=self.sample_rate,
                return_tensors="pt",
            ).input_features.to(self._device, dtype=self._torch_dtype)

            # Generate transcription
            with torch.no_grad():
                predicted_ids = self._model.generate(input_features)

            # Decode
            text = self._processor.batch_decode(
                predicted_ids,
                skip_special_tokens=True,
            )[0].strip()

        processing_time = time.time() - start_time

        return TranscriptionResult(
            text=text,
            language="en",
            duration=audio_duration,
            processing_time=processing_time,
        )

    def is_loaded(self) -> bool:
        return self._model is not None

    def cleanup(self) -> None:
        with self._lock:
            self._model = None
            self._processor = None
            logger.info("Voxtral model cleaned up")


class ASREngine:
    """Unified ASR Engine supporting multiple backends and models.

    Usage:
        engine = ASREngine(tier=ModelTier.BALANCED)
        engine.load()
        result = engine.transcribe(audio)
        print(result.text)
    """

    def __init__(
        self,
        tier: Optional[ModelTier] = None,
        model_name: Optional[str] = None,
        device: str = "auto",
        compute_type: str = "int8",
        sample_rate: int = 16000,
        enable_diarization: bool = False,
        enable_word_timestamps: bool = True,
        vad_filter: bool = True,
        cpu_threads: int = 0,
        asr_num_workers: int = 1,
        beam_size: int = 1,
        best_of: int = 1,
        temperature: float = 0.0,
        condition_on_previous_text: bool = False,
    ):
        """Initialize the ASR engine.

        Args:
            tier: Model tier (TINY, QUICK, BALANCED, QUALITY, VOXTRAL)
            model_name: Specific model name (overrides tier)
            device: "cpu", "cuda", or "auto"
            compute_type: "int8", "float16", or "float32"
            sample_rate: Audio sample rate (default 16000)
            enable_diarization: Enable speaker diarization
            enable_word_timestamps: Enable word-level timestamps
            vad_filter: Enable backend VAD filtering before decode
            cpu_threads: Number of CPU threads for ctranslate2 (0 = auto)
            asr_num_workers: Number of ctranslate2 workers for model inference
            beam_size: Beam search size (1 keeps greedy fastest path)
            best_of: Number of sampled candidates per segment
            temperature: Decoding temperature (0.0 deterministic)
            condition_on_previous_text: Whether to chain previous text context
        """
        requested_device = str(device or "auto").strip().lower()
        if requested_device not in {"cpu", "cuda", "auto"}:
            requested_device = "auto"

        if requested_device == "auto":
            requested_device = "cuda" if _cuda_runtime_ready() else "cpu"

        # An explicit CUDA request with a missing runtime is a fallback, not a
        # different request: the intent stays "cuda" so the engine enters the same
        # announced, retried CPU-fallback state a failed model load does (VF-18).
        # ("auto" already resolved above using the same check, so it never gets here.)
        cuda_runtime_missing = False
        if requested_device == "cuda" and not _cuda_runtime_ready():
            cuda_runtime_missing = True
            missing_dlls = _missing_cuda_dlls(list(CUDA_REQUIRED_DLLS))
            cuda_missing_reason = (
                "missing_runtime: CUDA runtime not ready"
                + (f" (missing {', '.join(missing_dlls)})" if missing_dlls else " (no usable CUDA device reported)")
            )
            logger.warning("CUDA requested but the runtime is not ready. Falling back to CPU int8.")

        resolved_compute = str(compute_type or "int8").strip().lower()
        if requested_device == "cuda":
            if resolved_compute in {"int8", "auto", ""}:
                resolved_compute = "float16"
        else:
            if resolved_compute in {"float16", "int8_float16", "int8_bfloat16", "auto", ""}:
                resolved_compute = "int8"

        device = requested_device
        compute_type = resolved_compute

        # Determine model to use. Every engine gets its own copy of the config:
        # MODEL_CONFIGS entries are module-level, and a CPU fallback (or any
        # per-engine tweak) written into a shared entry used to leak into every
        # later engine built from the same key.
        if model_name:
            if model_name not in MODEL_CONFIGS:
                # Check if it's a valid faster-whisper model
                self.model_key = model_name
                self.model_config = ModelConfig(
                    name=model_name,
                    model_id=model_name,
                    backend="faster-whisper",
                    device=device,
                    compute_type=compute_type,
                )
            else:
                self.model_key = canonical_model_key(model_name)
                self.model_config = dataclasses.replace(MODEL_CONFIGS[model_name])
        elif tier:
            # Tier routing is hardware-aware: with no usable CUDA it picks the
            # model that suits the CPU it will actually run on.
            model_key = resolve_tier_model_key(tier, "cpu" if cuda_runtime_missing else device)
            self.model_key = canonical_model_key(model_key)
            self.model_config = dataclasses.replace(MODEL_CONFIGS[model_key])
        else:
            # Default to QUICK tier
            model_key = resolve_tier_model_key(
                ModelTier.QUICK, "cpu" if cuda_runtime_missing else device
            )
            self.model_key = canonical_model_key(model_key)
            self.model_config = dataclasses.replace(MODEL_CONFIGS[model_key])
        self.requested_label = str(model_name or (tier.value if tier else "quick"))

        # Update device and compute type
        self.model_config.device = device
        self.model_config.compute_type = compute_type
        self.model_config.vad_filter = vad_filter
        self.model_config.cpu_threads = cpu_threads
        self.model_config.asr_num_workers = asr_num_workers
        self.model_config.beam_size = max(1, int(beam_size))
        self.model_config.best_of = max(1, int(best_of))
        self.model_config.temperature = float(temperature)
        self.model_config.condition_on_previous_text = bool(condition_on_previous_text)

        self.sample_rate = sample_rate
        self.enable_diarization = enable_diarization
        self.enable_word_timestamps = enable_word_timestamps

        # Create backend
        self._backend: Optional[ASRBackend] = None
        self._create_backend()

        if cuda_runtime_missing:
            if isinstance(self._backend, FasterWhisperBackend):
                # Same state a failed CUDA model load ends in: warning, tray
                # message, and the idle retry that puts the GPU back.
                self._backend._enter_cpu_fallback(compute_type, cuda_missing_reason)
            else:
                # Other backends have no announced-fallback path; run them on CPU.
                self.model_config.device = "cpu"
                self.model_config.compute_type = "int8"
                device, compute_type = "cpu", "int8"

        # Statistics
        self.transcription_count = 0
        self.total_processing_time = 0.0
        self.total_audio_duration = 0.0

        logger.info(
            f"ASR Engine initialized - model: {self.model_config.name}, "
            f"backend: {self.model_config.backend}, device: {self.model_config.device}"
        )
        logging.getLogger("voiceflow").info(
            "asr_engine_initialized model=%s model_id=%s backend=%s device=%s compute=%s "
            "key=%s requested=%s weights=%s",
            self.model_config.name,
            self.model_config.model_id,
            self.model_config.backend,
            self.model_config.device,
            self.model_config.compute_type,
            self.model_key,
            self.requested_label,
            self.model_config.model_id,
        )

    def _create_backend(self) -> None:
        """Create the appropriate backend"""
        backend_type = self.model_config.backend

        if backend_type == "faster-whisper":
            self._backend = FasterWhisperBackend(self.model_config, self.sample_rate)
        elif backend_type == "whisperx":
            self._backend = WhisperXBackend(
                self.model_config,
                self.sample_rate,
                self.enable_diarization,
                self.enable_word_timestamps,
            )
        elif backend_type == "voxtral":
            self._backend = VoxtralBackend(self.model_config, self.sample_rate)
        else:
            raise ValueError(f"Unknown backend: {backend_type}")

    def load(self) -> None:
        """Load the model"""
        if self._backend:
            self._backend.load()

    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        return self._backend is not None and self._backend.is_loaded()

    def transcribe(self, audio: np.ndarray, initial_prompt: Optional[str] = None, beam_size_override: Optional[int] = None, vad_filter_override: Optional[bool] = None) -> TranscriptionResult:
        """Transcribe audio data.

        Args:
            audio: Audio data as numpy array (float32, 16kHz mono)
            initial_prompt: Optional text to condition the model on (improves continuity)
            beam_size_override: Override beam size for this call only
            vad_filter_override: Override VAD filter setting for this call only

        Returns:
            TranscriptionResult with text and metadata
        """
        if audio is None or audio.size == 0:
            self.last_no_speech_prob = 1.0
            return TranscriptionResult(text="", duration=0.0, processing_time=0.0)

        # Basic validation
        audio_duration = len(audio) / self.sample_rate
        if audio_duration < 0.1:
            logger.debug("Audio too short (<0.1s), skipping")
            self.last_no_speech_prob = 1.0
            return TranscriptionResult(text="", duration=audio_duration, processing_time=0.0)

        # Check for silence
        energy = np.mean(audio ** 2)
        if energy < 1e-8:
            logger.debug("Audio too quiet, skipping")
            self.last_no_speech_prob = 1.0
            return TranscriptionResult(text="", duration=audio_duration, processing_time=0.0)

        # Transcribe
        result = self._backend.transcribe(audio, initial_prompt=initial_prompt, beam_size_override=beam_size_override, vad_filter_override=vad_filter_override)

        # Expose the decoder's silence evidence to callers that only receive a
        # string. Set on every path, including the early returns above, so a
        # stale value can never leak into the next utterance's decision.
        self.last_no_speech_prob = float(getattr(result, "max_no_speech_prob", 0.0) or 0.0)

        # Update statistics
        self.transcription_count += 1
        self.total_processing_time += result.processing_time
        self.total_audio_duration += result.duration

        # Log performance
        if result.duration > 0:
            rtf = result.processing_time / result.duration
            logger.debug(f"Transcribed {result.duration:.2f}s in {result.processing_time:.2f}s "
                        f"(RTF: {rtf:.2f}, speed: {1 / max(rtf, 0.001):.1f}x realtime)")

        return result

    def transcribe_simple(self, audio: np.ndarray) -> str:
        """Simple transcription returning just text"""
        return self.transcribe(audio).text

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        avg_processing = self.total_processing_time / max(self.transcription_count, 1)
        avg_duration = self.total_audio_duration / max(self.transcription_count, 1)
        avg_rtf = avg_processing / max(avg_duration, 0.001)

        return {
            "model": self.model_config.name,
            "model_id": self.model_config.model_id,
            "backend": self.model_config.backend,
            "device": self.model_config.device,
            "transcription_count": self.transcription_count,
            "total_processing_time": self.total_processing_time,
            "total_audio_duration": self.total_audio_duration,
            "avg_processing_time": avg_processing,
            "avg_realtime_factor": avg_rtf,
            "avg_speed": 1 / max(avg_rtf, 0.001),
            "model_loaded": self.is_loaded(),
        }

    def switch_model(
        self,
        tier: Optional[ModelTier] = None,
        model_name: Optional[str] = None,
    ) -> None:
        """Switch to a different model"""
        # Cleanup current backend
        self.cleanup()

        previous = self.model_config

        # Update model config
        if model_name:
            if model_name in MODEL_CONFIGS:
                self.model_key = canonical_model_key(model_name)
                self.model_config = dataclasses.replace(MODEL_CONFIGS[model_name])
            else:
                self.model_key = model_name
                self.model_config = ModelConfig(
                    name=model_name,
                    model_id=model_name,
                    backend="faster-whisper",
                    device=self.model_config.device,
                    compute_type=self.model_config.compute_type,
                )
        elif tier:
            model_key = resolve_tier_model_key(tier, self.model_config.device)
            self.model_key = canonical_model_key(model_key)
            self.model_config = dataclasses.replace(MODEL_CONFIGS[model_key])

        # The per-engine decode settings belong to the engine, not to the model
        # entry; carry them over to the fresh copy.
        if self.model_config is not previous:
            for attr in (
                "device", "compute_type", "vad_filter", "cpu_threads", "asr_num_workers",
                "beam_size", "best_of", "temperature", "condition_on_previous_text",
            ):
                setattr(self.model_config, attr, getattr(previous, attr))

        # Create new backend
        self._create_backend()
        logger.info(f"Switched to model: {self.model_config.name}")

    def cleanup(self) -> None:
        """Clean up resources"""
        if self._backend:
            self._backend.cleanup()
            self._backend = None

    def device_status(self) -> Dict[str, Any]:
        """Where the model is running, and whether that is where it was meant to."""
        backend = self._backend
        fell_back = bool(getattr(backend, "fell_back_to_cpu", False))
        return {
            "model_key": self.model_key,
            "model_id": self.model_config.model_id,
            "device": self.model_config.device,
            "compute_type": self.model_config.compute_type,
            "fell_back_to_cpu": fell_back,
            "fallback_reason": str(getattr(backend, "cpu_fallback_reason", "") or ""),
        }

    def retry_cuda_if_fallen_back(self, force: bool = False) -> bool:
        """Move a CPU-fallback model back to the GPU if it now fits. See the backend."""
        backend = self._backend
        retry = getattr(backend, "retry_cuda_if_fallen_back", None)
        return bool(retry(force=force)) if callable(retry) else False

    @staticmethod
    def list_models() -> Dict[str, Dict[str, Any]]:
        """List all available models"""
        return {
            name: {
                "name": config.name,
                "model_id": config.model_id,
                "backend": config.backend,
                "description": config.description,
                "size_mb": config.size_mb,
                "languages": config.languages,
                "supports_diarization": config.supports_diarization,
                "supports_word_timestamps": config.supports_word_timestamps,
            }
            for name, config in MODEL_CONFIGS.items()
        }

    @staticmethod
    def list_tiers() -> Dict[str, str]:
        """List model tiers with descriptions"""
        return {
            "tiny": "Fastest, lowest accuracy - good for testing",
            "quick": "Adaptive quick tier: small.en on CPU, distil-large-v3 on CUDA",
            "balanced": "Distil-Large-v3: Best speed/quality (recommended)",
            "quality": "Large-v3: Highest accuracy, slower",
            "voxtral": "Voxtral-3B: Mistral's new model, beats Whisper",
        }


# Backwards compatibility aliases
class ModernWhisperASR(ASREngine):
    """Backwards compatible alias for existing code"""

    def __init__(self, cfg):
        # Extract settings from legacy Config object
        device = getattr(cfg, 'device', 'auto')
        compute_type = getattr(cfg, 'compute_type', 'int8')
        model_name = getattr(cfg, 'model_name', 'tiny.en')
        model_tier = getattr(cfg, 'model_tier', None)
        sample_rate = getattr(cfg, 'sample_rate', 16000)
        vad_filter = getattr(cfg, 'vad_filter', False)
        cpu_threads = getattr(cfg, 'cpu_threads', 0)
        asr_num_workers = getattr(cfg, 'asr_num_workers', 1)
        beam_size = getattr(cfg, 'beam_size', 1)
        temperature = getattr(cfg, 'temperature', 0.0)
        condition_on_previous_text = getattr(cfg, 'condition_on_previous_text', False)
        force_cpu = str(os.environ.get("VOICEFLOW_FORCE_CPU", "")).strip().lower() in {"1", "true", "yes"}
        gpu_enabled = bool(getattr(cfg, "enable_gpu_acceleration", True))

        device_normalized = str(device or "auto").strip().lower()
        if not force_cpu and gpu_enabled and device_normalized == "cpu":
            # Respect legacy "cpu" config values while still allowing automatic CUDA promotion
            # when users opt in to GPU acceleration.
            device = "auto"

        # If model_tier is specified, use it to select the model
        tier = None
        if model_tier:
            tier_map = {
                'tiny': ModelTier.TINY,
                'quick': ModelTier.QUICK,
                'balanced': ModelTier.BALANCED,
                'quality': ModelTier.QUALITY,
                'voxtral': ModelTier.VOXTRAL,
            }
            tier = tier_map.get(model_tier.lower())

        if tier:
            super().__init__(
                tier=tier,
                device=device,
                compute_type=compute_type,
                sample_rate=sample_rate,
                vad_filter=vad_filter,
                cpu_threads=cpu_threads,
                asr_num_workers=asr_num_workers,
                beam_size=beam_size,
                temperature=temperature,
                condition_on_previous_text=condition_on_previous_text,
            )
            logger.info(f"Using model tier '{model_tier}' -> {self.model_config.name}")
        else:
            super().__init__(
                model_name=model_name,
                device=device,
                compute_type=compute_type,
                sample_rate=sample_rate,
                vad_filter=vad_filter,
                cpu_threads=cpu_threads,
                asr_num_workers=asr_num_workers,
                beam_size=beam_size,
                temperature=temperature,
                condition_on_previous_text=condition_on_previous_text,
            )
        self.cfg = cfg

        # Session tracking for legacy compatibility
        self.session_start_time = time.time()
        self.session_transcription_count = 0
        self.vad_fallback_triggered = False

    def transcribe(self, audio: np.ndarray, initial_prompt: Optional[str] = None, beam_size_override: Optional[int] = None, vad_filter_override: Optional[bool] = None) -> str:
        """Legacy interface returning just text"""
        self.session_transcription_count += 1
        if initial_prompt is None and bool(getattr(self.cfg, "enable_smart_prompting", True)):
            try:
                from voiceflow.core.vocab import initial_prompt as _vocab_initial_prompt

                vocab_prompt = _vocab_initial_prompt()
                if vocab_prompt:
                    initial_prompt = vocab_prompt
            except Exception:
                # Vocab is best-effort. If it fails, fall back to no prompt.
                pass
        # Call parent's transcribe method and extract text
        result = ASREngine.transcribe(self, audio, initial_prompt=initial_prompt, beam_size_override=beam_size_override, vad_filter_override=vad_filter_override)
        return result.text

    def get_clean_statistics(self) -> dict:
        """Get session statistics (legacy compatibility)"""
        session_duration = time.time() - self.session_start_time
        avg_speed = 0.0

        if self.total_processing_time > 0:
            avg_speed = self.total_audio_duration / self.total_processing_time

        return {
            'session_transcription_count': self.session_transcription_count,
            'transcription_count': self.transcription_count,
            'session_duration_seconds': session_duration,
            'total_audio_duration': self.total_audio_duration,
            'total_processing_time': self.total_processing_time,
            'average_speed_factor': avg_speed,
            'buffer_state_isolated': True,
            'vad_fallback_triggered': self.vad_fallback_triggered,
            'model_loaded': self.is_loaded(),
        }

    def get_statistics(self) -> dict:
        """Alias for get_clean_statistics"""
        return self.get_clean_statistics()

    def reset_session(self):
        """Reset session statistics"""
        self.session_transcription_count = 0
        self.session_start_time = time.time()
        self.total_audio_duration = 0.0
        self.total_processing_time = 0.0


# Also alias for other legacy names
BufferSafeWhisperASR = ModernWhisperASR
WhisperASR = ModernWhisperASR
EnhancedWhisperASR = ModernWhisperASR
