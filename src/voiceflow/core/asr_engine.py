"""
Unified ASR Engine - VoiceFlow 3.0

A unified speech recognition engine supporting multiple backends and models:
- faster-whisper (Distil-Whisper, Whisper)
- WhisperX (advanced features: diarization, word timestamps)
- Voxtral (Mistral AI's new open-source model)

Model Tiers:
- Quick: distil-large-v3 (6x faster, same accuracy)
- Balanced: distil-large-v3.5 (best speed/quality ratio)
- Quality: large-v3 or Voxtral-3B (highest accuracy)
- Tiny: tiny.en (fastest, lower accuracy - good for testing)
"""

import logging
import os
import time
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List, Any, Union
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)


def _find_dll_in_path(dll_name: str) -> bool:
    path_var = os.environ.get("PATH", "")
    for entry in path_var.split(os.pathsep):
        if not entry:
            continue
        candidate = Path(entry) / dll_name
        if candidate.exists():
            return True
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

    lib_path = str(torch_lib)
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


def _cuda_runtime_ready() -> bool:
    """Best-effort CUDA runtime check for faster-whisper/ctranslate2 on Windows."""
    try:
        import torch
    except Exception:
        return False

    if not torch.cuda.is_available():
        return False

    required_dlls = ["cudnn_ops64_9.dll", "cublas64_12.dll"]
    _register_torch_cuda_path(required_dlls)
    return all(_find_dll_in_path(name) for name in required_dlls)


class ModelTier(Enum):
    """Model tiers for easy selection"""
    TINY = "tiny"           # Fastest, lowest accuracy
    QUICK = "quick"         # Fast with good accuracy (distil-large-v3)
    BALANCED = "balanced"   # Best ratio (distil-large-v3.5)
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
    vad_filter: bool = False
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
    "distil-large-v3.5": ModelConfig(
        name="Distil Large v3.5",
        model_id="distil-whisper/distil-large-v3.5",
        backend="faster-whisper",
        description="Latest distil model (March 2025), best speed/quality",
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
    ModelTier.QUICK: "distil-large-v3",
    ModelTier.BALANCED: "distil-large-v3.5",
    ModelTier.QUALITY: "large-v3",
    ModelTier.VOXTRAL: "voxtral-3b",
}


@dataclass
class TranscriptionSegment:
    """Rich transcription segment with metadata"""
    text: str
    start: float
    end: float
    speaker: Optional[str] = None
    confidence: float = 1.0
    words: Optional[List[Dict[str, Any]]] = None


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


class ASRBackend(ABC):
    """Abstract base class for ASR backends"""

    @abstractmethod
    def load(self) -> None:
        """Load the model"""
        pass

    @abstractmethod
    def transcribe(self, audio: np.ndarray) -> TranscriptionResult:
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

            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self._model = None
                raise

    def _create_model(self, model_cls, model_ref: str):
        """Create model and gracefully fallback to CPU when CUDA init fails."""
        cpu_threads = int(self.config.cpu_threads or 0)
        if cpu_threads <= 0:
            # Keep one core free for UI/hotkeys; cap to avoid diminishing returns.
            cpu_threads = max(4, min(12, max(1, (os.cpu_count() or 4) - 1)))
        num_workers = max(1, int(self.config.asr_num_workers or 1))

        try:
            return model_cls(
                model_ref,
                device=self.config.device,
                compute_type=self.config.compute_type,
                cpu_threads=cpu_threads,
                num_workers=num_workers,
            )
        except Exception as primary_exc:
            if str(self.config.device).lower() != "cuda":
                raise
            logger.warning(
                "CUDA model init failed (%s). Falling back to CPU int8.",
                primary_exc,
            )
            self.config.device = "cpu"
            self.config.compute_type = "int8"
            return model_cls(
                model_ref,
                device="cpu",
                compute_type="int8",
                cpu_threads=cpu_threads,
                num_workers=num_workers,
            )

    @staticmethod
    def _resolve_model_ref(model_id: str) -> str:
        """Prefer pre-fetched local model directory when available."""
        local_prefetch = Path.home() / ".voiceflow" / "models" / model_id.replace("/", "__")
        if local_prefetch.exists():
            return str(local_prefetch)
        return model_id

    def transcribe(self, audio: np.ndarray) -> TranscriptionResult:
        if not self.is_loaded():
            self.load()

        start_time = time.time()
        audio_duration = len(audio) / self.sample_rate

        try:
            with self._lock:
                beam_size = max(1, int(getattr(self.config, "beam_size", 1)))
                best_of = max(1, int(getattr(self.config, "best_of", 1)))
                kwargs: Dict[str, Any] = {
                    "language": "en",
                    "beam_size": beam_size,
                    "best_of": max(best_of, beam_size),
                    "temperature": float(getattr(self.config, "temperature", 0.0)),
                    "condition_on_previous_text": bool(getattr(self.config, "condition_on_previous_text", False)),
                    "without_timestamps": True,
                    "vad_filter": self.config.vad_filter,
                }
                if self.config.vad_filter:
                    kwargs["vad_parameters"] = {
                        "threshold": 0.35,
                        "min_speech_duration_ms": 150,
                        "max_speech_duration_s": 300,
                    }
                segments_iter, info = self._model.transcribe(audio, **kwargs)
        except Exception as exc:
            if self._should_fallback_to_cpu(exc):
                logger.warning("CUDA runtime failure detected (%s). Falling back to CPU and retrying once.", exc)
                self._fallback_to_cpu()
                return self.transcribe(audio)
            raise

        segments = []
        text_parts = []

        for seg in segments_iter:
            if seg.text and seg.text.strip():
                text_parts.append(seg.text.strip())
                segments.append(TranscriptionSegment(
                    text=seg.text.strip(),
                    start=seg.start,
                    end=seg.end,
                    confidence=getattr(seg, 'avg_logprob', 1.0),
                ))

        processing_time = time.time() - start_time

        return TranscriptionResult(
            text=" ".join(text_parts).strip(),
            segments=segments,
            language=info.language,
            duration=audio_duration,
            processing_time=processing_time,
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
        ]
        return any(marker in message for marker in runtime_markers)

    def _fallback_to_cpu(self) -> None:
        with self._lock:
            self._model = None
            self.config.device = "cpu"
            self.config.compute_type = "int8"
            self._retried_cpu_fallback = True
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

    def transcribe(self, audio: np.ndarray) -> TranscriptionResult:
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
                from transformers import AutoModelForSpeechSeq2Seq, AutoProcessor
                import torch

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

    def transcribe(self, audio: np.ndarray) -> TranscriptionResult:
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
    """
    Unified ASR Engine supporting multiple backends and models.

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
        device: str = "cpu",
        compute_type: str = "int8",
        sample_rate: int = 16000,
        enable_diarization: bool = False,
        enable_word_timestamps: bool = True,
        vad_filter: bool = False,
        cpu_threads: int = 0,
        asr_num_workers: int = 1,
        beam_size: int = 1,
        best_of: int = 1,
        temperature: float = 0.0,
        condition_on_previous_text: bool = False,
    ):
        """
        Initialize the ASR engine.

        Args:
            tier: Model tier (TINY, QUICK, BALANCED, QUALITY, VOXTRAL)
            model_name: Specific model name (overrides tier)
            device: "cpu" or "cuda"
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
        if str(device).lower() == "cuda" and not _cuda_runtime_ready():
            logger.warning("CUDA requested but runtime dependencies are missing. Falling back to CPU int8.")
            device = "cpu"
            compute_type = "int8"

        # Determine model to use
        if model_name:
            if model_name not in MODEL_CONFIGS:
                # Check if it's a valid faster-whisper model
                self.model_config = ModelConfig(
                    name=model_name,
                    model_id=model_name,
                    backend="faster-whisper",
                    device=device,
                    compute_type=compute_type,
                )
            else:
                self.model_config = MODEL_CONFIGS[model_name]
        elif tier:
            model_key = TIER_MODELS.get(tier, "tiny.en")
            self.model_config = MODEL_CONFIGS[model_key]
        else:
            # Default to QUICK tier
            self.model_config = MODEL_CONFIGS["distil-large-v3"]

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

        # Statistics
        self.transcription_count = 0
        self.total_processing_time = 0.0
        self.total_audio_duration = 0.0

        logger.info(f"ASR Engine initialized - model: {self.model_config.name}, "
                   f"backend: {self.model_config.backend}, device: {device}")

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

    def transcribe(self, audio: np.ndarray) -> TranscriptionResult:
        """
        Transcribe audio data.

        Args:
            audio: Audio data as numpy array (float32, 16kHz mono)

        Returns:
            TranscriptionResult with text and metadata
        """
        if audio is None or audio.size == 0:
            return TranscriptionResult(text="", duration=0.0, processing_time=0.0)

        # Basic validation
        audio_duration = len(audio) / self.sample_rate
        if audio_duration < 0.1:
            logger.debug("Audio too short (<0.1s), skipping")
            return TranscriptionResult(text="", duration=audio_duration, processing_time=0.0)

        # Check for silence
        energy = np.mean(audio ** 2)
        if energy < 1e-8:
            logger.debug("Audio too quiet, skipping")
            return TranscriptionResult(text="", duration=audio_duration, processing_time=0.0)

        # Transcribe
        result = self._backend.transcribe(audio)

        # Update statistics
        self.transcription_count += 1
        self.total_processing_time += result.processing_time
        self.total_audio_duration += result.duration

        # Log performance
        if result.duration > 0:
            rtf = result.processing_time / result.duration
            logger.debug(f"Transcribed {result.duration:.2f}s in {result.processing_time:.2f}s "
                        f"(RTF: {rtf:.2f}, speed: {1/rtf:.1f}x realtime)")

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

        # Update model config
        if model_name:
            if model_name in MODEL_CONFIGS:
                self.model_config = MODEL_CONFIGS[model_name]
            else:
                self.model_config = ModelConfig(
                    name=model_name,
                    model_id=model_name,
                    backend="faster-whisper",
                    device=self.model_config.device,
                    compute_type=self.model_config.compute_type,
                )
        elif tier:
            model_key = TIER_MODELS.get(tier, "tiny.en")
            self.model_config = MODEL_CONFIGS[model_key]

        # Create new backend
        self._create_backend()
        logger.info(f"Switched to model: {self.model_config.name}")

    def cleanup(self) -> None:
        """Clean up resources"""
        if self._backend:
            self._backend.cleanup()
            self._backend = None

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
            "quick": "Distil-Large-v3: 6x faster, within 1% WER",
            "balanced": "Distil-Large-v3.5: Best speed/quality (recommended)",
            "quality": "Large-v3: Highest accuracy, slower",
            "voxtral": "Voxtral-3B: Mistral's new model, beats Whisper",
        }


# Backwards compatibility aliases
class ModernWhisperASR(ASREngine):
    """Backwards compatible alias for existing code"""

    def __init__(self, cfg):
        # Extract settings from legacy Config object
        device = getattr(cfg, 'device', 'cpu')
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

    def transcribe(self, audio: np.ndarray) -> str:
        """Legacy interface returning just text"""
        self.session_transcription_count += 1
        # Call parent's transcribe method and extract text
        result = ASREngine.transcribe(self, audio)
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
