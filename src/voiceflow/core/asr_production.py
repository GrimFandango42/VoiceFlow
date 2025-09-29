"""
Production ASR Implementation

State-of-the-art transcription using 2024 best practices:
- WhisperX with word-level timestamps
- Speaker diarization with pyannote-audio
- VAD preprocessing for quality
- Batched inference for performance
- Context-aware processing
"""

import logging
import time
import threading
from typing import Optional, Dict, List, Any, Tuple
import numpy as np
from dataclasses import dataclass
from datetime import datetime

from voiceflow.core.config import Config

logger = logging.getLogger(__name__)

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
    """Complete transcription result with metadata"""
    segments: List[TranscriptionSegment]
    language: str
    duration: float
    processing_time: float
    speaker_count: int = 0
    confidence: float = 1.0

class ProductionWhisperASR:
    """
    Production-quality ASR using state-of-the-art 2024 techniques.

    Features:
    - WhisperX for 70x realtime performance
    - Word-level timestamps with forced alignment
    - Speaker diarization for multi-speaker contexts
    - VAD preprocessing to reduce hallucinations
    - Batched inference for efficiency
    - Rich metadata output
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._model = None
        self._align_model = None
        self._diarize_model = None
        self._model_lock = threading.RLock()

        # Configuration
        self.enable_diarization = getattr(cfg, 'enable_diarization', True)
        self.enable_word_timestamps = getattr(cfg, 'enable_word_timestamps', True)
        self.batch_size = getattr(cfg, 'batch_size', 16)
        self.compute_type = getattr(cfg, 'compute_type', 'float16')
        self.device = cfg.device

        # Performance tracking
        self.transcription_count = 0
        self.total_processing_time = 0.0
        self.total_audio_duration = 0.0

        # Initialize WhisperX availability flag
        self._use_whisperx = False

        logger.info(f"Production ASR initialized - device: {self.device}, diarization: {self.enable_diarization}")

    def load(self):
        """Load all models for production use"""
        with self._model_lock:
            if self._model is not None:
                return

            logger.info("Loading production ASR models...")
            start_time = time.time()

            try:
                # Check if WhisperX is available
                try:
                    import whisperx
                    self._use_whisperx = True
                    logger.info("WhisperX available - using advanced features")
                except ImportError:
                    logger.warning("WhisperX not available - falling back to faster-whisper")
                    self._use_whisperx = False

                if self._use_whisperx:
                    self._load_whisperx()
                else:
                    self._load_faster_whisper()

                load_time = time.time() - start_time
                logger.info(f"Production models loaded in {load_time:.2f}s")

            except Exception as e:
                logger.error(f"Failed to load production models: {e}")
                self._model = None
                raise

    def _load_whisperx(self):
        """Load WhisperX models with all features"""
        import whisperx

        # Main transcription model
        model_name = getattr(self.cfg, 'model_name', 'large-v3')
        if model_name.endswith('.en'):
            model_name = model_name[:-3]  # WhisperX handles language internally

        logger.info(f"Loading WhisperX model: {model_name}")
        self._model = whisperx.load_model(
            model_name,
            device=self.device,
            compute_type=self.compute_type,
            language="en"
        )

        # Alignment model for word-level timestamps
        if self.enable_word_timestamps:
            logger.info("Loading alignment model for word-level timestamps")
            try:
                self._align_model, self._align_metadata = whisperx.load_align_model(
                    language_code="en",
                    device=self.device
                )
                logger.info("Alignment model loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to load alignment model: {e}")
                self._align_model = None

        # Diarization model for speaker identification
        if self.enable_diarization:
            logger.info("Loading diarization model for speaker identification")
            try:
                self._diarize_model = whisperx.DiarizationPipeline(
                    use_auth_token=getattr(self.cfg, 'hf_token', None),
                    device=self.device
                )
                logger.info("Diarization model loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to load diarization model: {e}")
                self._diarize_model = None

    def _load_faster_whisper(self):
        """Fallback to faster-whisper if WhisperX unavailable"""
        from faster_whisper import WhisperModel

        logger.info("Loading faster-whisper model")
        self._model = WhisperModel(
            self.cfg.model_name,
            device=self.cfg.device,
            compute_type=self.compute_type,
            cpu_threads=4,
            num_workers=1
        )

        # Quick warmup
        warmup_audio = np.zeros(1600, dtype=np.float32)
        list(self._model.transcribe(warmup_audio))

    def transcribe(self, audio: np.ndarray) -> TranscriptionResult:
        """
        Perform production-quality transcription with all features.

        Args:
            audio: Audio data as numpy array

        Returns:
            TranscriptionResult with segments, timestamps, and metadata
        """
        if audio is None or audio.size == 0:
            return TranscriptionResult([], "en", 0.0, 0.0)

        start_time = time.time()
        audio_duration = len(audio) / getattr(self.cfg, 'sample_rate', 16000)

        try:
            # Load models if needed
            if self._model is None:
                self.load()

            if self._model is None:
                raise RuntimeError("Failed to load ASR model")

            # Validate audio
            if audio_duration < 0.1:
                logger.debug("Audio too short, skipping")
                return TranscriptionResult([], "en", audio_duration, 0.0)

            # Check for silence
            energy = np.mean(audio ** 2)
            if energy < 1e-6:
                logger.debug("Audio too quiet, skipping")
                return TranscriptionResult([], "en", audio_duration, 0.0)

            # Transcribe with appropriate backend
            with self._model_lock:
                if self._use_whisperx:
                    result = self._transcribe_whisperx(audio, audio_duration)
                else:
                    result = self._transcribe_faster_whisper(audio, audio_duration)

            # Update statistics
            processing_time = time.time() - start_time
            self.transcription_count += 1
            self.total_processing_time += processing_time
            self.total_audio_duration += audio_duration

            result.processing_time = processing_time

            # Log performance
            rtf = processing_time / audio_duration if audio_duration > 0 else 0
            logger.debug(f"Transcribed {audio_duration:.2f}s in {processing_time:.2f}s (RTF: {rtf:.2f})")

            return result

        except Exception as e:
            logger.error(f"Transcription failed: {e}")
            processing_time = time.time() - start_time
            return TranscriptionResult([], "en", audio_duration, processing_time)

    def _transcribe_whisperx(self, audio: np.ndarray, audio_duration: float) -> TranscriptionResult:
        """Transcribe using WhisperX with all advanced features"""
        import whisperx

        # Step 1: Basic transcription
        logger.debug("Step 1: WhisperX transcription")
        result = self._model.transcribe(
            audio,
            batch_size=self.batch_size,
            language="en"
        )

        segments = []
        language = result.get("language", "en")

        # Step 2: Word-level alignment
        if self.enable_word_timestamps and self._align_model and result.get("segments"):
            logger.debug("Step 2: Word-level alignment")
            try:
                aligned_result = whisperx.align(
                    result["segments"],
                    self._align_model,
                    self._align_metadata,
                    audio,
                    self.device,
                    return_char_alignments=False
                )
                result = aligned_result
            except Exception as e:
                logger.warning(f"Alignment failed: {e}")

        # Step 3: Speaker diarization
        if self.enable_diarization and self._diarize_model and result.get("segments"):
            logger.debug("Step 3: Speaker diarization")
            try:
                diarize_segments = self._diarize_model(audio, num_speakers=None)
                result = whisperx.assign_word_speakers(diarize_segments, result)
            except Exception as e:
                logger.warning(f"Diarization failed: {e}")

        # Convert to our format
        speaker_set = set()
        for segment in result.get("segments", []):
            if not segment.get("text", "").strip():
                continue

            speaker = segment.get("speaker", None)
            if speaker:
                speaker_set.add(speaker)

            # Extract words if available
            words = None
            if segment.get("words"):
                words = [
                    {
                        "text": word.get("word", ""),
                        "start": word.get("start", 0.0),
                        "end": word.get("end", 0.0),
                        "confidence": word.get("score", 1.0)
                    }
                    for word in segment["words"]
                ]

            segments.append(TranscriptionSegment(
                text=segment["text"].strip(),
                start=segment.get("start", 0.0),
                end=segment.get("end", audio_duration),
                speaker=speaker,
                confidence=segment.get("score", 1.0),
                words=words
            ))

        return TranscriptionResult(
            segments=segments,
            language=language,
            duration=audio_duration,
            processing_time=0.0,  # Will be set by caller
            speaker_count=len(speaker_set)
        )

    def _transcribe_faster_whisper(self, audio: np.ndarray, audio_duration: float) -> TranscriptionResult:
        """Fallback transcription using faster-whisper"""
        segments_iter, info = self._model.transcribe(
            audio,
            language="en",
            beam_size=1,
            condition_on_previous_text=False,
            vad_filter=True,
            temperature=0.0
        )

        segments = []
        for segment in segments_iter:
            if segment.text and segment.text.strip():
                segments.append(TranscriptionSegment(
                    text=segment.text.strip(),
                    start=segment.start,
                    end=segment.end,
                    confidence=segment.avg_logprob if hasattr(segment, 'avg_logprob') else 1.0
                ))

        return TranscriptionResult(
            segments=segments,
            language=info.language,
            duration=audio_duration,
            processing_time=0.0,  # Will be set by caller
            speaker_count=0
        )

    def get_simple_text(self, result: TranscriptionResult) -> str:
        """Extract simple text from transcription result"""
        if not result.segments:
            return ""

        return " ".join(segment.text for segment in result.segments).strip()

    def get_formatted_result(self, result: TranscriptionResult) -> Dict[str, Any]:
        """Get formatted result with all metadata"""
        return {
            "text": self.get_simple_text(result),
            "segments": [
                {
                    "text": seg.text,
                    "start": seg.start,
                    "end": seg.end,
                    "speaker": seg.speaker,
                    "confidence": seg.confidence,
                    "words": seg.words
                }
                for seg in result.segments
            ],
            "language": result.language,
            "duration": result.duration,
            "processing_time": result.processing_time,
            "speaker_count": result.speaker_count,
            "confidence": result.confidence
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        avg_processing = self.total_processing_time / max(self.transcription_count, 1)
        avg_rtf = avg_processing / max(self.total_audio_duration / max(self.transcription_count, 1), 0.001)

        return {
            "transcription_count": self.transcription_count,
            "total_processing_time": self.total_processing_time,
            "total_audio_duration": self.total_audio_duration,
            "avg_processing_time": avg_processing,
            "avg_realtime_factor": avg_rtf,
            "model_loaded": self._model is not None,
            "whisperx_enabled": self._use_whisperx,
            "diarization_enabled": self.enable_diarization and self._diarize_model is not None,
            "word_timestamps_enabled": self.enable_word_timestamps and self._align_model is not None
        }

    def cleanup(self):
        """Clean shutdown"""
        with self._model_lock:
            self._model = None
            self._align_model = None
            self._diarize_model = None
            logger.info("Production ASR models cleaned up")


# Compatibility alias
ModernWhisperASR = ProductionWhisperASR