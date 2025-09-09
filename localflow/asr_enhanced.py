from __future__ import annotations

from typing import Iterable, Optional
import logging
import time

import numpy as np

from .config import Config

logger = logging.getLogger(__name__)


class EnhancedWhisperASR:
    """Enhanced ASR with VAD fallback and error recovery"""
    
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._model = None
        
        # VAD monitoring
        self.consecutive_empty_results = 0
        self.vad_enabled = cfg.vad_filter
        self.vad_fallback_triggered = False
        self.transcription_count = 0
        
        # Performance tracking
        self.total_audio_duration = 0.0
        self.total_processing_time = 0.0
        
        # Error recovery
        self.consecutive_errors = 0
        self.max_consecutive_errors = 3
    
    def load(self):
        """Load the Whisper model with error handling"""
        try:
            from faster_whisper import WhisperModel
        except Exception as e:
            raise RuntimeError(
                "faster-whisper is not installed or failed to import. "
                "Run LAUNCH_LOCALFLOW.bat to install dependencies."
            ) from e
        
        try:
            self._model = WhisperModel(
                self.cfg.model_name,
                device=self.cfg.device,
                compute_type=self.cfg.compute_type,
            )
            
            # Warmup with silence
            silence = np.zeros(16000, dtype=np.float32)
            segs, _info = self._model.transcribe(
                silence, 
                language=self.cfg.language,
                vad_filter=False  # Don't use VAD for warmup
            )
            _ = list(segs)
            
            logger.info(f"WhisperASR loaded: model={self.cfg.model_name}, device={self.cfg.device}")
            
        except Exception as e:
            logger.error(f"Failed to load Whisper model: {e}")
            raise
    
    def _check_audio_validity(self, audio: np.ndarray) -> bool:
        """Check if audio data is valid"""
        if audio is None or len(audio) == 0:
            logger.warning("Empty audio data received")
            return False
        
        # Check for all zeros (silent audio)
        if np.all(audio == 0):
            logger.debug("Audio is all zeros (complete silence)")
            return True  # Silent audio is valid, just empty
        
        # Check for NaN or Inf
        if np.any(np.isnan(audio)) or np.any(np.isinf(audio)):
            logger.error("Audio contains NaN or Inf values")
            return False
        
        # Check audio level
        max_amplitude = np.max(np.abs(audio))
        if max_amplitude > 10.0:
            logger.warning(f"Audio amplitude too high: {max_amplitude}")
            # Normalize instead of rejecting
            audio = audio / max_amplitude
        
        return True
    
    def _monitor_vad_behavior(self, result: str, audio_duration: float):
        """Monitor VAD behavior and trigger fallback if needed"""
        if not self.vad_enabled:
            return
        
        if result == "" and audio_duration > 0.5:
            # VAD removed non-trivial audio
            self.consecutive_empty_results += 1
            logger.warning(f"VAD removed {audio_duration:.2f}s of audio (occurrence {self.consecutive_empty_results})")
            
            if self.consecutive_empty_results >= 2:
                # Disable VAD as it's misbehaving
                logger.error("VAD is removing valid audio, disabling as fallback")
                self.vad_enabled = False
                self.vad_fallback_triggered = True
        else:
            # Reset counter on successful transcription
            if result != "":
                self.consecutive_empty_results = 0
    
    def transcribe(self, audio: np.ndarray) -> str:
        """Transcribe audio with enhanced error handling and VAD fallback"""
        if self._model is None:
            self.load()
        
        self.transcription_count += 1
        start_time = time.perf_counter()
        
        # Validate audio
        if not self._check_audio_validity(audio):
            logger.error("Invalid audio data, returning empty string")
            return ""
        
        audio_duration = len(audio) / 16000.0
        self.total_audio_duration += audio_duration
        
        try:
            # Determine whether to use VAD
            use_vad = self.vad_enabled and not self.vad_fallback_triggered
            
            if self.transcription_count <= 2 and use_vad:
                # Extra caution for first transcriptions
                logger.debug(f"Transcription {self.transcription_count}: Using VAD (early stage)")
            elif self.vad_fallback_triggered:
                logger.debug(f"Transcription {self.transcription_count}: VAD disabled (fallback active)")
                use_vad = False
            
            # Perform transcription
            segments, info = self._model.transcribe(
                audio,
                language=self.cfg.language,
                vad_filter=use_vad,
                beam_size=self.cfg.beam_size,
                temperature=self.cfg.temperature,
            )
            
            # Collect text from segments
            parts = []
            segment_count = 0
            for seg in segments:
                parts.append(seg.text)
                segment_count += 1
            
            text = " ".join(p.strip() for p in parts).strip()
            
            # Monitor VAD behavior
            self._monitor_vad_behavior(text, audio_duration)
            
            # Track performance
            processing_time = time.perf_counter() - start_time
            self.total_processing_time += processing_time
            
            if audio_duration > 0:
                speed_factor = audio_duration / processing_time
                logger.debug(f"Transcription {self.transcription_count}: "
                           f"{len(text)} chars, {segment_count} segments, "
                           f"{speed_factor:.1f}x realtime")
            
            # Reset error counter on success
            self.consecutive_errors = 0
            
            return text
            
        except Exception as e:
            self.consecutive_errors += 1
            logger.error(f"Transcription error (attempt {self.consecutive_errors}): {e}")
            
            if self.consecutive_errors >= self.max_consecutive_errors:
                logger.critical("Max consecutive errors reached, attempting recovery")
                # Try to reload model
                try:
                    self._model = None
                    self.load()
                    self.consecutive_errors = 0
                except Exception as reload_error:
                    logger.critical(f"Failed to reload model: {reload_error}")
            
            return ""
    
    def get_statistics(self) -> dict:
        """Get transcription statistics"""
        avg_speed = 0.0
        if self.total_processing_time > 0:
            avg_speed = self.total_audio_duration / self.total_processing_time
        
        return {
            "transcription_count": self.transcription_count,
            "total_audio_duration": self.total_audio_duration,
            "total_processing_time": self.total_processing_time,
            "average_speed_factor": avg_speed,
            "vad_enabled": self.vad_enabled,
            "vad_fallback_triggered": self.vad_fallback_triggered,
            "consecutive_errors": self.consecutive_errors,
        }