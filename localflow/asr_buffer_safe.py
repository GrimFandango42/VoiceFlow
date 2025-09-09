from __future__ import annotations

from typing import Iterable, Optional
import logging
import time
import threading
import copy

import numpy as np

from .config import Config

logger = logging.getLogger(__name__)


class BufferSafeWhisperASR:
    """
    Buffer-Safe ASR with complete state isolation between recordings.
    
    Fixes buffer corruption patterns identified in production:
    - VAD state pollution between recordings
    - Previous buffer content bleeding into new recordings  
    - Repeating outputs from previous buffers
    - Memory state corruption in long sessions
    """
    
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._model = None
        self._model_lock = threading.Lock()  # Thread safety for model access
        
        # Session tracking (persistent)
        self.session_transcription_count = 0
        self.session_start_time = time.time()
        self.total_audio_duration = 0.0
        self.total_processing_time = 0.0
        
        # Progressive degradation prevention
        self._transcriptions_since_reload = 0
        self._max_transcriptions_before_reload = 5  # Reload model every 5 transcriptions
        
        # Critical: NO persistent state between recordings
        # Each transcription starts with a clean slate
    
    def load(self):
        """Load the Whisper model with thread safety"""
        with self._model_lock:
            if self._model is not None:
                return
                
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
                
                # Clean warmup - no state pollution
                silence = np.zeros(8000, dtype=np.float32)  # Shorter warmup
                segs, _info = self._model.transcribe(
                    silence, 
                    language=self.cfg.language,
                    vad_filter=False,  # Never use VAD in warmup
                    beam_size=1,
                    temperature=0.0
                )
                _ = list(segs)
                
                logger.info(f"BufferSafeASR loaded: model={self.cfg.model_name}, device={self.cfg.device}")
                
            except Exception as e:
                logger.error(f"Failed to load Whisper model: {e}")
                raise
    
    def _reload_model_fresh(self):
        """Force reload the model with completely fresh state"""
        with self._model_lock:
            # Explicitly delete the old model
            if self._model is not None:
                del self._model
                self._model = None
            
            # Force garbage collection to clear memory
            import gc
            gc.collect()
            
            # Load fresh model
            self.load()
    
    def transcribe(self, audio: np.ndarray) -> str:
        """
        Transcribe audio with complete buffer isolation.
        Each call starts with a completely clean state.
        """
        if self._model is None:
            self.load()
        
        # CRITICAL: Prevent progressive degradation with model reinitialization
        self._transcriptions_since_reload += 1
        if self._transcriptions_since_reload >= self._max_transcriptions_before_reload:
            logger.info(f"Reloading Whisper model after {self._transcriptions_since_reload} transcriptions to prevent degradation")
            self._reload_model_fresh()
            self._transcriptions_since_reload = 0
        
        # CRITICAL: Create completely isolated transcription state
        recording_state = self._create_clean_recording_state(audio)
        
        try:
            result = self._perform_isolated_transcription(recording_state)
            
            # Update only persistent session stats (no per-recording state kept)
            self._update_session_stats(recording_state, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Transcription error: {e}")
            # Don't persist error state - each recording is isolated
            return ""
        finally:
            # CRITICAL: Explicitly clean up recording state
            del recording_state
    
    def _create_clean_recording_state(self, audio: np.ndarray) -> dict:
        """Create completely isolated state for this recording"""
        
        # Validate audio with no persistent state
        if not self._validate_audio_isolated(audio):
            raise ValueError("Invalid audio data")
        
        audio_duration = len(audio) / 16000.0
        
        # Completely isolated recording state
        recording_state = {
            'audio': audio.copy(),  # Isolated copy
            'audio_duration': audio_duration,
            'recording_id': f"{time.time()}_{self.session_transcription_count}",  # Unique ID
            'start_time': time.perf_counter(),
            'use_vad': False,  # NEVER use VAD to prevent state pollution
            'beam_size': self.cfg.beam_size,
            'temperature': self.cfg.temperature,
            'language': self.cfg.language,
        }
        
        logger.debug(f"Created clean recording state: {recording_state['recording_id']}")
        return recording_state
    
    def _validate_audio_isolated(self, audio: np.ndarray) -> bool:
        """Validate audio with no persistent state changes"""
        if audio is None or len(audio) == 0:
            return False
        
        if np.any(np.isnan(audio)) or np.any(np.isinf(audio)):
            return False
        
        # Amplitude check without modifying the original audio
        max_amplitude = np.max(np.abs(audio))
        if max_amplitude > 10.0:
            logger.warning(f"High audio amplitude: {max_amplitude}")
            # Don't modify the audio in place - let the caller handle it
        
        return True
    
    def _perform_isolated_transcription(self, recording_state: dict) -> str:
        """Perform transcription with complete isolation"""
        
        with self._model_lock:  # Thread-safe model access
            # CRITICAL: Use completely isolated parameters with explicit state clearing
            segments, info = self._model.transcribe(
                recording_state['audio'],
                language=recording_state['language'],
                vad_filter=recording_state['use_vad'],  # Always False for safety
                beam_size=recording_state['beam_size'],
                temperature=recording_state['temperature'],
                word_timestamps=False,      # Disable to prevent timestamp buffer issues
                initial_prompt=None,        # CRITICAL: No context from previous calls
                prefix=None,                # No prefix context
                condition_on_previous_text=False,  # CRITICAL: Don't use previous text as context
                compression_ratio_threshold=2.4,   # Standard threshold
                logprob_threshold=-1.0,     # Standard threshold  
                no_speech_threshold=0.6,    # Standard threshold
            )
            
            # Process segments with isolation
            text = self._process_segments_isolated(segments, recording_state['recording_id'])
            
            return text
    
    def _process_segments_isolated(self, segments, recording_id: str) -> str:
        """Process segments with complete isolation and proper ordering"""
        
        # Convert iterator to list for processing
        segments_list = list(segments)
        
        if not segments_list:
            logger.debug(f"No segments for recording {recording_id}")
            return ""
        
        # Sort segments chronologically (fixes buffer ordering issue)
        segments_list.sort(key=lambda s: getattr(s, 'start', 0))
        
        # Process each segment independently
        processed_segments = []
        for i, seg in enumerate(segments_list):
            segment_text = self._clean_segment_text_isolated(seg.text)
            
            if segment_text.strip():  # Only add non-empty segments
                processed_segments.append(segment_text)
                
                logger.debug(f"Recording {recording_id} segment {i+1}: "
                           f"[{getattr(seg, 'start', 0):.2f}s-{getattr(seg, 'end', 0):.2f}s] "
                           f"'{segment_text}'")
        
        # Combine segments cleanly
        final_text = " ".join(processed_segments).strip()
        
        logger.debug(f"Recording {recording_id} final: '{final_text}' ({len(processed_segments)} segments)")
        return final_text
    
    def _clean_segment_text_isolated(self, text: str) -> str:
        """Clean segment text without persistent state"""
        if not text:
            return ""
        
        text = text.strip()
        
        # Detect fallback phrases (no persistent state)
        fallback_phrases = [
            "read this", "thank you", "thanks for watching", 
            "subscribe", "like and subscribe"
        ]
        
        is_fallback = any(text.lower() == fallback.lower() for fallback in fallback_phrases)
        
        if is_fallback:
            logger.warning(f"Fallback phrase detected: '{text}' - poor audio quality")
            return f"[UNCERTAIN: {text}]"
        
        # Basic cleaning without state
        import re
        text = re.sub(r'\s+([,.!?])', r'\1', text)
        text = re.sub(r'([,.!?])\s*([A-Z])', r'\1 \2', text)
        
        return text.strip()
    
    def _update_session_stats(self, recording_state: dict, result: str):
        """Update only session-level statistics (no recording state persisted)"""
        
        processing_time = time.perf_counter() - recording_state['start_time']
        
        # Update session stats atomically
        self.session_transcription_count += 1
        self.total_audio_duration += recording_state['audio_duration']
        self.total_processing_time += processing_time
        
        # Calculate performance
        speed_factor = recording_state['audio_duration'] / processing_time if processing_time > 0 else 0
        
        logger.info(f"Recording {self.session_transcription_count}: "
                   f"{len(result)} chars, "
                   f"{speed_factor:.1f}x realtime, "
                   f"session total: {self.session_transcription_count} recordings")
    
    def get_clean_statistics(self) -> dict:
        """Get session statistics with no persistent recording state"""
        
        session_duration = time.time() - self.session_start_time
        avg_speed = 0.0
        
        if self.total_processing_time > 0:
            avg_speed = self.total_audio_duration / self.total_processing_time
        
        return {
            'session_transcription_count': self.session_transcription_count,
            'session_duration_seconds': session_duration,
            'total_audio_duration': self.total_audio_duration,
            'total_processing_time': self.total_processing_time,
            'average_speed_factor': avg_speed,
            'buffer_state_isolated': True,  # Confirms clean state management
            'vad_always_disabled': True,    # Confirms no VAD pollution
        }
    
    def reset_session(self):
        """Reset session statistics while keeping model loaded"""
        logger.info("Resetting session state for clean start")
        
        self.session_transcription_count = 0
        self.session_start_time = time.time()
        self.total_audio_duration = 0.0
        self.total_processing_time = 0.0
        
        # Model stays loaded for performance
        # No per-recording state to clear (already isolated)