from __future__ import annotations

from typing import Iterable, Optional
import logging
import time
import threading
import copy

import numpy as np

from voiceflow.core.config import Config

logger = logging.getLogger(__name__)

# Production logging integration
try:
    from voiceflow.utils.production_logging import get_production_logger, log_info
    PRODUCTION_LOGGING_AVAILABLE = True
except ImportError:
    PRODUCTION_LOGGING_AVAILABLE = False


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
        
        # Progressive degradation prevention - REDUCED frequency for stability
        self._transcriptions_since_reload = 0
        self._max_transcriptions_before_reload = 20  # Reload model every 20 transcriptions (was 5)
        
        # Smart conversation management - less aggressive timeouts
        self._last_transcription_time = time.time()
        self._conversation_timeout = 300.0  # Clear after 5 MINUTES of inactivity (was 30s - too aggressive!)
        self._total_conversation_duration = 0.0
        self._max_conversation_duration = 600.0  # Force reload after 10 minutes of total conversation (was 3min)
        self._is_processing = False  # Track if actively processing to prevent timeout during transcription
        
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
        Transcribe audio with complete buffer isolation and enhanced validation.
        Each call starts with a completely clean state.
        """
        transcription_start_time = time.perf_counter()

        try:
            # CRITICAL: Pre-validation to catch issues early
            if audio is None:
                logger.error("Transcription called with None audio")
                return ""

            if self._model is None:
                logger.info("Loading ASR model for transcription")
                self.load()

            # CRITICAL: Smart timeout checking - don't reload during active processing
            current_time = time.time()
            time_since_last = current_time - self._last_transcription_time

            # Only check timeouts if not actively processing (prevents mid-transcription reloads)
            if not self._is_processing:
                # Force model reload if conversation has been too long or inactive too long
                conversation_too_long = self._total_conversation_duration > self._max_conversation_duration
                inactive_too_long = time_since_last > self._conversation_timeout

                if conversation_too_long or inactive_too_long:
                    reason = "long conversation" if conversation_too_long else "inactivity timeout"
                    logger.info(f"Model reload triggered: {reason} (total duration: {self._total_conversation_duration:.1f}s, idle: {time_since_last:.1f}s)")
                    self._reload_model_fresh()
                    self._transcriptions_since_reload = 0
                    # Reset conversation tracking
                    self._total_conversation_duration = 0.0
                    self._last_transcription_time = current_time

            # Mark as processing to prevent timeouts during transcription
            self._is_processing = True

            # CRITICAL: Prevent progressive degradation with model reinitialization
            self._transcriptions_since_reload += 1
            if self._transcriptions_since_reload >= self._max_transcriptions_before_reload:
                logger.info(f"Reloading Whisper model after {self._transcriptions_since_reload} transcriptions to prevent degradation")
                self._reload_model_fresh()
                self._transcriptions_since_reload = 0

            # CRITICAL: Create completely isolated transcription state with validation
            recording_state = self._create_clean_recording_state(audio)

            # Buffer integrity check
            if not self._check_buffer_integrity(recording_state):
                raise ValueError("Buffer integrity check failed")

            result = self._perform_isolated_transcription(recording_state)

            # Update only persistent session stats (no per-recording state kept)
            self._update_session_stats(recording_state, result)

            # Mark processing complete to allow timeout checks again
            self._is_processing = False

            # Log successful transcription
            total_time = time.perf_counter() - transcription_start_time
            logger.debug(f"Transcription completed in {total_time:.3f}s: '{result[:50]}{'...' if len(result) > 50 else ''}'")

            return result

        except Exception as e:
            logger.error(f"Transcription error: {e}")

            # Emit error metrics for dashboard monitoring
            if PRODUCTION_LOGGING_AVAILABLE:
                try:
                    from voiceflow.utils.production_logging import log_error
                    error_metrics = {
                        'transcription_error': True,
                        'error_message': str(e),
                        'audio_duration': recording_state.get('audio_duration', 0.0) if 'recording_state' in locals() else 0.0,
                        'model_name': self.cfg.model_name,
                        'transcription_id': recording_state.get('recording_id', 'unknown') if 'recording_state' in locals() else 'unknown',
                        'session_count': self.session_transcription_count,
                        'total_time': time.perf_counter() - transcription_start_time
                    }

                    log_error("BufferSafeWhisperASR", f"Transcription failed: {str(e)}", error_metrics)
                except (OSError, RuntimeError, AttributeError):
                    pass  # Don't let logging errors compound the problem

            # Mark processing complete even on error
            self._is_processing = False
            # Don't persist error state - each recording is isolated
            return ""

        finally:
            # CRITICAL: Explicitly clean up recording state
            if 'recording_state' in locals():
                del recording_state
    
    def _create_clean_recording_state(self, audio: np.ndarray) -> dict:
        """Create completely isolated state for this recording with enhanced validation"""

        try:
            # Import validation guard function
            from voiceflow.core.audio_enhanced import audio_validation_guard

            # CRITICAL: Sanitize and validate audio data first
            sanitized_audio = audio_validation_guard(audio, "ASR_StateCreation", allow_empty=False)

            # Additional validation with ASR-specific checks
            if not self._validate_audio_isolated(sanitized_audio):
                raise ValueError("Audio failed ASR-specific validation")

            audio_duration = len(sanitized_audio) / 16000.0

            # Completely isolated recording state
            recording_state = {
                'audio': sanitized_audio,  # Use sanitized audio
                'audio_duration': audio_duration,
                'recording_id': f"{time.time()}_{self.session_transcription_count}",  # Unique ID
                'start_time': time.perf_counter(),
                'use_vad': False,  # NEVER use VAD to prevent state pollution
                'beam_size': self.cfg.beam_size,
                'temperature': self.cfg.temperature,
                'language': self.cfg.language,
                'audio_metadata': {
                    'original_length': len(audio),
                    'sanitized_length': len(sanitized_audio),
                    'max_amplitude': float(np.max(np.abs(sanitized_audio))),
                    'rms_energy': float(np.sqrt(np.mean(sanitized_audio ** 2))),
                }
            }

            logger.debug(f"Created clean recording state: {recording_state['recording_id']} "
                        f"({recording_state['audio_duration']:.2f}s)")
            return recording_state

        except Exception as e:
            logger.error(f"Failed to create recording state: {e}")
            raise ValueError(f"Cannot create valid recording state: {e}")
    
    def _validate_audio_isolated(self, audio: np.ndarray) -> bool:
        """
        Enhanced audio validation with comprehensive checks.
        Validates audio with no persistent state changes.
        """
        try:
            # Import validation guard function
            from voiceflow.core.audio_enhanced import audio_validation_guard

            # Use the comprehensive validation guard
            validated_audio = audio_validation_guard(audio, "ASR_Validation", allow_empty=False)

            # If we get here, audio passed validation
            # Check for potential quality issues
            max_amplitude = np.max(np.abs(validated_audio))

            # Additional ASR-specific validations
            if len(validated_audio) < 1600:  # Less than 0.1 seconds at 16kHz
                logger.warning(f"Audio too short for reliable transcription: {len(validated_audio)} samples")
                return False

            # Check for mostly silent audio
            energy = np.mean(validated_audio ** 2)
            if energy < 1e-6:  # Very low energy threshold
                logger.info("Audio appears to be silent or very quiet")
                # Still return True - might be intentional silence

            # Check for clipping (digital distortion)
            clipped_samples = np.count_nonzero(np.abs(validated_audio) >= 0.99)
            if clipped_samples > len(validated_audio) * 0.01:  # More than 1% clipped
                logger.warning(f"Audio may be clipped: {clipped_samples} samples at maximum")

            return True

        except ValueError as e:
            logger.error(f"Audio validation failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error in audio validation: {e}")
            return False

    def _check_buffer_integrity(self, recording_state: dict) -> bool:
        """
        Check buffer integrity and state consistency before transcription.

        Args:
            recording_state: The recording state dictionary to validate

        Returns:
            bool: True if buffer integrity is intact, False otherwise
        """
        try:
            # Check required keys exist
            required_keys = ['audio', 'recording_id', 'audio_duration', 'audio_metadata']
            for key in required_keys:
                if key not in recording_state:
                    logger.error(f"Buffer integrity check failed: missing key '{key}'")
                    return False

            audio = recording_state['audio']
            metadata = recording_state['audio_metadata']

            # Verify audio data consistency
            if not isinstance(audio, np.ndarray):
                logger.error("Buffer integrity check failed: audio is not numpy array")
                return False

            # Check audio buffer bounds
            if audio.size == 0:
                logger.warning("Buffer integrity check: audio buffer is empty")
                return False

            # Verify metadata consistency
            actual_length = len(audio)
            if actual_length != metadata['sanitized_length']:
                logger.error(f"Buffer integrity check failed: length mismatch - "
                           f"actual: {actual_length}, metadata: {metadata['sanitized_length']}")
                return False

            # Check for buffer corruption (memory safety)
            try:
                # Basic memory bounds check
                _ = audio[0]  # First element
                _ = audio[-1]  # Last element

                # Check if data is still valid (not corrupted)
                current_max = np.max(np.abs(audio))
                if abs(current_max - metadata['max_amplitude']) > 1e-6:
                    logger.warning(f"Buffer integrity check: amplitude changed - "
                                 f"original: {metadata['max_amplitude']:.6f}, "
                                 f"current: {current_max:.6f}")

            except (IndexError, ValueError, FloatingPointError) as e:
                logger.error(f"Buffer integrity check failed: memory corruption detected - {e}")
                return False

            # Check processing state consistency
            if self._is_processing and hasattr(self, '_current_recording_id'):
                if getattr(self, '_current_recording_id') != recording_state['recording_id']:
                    logger.warning("Buffer integrity check: concurrent processing detected")

            logger.debug(f"Buffer integrity check passed for recording: {recording_state['recording_id']}")
            return True

        except Exception as e:
            logger.error(f"Buffer integrity check failed with exception: {e}")
            return False
    
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
                log_prob_threshold=-1.0,     # Standard threshold  
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
        
        # Update conversation tracking for long conversation management
        self._total_conversation_duration += recording_state['audio_duration']
        self._last_transcription_time = time.time()
        
        # Calculate performance
        speed_factor = recording_state['audio_duration'] / processing_time if processing_time > 0 else 0
        word_count = len(result.split()) if result else 0
        
        # Emit performance metrics for dashboard monitoring
        if PRODUCTION_LOGGING_AVAILABLE:
            try:
                metrics = {
                    'transcription_complete': True,
                    'audio_duration': recording_state['audio_duration'],
                    'processing_time': processing_time,
                    'speed_factor': speed_factor,
                    'word_count': word_count,
                    'model_name': self.cfg.model_name,
                    'transcription_id': recording_state['recording_id'],
                    'session_count': self.session_transcription_count,
                    'chars_transcribed': len(result)
                }
                
                log_info("BufferSafeWhisperASR", 
                        f"Transcription complete: {speed_factor:.1f}x realtime, {word_count} words", 
                        metrics)
                        
            except Exception as e:
                # Don't let logging errors affect transcription
                pass
        
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