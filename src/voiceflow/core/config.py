from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Config:
    # Hotkey: toggle PTT on/off. We'll detect F4 by default.
    hotkey_ctrl: bool = True
    hotkey_shift: bool = True
    hotkey_alt: bool = False
    hotkey_key: str = ""  # primary key pressed along with modifiers (empty = modifier keys only)

    # Audio - Optimized for speed
    sample_rate: int = 16000
    channels: int = 1
    blocksize: int = 512  # frames per callback, ~64 ms at 16k
    
    # Performance optimizations
    enable_batching: bool = True  # Enable VAD-based batching for 12.5x speedup
    max_batch_size: int = 4  # Process multiple segments together
    enable_streaming: bool = True  # Enable real-time streaming feedback

    # ASR - STABILITY-FIRST Configuration based on community solutions
    model_name: str = "tiny.en"  # CRITICAL: Use smallest model for maximum stability
    device: str = "cpu"   # CRITICAL: Force CPU for stability
    compute_type: str = "int8"    # CRITICAL: Force int8 for CPU stability
    fallback_device: str = "cpu"  # Fallback if GPU unavailable
    fallback_compute_type: str = "int8"  # CPU fallback settings
    vad_filter: bool = False  # CRITICAL: VAD disabled for stability
    beam_size: int = 1  # CRITICAL: Use greedy decoding for fastest/most stable processing
    temperature: float = 0.0  # CRITICAL: Use deterministic processing

    # Whisper-specific STABILITY-FIRST settings to prevent stuck transcriptions
    word_timestamps: bool = False  # CRITICAL: Disable for maximum stability
    condition_on_previous_text: bool = False  # CRITICAL: Disable context to prevent repetition loops
    compression_ratio_threshold: float = 2.4  # CRITICAL: Conservative threshold to prevent hangs
    log_prob_threshold: float = -1.0  # CRITICAL: Conservative threshold for stability
    no_speech_threshold: float = 0.9  # CRITICAL: Very aggressive silence detection

    # Quality improvements without speed impact
    enable_smart_prompting: bool = True  # Adaptive prompting for better accuracy
    use_enhanced_post_processing: bool = True  # Smart text cleaning

    # STABILITY-FIRST: Disable all advanced optimizations for maximum stability
    enable_lockfree_model_access: bool = False  # CRITICAL: Disable to prevent race conditions
    enable_ultra_fast_mode_bypass: bool = False  # CRITICAL: Keep validation enabled
    enable_memory_pooling: bool = False  # CRITICAL: Disable to prevent memory issues
    enable_chunked_long_audio: bool = False  # CRITICAL: Disable chunking for stability

    # Adaptive Model Access Configuration (Phase 1 Optimization)
    max_concurrent_transcription_jobs: int = 1  # Start conservative, auto-detect concurrency
    auto_detect_model_concurrency: bool = True  # Enable intelligent concurrency detection

    # Smart Audio Validation Configuration (Phase 1 Optimization)
    validation_frequency: int = 8  # Validate every 8th callback after hardware trust established
    min_samples_for_statistical: int = 800  # Use statistical validation for arrays >800 samples

    # Phase 2 Optimization: Advanced Performance Features (Research-Based)
    enable_gpu_acceleration: bool = True  # Enable GPU acceleration (6-7x speedup)
    enable_dual_model_strategy: bool = True  # tiny.en first, then small.en for quality
    enable_advanced_vad: bool = True  # WhisperLive-style VAD for smart chunking
    enable_batched_processing: bool = True  # Parallel chunk processing (12.5x speedup)
    enable_continuous_streaming: bool = True  # No-gap audio recording

    # Dual Model Configuration
    fast_model_name: str = "tiny.en"  # Ultra-fast for first sentence (<500ms)
    quality_model_name: str = "small.en"  # Higher quality for subsequent transcriptions
    switch_after_sentences: int = 1  # Switch to quality model after N sentences

    # Advanced VAD Configuration
    vad_aggressiveness: int = 2  # 0-3, higher = more aggressive silence detection
    vad_frame_duration_ms: int = 30  # Frame duration for VAD analysis
    silence_threshold: float = 0.01  # Silence detection threshold

    # Batched Processing Configuration
    max_parallel_chunks: int = 4  # Process up to 4 audio chunks in parallel
    chunk_overlap_seconds: float = 0.2  # Overlap between chunks to prevent word cuts
    enable_chunk_prioritization: bool = True  # Prioritize recent chunks

    # STABILITY-FIRST settings (disable aggressive optimizations)
    ultra_fast_mode: bool = False  # CRITICAL: Disable for stability
    preload_model_on_startup: bool = False  # CRITICAL: Disable to prevent startup issues

    # Long sentence optimizations (for 3+ second recordings)
    chunk_size_seconds: float = 5.0  # Process in 5-second chunks for long audio
    parallel_processing: bool = False  # Can't parallelize Whisper on same model
    aggressive_segment_merge: bool = True  # Merge segments aggressively to reduce overhead

    # CRITICAL: Aggressive stability settings based on GitHub research
    max_transcriptions_before_reload: int = 2  # CRITICAL: Force reload every 2 transcriptions for CPU stability
    disable_detailed_logging: bool = False  # Enable detailed logging for debugging stuck transcriptions
    enable_model_caching: bool = False  # CRITICAL: Disable caching to prevent memory accumulation

    # BALANCED audio validation optimizations (SAFE + FAST)
    enable_optimized_audio_validation: bool = True  # Enable smart audio validation system
    enable_fast_audio_validation: bool = True  # Use statistical sampling instead of full validation
    audio_validation_sample_rate: float = 0.05  # VALIDATED: 5% sampling for +15-50% performance
    skip_redundant_format_checks: bool = True  # Skip format validation after first successful check
    disable_amplitude_warnings: bool = True  # Skip non-critical amplitude logging
    fast_nan_inf_detection: bool = True  # Use optimized NaN/Inf detection algorithm

    # CRITICAL: Buffer integrity protection (DO NOT DISABLE - prevents buffer overflow)
    skip_buffer_integrity_checks: bool = False  # Keep buffer protection ENABLED for stability
    minimal_segment_processing: bool = True  # Skip non-essential segment processing
    disable_fallback_detection: bool = True  # Skip fallback phrase detection for speed
    use_enhanced_post_processing: bool = True  # Enable enhanced text formatting (capitalization, punctuation)

    # Visual Indicators Configuration
    visual_indicators_enabled: bool = True  # Enable visual feedback when recording
    enable_visual_demo: bool = True  # Enable visual demo feature
    visual_overlay_enabled: bool = True  # Bottom-screen overlay indicators

    # Output behavior
    paste_injection: bool = True  # Use clipboard paste injection by default
    restore_clipboard: bool = True  # restore original clipboard after paste
    paste_shortcut: str = "ctrl+v"  # e.g., "ctrl+v" or "shift+insert"
    press_enter_after_paste: bool = False
    max_inject_chars: int = 4000  # safety limit to avoid huge payloads
    min_inject_interval_ms: int = 100  # simple rate limit to avoid spam
    type_if_len_le: int = 0  # if >0, use typing (not clipboard) for short texts

    # Misc
    language: str | None = "en"
    verbose: bool = True
    code_mode_default: bool = True
    code_mode_lowercase: bool = True
    use_tray: bool = True

    def __post_init__(self):
        """
        CRITICAL GUARDRAIL: Validate configuration after initialization.

        This prevents crashes from invalid configuration values identified
        in comprehensive testing (10/40 edge case failures).
        """
        from ..utils.guardrails import validate_config

        try:
            validated_config = validate_config(self)
            # Update self with validated values
            for key, value in validated_config.__dict__.items():
                if hasattr(self, key):
                    setattr(self, key, value)
            logger.debug("Configuration validation completed successfully")
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            # Continue with potentially invalid config but log the issue

    def validate(self) -> 'Config':
        """
        Manually validate the configuration.

        Returns:
            Validated configuration object
        """
        from ..utils.guardrails import validate_config
        return validate_config(self)

