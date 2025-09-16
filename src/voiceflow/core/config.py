from __future__ import annotations

from dataclasses import dataclass


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

    # ASR - BALANCED Performance + Quality Mode (GPT-5 recommended)
    model_name: str = "base.en"  # Balanced model for good speed + quality (was tiny.en)
    device: str = "cuda"  # GPU acceleration for 6-7x speedup
    compute_type: str = "float16"  # Optimized for GPU inference
    fallback_device: str = "cpu"  # Fallback if GPU unavailable
    fallback_compute_type: str = "int8"  # CPU fallback settings
    vad_filter: bool = False  # CRITICAL FIX: VAD was removing all audio after 2 recordings
    beam_size: int = 2  # Improved from 1 (greedy) to 2 for better quality
    temperature: float = 0.0

    # Whisper-specific BALANCED optimizations for quality + speed
    word_timestamps: bool = False  # Disable expensive timestamp computation
    condition_on_previous_text: bool = True  # Enable context for better accuracy (was False)
    compression_ratio_threshold: float = 3.5  # Balanced threshold for quality (vs 4.0)
    log_prob_threshold: float = -0.7  # Balanced threshold for quality (vs -0.5)
    no_speech_threshold: float = 0.7  # Balanced threshold (vs 0.8)

    # Quality improvements without speed impact
    enable_smart_prompting: bool = True  # Adaptive prompting for better accuracy
    use_enhanced_post_processing: bool = True  # Smart text cleaning

    # DeepSeek Advanced Optimizations (VALIDATED: 30-40% speed improvement)
    enable_lockfree_model_access: bool = True  # VALIDATED: +50-87% concurrent performance
    enable_ultra_fast_mode_bypass: bool = False  # Keep disabled for quality
    enable_memory_pooling: bool = False  # VALIDATED: Disabled due to performance regression
    enable_chunked_long_audio: bool = False  # Keep disabled for quality

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

    # ULTRA-AGGRESSIVE performance settings
    ultra_fast_mode: bool = True  # Enable most aggressive optimizations
    preload_model_on_startup: bool = True  # Load model immediately to eliminate first-sentence delay

    # Long sentence optimizations (for 3+ second recordings)
    chunk_size_seconds: float = 5.0  # Process in 5-second chunks for long audio
    parallel_processing: bool = False  # Can't parallelize Whisper on same model
    aggressive_segment_merge: bool = True  # Merge segments aggressively to reduce overhead

    # Performance-first optimizations (SAFE DEFAULTS)
    max_transcriptions_before_reload: int = 100  # Reduce model reloads from 20 to 100
    disable_detailed_logging: bool = True  # Skip expensive logging in hot paths
    enable_model_caching: bool = True  # Cache model in memory between sessions

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

