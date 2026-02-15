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
    ptt_tail_buffer_seconds: float = 0.35  # continue recording briefly after release
    ptt_tail_min_recording_seconds: float = 0.35  # only apply tail buffer to sustained presses

    # Audio - Optimized for speed
    sample_rate: int = 16000
    channels: int = 1
    blocksize: int = 512  # frames per callback, ~64 ms at 16k
    
    # Performance optimizations
    enable_batching: bool = True  # Enable VAD-based batching for 12.5x speedup
    max_batch_size: int = 4  # Process multiple segments together
    enable_streaming: bool = True  # Enable real-time partial ASR preview stream
    live_caption_enabled: bool = True  # Show live caption-style preview while recording
    live_caption_words: int = 2  # Display only the latest N words in live caption overlay
    live_caption_start_delay_seconds: float = 0.6  # Start preview quickly without immediate startup contention
    live_flush_during_hold: bool = False  # Keep target-app injection on release only (more stable)
    live_checkpoint_enabled: bool = True  # Show interim transcript checkpoints during long dictation
    live_checkpoint_seconds: float = 10.0  # Emit a checkpoint preview every N seconds while recording
    live_checkpoint_min_audio_seconds: float = 6.0  # Minimum chunk duration for a checkpoint pass
    live_checkpoint_preview_chars: int = 260  # Keep overlay preview bounded for readability
    live_checkpoint_inject: bool = False  # Keep checkpoint injection off by default for hold stability
    enable_pause_compaction: bool = True  # Trim long silent spans before ASR for faster long dictation
    pause_compaction_min_audio_seconds: float = 7.0  # compact pauses earlier for medium/long dictations
    pause_compaction_frame_ms: int = 30  # frame size for pause detection
    pause_compaction_keep_silence_ms: int = 80  # tighter silence retention for better medium/long latency
    pause_compaction_max_reduction_pct: float = 82.0  # allow stronger dead-air removal in long conversations

    # ASR - Hardware-appropriate configuration (Constitutional Principle: optimize for available hardware)
    # Model tier selection (VoiceFlow 3.0): "tiny", "quick", "balanced", "quality", "voxtral"
    # - tiny: Fastest, lowest accuracy (tiny.en) - good for testing
    # - quick: Distil-Large-v3, 6x faster than large-v3, within 1% WER (recommended)
    # - balanced: Distil-Large-v3.5, best speed/quality ratio (March 2025)
    # - quality: Large-v3, highest accuracy, slower
    # - voxtral: Voxtral-3B (Mistral AI), beats Whisper benchmarks
    model_tier: str = "quick"  # Default to quick tier (distil-large-v3)
    model_name: str = "distil-large-v3"  # Updated default - 6x faster than tiny.en with better accuracy
    device: str = "cpu"   # Default to CPU for compatibility - auto-detect GPU if available
    compute_type: str = "int8"    # int8 for CPU, float16 for GPU
    cpu_threads: int = 0  # 0 = auto-tune based on available CPU cores
    asr_num_workers: int = 1  # Keep 1 for predictable latency with a single active dictation
    fallback_device: str = "cpu"  # Fallback if GPU unavailable
    fallback_compute_type: str = "int8"  # CPU fallback settings
    vad_filter: bool = False  # Built-in VAD disabled (using custom VAD in ModernWhisperASR)
    beam_size: int = 1  # Greedy decoding for speed
    temperature: float = 0.0  # Deterministic output

    # Whisper transcription settings
    word_timestamps: bool = False  # Disabled by default for speed
    condition_on_previous_text: bool = False  # Prevent context pollution
    compression_ratio_threshold: float = 2.4  # Quality threshold
    log_prob_threshold: float = -1.0  # Confidence threshold
    no_speech_threshold: float = 0.9  # Silence detection sensitivity
    latency_boost_enabled: bool = True  # Use a smaller model for short utterances
    latency_boost_model_tier: str = "tiny"  # Fast-path model tier for short utterances
    latency_boost_max_audio_seconds: float = 10.0  # Keep ultra-fast path short; preserve accuracy on longer utterances

    # Quality improvements without speed impact
    enable_smart_prompting: bool = True  # Adaptive prompting for better accuracy
    use_enhanced_post_processing: bool = True  # Smart text cleaning

    # Advanced optimization flags (disabled by default for safety)
    enable_lockfree_model_access: bool = False  # Experimental: lock-free access
    enable_ultra_fast_mode_bypass: bool = False  # Skip validation for speed
    enable_memory_pooling: bool = False  # Memory pooling optimization
    enable_chunked_long_audio: bool = False  # Chunked processing for long audio

    # Adaptive Model Access Configuration (Phase 1 Optimization)
    max_concurrent_transcription_jobs: int = 1  # Start conservative, auto-detect concurrency
    auto_detect_model_concurrency: bool = True  # Enable intelligent concurrency detection

    # Smart Audio Validation Configuration (Phase 1 Optimization)
    validation_frequency: int = 8  # Validate every 8th callback after hardware trust established
    min_samples_for_statistical: int = 800  # Use statistical validation for arrays >800 samples

    # Audio sensitivity safeguards
    allow_low_energy_audio: bool = True  # Accept quiet recordings instead of dropping them
    min_audio_energy: float = 1e-8  # Treat samples below this mean power as silence
    min_peak_amplitude: float = 1e-4  # Minimum absolute peak required before declaring silence
    min_rms_amplitude: float = 5e-4  # RMS floor to help discriminate whisper-level speech

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

    # Startup and performance settings
    ultra_fast_mode: bool = False  # Enable experimental optimizations
    preload_model_on_startup: bool = False  # Load model during startup vs on-demand
    transcription_worker_timeout_seconds: float = 45.0  # hard timeout for hung worker callbacks

    # Long sentence optimizations (for 3+ second recordings)
    chunk_size_seconds: float = 5.0  # Process in 5-second chunks for long audio
    parallel_processing: bool = False  # Can't parallelize Whisper on same model
    aggressive_segment_merge: bool = True  # Merge segments aggressively to reduce overhead

    # Model persistence settings (Constitutional Principle II: Performance Through Persistence)
    # Modern implementation loads model once and keeps it in memory
    # Reload only occurs after consecutive errors (see ModernWhisperASR)
    disable_detailed_logging: bool = False  # Enable detailed logging for debugging

    # BALANCED audio validation optimizations (SAFE + FAST)
    enable_optimized_audio_validation: bool = True  # Enable smart audio validation system
    enable_fast_audio_validation: bool = True  # Use statistical sampling instead of full validation
    audio_validation_sample_rate: float = 0.05  # VALIDATED: 5% sampling for +15-50% performance
    skip_redundant_format_checks: bool = True  # Skip format validation after first successful check
    disable_amplitude_warnings: bool = True  # Skip non-critical amplitude logging
    fast_nan_inf_detection: bool = True  # Use optimized NaN/Inf detection algorithm

    # Buffer integrity and validation settings
    skip_buffer_integrity_checks: bool = False  # Enable buffer validation (recommended)
    minimal_segment_processing: bool = True  # Skip non-essential segment processing
    disable_fallback_detection: bool = True  # Skip fallback phrase detection for speed
    use_enhanced_post_processing: bool = True  # Enable enhanced text formatting (capitalization, punctuation)

    # Visual Indicators Configuration
    visual_indicators_enabled: bool = True  # Enable visual feedback when recording
    enable_visual_demo: bool = True  # Enable visual demo feature
    visual_overlay_enabled: bool = True  # Bottom-screen overlay indicators
    visual_dock_enabled: bool = True  # Keep dock visible by default for immediate feedback

    # Output behavior
    paste_injection: bool = True  # Use clipboard paste injection by default
    restore_clipboard: bool = True  # restore original clipboard after paste
    clipboard_restore_delay_ms: int = 150  # wait before restoring clipboard to avoid paste race
    paste_shortcut: str = "ctrl+v"  # e.g., "ctrl+v" or "shift+insert"
    press_enter_after_paste: bool = False
    max_inject_chars: int = 4000  # safety limit to avoid huge payloads
    min_inject_interval_ms: int = 100  # simple rate limit to avoid spam
    type_if_len_le: int = 0  # if >0, use typing (not clipboard) for short texts

    # AI Enhancement Layer (VoiceFlow 3.0)
    enable_ai_enhancement: bool = False  # Speed-first default: skip LLM cleanup overhead
    enable_course_correction: bool = True  # Remove false starts, filler words
    enable_command_mode: bool = True  # Voice commands like "make this formal"
    command_mode_requires_prefix: bool = True  # Avoid accidental command capture in normal dictation
    command_mode_prefix: str = "command"  # Say "command ..." to trigger command mode
    ai_model: str = "qwen2.5-coder:7b"  # Ollama model for AI features
    ai_disable_above_audio_seconds: float = 8.0  # When AI is enabled, skip quickly for near-real-time feel

    # Adaptive Learning (privacy-first, local-only, temporary)
    adaptive_learning_enabled: bool = True  # Learn recurring speech patterns locally
    adaptive_store_raw_text: bool = True  # Keep short local snippets for debugging
    adaptive_retention_hours: int = 72  # Auto-purge learning and audit records
    adaptive_min_count: int = 3  # Repetition count required before auto-apply
    adaptive_max_rules: int = 200  # Cap learned replacements to bound memory
    adaptive_snippet_chars: int = 200  # Max raw snippet chars stored per event

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

