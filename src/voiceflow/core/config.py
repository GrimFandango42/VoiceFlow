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
    live_caption_words: int = 8  # Display the latest N words in live caption overlay
    live_caption_max_chars: int = 150  # Keep live caption compact while allowing richer context
    live_caption_font_size: int = 14  # Smaller caption font so more words fit below waveform
    live_caption_correction_window_seconds: float = 2.0  # Keep corrected words visually highlighted briefly
    live_caption_start_delay_seconds: float = 0.6  # Start preview quickly without immediate startup contention
    live_flush_during_hold: bool = False  # Keep target-app injection on release only (more stable)
    live_checkpoint_enabled: bool = True  # Show interim transcript checkpoints during long dictation
    live_checkpoint_seconds: float = 10.0  # Emit a checkpoint preview every N seconds while recording
    live_checkpoint_min_audio_seconds: float = 6.0  # Minimum chunk duration for a checkpoint pass
    live_checkpoint_preview_chars: int = 380  # Show more running transcript context while speaking
    live_checkpoint_inject: bool = False  # Keep checkpoint injection off by default for hold stability
    enable_pause_compaction: bool = True  # Trim long silent spans before ASR for faster long dictation
    pause_compaction_min_audio_seconds: float = 7.0  # compact pauses earlier for medium/long dictations
    pause_compaction_frame_ms: int = 30  # frame size for pause detection
    pause_compaction_keep_silence_ms: int = 80  # tighter silence retention for better medium/long latency
    pause_compaction_max_reduction_pct: float = 82.0  # allow stronger dead-air removal in long conversations
    pause_compaction_retry_on_short_output: bool = True  # Retry raw audio when compaction result looks clipped
    pause_compaction_retry_min_reduction_pct: float = 38.0  # Trigger raw retry only after heavy compaction
    pause_compaction_retry_max_words: int = 8  # Treat very short result as likely clipped output
    pause_compaction_retry_min_raw_audio_seconds: float = 4.0  # Only retry for medium/long dictation
    pause_compaction_retry_max_raw_audio_seconds: float = 20.0  # Avoid expensive second-pass decode on very long clips
    pause_compaction_retry_hard_max_raw_audio_seconds: float = 75.0  # Allow long-clip retry only when output looks clearly sparse
    pause_compaction_retry_chunked_long_enabled: bool = True  # Use bounded chunked raw retry beyond hard max
    pause_compaction_retry_chunked_max_raw_audio_seconds: float = 210.0  # Upper bound for chunked long-clip retries
    pause_compaction_retry_chunk_seconds: float = 32.0  # Chunk size for bounded long-clip raw retry
    pause_compaction_retry_chunk_overlap_seconds: float = 0.35  # Overlap to reduce boundary word loss
    pause_compaction_retry_chunk_max_chunks: int = 8  # Hard cap for chunked retry cost
    pause_compaction_retry_fast_path_max_raw_audio_seconds: float = 18.0  # Keep retry on fast model for short-medium clips
    pause_compaction_retry_min_words_per_second: float = 1.15  # Trigger retry when transcript density is suspiciously low
    pause_compaction_retry_min_chars_per_second: float = 5.0  # Pair with words/sec to avoid false positives
    pause_compaction_engine_guard_enabled: bool = True  # Use raw duration for model routing when compaction is aggressive
    pause_compaction_engine_guard_min_reduction_pct: float = 45.0  # Minimum compaction reduction before routing guard applies
    pause_compaction_engine_guard_min_raw_audio_seconds: float = 6.0  # Ignore tiny utterances for routing guard
    idle_resume_guard_enabled: bool = True  # Apply safer first-pass policy after long idle gaps
    idle_resume_threshold_seconds: float = 1200.0  # Idle gap that activates resume guardrails
    idle_resume_compaction_keep_silence_ms: int = 140  # Preserve more phrase boundaries after long idle
    idle_resume_compaction_max_reduction_pct: float = 68.0  # Limit aggressive compaction after long idle
    idle_resume_force_primary_model: bool = True  # Force primary ASR path on first long-idle utterance
    idle_resume_force_primary_min_audio_seconds: float = 1.8  # Skip fast path when resume utterance is sustained
    idle_resume_warmup_enabled: bool = True  # Warm ASR runtime once before first long-idle decode
    idle_resume_warmup_audio_seconds: float = 0.45  # Warmup clip duration for idle-resume guardrail
    idle_resume_skip_pause_compaction: bool = True  # Favor completeness over latency on the first long post-idle utterance
    idle_resume_skip_pause_compaction_min_audio_seconds: float = 18.0  # Only bypass compaction when the first post-idle clip is meaningfully long
    idle_resume_retry_on_compaction: bool = True  # Retry raw audio on the first post-idle decode when compaction was aggressive
    idle_resume_retry_min_reduction_pct: float = 55.0  # Treat heavy post-idle compaction as suspicious sooner than general retry logic
    idle_resume_retry_min_raw_audio_seconds: float = 12.0  # Only apply the post-idle raw retry bias to meaningful dictation
    enable_non_speech_guard: bool = True  # Reject likely sneeze/cough/throat-clear bursts before ASR
    non_speech_guard_soft_mode: bool = True  # Prefer salvage/retry over hard drop on suspected bursts
    non_speech_max_audio_seconds: float = 1.25  # Only run non-speech filter on short clips
    non_speech_min_peak: float = 0.16  # Minimum peak for impulsive-noise consideration
    non_speech_min_crest_factor: float = 9.0  # Peak/RMS threshold for transient noise
    non_speech_max_voiced_ratio: float = 0.24  # Upper bound of voiced-frame ratio for non-speech
    non_speech_max_voiced_run_seconds: float = 0.16  # Upper bound for sustained voiced run in burst detection
    non_speech_speech_hint_min_voiced_seconds: float = 0.20  # Keep clip when sustained voicing suggests real speech
    non_speech_speech_hint_min_voiced_ratio: float = 0.20  # Keep clip when voiced frame ratio suggests speech
    non_speech_min_flatness: float = 0.50  # Spectral flatness threshold for broadband noise
    non_speech_min_zcr: float = 0.10  # Zero-crossing threshold for noisy bursts

    # ASR - Hardware-appropriate configuration (Constitutional Principle: optimize for available hardware)
    # Model tier selection (VoiceFlow 3.0): "tiny", "quick", "balanced", "quality", "voxtral"
    # - tiny: Fastest, lowest accuracy (tiny.en) - good for testing
    # - quick: Adaptive quick tier (small.en on CPU, distil-large-v3 on CUDA)
    # - balanced: Distil-Large-v3.5, best speed/quality ratio (March 2025)
    # - quality: Large-v3, highest accuracy, slower
    # - voxtral: Voxtral-3B (Mistral AI), beats Whisper benchmarks
    model_tier: str = "quick"  # Default to adaptive quick tier
    model_name: str = "distil-large-v3"  # Used when tier is not set; tier routing is preferred
    device: str = "auto"   # Prefer CUDA when available, otherwise use CPU
    compute_type: str = "int8"    # int8 for CPU, float16 for GPU
    cpu_threads: int = 0  # 0 = auto-tune based on available CPU cores
    asr_num_workers: int = 1  # Keep 1 for predictable latency with a single active dictation
    fallback_device: str = "cpu"  # Fallback if GPU unavailable
    fallback_compute_type: str = "int8"  # CPU fallback settings
    vad_filter: bool = False  # Built-in VAD disabled (using custom VAD in ModernWhisperASR)
    beam_size: int = 1  # Greedy decoding for speed
    streaming_beam_size: int = 2  # Beam search for streaming preview (trades ~20ms for better accuracy)
    streaming_partial_max_audio_seconds: float = 8.0  # Context window for streaming preview (longer = more context, more compute)
    streaming_vad_filter: bool = True  # Enable Silero VAD for streaming to skip silence frames
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
    latency_boost_tiny_max_audio_seconds: float = 3.0  # Hard cap for tiny tier to protect recognition quality

    # Quality improvements without speed impact
    enable_smart_prompting: bool = True  # Adaptive prompting for better accuracy
    use_enhanced_post_processing: bool = True  # Smart text cleaning
    enable_light_typo_correction: bool = True  # Low-latency typo/spelling cleanup before injection
    enable_safe_second_pass_cleanup: bool = True  # Deterministic low-cost cleanup after main formatting
    enable_heavy_second_pass_cleanup: bool = False  # Optional stronger cleanup; keep opt-in
    heavy_second_pass_min_chars: int = 180  # Run heavy pass only for longer transcript payloads
    enable_aggressive_context_corrections: bool = False  # Keep high-risk phrase rewrites opt-in
    destination_aware_formatting: bool = True  # Adjust output layout by destination app/window
    destination_wrap_enabled: bool = True  # Wrap long output for target window width
    destination_default_chars: int = 84  # Slightly wider default wrapping for compact output
    destination_terminal_chars: int = 104  # Wider terminal columns
    destination_chat_chars: int = 68  # Keep chat readable while reducing over-wrapping
    destination_editor_chars: int = 94  # Comfortable width for editors/docs

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

    # Audio preprocessing pipeline (applied before ASR)
    audio_preprocessing_enabled: bool = True   # Master switch for the preprocessing pipeline
    audio_highpass_enabled: bool = True         # High-pass filter to remove HVAC/rumble noise
    audio_highpass_cutoff_hz: float = 80.0      # Cutoff frequency in Hz (speech starts ~85 Hz)
    audio_normalize_enabled: bool = True        # RMS normalization for consistent input levels
    audio_normalize_target_rms: float = 0.1     # Target RMS level (0–1 scale)
    audio_normalize_max_gain: float = 10.0      # Max amplification factor (20 dB) to protect silence
    audio_noise_gate_enabled: bool = False      # Noise gate: suppress frames below energy threshold
    audio_noise_gate_threshold: float = 0.005  # RMS below which a frame is gated to silence
    audio_noise_gate_frame_ms: float = 20.0     # Analysis frame size for noise gate in milliseconds


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
    setup_completed: bool = False  # first-run setup gate for visual defaults wizard
    show_setup_on_startup: bool = True  # allow users to re-open setup automatically on launch
    setup_profile: str = "recommended"  # last selected setup profile
    setup_flow_version: int = 3  # prompt setup once when onboarding flow is upgraded

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
    # Visual Indicators Configuration
    visual_indicators_enabled: bool = True  # Enable visual feedback when recording
    enable_visual_demo: bool = True  # Enable visual demo feature
    visual_overlay_enabled: bool = True  # Bottom-screen overlay indicators
    visual_dock_enabled: bool = True  # Keep dock visible by default for immediate feedback
    visual_animation_quality: str = "auto"  # auto|high|balanced|low
    visual_reduced_motion: bool = False  # reduce expensive animation effects
    visual_target_fps: int = 28  # preferred animation refresh target for auto mode

    # Output behavior
    paste_injection: bool = True  # Use clipboard paste injection by default
    restore_clipboard: bool = True  # restore original clipboard after paste
    clipboard_restore_delay_ms: int = 150  # wait before restoring clipboard to avoid paste race
    clipboard_restore_retry_attempts: int = 10  # immediate restore retries when clipboard is busy
    clipboard_restore_retry_base_delay_ms: int = 30  # base delay between clipboard restore retries
    clipboard_restore_async_retry_seconds: float = 8.0  # bounded background retry window on restore failure
    paste_shortcut: str = "ctrl+v"  # e.g., "ctrl+v" or "shift+insert"
    press_enter_after_paste: bool = False
    max_inject_chars: int = 4000  # safety limit to avoid huge payloads
    min_inject_interval_ms: int = 100  # simple rate limit to avoid spam
    type_if_len_le: int = 0  # if >0, use typing (not clipboard) for short texts
    inject_require_target_focus: bool = True  # prevent typing into unintended foreground windows
    inject_refocus_on_miss: bool = True  # try to restore captured target before final injection
    inject_refocus_attempts: int = 3  # bounded retries for transient popup/focus steals
    inject_refocus_delay_ms: int = 90  # short settle time between refocus attempts

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
    adaptive_store_raw_text: bool = False  # Keep short local snippets only when explicitly enabled
    adaptive_retention_hours: int = 72  # Auto-purge learning and audit records
    adaptive_min_count: int = 3  # Repetition count required before auto-apply
    adaptive_user_correction_min_count: int = 2  # Lower threshold for user-driven corrections
    adaptive_max_rules: int = 200  # Cap learned replacements to bound memory
    adaptive_max_phrase_tokens: int = 4  # Allow short phrase learning, not just single-token swaps
    adaptive_snippet_chars: int = 200  # Max raw snippet chars stored per event
    adaptive_ai_analysis_enabled: bool = True  # Use local LLM during daily learning to suggest higher-level learning changes
    adaptive_ai_analysis_max_items: int = 8  # Bound history/correction samples sent to the local LLM
    adaptive_ai_analysis_max_suggestions: int = 8  # Bound AI-proposed phrase/protected-term suggestions
    longrun_housekeeping_enabled: bool = True  # periodic long-run health telemetry and cleanup hooks
    longrun_health_log_interval_seconds: float = 900.0  # periodic memory/queue health snapshot cadence
    longrun_soft_gc_memory_mb: float = 0.0  # 0 = use adaptive threshold derived from current runtime profile
    daily_learning_autorun_enabled: bool = True  # Startup catch-up in case scheduled task is missing
    daily_learning_autorun_days_back: int = 1  # Process prior-day data by default
    daily_learning_autorun_startup_delay_seconds: float = 22.0  # Delay to avoid startup contention
    daily_learning_task_name: str = "VoiceFlow-DailyLearning"  # Windows scheduled task name
    daily_learning_max_history_items: int = 400  # Bound startup catch-up workload
    daily_learning_max_correction_items: int = 400  # Bound startup catch-up workload

    # Misc
    language: str | None = "en"
    verbose: bool = True
    code_mode_default: bool = True
    code_mode_lowercase: bool = True
    use_tray: bool = True

    def __post_init__(self):
        """CRITICAL GUARDRAIL: Validate configuration after initialization.

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

    def validate(self) -> Config:
        """Manually validate the configuration.

        Returns:
            Validated configuration object
        """
        from ..utils.guardrails import validate_config
        return validate_config(self)

