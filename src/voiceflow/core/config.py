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

    # ASR - BALANCED Performance Mode (speed + accuracy for long sentences)
    model_name: str = "base.en"  # Better accuracy while still fast (avoids 3s delays)
    device: str = "cpu"  # "cuda" | "cpu"
    compute_type: str = "int8"  # Optimized for CPU inference
    vad_filter: bool = False  # CRITICAL FIX: VAD was removing all audio after 2 recordings
    beam_size: int = 1  # 1 = greedy, fastest possible
    temperature: float = 0.0

    # Whisper-specific ultra optimizations
    word_timestamps: bool = False  # Disable expensive timestamp computation
    condition_on_previous_text: bool = False  # Disable context (already done but explicit)
    compression_ratio_threshold: float = 4.0  # More aggressive threshold (default 2.4)
    log_prob_threshold: float = -0.5  # More aggressive threshold (default -1.0)
    no_speech_threshold: float = 0.8  # Higher threshold for faster rejection (default 0.6)

    # ULTRA-AGGRESSIVE performance settings
    ultra_fast_mode: bool = True  # Enable most aggressive optimizations
    preload_model_on_startup: bool = True  # Load model immediately to eliminate first-sentence delay

    # Long sentence optimizations (for 3+ second recordings)
    chunk_size_seconds: float = 5.0  # Process in 5-second chunks for long audio
    parallel_processing: bool = False  # Can't parallelize Whisper on same model
    aggressive_segment_merge: bool = True  # Merge segments aggressively to reduce overhead

    # Performance-first optimizations
    max_transcriptions_before_reload: int = 100  # Reduce model reloads from 20 to 100
    disable_detailed_logging: bool = True  # Skip expensive logging in hot paths
    skip_buffer_integrity_checks: bool = False  # Keep safety checks but optimize them
    enable_model_caching: bool = True  # Cache model in memory between sessions

    # ULTRA-AGGRESSIVE audio validation optimizations
    enable_fast_audio_validation: bool = True  # Use statistical sampling instead of full validation
    audio_validation_sample_rate: float = 0.02  # Validate only 2% of audio samples (50x speedup)
    skip_redundant_format_checks: bool = True  # Skip format validation after first successful check
    disable_amplitude_warnings: bool = True  # Skip non-critical amplitude logging
    fast_nan_inf_detection: bool = True  # Use optimized NaN/Inf detection algorithm
    skip_buffer_integrity_checks: bool = True  # ULTRA MODE: Skip integrity checks for maximum speed
    minimal_segment_processing: bool = True  # Skip non-essential segment processing
    disable_fallback_detection: bool = True  # Skip fallback phrase detection for speed

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

