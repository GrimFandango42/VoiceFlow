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

    # ASR - Performance Optimized
    model_name: str = "tiny.en"  # 4x faster than base.en for speed-first optimization
    device: str = "cpu"  # "cuda" | "cpu"
    compute_type: str = "int8"  # Optimized for CPU inference
    vad_filter: bool = False  # CRITICAL FIX: VAD was removing all audio after 2 recordings
    beam_size: int = 1  # 1 = greedy, fastest possible
    temperature: float = 0.0

    # Performance-first optimizations
    max_transcriptions_before_reload: int = 100  # Reduce model reloads from 20 to 100
    disable_detailed_logging: bool = True  # Skip expensive logging in hot paths
    skip_buffer_integrity_checks: bool = False  # Keep safety checks but optimize them
    enable_model_caching: bool = True  # Cache model in memory between sessions

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

