from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Config:
    # Hotkey: toggle PTT on/off. We'll detect Ctrl+Shift+Space by default.
    hotkey_ctrl: bool = True
    hotkey_shift: bool = True
    hotkey_alt: bool = False
    hotkey_key: str = "space"  # primary key pressed along with modifiers

    # Audio
    sample_rate: int = 16000
    channels: int = 1
    blocksize: int = 1024  # frames per callback, ~64 ms at 16k

    # ASR
    model_name: str = "small.en"  # fast first run; switch to medium.en for accuracy
    device: str = "cuda"  # "cuda" | "cpu"
    compute_type: str = "float16"  # 4080 supports fp16 nicely
    vad_filter: bool = True
    beam_size: int = 1  # 1 = greedy, faster
    temperature: float = 0.0

    # Output behavior
    paste_injection: bool = True  # Use clipboard paste injection by default
    restore_clipboard: bool = True  # restore original clipboard after paste
    paste_shortcut: str = "ctrl+v"  # e.g., "ctrl+v" or "shift+insert"
    press_enter_after_paste: bool = False
    max_inject_chars: int = 4000  # safety limit to avoid huge payloads
    min_inject_interval_ms: int = 100  # simple rate limit to avoid spam
    type_if_len_le: int = 0  # if >0, use typing (not clipboard) for short texts
    press_enter_after_paste: bool = False

    # Misc
    language: str | None = "en"
    verbose: bool = True
    code_mode_default: bool = True
    code_mode_lowercase: bool = True
    use_tray: bool = True
