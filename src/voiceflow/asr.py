"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.core.asr_engine
"""

from .core.asr_engine import ASREngine, ModernWhisperASR, TranscriptionResult

# Historical alias retained for compatibility.
WhisperASR = ModernWhisperASR

__all__ = ["ASREngine", "ModernWhisperASR", "TranscriptionResult", "WhisperASR"]
