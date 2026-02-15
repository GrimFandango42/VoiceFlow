"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.core.asr_engine
"""

from .core.asr_engine import ModernWhisperASR

# Historical class alias retained for compatibility.
BufferSafeWhisperASR = ModernWhisperASR

__all__ = ["BufferSafeWhisperASR"]
