"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.core.asr_engine
"""

from .asr import ASREngine, ModernWhisperASR, TranscriptionResult, WhisperASR

__all__ = ["ASREngine", "ModernWhisperASR", "TranscriptionResult", "WhisperASR"]
