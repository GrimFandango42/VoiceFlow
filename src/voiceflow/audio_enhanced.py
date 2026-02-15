"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.core.audio_enhanced
"""

from .core.audio_enhanced import EnhancedAudioRecorder, audio_validation_guard

__all__ = ["EnhancedAudioRecorder", "audio_validation_guard"]
