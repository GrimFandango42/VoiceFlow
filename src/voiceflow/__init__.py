"""VoiceFlow - AI Voice Transcription System.

A modern voice-to-text application with real-time processing,
visual feedback, and system integration.
"""

__version__ = "2.0.0"
__author__ = "VoiceFlow Team"
__email__ = "support@voiceflow.dev"

from .core.config import Config
from .ui.tray import TrayController
from .ui.enhanced_tray import EnhancedTrayController

__all__ = [
    "Config",
    "TrayController",
    "EnhancedTrayController",
]
