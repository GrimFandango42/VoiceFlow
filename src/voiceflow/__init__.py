"""VoiceFlow - AI Voice Transcription System.

A modern voice-to-text application with real-time processing,
visual feedback, and system integration.
"""

__version__ = "3.2.1"
__author__ = "VoiceFlow Team"
__email__ = "support@voiceflow.dev"

from .core.config import Config
from .ui.enhanced_tray import EnhancedTrayController
from .ui.tray import TrayController

__all__ = [
    "Config",
    "TrayController",
    "EnhancedTrayController",
]
