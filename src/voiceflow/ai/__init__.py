"""
VoiceFlow AI Enhancement Layer

Provides intelligent text processing using local LLMs:
- Course Correction: Cleans transcription errors and false starts
- Command Mode: Voice-controlled text editing
"""

from voiceflow.ai.course_corrector import CourseCorrector
from voiceflow.ai.command_mode import CommandMode
from voiceflow.ai.adaptive_memory import AdaptiveLearningManager

__all__ = ['CourseCorrector', 'CommandMode', 'AdaptiveLearningManager']
