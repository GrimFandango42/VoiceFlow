"""
Smart Text Formatter with Pause-Based Formatting

Uses timing data from production ASR to format transcription text
with natural sentence breaks and punctuation based on speech pauses.
"""

import re
from typing import List, Optional
# Use new unified ASR engine
from voiceflow.core.asr_engine import TranscriptionResult, TranscriptionSegment

class SmartTextFormatter:
    """
    Intelligent text formatter that uses timing data to create
    natural sentence breaks and punctuation based on speech pauses.
    """

    def __init__(self):
        # Pause thresholds (in seconds)
        self.sentence_pause_threshold = 0.8   # Add period for pauses > 0.8s
        self.paragraph_pause_threshold = 2.0  # Add paragraph break for pauses > 2.0s
        self.comma_pause_threshold = 0.3      # Add comma for pauses > 0.3s

        # Word patterns that likely end sentences
        self.sentence_endings = {
            'period', 'question', 'exclamation', 'done', 'finished', 'complete',
            'end', 'stop', 'final', 'conclusion', 'summary', 'thanks', 'goodbye'
        }

        # Question indicators
        self.question_words = {
            'what', 'where', 'when', 'why', 'how', 'who', 'which', 'whom',
            'could', 'would', 'should', 'can', 'will', 'do', 'does', 'did',
            'is', 'are', 'was', 'were', 'have', 'has', 'had'
        }

    def format_with_pauses(self, result: TranscriptionResult) -> str:
        """
        Format transcription using timing data to add natural punctuation
        and breaks based on speech pauses.
        """
        if not result.segments:
            return ""

        formatted_parts = []

        for i, segment in enumerate(result.segments):
            # Clean and process segment text
            text = segment.text.strip()
            if not text:
                continue

            # Add punctuation based on content and timing
            text = self._add_smart_punctuation(text, segment, i == len(result.segments) - 1)

            # Determine spacing based on pause duration
            if i > 0:
                prev_segment = result.segments[i-1]
                pause_duration = segment.start - prev_segment.end

                if pause_duration > self.paragraph_pause_threshold:
                    # Long pause - paragraph break
                    formatted_parts.append("\n\n" + text)
                elif pause_duration > self.sentence_pause_threshold:
                    # Medium pause - sentence break
                    formatted_parts.append(" " + text)
                elif pause_duration > self.comma_pause_threshold:
                    # Short pause - comma or natural break
                    if not formatted_parts[-1].endswith(('.', '!', '?', ',')):
                        formatted_parts.append(", " + text)
                    else:
                        formatted_parts.append(" " + text)
                else:
                    # Very short pause - continue naturally
                    formatted_parts.append(" " + text)
            else:
                # First segment
                formatted_parts.append(text)

        # Join and clean up
        result_text = "".join(formatted_parts)
        return self._final_cleanup(result_text)

    def _add_smart_punctuation(self, text: str, segment: TranscriptionSegment, is_last: bool) -> str:
        """Add intelligent punctuation based on content and context."""
        text = text.strip()
        if not text:
            return text

        # Don't add punctuation if already present
        if text.endswith(('.', '!', '?', ',', ';', ':')):
            return text

        # Check for question patterns
        words = text.lower().split()
        if words and (words[0] in self.question_words or
                     any(word in text.lower() for word in ['?', 'huh', 'right'])):
            return text + "?"

        # Check for sentence ending patterns
        if any(word in words for word in self.sentence_endings):
            return text + "."

        # Add period to last segment if it seems complete
        if is_last and len(words) > 2:
            return text + "."

        return text

    def _final_cleanup(self, text: str) -> str:
        """Final cleanup and formatting."""
        # Fix spacing around punctuation
        text = re.sub(r'\s+([,.!?;:])', r'\1', text)

        # Fix multiple spaces
        text = re.sub(r'\s+', ' ', text)

        # Capitalize after sentence endings
        text = re.sub(r'([.!?])\s+([a-z])', lambda m: m.group(1) + ' ' + m.group(2).upper(), text)

        # Capitalize first word
        if text:
            text = text[0].upper() + text[1:] if len(text) > 1 else text.upper()

        # Clean up paragraph breaks
        text = re.sub(r'\n\n+', '\n\n', text)
        text = text.strip()

        return text

    def format_simple_with_pauses(self, segments: List[TranscriptionSegment]) -> str:
        """
        Simplified formatter for when full result object isn't available.
        """
        if not segments:
            return ""

        # Create minimal result object
        from voiceflow.core.asr_engine import TranscriptionResult
        result = TranscriptionResult(
            segments=segments,
            language="en",
            duration=segments[-1].end if segments else 0.0,
            processing_time=0.0
        )

        return self.format_with_pauses(result)

    def get_summary_text(self, text: str, max_length: int = 50) -> str:
        """Get a truncated summary for notifications."""
        if len(text) <= max_length:
            return text

        # Try to break at sentence boundary
        sentences = text.split('.')
        if sentences and len(sentences[0]) <= max_length:
            return sentences[0].strip() + "."

        # Fall back to simple truncation with ellipsis
        return text[:max_length-3].strip() + "..."


# Global formatter instance
_formatter = None

def get_smart_formatter() -> SmartTextFormatter:
    """Get the global smart formatter instance."""
    global _formatter
    if _formatter is None:
        _formatter = SmartTextFormatter()
    return _formatter

def format_transcription_with_pauses(result: TranscriptionResult) -> str:
    """
    Convenience function to format transcription with pause-based formatting.
    """
    formatter = get_smart_formatter()
    return formatter.format_with_pauses(result)

def get_notification_summary(text: str, max_length: int = 50) -> str:
    """
    Convenience function to get notification-friendly summary.
    """
    formatter = get_smart_formatter()
    return formatter.get_summary_text(text, max_length)