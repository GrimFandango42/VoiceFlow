"""
Buffer Overflow Protection and Repetition Detection Guardrails

Prevents issues like:
- Garbage text at end of transcriptions
- Repetitive patterns from model hallucination
- Buffer corruption from overflow conditions
"""

import re
import logging
from typing import Optional, List, Tuple
import numpy as np

logger = logging.getLogger(__name__)


class BufferOverflowProtection:
    """Protection against buffer overflow and corruption issues"""

    def __init__(self):
        # Common garbage patterns that indicate buffer issues
        self.garbage_patterns = [
            r'[\x00-\x1f]+',  # Control characters
            r'[\x7f-\x9f]+',  # Extended control characters
            r'(.)\1{10,}',    # Same character repeated 10+ times
            r'(\b\w+\b)(?:\s+\1){5,}',  # Same word repeated 5+ times
            r'[^\x20-\x7e\u00a0-\u00ff]+',  # Non-printable ASCII
        ]

        # Whisper hallucination patterns
        self.hallucination_patterns = [
            # CRITICAL: "okay okay okay" spam patterns (your exact issue)
            (r'(?i)^(?:okay[.!]?\s*){2,}$', ''),  # "okay. okay. okay..."
            (r'(?i)^(?:ok[.!]?\s*){2,}$', ''),    # "ok. ok. ok..."
            (r'(?i)^(?:o\.?k\.?[.!]?\s*){2,}$', ''),  # "o.k. o.k. o.k..."

            # Other common hallucinations
            (r'(?i)^(?:thank you for watching[.!]?\s*){2,}', ''),
            (r'(?i)^(?:please subscribe and like[.!]?\s*){2,}', ''),
            (r'(?i)^(?:thanks for listening[.!]?\s*){2,}', ''),
            (r'(?i)(?:you you you\s*){3,}', ''),
            (r'(?i)(?:the the the\s*){3,}', ''),
            (r'(?i)(?:and and and\s*){3,}', ''),
            (r'\s*(?:\.{10,}|\!{10,}|\?{10,})', ''),  # Excessive punctuation
            (r'(\b\w{1,3}\b)(?:\s+\1){10,}', r'\1'),  # Short word spam
        ]

        # Maximum sane length for transcription (characters)
        self.max_transcription_length = 10000

        # Repetition thresholds
        self.max_word_repetitions = 5
        self.max_phrase_repetitions = 3

    def validate_audio_buffer(self, audio: np.ndarray) -> Tuple[bool, Optional[str]]:
        """
        Validate audio buffer for corruption before transcription

        Returns:
            (is_valid, error_message)
        """
        if audio is None:
            return False, "Audio buffer is None"

        if len(audio) == 0:
            return False, "Audio buffer is empty"

        # Check for NaN or infinite values
        if np.any(np.isnan(audio)):
            return False, "Audio buffer contains NaN values"

        if np.any(np.isinf(audio)):
            return False, "Audio buffer contains infinite values"

        # Check for extreme values that might indicate corruption
        max_val = np.max(np.abs(audio))
        if max_val > 100:  # Audio should be normalized to [-1, 1] range
            logger.warning(f"Audio buffer has extreme values: max={max_val}")
            # Don't reject but warn

        # Check for all zeros (dead buffer)
        if np.all(audio == 0):
            return False, "Audio buffer is all zeros (dead buffer)"

        # Check for repeating patterns that indicate corruption
        if len(audio) > 1000:
            # Sample check for repeating blocks
            chunk_size = 100
            first_chunk = audio[:chunk_size]

            # Check if the same chunk repeats throughout
            repeat_count = 0
            for i in range(chunk_size, min(len(audio), 1000), chunk_size):
                if np.array_equal(audio[i:i+chunk_size], first_chunk):
                    repeat_count += 1

            if repeat_count > 5:
                return False, f"Audio buffer has repeating pattern (corruption detected)"

        return True, None

    def clean_transcription(self, text: str) -> str:
        """
        Clean transcription output to remove garbage and hallucinations

        Args:
            text: Raw transcription text

        Returns:
            Cleaned text
        """
        if not text:
            return text

        original_text = text

        # Truncate if too long (likely corruption)
        if len(text) > self.max_transcription_length:
            logger.warning(f"Transcription truncated from {len(text)} to {self.max_transcription_length} chars")
            text = text[:self.max_transcription_length]

        # Remove garbage patterns
        for pattern in self.garbage_patterns:
            text = re.sub(pattern, '', text, flags=re.MULTILINE)

        # Remove hallucination patterns
        for pattern, replacement in self.hallucination_patterns:
            text = re.sub(pattern, replacement, text)

        # Remove excessive repetitions
        text = self._remove_repetitions(text)

        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()

        # If we removed too much, it was likely all garbage
        if len(text) < len(original_text) * 0.1:  # Lost 90% of content
            logger.warning("Transcription appears to be mostly garbage, returning empty")
            return ""

        # Log if significant cleaning occurred
        if len(text) < len(original_text) * 0.8:
            logger.info(f"Cleaned transcription: {len(original_text)} -> {len(text)} chars")

        return text

    def _remove_repetitions(self, text: str) -> str:
        """Remove excessive word and phrase repetitions"""
        if not text:
            return text

        words = text.split()
        if len(words) < 2:
            return text

        cleaned_words = []
        prev_word = None
        repeat_count = 0

        for word in words:
            if word == prev_word:
                repeat_count += 1
                if repeat_count < self.max_word_repetitions:
                    cleaned_words.append(word)
            else:
                cleaned_words.append(word)
                prev_word = word
                repeat_count = 0

        text = ' '.join(cleaned_words)

        # Check for phrase repetitions (3-5 word patterns)
        for phrase_len in range(3, 6):
            pattern = r'\b(' + r'\s+'.join([r'(\S+)'] * phrase_len) + r')\b'
            pattern += r'(?:\s+' + r'\s+'.join([r'\1'] * phrase_len) + r'){' + str(self.max_phrase_repetitions) + ',}'

            # Replace excessive phrase repetitions with single instance
            text = re.sub(pattern, r'\1', text, flags=re.IGNORECASE)

        return text

    def detect_trailing_garbage(self, text: str) -> str:
        """
        Detect and remove trailing garbage that often appears at the end

        Common patterns:
        - Sudden repetition at the end
        - Non-sensical characters
        - YouTube-style endings
        """
        if not text or len(text) < 50:
            return text

        # Split into sentences
        sentences = re.split(r'[.!?]+', text)
        if len(sentences) < 2:
            return text

        # Check last sentence for garbage patterns
        last_sentence = sentences[-1].strip()
        if not last_sentence:
            return text

        # Check if last sentence is repetitive garbage
        words_in_last = last_sentence.split()
        if len(words_in_last) > 3:
            # Check if it's mostly repetition of same word
            word_counts = {}
            for word in words_in_last:
                word_lower = word.lower()
                word_counts[word_lower] = word_counts.get(word_lower, 0) + 1

            max_count = max(word_counts.values())
            if max_count > len(words_in_last) * 0.5:  # More than 50% same word
                logger.info(f"Removing repetitive trailing sentence: {last_sentence[:50]}...")
                # Remove the last sentence
                return '.'.join(sentences[:-1]).strip() + '.'

        # CRITICAL: Special check for trailing "okay" repetitions
        # This catches cases like "okay okay okay" at the end of transcription
        normalized_last = last_sentence.lower().strip()
        # Remove punctuation for checking
        import string
        normalized_last_no_punct = normalized_last.translate(str.maketrans('', '', string.punctuation))
        words_normalized = normalized_last_no_punct.split()

        if len(words_normalized) >= 2:
            okay_variations = ['okay', 'ok', 'o k']
            okay_count = sum(1 for word in words_normalized if word in okay_variations)

            # If last sentence is mostly "okay" variations, remove it
            if okay_count >= 2 and okay_count >= len(words_normalized) * 0.5:
                logger.warning(f"Removing trailing 'okay' repetition: {last_sentence[:50]}...")
                cleaned = '.'.join(sentences[:-1]).strip()
                return cleaned + '.' if cleaned else ''

        # Check for common garbage endings
        garbage_endings = [
            r'thank you for watching',
            r'please subscribe',
            r'see you next time',
            r'bye bye bye',
            r'the end the end',
            r'\[music\]',
            r'\[applause\]',
        ]

        for pattern in garbage_endings:
            if re.search(pattern, last_sentence, re.IGNORECASE):
                logger.info(f"Removing garbage ending: {last_sentence[:50]}...")
                return '.'.join(sentences[:-1]).strip() + '.'

        return text

    def detect_okay_hallucination(self, text: str) -> bool:
        """
        Detect the specific 'okay okay okay' Whisper hallucination pattern

        This is the exact pattern the user reported: "okay. okay. okay. okay..."
        Happens when Whisper gets background noise and condition_on_previous_text
        creates a repetition loop.

        Returns:
            True if text appears to be the hallucination pattern
        """
        if not text or len(text) < 10:
            return False

        # Normalize text for analysis
        normalized = text.lower().strip()

        # Remove punctuation and extra spaces
        import string
        normalized = normalized.translate(str.maketrans('', '', string.punctuation))
        normalized = ' '.join(normalized.split())

        # Check for repetitive "okay" patterns
        words = normalized.split()
        if len(words) < 3:
            return False

        # Count "okay" and related variations
        okay_count = 0
        total_words = len(words)

        for word in words:
            if word in ['okay', 'ok', 'o k']:
                okay_count += 1

        # If more than 50% of words are "okay" variations, it's likely hallucination
        okay_ratio = okay_count / total_words

        if okay_ratio > 0.5 and okay_count >= 3:
            logger.warning(f"Detected 'okay' hallucination pattern: {okay_count}/{total_words} words are 'okay' variants")
            return True

        # Additional check for exact repetition patterns
        if len(set(words)) <= 2 and okay_count >= 3:
            logger.warning(f"Detected exact repetition hallucination: {normalized[:50]}...")
            return True

        return False


# Global instance for easy access
buffer_protector = BufferOverflowProtection()