"""
VoiceFlow Hallucination Detection System

Advanced detection and filtering of Whisper model hallucinations.
Specifically addresses the "okay okay okay" repetition pattern issue.
"""

import re
import string
import logging
from typing import Optional
from .models import StabilityConfig
from .logging_config import setup_stability_logging

logger = setup_stability_logging()

class HallucinationDetector:
    """
    Advanced hallucination detection and filtering system.

    Implements IHallucinationDetector interface for comprehensive
    detection of Whisper model hallucinations and artifacts.
    """

    def __init__(self, config: Optional[StabilityConfig] = None):
        """
        Initialize hallucination detector.

        Args:
            config: Stability configuration (uses defaults if None)
        """
        self.config = config or StabilityConfig()

        # Specific hallucination patterns (based on user's exact issue)
        self.hallucination_patterns = [
            # CRITICAL: "okay okay okay" spam patterns (user's exact issue)
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

        # Quality thresholds
        self.min_coherence_ratio = 0.3
        self.max_repetition_ratio = 0.6

    def detect_okay_hallucination(self, text: str) -> bool:
        """
        Detect the specific 'okay okay okay' Whisper hallucination pattern.

        This is the exact pattern the user reported: "okay. okay. okay. okay..."
        Happens when Whisper gets background noise and condition_on_previous_text
        creates a repetition loop.

        Args:
            text: Transcription text to analyze

        Returns:
            True if text appears to be the hallucination pattern
        """
        if not text or len(text) < 10:
            return False

        # Normalize text for analysis
        normalized = text.lower().strip()

        # Remove punctuation and extra spaces
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

    def detect_repetitive_patterns(self, text: str) -> bool:
        """
        Detect general repetitive patterns in transcription.

        Args:
            text: Text to analyze for repetitive patterns

        Returns:
            True if repetitive patterns detected
        """
        if not text or len(text) < 20:
            return False

        normalized = text.lower().strip()
        words = normalized.split()

        if len(words) < 5:
            return False

        # Check for word repetition
        word_counts = {}
        for word in words:
            word_counts[word] = word_counts.get(word, 0) + 1

        # Calculate repetition ratio
        max_count = max(word_counts.values())
        repetition_ratio = max_count / len(words)

        if repetition_ratio > self.max_repetition_ratio:
            logger.info(f"High repetition ratio detected: {repetition_ratio:.2f}")
            return True

        # Check for sequential repetition patterns
        for i in range(len(words) - 4):
            # Check if next 4 words are the same
            if words[i] == words[i+1] == words[i+2] == words[i+3]:
                logger.info(f"Sequential repetition detected: '{words[i]}' repeated 4+ times")
                return True

        # Check for phrase repetition
        for phrase_len in range(2, 5):
            if len(words) < phrase_len * 3:
                continue

            for i in range(len(words) - phrase_len * 3):
                phrase1 = ' '.join(words[i:i+phrase_len])
                phrase2 = ' '.join(words[i+phrase_len:i+phrase_len*2])
                phrase3 = ' '.join(words[i+phrase_len*2:i+phrase_len*3])

                if phrase1 == phrase2 == phrase3:
                    logger.info(f"Phrase repetition detected: '{phrase1}' repeated 3+ times")
                    return True

        return False

    def clean_transcription(self, text: str) -> str:
        """
        Clean transcription output to remove hallucination artifacts.

        Args:
            text: Raw transcription text

        Returns:
            Cleaned text with hallucinations removed
        """
        if not text:
            return text

        original_text = text
        cleaned_text = text

        # Apply hallucination pattern removal
        for pattern, replacement in self.hallucination_patterns:
            cleaned_text = re.sub(pattern, replacement, cleaned_text)

        # Remove excessive repetitions
        cleaned_text = self._remove_excessive_repetitions(cleaned_text)

        # Clean up whitespace
        cleaned_text = re.sub(r'\s+', ' ', cleaned_text)
        cleaned_text = cleaned_text.strip()

        # If we removed too much, it was likely all garbage
        if len(cleaned_text) < len(original_text) * 0.1:  # Lost 90% of content
            logger.warning("Transcription appears to be mostly garbage, returning empty")
            return ""

        # Log if significant cleaning occurred
        if len(cleaned_text) < len(original_text) * 0.8:
            logger.info(f"Cleaned transcription: {len(original_text)} -> {len(cleaned_text)} chars")

        return cleaned_text

    def calculate_quality_score(self, text: str, audio_duration: float) -> float:
        """
        Calculate transcription quality score based on multiple factors.

        Args:
            text: Transcription text to analyze
            audio_duration: Duration of source audio in seconds

        Returns:
            Quality score between 0.0 and 1.0
        """
        if not text or audio_duration <= 0:
            return 0.0

        score = 1.0

        # Length-based scoring
        words = text.split()
        words_per_second = len(words) / audio_duration

        # Penalize extreme word rates (too fast or too slow)
        if words_per_second > 10:  # Too fast (likely artifacts)
            score *= 0.5
        elif words_per_second < 0.5:  # Too slow (likely padding)
            score *= 0.7

        # Repetition penalty
        if self.detect_repetitive_patterns(text):
            score *= 0.3

        # Hallucination penalty
        if self.detect_okay_hallucination(text):
            score *= 0.1  # Severe penalty for "okay" hallucinations

        # Coherence check
        coherence_score = self._calculate_coherence(text)
        score *= coherence_score

        # Ensure score stays in valid range
        return max(0.0, min(1.0, score))

    def _remove_excessive_repetitions(self, text: str) -> str:
        """
        Remove excessive word and phrase repetitions.

        Args:
            text: Text to clean

        Returns:
            Text with excessive repetitions removed
        """
        if not text:
            return text

        words = text.split()
        if len(words) < 2:
            return text

        cleaned_words = []
        prev_word = None
        repeat_count = 0
        max_word_repetitions = 3

        for word in words:
            if word.lower() == prev_word:
                repeat_count += 1
                if repeat_count < max_word_repetitions:
                    cleaned_words.append(word)
            else:
                cleaned_words.append(word)
                prev_word = word.lower()
                repeat_count = 0

        return ' '.join(cleaned_words)

    def _calculate_coherence(self, text: str) -> float:
        """
        Calculate text coherence score.

        Args:
            text: Text to analyze

        Returns:
            Coherence score between 0.0 and 1.0
        """
        if not text:
            return 0.0

        words = text.split()
        if len(words) < 3:
            return 0.5  # Neutral score for very short text

        # Calculate vocabulary diversity
        unique_words = set(word.lower() for word in words)
        diversity_ratio = len(unique_words) / len(words)

        # Calculate sentence structure score
        sentences = re.split(r'[.!?]+', text)
        valid_sentences = [s.strip() for s in sentences if len(s.strip()) > 3]

        if len(valid_sentences) == 0:
            sentence_score = 0.3
        else:
            avg_sentence_length = sum(len(s.split()) for s in valid_sentences) / len(valid_sentences)
            # Prefer moderate sentence lengths (5-15 words)
            if 5 <= avg_sentence_length <= 15:
                sentence_score = 1.0
            elif avg_sentence_length < 5:
                sentence_score = 0.7
            else:
                sentence_score = 0.8

        # Combine scores
        coherence_score = (diversity_ratio * 0.6) + (sentence_score * 0.4)

        return min(1.0, coherence_score)