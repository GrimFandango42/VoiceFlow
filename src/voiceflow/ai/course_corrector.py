"""
Course Correction for VoiceFlow

Intelligently cleans transcription output:
- Removes false starts ("no wait, actually...")
- Fixes common speech patterns
- Removes filler words
- Corrects obvious errors

Works with or without LLM - falls back to rule-based correction.
"""

import re
import logging
from typing import Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CorrectionResult:
    """Result of course correction"""
    text: str
    original: str
    was_corrected: bool
    used_llm: bool
    correction_type: str = ""


class CourseCorrector:
    """
    Intelligent course correction for voice transcription.

    Handles common speech patterns like:
    - "send to John, no wait, send to Jane" → "send to Jane"
    - "um, so, like, the thing is" → "the thing is"
    - "I want to to go" → "I want to go"
    """

    # Correction phrases that indicate user is changing their mind
    CORRECTION_PATTERNS = [
        r"\b(no|nope),?\s*(wait|actually|I mean|sorry|scratch that|never mind)",
        r"\b(actually|wait),?\s*(no|let me)",
        r"\bI mean\b",
        r"\bsorry,?\s*(I meant|let me)",
        r"\bscratch that\b",
        r"\blet me (start over|rephrase|try again)\b",
        r"\bwhat I meant (was|is)\b",
    ]

    # Filler words to remove
    FILLER_WORDS = [
        r"\b(um+|uh+|er+|ah+)\b",
        r"\b(like,?\s+){2,}",  # Multiple "like"s
        r"\b(so,?\s+){2,}",    # Multiple "so"s
        r"\byou know,?\s*",
        r"\bI guess,?\s*",
        r"\bkind of\s+like\b",
        r"\bsort of\s+like\b",
    ]

    # Word repetitions
    REPETITION_PATTERNS = [
        r"\b(\w+)\s+\1\b",  # Single word repeated
        r"\b(the|a|an|to|I|is|it)\s+\1\b",  # Common word doubled
    ]

    def __init__(
        self,
        use_llm: bool = True,
        llm_model: Optional[str] = None,
        llm_timeout: float = 5.0,
    ):
        """
        Initialize course corrector.

        Args:
            use_llm: Whether to use LLM for advanced correction
            llm_model: Specific Ollama model to use
            llm_timeout: Timeout for LLM requests (keep short for responsiveness)
        """
        self.use_llm = use_llm
        self.llm_model = llm_model
        self.llm_timeout = llm_timeout
        self._llm_client = None
        self._llm_available = None

        # Compile patterns for speed
        self._correction_re = [re.compile(p, re.IGNORECASE) for p in self.CORRECTION_PATTERNS]
        self._filler_re = [re.compile(p, re.IGNORECASE) for p in self.FILLER_WORDS]
        self._repetition_re = [re.compile(p, re.IGNORECASE) for p in self.REPETITION_PATTERNS]

    def _get_llm_client(self):
        """Lazy load LLM client"""
        if self._llm_client is None and self.use_llm:
            try:
                from voiceflow.ai.llm_client import OllamaClient
                self._llm_client = OllamaClient(
                    model=self.llm_model or "qwen2.5-coder:7b",
                    timeout=self.llm_timeout,
                )
                self._llm_available = self._llm_client.is_available()
            except Exception as e:
                logger.warning(f"Failed to initialize LLM client: {e}")
                self._llm_available = False

        return self._llm_client if self._llm_available else None

    def correct(self, text: str) -> CorrectionResult:
        """
        Apply course correction to transcribed text.

        Args:
            text: Raw transcription text

        Returns:
            CorrectionResult with corrected text
        """
        if not text or not text.strip():
            return CorrectionResult(
                text="",
                original=text,
                was_corrected=False,
                used_llm=False,
            )

        original = text
        text = text.strip()

        # Check if correction is needed
        needs_correction = self._needs_correction(text)

        if not needs_correction:
            return CorrectionResult(
                text=text,
                original=original,
                was_corrected=False,
                used_llm=False,
            )

        # Try LLM correction first (if available and text is complex)
        if self.use_llm and self._has_correction_phrase(text):
            llm_result = self._llm_correct(text)
            if llm_result:
                return CorrectionResult(
                    text=llm_result,
                    original=original,
                    was_corrected=True,
                    used_llm=True,
                    correction_type="llm",
                )

        # Fall back to rule-based correction
        corrected = self._rule_based_correct(text)

        return CorrectionResult(
            text=corrected,
            original=original,
            was_corrected=corrected != text,
            used_llm=False,
            correction_type="rules",
        )

    def _needs_correction(self, text: str) -> bool:
        """Check if text needs any correction"""
        # Check for correction phrases
        if self._has_correction_phrase(text):
            return True

        # Check for filler words
        for pattern in self._filler_re:
            if pattern.search(text):
                return True

        # Check for repetitions
        for pattern in self._repetition_re:
            if pattern.search(text):
                return True

        return False

    def _has_correction_phrase(self, text: str) -> bool:
        """Check if text contains a self-correction phrase"""
        for pattern in self._correction_re:
            if pattern.search(text):
                return True
        return False

    def _llm_correct(self, text: str) -> Optional[str]:
        """Use LLM for intelligent correction"""
        client = self._get_llm_client()
        if not client:
            return None

        try:
            system_prompt = """You are a transcription cleaner. Your job is to:
1. Remove false starts and self-corrections (keep only the final intended meaning)
2. Remove filler words (um, uh, like, you know)
3. Fix obvious word repetitions
4. Keep the original meaning and tone

Output ONLY the cleaned text, nothing else. Do not add quotes or explanations."""

            prompt = f"Clean this transcription:\n\n{text}"

            response = client.generate(
                prompt=prompt,
                system=system_prompt,
                temperature=0.0,
                max_tokens=len(text) + 50,
            )

            if response.success and response.text:
                # Validate result is reasonable
                result = response.text.strip()

                # Remove quotes if LLM added them
                if result.startswith('"') and result.endswith('"'):
                    result = result[1:-1]

                # Sanity check: result shouldn't be empty or way longer
                if result and len(result) <= len(text) * 1.5:
                    logger.debug(f"LLM correction: '{text}' -> '{result}'")
                    return result

        except Exception as e:
            logger.warning(f"LLM correction failed: {e}")

        return None

    def _rule_based_correct(self, text: str) -> str:
        """Apply rule-based corrections"""
        result = text

        # Handle self-corrections: keep text after correction phrase
        for pattern in self._correction_re:
            match = pattern.search(result)
            if match:
                # Keep text after the correction phrase
                after = result[match.end():].strip()
                if after:
                    # Also check if there's meaningful content before
                    before = result[:match.start()].strip()
                    # If the correction is in the middle, keep what comes after
                    if after and len(after) > 3:
                        result = after
                        break

        # Remove filler words
        for pattern in self._filler_re:
            result = pattern.sub(" ", result)

        # Fix word repetitions
        for pattern in self._repetition_re:
            result = pattern.sub(r"\1", result)

        # Clean up extra whitespace
        result = re.sub(r'\s+', ' ', result).strip()

        # Capitalize first letter
        if result:
            result = result[0].upper() + result[1:]

        return result


# Global instance for easy access
_corrector: Optional[CourseCorrector] = None


def get_course_corrector(use_llm: bool = True) -> CourseCorrector:
    """Get or create global course corrector instance"""
    global _corrector

    if _corrector is None:
        _corrector = CourseCorrector(use_llm=use_llm)

    return _corrector


def correct_transcription(text: str) -> str:
    """
    Convenience function to correct transcription text.

    Args:
        text: Raw transcription

    Returns:
        Corrected text
    """
    corrector = get_course_corrector()
    result = corrector.correct(text)
    return result.text
