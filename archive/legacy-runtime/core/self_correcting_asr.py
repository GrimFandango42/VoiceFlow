#!/usr/bin/env python3
"""
Self-Correcting ASR System
=========================
Monitors transcription quality and applies intelligent corrections.

Features:
- Context-aware error detection and correction
- Learning from user patterns and corrections
- Quality scoring and confidence analysis
- Adaptive improvement suggestions
"""

import logging
import re
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import deque, defaultdict
import json
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class TranscriptionQuality:
    """Quality metrics for a transcription"""
    confidence_score: float
    word_count: int
    avg_word_confidence: float
    has_hesitations: bool
    has_repetitions: bool
    grammar_score: float
    context_coherence: float
    overall_score: float

@dataclass
class CorrectionSuggestion:
    """A suggested correction for transcribed text"""
    original_text: str
    suggested_text: str
    confidence: float
    reason: str
    category: str  # grammar, context, common_error, etc.

@dataclass
class UserPattern:
    """Learning pattern from user behavior"""
    correction_pairs: List[Tuple[str, str]] = field(default_factory=list)
    common_words: Dict[str, int] = field(default_factory=dict)
    domain_vocabulary: Dict[str, int] = field(default_factory=dict)
    speaking_patterns: Dict[str, Any] = field(default_factory=dict)

class SelfCorrectingASR:
    """
    Self-correcting ASR system that learns and improves over time.
    """

    def __init__(self, base_asr, learning_data_path: Optional[str] = None):
        self.base_asr = base_asr
        self.learning_data_path = Path(learning_data_path or "voiceflow_learning.json")

        # Learning components
        self.user_patterns = UserPattern()
        self.recent_transcriptions = deque(maxlen=50)
        self.correction_history = deque(maxlen=100)

        # Quality thresholds
        self.min_confidence_threshold = 0.7
        self.grammar_threshold = 0.6
        self.coherence_threshold = 0.5

        # Common error patterns
        self.common_corrections = {
            # Technical terms
            r'\bAPI\b': 'API',
            r'\bGPU\b': 'GPU',
            r'\bCPU\b': 'CPU',
            r'\bHTTP\b': 'HTTP',
            r'\bJSON\b': 'JSON',
            r'\bSQL\b': 'SQL',
            r'\bHTML\b': 'HTML',
            r'\bCSS\b': 'CSS',

            # Programming terms
            r'\bpython\b': 'Python',
            r'\bjavascript\b': 'JavaScript',
            r'\btypescript\b': 'TypeScript',
            r'\breact\b': 'React',
            r'\bgithub\b': 'GitHub',

            # Common misheard words
            r'\btheir\b(?=\s+(?:is|are|was|were))': 'there',
            r'\bthere\b(?=\s+(?:car|house|dog|cat))': 'their',
            r'\byour\b(?=\s+welcome)': "you're",
            r'\bits\b(?=\s+(?:raining|sunny|cold))': "it's",
        }

        # Load existing learning data
        self._load_learning_data()

        logger.info("Self-correcting ASR initialized with learning capabilities")

    def transcribe(self, audio_data) -> 'TranscriptionResult':
        """Enhanced transcribe with quality analysis and correction"""
        # Get base transcription
        result = self.base_asr.transcribe(audio_data)

        if not result.segments:
            return result

        # Analyze quality
        quality = self._analyze_quality(result)

        # Apply corrections if needed
        if quality.overall_score < 0.8:
            corrected_result = self._apply_corrections(result, quality)

            # Track the correction for learning
            self._track_correction(result, corrected_result, quality)

            return corrected_result

        # Learn from high-quality transcriptions
        self._learn_from_transcription(result, quality)

        return result

    def _analyze_quality(self, result) -> TranscriptionQuality:
        """Analyze transcription quality across multiple dimensions"""
        text = " ".join(seg.text for seg in result.segments)

        # Basic metrics
        word_count = len(text.split())
        avg_confidence = sum(seg.confidence for seg in result.segments) / len(result.segments)

        # Detect hesitations (um, uh, er, etc.)
        hesitation_pattern = r'\b(um|uh|er|ah|like|you know)\b'
        has_hesitations = bool(re.search(hesitation_pattern, text.lower()))

        # Detect repetitions
        words = text.lower().split()
        repetitions = 0
        for i in range(len(words) - 1):
            if words[i] == words[i + 1]:
                repetitions += 1
        has_repetitions = repetitions > 0

        # Grammar scoring (simplified)
        grammar_score = self._score_grammar(text)

        # Context coherence with recent transcriptions
        context_coherence = self._score_coherence(text)

        # Calculate overall score
        confidence_weight = 0.3
        grammar_weight = 0.3
        coherence_weight = 0.2
        hesitation_penalty = 0.1 if has_hesitations else 0
        repetition_penalty = 0.1 if has_repetitions else 0

        overall_score = (
            avg_confidence * confidence_weight +
            grammar_score * grammar_weight +
            context_coherence * coherence_weight -
            hesitation_penalty -
            repetition_penalty
        )

        return TranscriptionQuality(
            confidence_score=avg_confidence,
            word_count=word_count,
            avg_word_confidence=avg_confidence,
            has_hesitations=has_hesitations,
            has_repetitions=has_repetitions,
            grammar_score=grammar_score,
            context_coherence=context_coherence,
            overall_score=max(0, min(1, overall_score))
        )

    def _score_grammar(self, text: str) -> float:
        """Simple grammar scoring based on basic rules"""
        score = 1.0

        # Check for basic sentence structure
        sentences = re.split(r'[.!?]+', text)
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue

            words = sentence.split()
            if len(words) < 2:
                score -= 0.1
                continue

            # First word should be capitalized (if sentence)
            if not words[0][0].isupper():
                score -= 0.05

            # Check for basic subject-verb patterns
            if not self._has_subject_verb_pattern(words):
                score -= 0.1

        return max(0, min(1, score))

    def _has_subject_verb_pattern(self, words: List[str]) -> bool:
        """Check if sentence has basic subject-verb pattern"""
        # Very simplified check for common patterns
        common_verbs = {'is', 'are', 'was', 'were', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'can', 'could', 'should'}

        for word in words:
            if word.lower() in common_verbs:
                return True

        # Check for words ending in common verb patterns
        for word in words:
            if word.lower().endswith(('ed', 'ing', 's')):
                return True

        return False

    def _score_coherence(self, text: str) -> float:
        """Score coherence with recent transcriptions"""
        if not self.recent_transcriptions:
            return 0.5  # Neutral score for first transcription

        current_words = set(text.lower().split())

        # Check overlap with recent transcriptions
        total_overlap = 0
        for recent_text in list(self.recent_transcriptions)[-5:]:  # Last 5 transcriptions
            recent_words = set(recent_text.lower().split())
            overlap = len(current_words.intersection(recent_words))
            total_overlap += overlap

        # Normalize by vocabulary size
        vocab_size = len(current_words)
        if vocab_size == 0:
            return 0

        coherence_score = min(1.0, total_overlap / (vocab_size * 2))
        return coherence_score

    def _apply_corrections(self, result, quality: TranscriptionQuality) -> 'TranscriptionResult':
        """Apply intelligent corrections to improve transcription"""
        from copy import deepcopy
        corrected_result = deepcopy(result)

        for i, segment in enumerate(corrected_result.segments):
            original_text = segment.text
            corrected_text = self._correct_text(original_text, quality)

            if corrected_text != original_text:
                segment.text = corrected_text
                logger.info(f"Applied correction: '{original_text}' -> '{corrected_text}'")

        return corrected_result

    def _correct_text(self, text: str, quality: TranscriptionQuality) -> str:
        """Apply various correction strategies"""
        corrected = text

        # Apply common correction patterns
        for pattern, replacement in self.common_corrections.items():
            corrected = re.sub(pattern, replacement, corrected, flags=re.IGNORECASE)

        # Apply learned corrections from user patterns
        for original, correction in self.user_patterns.correction_pairs:
            if original.lower() in corrected.lower():
                corrected = corrected.replace(original, correction)

        # Context-based corrections
        corrected = self._apply_context_corrections(corrected)

        # Grammar improvements
        if quality.grammar_score < self.grammar_threshold:
            corrected = self._apply_grammar_corrections(corrected)

        return corrected

    def _apply_context_corrections(self, text: str) -> str:
        """Apply corrections based on context and domain knowledge"""
        words = text.split()
        corrected_words = []

        for i, word in enumerate(words):
            corrected_word = word

            # Check if word is in domain vocabulary with higher frequency
            word_lower = word.lower()
            if word_lower in self.user_patterns.domain_vocabulary:
                # Find the most common capitalization
                if self.user_patterns.domain_vocabulary[word_lower] > 3:
                    # Use domain-specific capitalization
                    for domain_word in self.user_patterns.domain_vocabulary:
                        if domain_word.lower() == word_lower:
                            corrected_word = domain_word
                            break

            corrected_words.append(corrected_word)

        return " ".join(corrected_words)

    def _apply_grammar_corrections(self, text: str) -> str:
        """Apply basic grammar corrections"""
        # Capitalize first letter of sentences
        sentences = re.split(r'([.!?]+)', text)
        corrected_sentences = []

        for sentence in sentences:
            if sentence.strip() and not re.match(r'^[.!?]+$', sentence):
                words = sentence.strip().split()
                if words:
                    words[0] = words[0].capitalize()
                    corrected_sentences.append(' '.join(words))
                else:
                    corrected_sentences.append(sentence)
            else:
                corrected_sentences.append(sentence)

        return ''.join(corrected_sentences)

    def _track_correction(self, original_result, corrected_result, quality: TranscriptionQuality):
        """Track corrections for learning purposes"""
        original_text = " ".join(seg.text for seg in original_result.segments)
        corrected_text = " ".join(seg.text for seg in corrected_result.segments)

        if original_text != corrected_text:
            self.correction_history.append({
                'original': original_text,
                'corrected': corrected_text,
                'quality': quality,
                'timestamp': time.time()
            })

            # Learn from the correction
            self._learn_correction_pattern(original_text, corrected_text)

    def _learn_correction_pattern(self, original: str, corrected: str):
        """Learn from correction patterns"""
        # Find word-level differences
        original_words = original.split()
        corrected_words = corrected.split()

        if len(original_words) == len(corrected_words):
            for orig_word, corr_word in zip(original_words, corrected_words):
                if orig_word != corr_word:
                    # Add to correction patterns
                    self.user_patterns.correction_pairs.append((orig_word, corr_word))

                    # Limit size to prevent memory bloat
                    if len(self.user_patterns.correction_pairs) > 200:
                        self.user_patterns.correction_pairs.pop(0)

    def _learn_from_transcription(self, result, quality: TranscriptionQuality):
        """Learn from high-quality transcriptions"""
        text = " ".join(seg.text for seg in result.segments)

        # Add to recent transcriptions
        self.recent_transcriptions.append(text)

        # Update word frequency
        words = text.split()
        for word in words:
            self.user_patterns.common_words[word] = self.user_patterns.common_words.get(word, 0) + 1

            # Add to domain vocabulary if it appears frequently
            if self.user_patterns.common_words[word] > 2:
                self.user_patterns.domain_vocabulary[word] = self.user_patterns.common_words[word]

    def get_suggestions(self, text: str) -> List[CorrectionSuggestion]:
        """Get correction suggestions for given text"""
        suggestions = []

        # Check against common patterns
        for pattern, replacement in self.common_corrections.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                if match.group() != replacement:
                    suggestions.append(CorrectionSuggestion(
                        original_text=match.group(),
                        suggested_text=replacement,
                        confidence=0.8,
                        reason="Common technical term correction",
                        category="technical"
                    ))

        # Check against learned patterns
        for original, correction in self.user_patterns.correction_pairs[-20:]:  # Recent patterns
            if original.lower() in text.lower():
                suggestions.append(CorrectionSuggestion(
                    original_text=original,
                    suggested_text=correction,
                    confidence=0.9,
                    reason="Learned from previous corrections",
                    category="learned"
                ))

        return suggestions

    def get_quality_report(self) -> Dict[str, Any]:
        """Get a quality report for recent transcriptions"""
        if not self.correction_history:
            return {"status": "No corrections tracked yet"}

        recent_corrections = list(self.correction_history)[-20:]

        return {
            "total_corrections": len(self.correction_history),
            "recent_corrections": len(recent_corrections),
            "common_correction_patterns": self._get_common_patterns(),
            "vocabulary_size": len(self.user_patterns.domain_vocabulary),
            "learning_effectiveness": self._calculate_learning_effectiveness()
        }

    def _get_common_patterns(self) -> List[Dict[str, Any]]:
        """Get most common correction patterns"""
        pattern_counts = defaultdict(int)

        for correction in self.correction_history:
            pattern_counts[f"{correction['original']} -> {correction['corrected']}"] += 1

        return [
            {"pattern": pattern, "frequency": count}
            for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

    def _calculate_learning_effectiveness(self) -> float:
        """Calculate how well the system is learning"""
        if len(self.correction_history) < 10:
            return 0.0

        recent_corrections = list(self.correction_history)[-10:]
        older_corrections = list(self.correction_history)[-20:-10] if len(self.correction_history) >= 20 else []

        if not older_corrections:
            return 0.5

        # Check if recent corrections are improving (fewer needed)
        recent_avg_quality = sum(c['quality'].overall_score for c in recent_corrections) / len(recent_corrections)
        older_avg_quality = sum(c['quality'].overall_score for c in older_corrections) / len(older_corrections)

        improvement = (recent_avg_quality - older_avg_quality + 1) / 2  # Normalize to 0-1
        return max(0, min(1, improvement))

    def _save_learning_data(self):
        """Save learning data to disk"""
        try:
            data = {
                'correction_pairs': self.user_patterns.correction_pairs,
                'common_words': dict(self.user_patterns.common_words),
                'domain_vocabulary': dict(self.user_patterns.domain_vocabulary),
                'speaking_patterns': self.user_patterns.speaking_patterns,
                'timestamp': time.time()
            }

            with open(self.learning_data_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Learning data saved to {self.learning_data_path}")

        except Exception as e:
            logger.error(f"Failed to save learning data: {e}")

    def _load_learning_data(self):
        """Load learning data from disk"""
        try:
            if self.learning_data_path.exists():
                with open(self.learning_data_path, 'r') as f:
                    data = json.load(f)

                self.user_patterns.correction_pairs = data.get('correction_pairs', [])
                self.user_patterns.common_words = data.get('common_words', {})
                self.user_patterns.domain_vocabulary = data.get('domain_vocabulary', {})
                self.user_patterns.speaking_patterns = data.get('speaking_patterns', {})

                logger.info(f"Learning data loaded from {self.learning_data_path}")

        except Exception as e:
            logger.warning(f"Could not load learning data: {e}")

    def shutdown(self):
        """Save learning data on shutdown"""
        self._save_learning_data()