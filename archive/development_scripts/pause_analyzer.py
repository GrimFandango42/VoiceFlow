#!/usr/bin/env python3
"""
VoiceFlow Pause Detection Optimization Engine
====================================================

Intelligent pause classification and interruption handling system that distinguishes
between natural speech pauses and intentional speech completion.

Features:
- Context-aware pause duration analysis
- Speech pattern learning for individual users
- Confidence scoring for pause decisions
- Adaptive thresholds based on speaking patterns
- Cross-VAD validation for improved accuracy
"""

import time
import json
import math
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import deque, defaultdict
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
from pathlib import Path


class PauseType(Enum):
    """Classification of different pause types"""
    NATURAL_BREATH = "natural_breath"          # 0.1-0.5s breathing pauses
    THINKING_PAUSE = "thinking_pause"          # 0.5-2.0s thinking/formulating
    SENTENCE_BREAK = "sentence_break"          # 1.0-3.0s between sentences
    TOPIC_TRANSITION = "topic_transition"     # 2.0-5.0s changing topics
    INTENTIONAL_STOP = "intentional_stop"     # 3.0+s deliberate completion
    INTERRUPTION = "interruption"             # External interruption detected


class ContextType(Enum):
    """Different conversation contexts that affect pause patterns"""
    CODING = "coding"                 # Technical dictation, longer pauses
    WRITING = "writing"               # Creative writing, varied pauses
    CHAT = "chat"                     # Casual conversation, shorter pauses
    PRESENTATION = "presentation"     # Formal speaking, structured pauses
    DICTATION = "dictation"          # Pure transcription, minimal pauses


@dataclass
class PauseEvent:
    """Represents a detected pause with analysis metadata"""
    start_time: float
    duration: float
    classification: PauseType
    confidence: float
    context: ContextType
    speech_before: str = ""
    speech_after: str = ""
    vad_agreement: float = 0.0  # Agreement between multiple VAD engines
    user_pattern_match: float = 0.0  # How well it matches user's typical patterns


@dataclass
class SpeechPattern:
    """Learned speech patterns for a user"""
    avg_pause_duration: float
    pause_variance: float
    words_per_minute: float
    sentence_pause_avg: float
    breath_pause_avg: float
    context_patterns: Dict[ContextType, Dict[str, float]]
    last_updated: datetime


class PauseClassifier:
    """Intelligent pause classification engine"""
    
    def __init__(self, user_id: str = "default"):
        self.user_id = user_id
        self.pattern_file = Path.home() / ".voiceflow" / f"speech_patterns_{user_id}.json"
        
        # Load or initialize user patterns
        self.user_patterns = self._load_user_patterns()
        
        # Real-time analysis state
        self.recent_pauses = deque(maxlen=50)  # Last 50 pauses for analysis
        self.current_context = ContextType.CHAT
        self.session_start = time.time()
        
        # Adaptive thresholds (will be tuned based on user patterns)
        self.thresholds = self._initialize_thresholds()
        
        # Threading for background pattern learning
        self._learning_lock = threading.Lock()
        self._pattern_update_timer = None
        
    def _load_user_patterns(self) -> Optional[SpeechPattern]:
        """Load learned speech patterns from disk"""
        try:
            if self.pattern_file.exists():
                with open(self.pattern_file, 'r') as f:
                    data = json.load(f)
                    
                # Convert context patterns back to enum keys
                context_patterns = {}
                for context_str, patterns in data.get('context_patterns', {}).items():
                    try:
                        context_key = ContextType(context_str)
                        context_patterns[context_key] = patterns
                    except ValueError:
                        continue
                        
                return SpeechPattern(
                    avg_pause_duration=data.get('avg_pause_duration', 1.0),
                    pause_variance=data.get('pause_variance', 0.5),
                    words_per_minute=data.get('words_per_minute', 120),
                    sentence_pause_avg=data.get('sentence_pause_avg', 1.5),
                    breath_pause_avg=data.get('breath_pause_avg', 0.3),
                    context_patterns=context_patterns,
                    last_updated=datetime.fromisoformat(data.get('last_updated', datetime.now().isoformat()))
                )
        except Exception as e:
            print(f"[PAUSE] Warning: Could not load user patterns: {e}")
        
        return None
    
    def _save_user_patterns(self):
        """Save learned patterns to disk"""
        if not self.user_patterns:
            return
            
        try:
            self.pattern_file.parent.mkdir(exist_ok=True)
            
            # Convert enum keys to strings for JSON serialization
            context_patterns = {}
            for context, patterns in self.user_patterns.context_patterns.items():
                context_patterns[context.value] = patterns
            
            data = {
                'avg_pause_duration': self.user_patterns.avg_pause_duration,
                'pause_variance': self.user_patterns.pause_variance,
                'words_per_minute': self.user_patterns.words_per_minute,
                'sentence_pause_avg': self.user_patterns.sentence_pause_avg,
                'breath_pause_avg': self.user_patterns.breath_pause_avg,
                'context_patterns': context_patterns,
                'last_updated': self.user_patterns.last_updated.isoformat()
            }
            
            with open(self.pattern_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            print(f"[PAUSE] Warning: Could not save user patterns: {e}")
    
    def _initialize_thresholds(self) -> Dict[str, float]:
        """Initialize adaptive thresholds based on user patterns"""
        if self.user_patterns:
            # Use learned patterns to set thresholds
            base_pause = self.user_patterns.avg_pause_duration
            variance = self.user_patterns.pause_variance
        else:
            # Default conservative thresholds
            base_pause = 1.0
            variance = 0.5
        
        return {
            'breath_max': min(0.5, base_pause * 0.3),
            'thinking_min': max(0.4, base_pause * 0.4),
            'thinking_max': min(2.5, base_pause * 1.5),
            'sentence_min': max(1.0, base_pause * 0.8),
            'sentence_max': min(4.0, base_pause * 2.5),
            'topic_min': max(2.0, base_pause * 1.5),
            'topic_max': min(6.0, base_pause * 4.0),
            'intentional_min': max(3.0, base_pause * 2.5),
            'confidence_threshold': 0.75
        }
    
    def classify_pause(self, duration: float, speech_before: str = "", 
                      speech_after: str = "", vad_sources: List[str] = None) -> PauseEvent:
        """
        Classify a pause with intelligent analysis
        
        Args:
            duration: Pause duration in seconds
            speech_before: Text spoken before the pause
            speech_after: Text spoken after the pause (if available)
            vad_sources: List of VAD sources that detected this pause
            
        Returns:
            PauseEvent with classification and confidence
        """
        
        # Calculate VAD agreement (more sources = higher confidence)
        vad_agreement = len(vad_sources or []) / 2.0  # Normalize to 0-1 scale
        vad_agreement = min(1.0, vad_agreement)
        
        # Classify based on duration and context
        pause_type, base_confidence = self._classify_by_duration(duration)
        
        # Adjust confidence based on context analysis
        context_confidence = self._analyze_speech_context(speech_before, speech_after, duration)
        
        # User pattern matching
        pattern_confidence = self._match_user_patterns(duration, pause_type)
        
        # Combine confidence scores
        final_confidence = (base_confidence * 0.4 + 
                          context_confidence * 0.3 + 
                          pattern_confidence * 0.2 + 
                          vad_agreement * 0.1)
        
        pause_event = PauseEvent(
            start_time=time.time(),
            duration=duration,
            classification=pause_type,
            confidence=final_confidence,
            context=self.current_context,
            speech_before=speech_before[-100:],  # Keep last 100 chars for analysis
            speech_after=speech_after[:100],     # Keep first 100 chars
            vad_agreement=vad_agreement,
            user_pattern_match=pattern_confidence
        )
        
        # Store for learning
        self.recent_pauses.append(pause_event)
        
        # Trigger background learning update
        self._schedule_pattern_update()
        
        return pause_event
    
    def _classify_by_duration(self, duration: float) -> Tuple[PauseType, float]:
        """Basic classification by duration with confidence"""
        thresholds = self.thresholds
        
        if duration <= thresholds['breath_max']:
            return PauseType.NATURAL_BREATH, 0.9
        elif duration <= thresholds['thinking_max']:
            if duration >= thresholds['thinking_min']:
                return PauseType.THINKING_PAUSE, 0.8
            else:
                return PauseType.NATURAL_BREATH, 0.7
        elif duration <= thresholds['sentence_max']:
            if duration >= thresholds['sentence_min']:
                return PauseType.SENTENCE_BREAK, 0.8
            else:
                return PauseType.THINKING_PAUSE, 0.6
        elif duration <= thresholds['topic_max']:
            if duration >= thresholds['topic_min']:
                return PauseType.TOPIC_TRANSITION, 0.7
            else:
                return PauseType.SENTENCE_BREAK, 0.6
        else:
            return PauseType.INTENTIONAL_STOP, min(0.9, 0.6 + (duration - thresholds['topic_max']) * 0.1)
    
    def _analyze_speech_context(self, before: str, after: str, duration: float) -> float:
        """Analyze speech context to improve classification confidence"""
        confidence = 0.5  # Base confidence
        
        if not before:
            return confidence
        
        before_lower = before.lower().strip()
        after_lower = after.lower().strip() if after else ""
        
        # Sentence completion indicators
        sentence_endings = ['.', '!', '?', '...']
        if any(before_lower.endswith(ending) for ending in sentence_endings):
            if duration > 1.0:
                confidence += 0.3
        
        # Question patterns suggest intentional pause for response
        question_words = ['what', 'how', 'why', 'when', 'where', 'who', 'which', 'would', 'could', 'should']
        if any(word in before_lower.split()[-5:] for word in question_words):
            if duration > 2.0:
                confidence += 0.2
        
        # Filler words suggest thinking pause
        filler_words = ['um', 'uh', 'er', 'ah', 'hmm', 'well', 'so', 'like']
        before_words = before_lower.split()
        if before_words and before_words[-1] in filler_words:
            if 0.5 <= duration <= 2.0:
                confidence += 0.2
        
        # Topic transition indicators
        transition_phrases = ['anyway', 'speaking of', 'by the way', 'incidentally', 'meanwhile']
        if any(phrase in before_lower for phrase in transition_phrases):
            if duration > 1.5:
                confidence += 0.25
        
        # Context-specific analysis
        if self.current_context == ContextType.CODING:
            # Longer pauses are normal in coding contexts
            if duration > 2.0:
                confidence += 0.1
        elif self.current_context == ContextType.CHAT:
            # Shorter pauses expected in casual chat
            if duration > 3.0:
                confidence += 0.2  # Likely intentional stop
        
        return min(1.0, confidence)
    
    def _match_user_patterns(self, duration: float, pause_type: PauseType) -> float:
        """Match against learned user patterns"""
        if not self.user_patterns:
            return 0.5
        
        # Get context-specific patterns if available
        context_patterns = self.user_patterns.context_patterns.get(self.current_context, {})
        
        # Calculate how well this pause matches user's typical patterns
        if pause_type == PauseType.NATURAL_BREATH:
            expected = context_patterns.get('breath_avg', self.user_patterns.breath_pause_avg)
        elif pause_type == PauseType.SENTENCE_BREAK:
            expected = context_patterns.get('sentence_avg', self.user_patterns.sentence_pause_avg)
        else:
            expected = self.user_patterns.avg_pause_duration
        
        # Calculate deviation from expected
        deviation = abs(duration - expected) / max(expected, 0.1)
        
        # Convert deviation to confidence (closer to expected = higher confidence)
        confidence = max(0.1, 1.0 - (deviation * 0.5))
        
        return min(1.0, confidence)
    
    def _schedule_pattern_update(self):
        """Schedule background pattern learning update"""
        if self._pattern_update_timer:
            self._pattern_update_timer.cancel()
        
        # Update patterns every 30 seconds
        self._pattern_update_timer = threading.Timer(30.0, self._update_patterns)
        self._pattern_update_timer.daemon = True
        self._pattern_update_timer.start()
    
    def _update_patterns(self):
        """Update user patterns based on recent pause data"""
        with self._learning_lock:
            if len(self.recent_pauses) < 5:
                return
            
            # Calculate new patterns from recent data
            durations = [p.duration for p in self.recent_pauses]
            
            new_avg = statistics.mean(durations)
            new_variance = statistics.stdev(durations) if len(durations) > 1 else 0.5
            
            # Extract pause types
            breath_pauses = [p.duration for p in self.recent_pauses if p.classification == PauseType.NATURAL_BREATH]
            sentence_pauses = [p.duration for p in self.recent_pauses if p.classification == PauseType.SENTENCE_BREAK]
            
            new_breath_avg = statistics.mean(breath_pauses) if breath_pauses else 0.3
            new_sentence_avg = statistics.mean(sentence_pauses) if sentence_pauses else 1.5
            
            # Update context-specific patterns
            context_patterns = defaultdict(dict)
            for context in ContextType:
                context_pauses = [p for p in self.recent_pauses if p.context == context]
                if context_pauses:
                    context_patterns[context] = {
                        'avg_duration': statistics.mean([p.duration for p in context_pauses]),
                        'breath_avg': statistics.mean([p.duration for p in context_pauses if p.classification == PauseType.NATURAL_BREATH]) if any(p.classification == PauseType.NATURAL_BREATH for p in context_pauses) else new_breath_avg,
                        'sentence_avg': statistics.mean([p.duration for p in context_pauses if p.classification == PauseType.SENTENCE_BREAK]) if any(p.classification == PauseType.SENTENCE_BREAK for p in context_pauses) else new_sentence_avg
                    }
            
            # Create or update user patterns
            if self.user_patterns:
                # Weighted update (70% old, 30% new)
                self.user_patterns.avg_pause_duration = (self.user_patterns.avg_pause_duration * 0.7 + new_avg * 0.3)
                self.user_patterns.pause_variance = (self.user_patterns.pause_variance * 0.7 + new_variance * 0.3)
                self.user_patterns.breath_pause_avg = (self.user_patterns.breath_pause_avg * 0.7 + new_breath_avg * 0.3)
                self.user_patterns.sentence_pause_avg = (self.user_patterns.sentence_pause_avg * 0.7 + new_sentence_avg * 0.3)
                
                # Update context patterns
                for context, patterns in context_patterns.items():
                    if context not in self.user_patterns.context_patterns:
                        self.user_patterns.context_patterns[context] = patterns
                    else:
                        # Weighted update for existing context patterns
                        existing = self.user_patterns.context_patterns[context]
                        for key, value in patterns.items():
                            existing[key] = existing.get(key, value) * 0.7 + value * 0.3
                        
                self.user_patterns.last_updated = datetime.now()
            else:
                # Create new patterns
                self.user_patterns = SpeechPattern(
                    avg_pause_duration=new_avg,
                    pause_variance=new_variance,
                    words_per_minute=120,  # Default, will be learned over time
                    sentence_pause_avg=new_sentence_avg,
                    breath_pause_avg=new_breath_avg,
                    context_patterns=dict(context_patterns),
                    last_updated=datetime.now()
                )
            
            # Update thresholds based on new patterns
            self.thresholds = self._initialize_thresholds()
            
            # Save patterns
            self._save_user_patterns()
    
    def set_context(self, context: ContextType):
        """Set the current conversation context"""
        self.current_context = context
        print(f"[PAUSE] Context set to: {context.value}")
    
    def should_continue_listening(self, pause_event: PauseEvent) -> bool:
        """
        Determine if system should continue listening or treat as intentional stop
        
        Returns:
            True if should continue listening, False if should stop
        """
        # High confidence intentional stops
        if (pause_event.classification == PauseType.INTENTIONAL_STOP and 
            pause_event.confidence > self.thresholds['confidence_threshold']):
            return False
        
        # Very long pauses are likely intentional
        if pause_event.duration > 8.0:
            return False
        
        # Context-specific decisions
        if self.current_context == ContextType.CHAT:
            # In chat, be more aggressive about stopping
            if pause_event.duration > 4.0 and pause_event.confidence > 0.6:
                return False
        elif self.current_context == ContextType.CODING:
            # In coding, allow longer pauses
            if pause_event.duration > 10.0 and pause_event.confidence > 0.7:
                return False
        
        return True
    
    def get_pause_statistics(self) -> Dict[str, Any]:
        """Get current pause analysis statistics"""
        if not self.recent_pauses:
            return {"status": "no_data"}
        
        durations = [p.duration for p in self.recent_pauses]
        classifications = [p.classification.value for p in self.recent_pauses]
        confidences = [p.confidence for p in self.recent_pauses]
        
        return {
            "session_pauses": len(self.recent_pauses),
            "avg_duration": statistics.mean(durations),
            "max_duration": max(durations),
            "min_duration": min(durations),
            "avg_confidence": statistics.mean(confidences),
            "classification_counts": {cls: classifications.count(cls) for cls in set(classifications)},
            "current_context": self.current_context.value,
            "thresholds": self.thresholds,
            "pattern_learned": self.user_patterns is not None,
            "last_pattern_update": self.user_patterns.last_updated.isoformat() if self.user_patterns else None
        }


class AdaptiveVADManager:
    """Manages multiple VAD engines with adaptive configuration"""
    
    def __init__(self, pause_classifier: PauseClassifier):
        self.pause_classifier = pause_classifier
        self.vad_configs = self._initialize_vad_configs()
        self.active_profile = "balanced"
        
    def _initialize_vad_configs(self) -> Dict[str, Dict[str, float]]:
        """Initialize VAD configuration profiles"""
        return {
            "conservative": {
                "silero_sensitivity": 0.2,
                "webrtc_sensitivity": 1,
                "post_speech_silence_duration": 1.5,
                "min_length_of_recording": 0.4,
                "min_gap_between_recordings": 0.4
            },
            "balanced": {
                "silero_sensitivity": 0.3,
                "webrtc_sensitivity": 2,
                "post_speech_silence_duration": 1.0,
                "min_length_of_recording": 0.3,
                "min_gap_between_recordings": 0.2
            },
            "aggressive": {
                "silero_sensitivity": 0.5,
                "webrtc_sensitivity": 3,
                "post_speech_silence_duration": 0.6,
                "min_length_of_recording": 0.2,
                "min_gap_between_recordings": 0.1
            }
        }
    
    def get_config_for_context(self, context: ContextType) -> Dict[str, float]:
        """Get optimized VAD config for specific context"""
        base_config = self.vad_configs[self.active_profile].copy()
        
        # Context-specific adjustments
        if context == ContextType.CODING:
            # Allow longer pauses for thinking
            base_config["post_speech_silence_duration"] *= 1.5
            base_config["min_gap_between_recordings"] *= 1.2
        elif context == ContextType.CHAT:
            # Faster response for casual conversation
            base_config["post_speech_silence_duration"] *= 0.8
            base_config["min_gap_between_recordings"] *= 0.8
        elif context == ContextType.PRESENTATION:
            # More conservative for formal speaking
            base_config["silero_sensitivity"] *= 0.8
            base_config["post_speech_silence_duration"] *= 1.3
        
        # User pattern adjustments
        if self.pause_classifier.user_patterns:
            patterns = self.pause_classifier.user_patterns
            # Adjust based on user's typical pause duration
            adjustment_factor = patterns.avg_pause_duration / 1.0  # Normalize to 1.0s baseline
            base_config["post_speech_silence_duration"] *= adjustment_factor
        
        return base_config
    
    def set_profile(self, profile: str):
        """Set active VAD profile"""
        if profile in self.vad_configs:
            self.active_profile = profile
            print(f"[VAD] Profile set to: {profile}")
        else:
            print(f"[VAD] Unknown profile: {profile}")


# Factory function for easy integration
def create_pause_analyzer(user_id: str = "default") -> Tuple[PauseClassifier, AdaptiveVADManager]:
    """Create configured pause analysis system"""
    classifier = PauseClassifier(user_id)
    vad_manager = AdaptiveVADManager(classifier)
    return classifier, vad_manager