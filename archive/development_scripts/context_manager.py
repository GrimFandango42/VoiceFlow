#!/usr/bin/env python3
"""
VoiceFlow Context & Session Manager
==================================

Advanced context preservation and session state management system for handling
long interruptions and maintaining conversation continuity across pauses.

Features:
- Conversation context tracking across pauses
- Session state management for long interruptions
- Smart continuation detection
- Configurable context window sizes
- Multi-level context preservation (immediate, short-term, long-term)
"""

import time
import json
import threading
import pickle
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from collections import deque, defaultdict
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
import re


class ContextLevel(Enum):
    """Different levels of context preservation"""
    IMMEDIATE = "immediate"        # Last 30 seconds
    SHORT_TERM = "short_term"      # Last 5 minutes
    LONG_TERM = "long_term"        # Last 30 minutes
    SESSION = "session"            # Entire session


class InterruptionType(Enum):
    """Types of interruptions that can occur"""
    PHONE_CALL = "phone_call"
    MEETING = "meeting"
    BATHROOM_BREAK = "bathroom_break"
    FOOD_BREAK = "food_break"
    TASK_SWITCH = "task_switch"
    EXTERNAL_NOISE = "external_noise"
    TECHNICAL_ISSUE = "technical_issue"
    UNKNOWN = "unknown"


@dataclass
class ContextSnippet:
    """A piece of conversation context with metadata"""
    timestamp: float
    text: str
    speaker: str = "user"
    context_type: str = "speech"  # speech, action, metadata
    importance: float = 1.0
    topic_tags: List[str] = field(default_factory=list)
    

@dataclass
class SessionState:
    """Complete session state for recovery"""
    session_id: str
    start_time: datetime
    last_activity: datetime
    context_snippets: List[ContextSnippet]
    current_topic: str = ""
    active_tasks: List[str] = field(default_factory=list)
    user_preferences: Dict[str, Any] = field(default_factory=dict)
    interruption_count: int = 0
    total_pause_time: float = 0.0


class TopicDetector:
    """Intelligent topic detection and tracking"""
    
    def __init__(self):
        self.topic_keywords = self._load_topic_keywords()
        self.current_topics = deque(maxlen=5)  # Track last 5 topics
        
    def _load_topic_keywords(self) -> Dict[str, List[str]]:
        """Load topic detection keywords"""
        return {
            "coding": ["function", "variable", "class", "method", "bug", "debug", "code", "programming", "syntax", "error"],
            "writing": ["paragraph", "sentence", "chapter", "article", "story", "draft", "edit", "publish", "write"],
            "email": ["send", "reply", "message", "email", "inbox", "subject", "recipient", "attachment"],
            "scheduling": ["meeting", "calendar", "appointment", "schedule", "time", "date", "remind", "event"],
            "research": ["search", "information", "data", "study", "analyze", "investigate", "explore", "find"],
            "documentation": ["document", "note", "record", "log", "report", "summary", "list", "outline"],
            "communication": ["call", "talk", "discuss", "conversation", "chat", "speak", "tell", "ask"]
        }
    
    def detect_topic(self, text: str) -> Tuple[str, float]:
        """
        Detect the main topic of given text
        
        Returns:
            Tuple of (topic, confidence_score)
        """
        if not text:
            return "general", 0.0
            
        text_lower = text.lower()
        words = re.findall(r'\w+', text_lower)
        
        topic_scores = {}
        
        for topic, keywords in self.topic_keywords.items():
            matches = sum(1 for word in words if word in keywords)
            if matches > 0:
                # Normalize by text length and keyword count
                score = matches / (len(words) * len(keywords)) * 100
                topic_scores[topic] = score
        
        if not topic_scores:
            return "general", 0.5
        
        best_topic = max(topic_scores, key=topic_scores.get)
        confidence = min(1.0, topic_scores[best_topic] * 10)  # Scale to 0-1
        
        return best_topic, confidence
    
    def update_current_topics(self, topic: str, confidence: float):
        """Update the current topic tracking"""
        if confidence > 0.6:  # Only track high-confidence topics
            self.current_topics.append((topic, time.time()))


class ContextPreserver:
    """Advanced context preservation system"""
    
    def __init__(self, session_id: str = None, max_context_size: int = 1000):
        self.session_id = session_id or self._generate_session_id()
        self.max_context_size = max_context_size
        
        # Context storage by level
        self.context_levels = {
            ContextLevel.IMMEDIATE: deque(maxlen=20),
            ContextLevel.SHORT_TERM: deque(maxlen=100),
            ContextLevel.LONG_TERM: deque(maxlen=500),
            ContextLevel.SESSION: deque(maxlen=max_context_size)
        }
        
        # State management
        self.session_state = SessionState(
            session_id=self.session_id,
            start_time=datetime.now(),
            last_activity=datetime.now(),
            context_snippets=[]
        )
        
        # Topic tracking
        self.topic_detector = TopicDetector()
        
        # Interruption handling
        self.interruption_start = None
        self.interruption_type = None
        self.pre_interruption_context = None
        
        # Persistence
        self.state_file = Path.home() / ".voiceflow" / f"session_{self.session_id}.json"
        self.context_file = Path.home() / ".voiceflow" / f"context_{self.session_id}.pkl"
        
        # Auto-save timer
        self._save_timer = None
        self._save_lock = threading.Lock()
        
        # Load existing state if available
        self._load_session_state()
        
    def _generate_session_id(self) -> str:
        """Generate unique session identifier"""
        timestamp = str(time.time())
        return hashlib.md5(timestamp.encode()).hexdigest()[:12]
    
    def add_context(self, text: str, speaker: str = "user", 
                   context_type: str = "speech", importance: float = 1.0):
        """
        Add new context to all appropriate levels
        
        Args:
            text: The text content
            speaker: Who spoke (user, system, etc.)
            context_type: Type of context (speech, action, metadata)
            importance: Importance score (0.0-1.0)
        """
        current_time = time.time()
        
        # Detect topic
        topic, topic_confidence = self.topic_detector.detect_topic(text)
        topic_tags = [topic] if topic_confidence > 0.5 else []
        
        # Create context snippet
        snippet = ContextSnippet(
            timestamp=current_time,
            text=text,
            speaker=speaker,
            context_type=context_type,
            importance=importance,
            topic_tags=topic_tags
        )
        
        # Add to all context levels
        for level, storage in self.context_levels.items():
            storage.append(snippet)
        
        # Update session state
        self.session_state.last_activity = datetime.now()
        self.session_state.context_snippets.append(snippet)
        
        # Update current topic if confident
        if topic_confidence > 0.6:
            self.session_state.current_topic = topic
            self.topic_detector.update_current_topics(topic, topic_confidence)
        
        # Schedule auto-save
        self._schedule_save()
        
        print(f"[CONTEXT] Added: {len(text)} chars, topic: {topic} ({topic_confidence:.2f})")
    
    def get_context(self, level: ContextLevel = ContextLevel.SHORT_TERM, 
                   max_chars: int = 2000, include_topics: List[str] = None) -> str:
        """
        Retrieve context at specified level
        
        Args:
            level: Context level to retrieve
            max_chars: Maximum characters to return
            include_topics: Only include context from these topics
            
        Returns:
            Formatted context string
        """
        if level not in self.context_levels:
            return ""
        
        snippets = list(self.context_levels[level])
        
        # Filter by topics if specified
        if include_topics:
            snippets = [s for s in snippets if any(tag in include_topics for tag in s.topic_tags)]
        
        # Sort by importance and recency
        snippets.sort(key=lambda s: (s.importance, s.timestamp), reverse=True)
        
        # Build context string within character limit
        context_parts = []
        total_chars = 0
        
        for snippet in snippets:
            snippet_text = f"[{snippet.speaker}] {snippet.text}"
            
            if total_chars + len(snippet_text) > max_chars:
                break
                
            context_parts.append(snippet_text)
            total_chars += len(snippet_text)
        
        # Reverse to maintain chronological order
        context_parts.reverse()
        
        return "\n".join(context_parts)
    
    def handle_interruption_start(self, interruption_type: InterruptionType = InterruptionType.UNKNOWN):
        """
        Handle the start of an interruption
        
        Args:
            interruption_type: Type of interruption
        """
        self.interruption_start = time.time()
        self.interruption_type = interruption_type
        
        # Preserve pre-interruption context
        self.pre_interruption_context = {
            "immediate": self.get_context(ContextLevel.IMMEDIATE),
            "short_term": self.get_context(ContextLevel.SHORT_TERM),
            "current_topic": self.session_state.current_topic,
            "active_tasks": self.session_state.active_tasks.copy(),
            "timestamp": self.interruption_start
        }
        
        # Add interruption metadata
        self.add_context(
            f"INTERRUPTION_START: {interruption_type.value}",
            speaker="system",
            context_type="metadata",
            importance=0.8
        )
        
        self.session_state.interruption_count += 1
        
        print(f"[CONTEXT] Interruption started: {interruption_type.value}")
    
    def handle_interruption_end(self) -> Dict[str, Any]:
        """
        Handle the end of an interruption and provide recovery context
        
        Returns:
            Recovery information including pre-interruption context
        """
        if not self.interruption_start:
            return {"status": "no_interruption"}
        
        interruption_duration = time.time() - self.interruption_start
        self.session_state.total_pause_time += interruption_duration
        
        # Add interruption end metadata
        self.add_context(
            f"INTERRUPTION_END: {self.interruption_type.value}, duration: {interruption_duration:.1f}s",
            speaker="system",
            context_type="metadata",
            importance=0.8
        )
        
        # Prepare recovery information
        recovery_info = {
            "interruption_duration": interruption_duration,
            "interruption_type": self.interruption_type.value,
            "pre_interruption_context": self.pre_interruption_context,
            "context_preservation_score": self._calculate_context_preservation_score(interruption_duration),
            "suggested_continuation": self._generate_continuation_suggestion(),
            "topic_continuity": self._assess_topic_continuity()
        }
        
        # Reset interruption state
        self.interruption_start = None
        self.interruption_type = None
        self.pre_interruption_context = None
        
        print(f"[CONTEXT] Interruption ended: {interruption_duration:.1f}s, "
              f"preservation score: {recovery_info['context_preservation_score']:.2f}")
        
        return recovery_info
    
    def _calculate_context_preservation_score(self, interruption_duration: float) -> float:
        """Calculate how well context was preserved during interruption"""
        if interruption_duration < 30:
            return 1.0
        elif interruption_duration < 300:  # 5 minutes
            return max(0.8, 1.0 - (interruption_duration - 30) / 270 * 0.2)
        elif interruption_duration < 1800:  # 30 minutes
            return max(0.5, 0.8 - (interruption_duration - 300) / 1500 * 0.3)
        else:
            return max(0.2, 0.5 - (interruption_duration - 1800) / 3600 * 0.3)
    
    def _generate_continuation_suggestion(self) -> str:
        """Generate a suggestion for continuing the conversation"""
        if not self.pre_interruption_context:
            return "Continue where you left off."
        
        recent_context = self.pre_interruption_context.get("immediate", "")
        current_topic = self.pre_interruption_context.get("current_topic", "")
        
        if current_topic and recent_context:
            return f"You were working on {current_topic}. Recent context: {recent_context[-200:]}"
        elif recent_context:
            return f"Recent context: {recent_context[-200:]}"
        else:
            return "Continue your previous conversation."
    
    def _assess_topic_continuity(self) -> Dict[str, Any]:
        """Assess how well topic continuity was maintained"""
        if not self.pre_interruption_context:
            return {"status": "no_pre_context"}
        
        pre_topic = self.pre_interruption_context.get("current_topic", "")
        current_topic = self.session_state.current_topic
        
        return {
            "pre_interruption_topic": pre_topic,
            "current_topic": current_topic,
            "topic_maintained": pre_topic == current_topic,
            "continuity_score": 1.0 if pre_topic == current_topic else 0.5
        }
    
    def detect_continuation_intent(self, new_text: str) -> Dict[str, Any]:
        """
        Detect if new speech is a continuation of previous context
        
        Args:
            new_text: New speech text
            
        Returns:
            Analysis of continuation intent
        """
        if not self.pre_interruption_context:
            return {"is_continuation": False, "confidence": 0.0}
        
        pre_context = self.pre_interruption_context.get("immediate", "")
        
        # Simple continuation indicators
        continuation_words = ["and", "also", "furthermore", "moreover", "besides", "additionally"]
        reference_words = ["that", "this", "it", "they", "those", "these"]
        
        new_text_lower = new_text.lower()
        new_words = new_text_lower.split()
        
        confidence = 0.0
        
        # Check for continuation words at start
        if new_words and new_words[0] in continuation_words:
            confidence += 0.4
        
        # Check for reference words
        if any(word in new_words[:5] for word in reference_words):
            confidence += 0.3
        
        # Check topic similarity
        new_topic, topic_confidence = self.topic_detector.detect_topic(new_text)
        pre_topic = self.pre_interruption_context.get("current_topic", "")
        
        if new_topic == pre_topic and topic_confidence > 0.5:
            confidence += 0.4
        
        # Check for common words/phrases with pre-interruption context
        if pre_context:
            pre_words = set(re.findall(r'\w+', pre_context.lower()))
            new_words_set = set(new_words)
            overlap = len(pre_words.intersection(new_words_set))
            
            if overlap > 0:
                confidence += min(0.3, overlap / len(new_words_set))
        
        return {
            "is_continuation": confidence > 0.6,
            "confidence": min(1.0, confidence),
            "new_topic": new_topic,
            "topic_change": new_topic != pre_topic
        }
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get comprehensive session summary"""
        session_duration = (datetime.now() - self.session_state.start_time).total_seconds()
        
        # Topic distribution
        topic_counts = defaultdict(int)
        for snippet in self.session_state.context_snippets:
            for tag in snippet.topic_tags:
                topic_counts[tag] += 1
        
        # Calculate activity metrics
        recent_activity = len([s for s in self.session_state.context_snippets 
                              if time.time() - s.timestamp < 300])  # Last 5 minutes
        
        return {
            "session_id": self.session_id,
            "duration_seconds": session_duration,
            "total_context_snippets": len(self.session_state.context_snippets),
            "current_topic": self.session_state.current_topic,
            "topic_distribution": dict(topic_counts),
            "interruption_count": self.session_state.interruption_count,
            "total_pause_time": self.session_state.total_pause_time,
            "recent_activity_count": recent_activity,
            "context_levels": {level.value: len(storage) for level, storage in self.context_levels.items()},
            "last_activity": self.session_state.last_activity.isoformat()
        }
    
    def _schedule_save(self):
        """Schedule automatic saving of session state"""
        if self._save_timer:
            self._save_timer.cancel()
        
        self._save_timer = threading.Timer(60.0, self._save_session_state)  # Save every minute
        self._save_timer.daemon = True
        self._save_timer.start()
    
    def _save_session_state(self):
        """Save session state to disk"""
        with self._save_lock:
            try:
                # Ensure directory exists
                self.state_file.parent.mkdir(exist_ok=True)
                
                # Save session state as JSON
                state_data = {
                    "session_id": self.session_state.session_id,
                    "start_time": self.session_state.start_time.isoformat(),
                    "last_activity": self.session_state.last_activity.isoformat(),
                    "current_topic": self.session_state.current_topic,
                    "active_tasks": self.session_state.active_tasks,
                    "interruption_count": self.session_state.interruption_count,
                    "total_pause_time": self.session_state.total_pause_time,
                    "user_preferences": self.session_state.user_preferences
                }
                
                with open(self.state_file, 'w') as f:
                    json.dump(state_data, f, indent=2)
                
                # Save context snippets as pickle (more efficient for complex data)
                with open(self.context_file, 'wb') as f:
                    pickle.dump(self.context_levels, f)
                
            except Exception as e:
                print(f"[CONTEXT] Warning: Could not save session state: {e}")
    
    def _load_session_state(self):
        """Load existing session state from disk"""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    state_data = json.load(f)
                
                # Restore session state
                self.session_state.current_topic = state_data.get("current_topic", "")
                self.session_state.active_tasks = state_data.get("active_tasks", [])
                self.session_state.interruption_count = state_data.get("interruption_count", 0)
                self.session_state.total_pause_time = state_data.get("total_pause_time", 0.0)
                self.session_state.user_preferences = state_data.get("user_preferences", {})
                
                # Load last activity time
                if "last_activity" in state_data:
                    self.session_state.last_activity = datetime.fromisoformat(state_data["last_activity"])
            
            if self.context_file.exists():
                with open(self.context_file, 'rb') as f:
                    self.context_levels = pickle.load(f)
                    
                print(f"[CONTEXT] Loaded session state: {len(self.session_state.context_snippets)} snippets")
                
        except Exception as e:
            print(f"[CONTEXT] Warning: Could not load session state: {e}")
    
    def cleanup(self):
        """Clean up resources and save final state"""
        if self._save_timer:
            self._save_timer.cancel()
        
        self._save_session_state()
        print(f"[CONTEXT] Session cleanup completed: {self.session_id}")


# Factory function for easy integration
def create_context_manager(session_id: str = None, max_context_size: int = 1000) -> ContextPreserver:
    """Create configured context preservation system"""
    return ContextPreserver(session_id, max_context_size)