"""
VoiceFlow Core Engine

Consolidated speech processing engine extracted from duplicate implementations.
Combines functionality from stt_server.py, simple_server.py, and other variants.
"""

import os
import sqlite3
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Callable

# Import IDE integration and code context analysis
try:
    from .ide_integration import create_ide_manager, IDEIntegrationManager
    from .code_context_analyzer import create_code_context_analyzer, create_code_formatter, CodePosition
    IDE_INTEGRATION_AVAILABLE = True
except ImportError:
    IDE_INTEGRATION_AVAILABLE = False
    print("[WARNING] IDE integration not available - advanced text injection disabled")
from collections import deque

# Import secure database utilities and long session support
try:
    from utils.secure_db import create_secure_database
    from utils.memory_monitor import create_memory_monitor
    from utils.session_manager import create_session_manager
    ENCRYPTION_AVAILABLE = True
    LONG_SESSION_SUPPORT = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    LONG_SESSION_SUPPORT = False
    print("[WARNING] Enhanced features not available - install cryptography and psutil packages")

try:
    from RealtimeSTT import AudioToTextRecorder
    import pyautogui
    import keyboard
    SYSTEM_INTEGRATION = True
except ImportError:
    SYSTEM_INTEGRATION = False
    print("System integration packages not installed. Text injection disabled.")

# Import pause detection modules
try:
    from pause_analyzer import create_pause_analyzer, PauseType, ContextType, PauseEvent
    from context_manager import create_context_manager, ContextLevel, InterruptionType
    PAUSE_DETECTION = True
except ImportError:
    PAUSE_DETECTION = False
    print("Pause detection modules not available.")

# Import advanced noise processing components
try:
    from .noise_processing import (
        NoiseAnalyzer, NoiseReducer, NoiseGate,
        NoiseEnvironment, NoiseProfile, NoiseType, create_noise_processor
    )
    from ..utils.audio_quality_monitor import (
        AudioQualityMonitor, AudioQualityMetrics, create_quality_monitor
    )
    import numpy as np
    ADVANCED_NOISE_PROCESSING = True
    print("[NOISE] Advanced noise processing available")
except ImportError as e:
    ADVANCED_NOISE_PROCESSING = False
    print(f"[WARNING] Advanced noise processing not available: {e}")


class AdaptiveVADManager:
    """
    Adaptive VAD manager that adjusts VAD parameters based on speech patterns.
    Helps further reduce audio cutoff by learning from user's speech characteristics.
    """
    
    def __init__(self, initial_profile: str = 'balanced'):
        self.current_profile = initial_profile
        self.speech_history = deque(maxlen=50)  # Keep last 50 recordings
        self.cutoff_detection_history = deque(maxlen=20)  # Track potential cutoffs
        self.adaptation_enabled = False
        
        # Adaptation parameters
        self.min_recordings_for_adaptation = 10
        self.cutoff_threshold = 0.15  # 15% of recordings suspected of cutoff
        self.adaptation_cooldown = 30  # seconds between adaptations
        self.last_adaptation_time = 0
    
    def record_speech_event(self, duration: float, word_count: int, 
                          suspected_cutoff: bool = False):
        """
        Record a speech event for adaptive learning.
        
        Args:
            duration: Duration of the speech recording
            word_count: Number of words transcribed
            suspected_cutoff: Whether this recording may have been cut off
        """
        self.speech_history.append({
            'timestamp': time.time(),
            'duration': duration,
            'word_count': word_count,
            'words_per_second': word_count / max(duration, 0.1),
            'suspected_cutoff': suspected_cutoff
        })
        
        if suspected_cutoff:
            self.cutoff_detection_history.append(time.time())
        
        # Trigger adaptation check if enabled
        if self.adaptation_enabled:
            self._check_for_adaptation()
    
    def _check_for_adaptation(self):
        """Check if VAD parameters should be adapted."""
        if len(self.speech_history) < self.min_recordings_for_adaptation:
            return
        
        # Rate limiting for adaptations
        current_time = time.time()
        if current_time - self.last_adaptation_time < self.adaptation_cooldown:
            return
        
        # Calculate cutoff rate in recent history
        recent_cutoffs = [
            event for event in self.speech_history 
            if event['suspected_cutoff'] and 
            current_time - event['timestamp'] < 300  # Last 5 minutes
        ]
        
        cutoff_rate = len(recent_cutoffs) / len(self.speech_history)
        
        # Adapt if cutoff rate is too high
        if cutoff_rate > self.cutoff_threshold:
            self._adapt_to_reduce_cutoffs()
            self.last_adaptation_time = current_time
    
    def _adapt_to_reduce_cutoffs(self):
        """Adapt VAD settings to reduce cutoffs."""
        print(f"[ADAPTIVE VAD] High cutoff rate detected, adapting...")
        
        # Move towards more conservative settings
        if self.current_profile == 'aggressive':
            self.current_profile = 'balanced'
            print("[ADAPTIVE VAD] Switched from aggressive to balanced profile")
        elif self.current_profile == 'balanced':
            self.current_profile = 'conservative'
            print("[ADAPTIVE VAD] Switched from balanced to conservative profile")
        else:
            print("[ADAPTIVE VAD] Already at most conservative settings")
    
    def get_adaptive_adjustments(self, base_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get adaptive adjustments to base VAD configuration.
        
        Args:
            base_config: Base VAD configuration
            
        Returns:
            Adjusted VAD configuration
        """
        if not self.adaptation_enabled or len(self.speech_history) < 5:
            return base_config
        
        # Calculate average speech characteristics
        recent_events = list(self.speech_history)[-10:]  # Last 10 recordings
        avg_duration = sum(event['duration'] for event in recent_events) / len(recent_events)
        avg_words_per_sec = sum(event['words_per_second'] for event in recent_events) / len(recent_events)
        
        # Adjust post-speech silence based on user's speech patterns
        adjusted_config = base_config.copy()
        
        if avg_words_per_sec > 3.0:  # Fast speaker
            # Increase buffer for fast speakers who may have abrupt endings
            adjusted_config['post_speech_silence_duration'] *= 1.2
            print(f"[ADAPTIVE VAD] Fast speaker detected, increased silence buffer to {adjusted_config['post_speech_silence_duration']:.1f}s")
        elif avg_words_per_sec < 1.5:  # Slow speaker
            # Slightly reduce buffer for slow speakers
            adjusted_config['post_speech_silence_duration'] *= 0.9
            print(f"[ADAPTIVE VAD] Slow speaker detected, optimized silence buffer to {adjusted_config['post_speech_silence_duration']:.1f}s")
        
        return adjusted_config
    
    def enable_adaptation(self):
        """Enable adaptive VAD adjustments."""
        self.adaptation_enabled = True
        print("[ADAPTIVE VAD] ✅ Adaptive adjustments enabled")
    
    def disable_adaptation(self):
        """Disable adaptive VAD adjustments."""
        self.adaptation_enabled = False
        print("[ADAPTIVE VAD] ❌ Adaptive adjustments disabled")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get adaptive VAD statistics."""
        if not self.speech_history:
            return {"status": "no_data"}
        
        recent_events = list(self.speech_history)[-20:]
        cutoff_events = [e for e in recent_events if e['suspected_cutoff']]
        
        return {
            "adaptation_enabled": self.adaptation_enabled,
            "current_profile": self.current_profile,
            "total_recordings": len(self.speech_history),
            "recent_cutoff_rate": len(cutoff_events) / len(recent_events) if recent_events else 0,
            "avg_duration": sum(e['duration'] for e in recent_events) / len(recent_events),
            "avg_words_per_second": sum(e['words_per_second'] for e in recent_events) / len(recent_events)
        }


class VADDebugLogger:
    """
    VAD debugging and logging utility for troubleshooting audio cutoff issues.
    """
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.debug_log = deque(maxlen=100)  # Keep last 100 debug entries
        self.vad_events = deque(maxlen=50)   # Keep last 50 VAD events
    
    def log_vad_event(self, event_type: str, data: Dict[str, Any]):
        """Log a VAD event for debugging."""
        if not self.enabled:
            return
        
        timestamp = time.time()
        event = {
            'timestamp': timestamp,
            'type': event_type,
            'data': data
        }
        
        self.vad_events.append(event)
        self.debug_log.append(f"[{timestamp:.3f}] VAD-{event_type}: {data}")
        
        # Print debug info if enabled
        print(f"[VAD-DEBUG] {event_type}: {data}")
    
    def log_speech_start(self, vad_config: Dict[str, Any]):
        """Log speech start event."""
        self.log_vad_event('SPEECH_START', {
            'silero_sensitivity': vad_config.get('silero_sensitivity'),
            'webrtc_sensitivity': vad_config.get('webrtc_sensitivity'),
            'start_threshold': vad_config.get('start_threshold', 'N/A')
        })
    
    def log_speech_end(self, duration: float, silence_duration: float):
        """Log speech end event."""
        self.log_vad_event('SPEECH_END', {
            'speech_duration': duration,
            'silence_buffer': silence_duration
        })
    
    def log_potential_cutoff(self, text: str, indicators: list):
        """Log potential cutoff detection."""
        self.log_vad_event('POTENTIAL_CUTOFF', {
            'text_preview': text[:50] + '...' if len(text) > 50 else text,
            'cutoff_indicators': indicators
        })
    
    def log_vad_adaptation(self, old_settings: Dict[str, Any], new_settings: Dict[str, Any]):
        """Log VAD adaptation changes."""
        self.log_vad_event('VAD_ADAPTATION', {
            'old_settings': old_settings,
            'new_settings': new_settings
        })
    
    def get_debug_summary(self) -> Dict[str, Any]:
        """Get debug summary for troubleshooting."""
        if not self.vad_events:
            return {"status": "no_debug_data"}
        
        # Count event types
        event_counts = {}
        speech_durations = []
        cutoff_count = 0
        
        for event in self.vad_events:
            event_type = event['type']
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            if event_type == 'SPEECH_END':
                speech_durations.append(event['data']['speech_duration'])
            elif event_type == 'POTENTIAL_CUTOFF':
                cutoff_count += 1
        
        return {
            "debug_enabled": self.enabled,
            "total_events": len(self.vad_events),
            "event_counts": event_counts,
            "average_speech_duration": sum(speech_durations) / len(speech_durations) if speech_durations else 0,
            "potential_cutoffs": cutoff_count,
            "cutoff_rate": cutoff_count / len(self.vad_events) if self.vad_events else 0,
            "recent_events": list(self.vad_events)[-10:]  # Last 10 events
        }
    
    def enable_debug(self):
        """Enable VAD debugging."""
        self.enabled = True
        print("[VAD-DEBUG] ✅ VAD debugging enabled")
    
    def disable_debug(self):
        """Disable VAD debugging."""
        self.enabled = False
        print("[VAD-DEBUG] ❌ VAD debugging disabled")


class VoiceFlowEngine:
    """
    Core VoiceFlow engine consolidating speech processing functionality.
    
    This class combines the common functionality that was duplicated across:
    - stt_server.py
    - simple_server.py  
    - blazing_fast_working.py
    - voiceflow_performance.py
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize VoiceFlow engine with configuration."""
        self.config = config or {}
        
        # Core configuration with environment variable support
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "transcriptions.db"
        
        # Initialize secure database if encryption available
        if ENCRYPTION_AVAILABLE:
            self.secure_db = create_secure_database(self.data_dir)
            print("[DB] ✅ Encrypted database initialized")
        else:
            self.secure_db = None
            print("[DB] ⚠️  Using unencrypted database - install cryptography for security")
        
        # Audio configuration
        self.recorder = None
        self.is_recording = False
        self.last_recording_time = 0
        
        # Pause detection and context management
        if PAUSE_DETECTION:
            self.pause_classifier, self.vad_manager = create_pause_analyzer(config.get('user_id', 'default'))
            self.context_manager = create_context_manager(max_context_size=config.get('max_context_size', 1000))
            self.pause_detection_enabled = config.get('enable_pause_detection', True)
            print("[PAUSE] Intelligent pause detection enabled")
        else:
            self.pause_classifier = None
            self.vad_manager = None
            self.context_manager = None
            self.pause_detection_enabled = False
        
        # Pause state tracking
        self.current_pause_start = None
        self.speech_buffer = deque(maxlen=10)  # Buffer last 10 speech segments
        self.last_speech_end = 0
        
        # Performance tracking
        self.stats = {
            "total_transcriptions": 0,
            "total_words": 0,
            "session_start": datetime.now(),
            "processing_times": []
        }
        
        # Callbacks for integration
        self.on_transcription = None
        self.on_error = None
        
        # Browser integration
        self.browser_engine = None
        self.browser_integration_enabled = False
        
        # Terminal integration
        if TERMINAL_INTEGRATION:
            self.terminal_injector = create_terminal_injector()
            self.terminal_detector = TerminalDetector()
            self.terminal_integration_enabled = True
            print("[TERMINAL] ✅ Terminal integration enabled")
        else:
            self.terminal_injector = None
            self.terminal_detector = None
            self.terminal_integration_enabled = False
            print("[TERMINAL] ⚠️  Terminal integration not available")
        
        # Adaptive VAD manager for learning user speech patterns
        self.adaptive_vad = AdaptiveVADManager(self.config.get('vad_profile', 'balanced'))
        if self.config.get('adaptive_vad', False):
            self.adaptive_vad.enable_adaptation()
            print("[VAD] ✅ Adaptive VAD learning enabled")
        
        # VAD debug logger for troubleshooting
        self.vad_debug = VADDebugLogger(self.config.get('enable_vad_debugging', False))
        if self.vad_debug.enabled:
            print("[VAD] 🐛 VAD debugging enabled")
        
        # Advanced noise processing components
        if ADVANCED_NOISE_PROCESSING:
            self.noise_analyzer, self.noise_vad_manager, self.noise_reducer, self.noise_gate = create_noise_processor()
            self.quality_monitor = create_quality_monitor()
            self.current_noise_profile = None
            self.noise_processing_enabled = self.config.get('enable_noise_processing', True)
            self.adaptive_noise_vad_enabled = self.config.get('enable_adaptive_noise_vad', True)
            print("[NOISE] ✅ Advanced noise processing initialized")
        else:
            self.noise_analyzer = None
            self.noise_vad_manager = None
            self.noise_reducer = None
            self.noise_gate = None
            self.quality_monitor = None
            self.noise_processing_enabled = False
            self.adaptive_noise_vad_enabled = False
        
        # IDE Integration and Code Context
        self.ide_manager = None
        self.code_analyzer = None
        self.code_formatter = None
        self.smart_injection_enabled = self.config.get('smart_injection', True)
        
        # Long session support
        self.enable_long_sessions = self.config.get('enable_long_sessions', True) and LONG_SESSION_SUPPORT
        self.memory_monitor = None
        self.session_manager = None
        
        # Initialize enhanced features
        if self.enable_long_sessions:
            try:
                # Memory monitoring
                self.memory_monitor = create_memory_monitor({
                    'check_interval_seconds': 45.0,  # Less frequent for core engine
                    'max_process_memory_mb': 2048.0,
                    'enable_auto_cleanup': True
                })
                
                # Session management
                self.session_manager = create_session_manager(self.data_dir, {
                    'checkpoint_interval_minutes': 20,
                    'max_session_hours': 8,
                    'auto_save_enabled': True
                })
                
                print("[Core] ✅ Long session support enabled")
                
            except Exception as e:
                print(f"[Core] ⚠️  Long session setup failed: {e}")
                self.enable_long_sessions = False
        
        # Initialize components
        self.init_database()
        self.setup_ide_integration()
        self.setup_audio_recorder()
        self.setup_browser_integration()
        
        # Start long session if enabled
        if self.enable_long_sessions:
            self._start_long_session()
    
    def _get_vad_config(self, profile: str = 'balanced') -> Dict[str, Any]:
        """
        Get VAD configuration based on profile.
        
        Profiles:
        - conservative: Maximum speech capture, minimal cutoff risk
        - balanced: Optimized for general use (default, fixes cutoff issue)
        - aggressive: Fast response, higher cutoff risk
        """
        base_config = {
            "language": "en",
            "use_microphone": True,
            "spinner": False,
            "level": 0,
            "enable_realtime_transcription": True,
        }
        
        if profile == 'conservative':
            # Maximum speech capture, very low cutoff risk
            vad_config = {
                "silero_sensitivity": 0.2,           # Very low for maximum capture
                "webrtc_sensitivity": 1,             # Minimum sensitivity
                "post_speech_silence_duration": 1.8, # Extended buffer
                "min_length_of_recording": 0.1,      # Short minimum for quick start
                "min_gap_between_recordings": 0.1,   # Minimal gap
                "start_threshold": 0.2,              # Low start threshold
                "end_threshold": 0.15,               # Very low end threshold
            }
        elif profile == 'aggressive':
            # Fast response, higher performance, slight cutoff risk
            vad_config = {
                "silero_sensitivity": 0.5,           # Higher for quick detection
                "webrtc_sensitivity": 4,             # More aggressive
                "post_speech_silence_duration": 0.6, # Shorter buffer
                "min_length_of_recording": 0.3,      # Longer minimum
                "min_gap_between_recordings": 0.4,   # Longer gap
                "start_threshold": 0.4,              # Higher start threshold
                "end_threshold": 0.3,                # Higher end threshold
            }
        else:  # balanced (default - FIXES the cutoff issue)
            # Optimized for general use with cutoff fix
            vad_config = {
                "silero_sensitivity": 0.3,           # Reduced from original 0.4
                "webrtc_sensitivity": 2,             # Reduced from original 3
                "post_speech_silence_duration": 1.3, # Increased from original 0.8
                "min_length_of_recording": 0.15,     # Optimized
                "min_gap_between_recordings": 0.25,  # Optimized
                "start_threshold": 0.3,              # Lower threshold for speech start
                "end_threshold": 0.2,                # Lower threshold for speech end
                "wake_words_sensitivity": 0.6,       # Balance sensitivity
                "wake_words_timeout": 5.0,           # Timeout for wake word detection
            }
        
        # Merge base config with VAD-specific config
        result = {**base_config, **vad_config}
        
        # Apply adaptive adjustments if enabled
        if hasattr(self, 'adaptive_vad') and self.adaptive_vad:
            result = self.adaptive_vad.get_adaptive_adjustments(result)
        
        # Add debug logging if enabled
        if self.config.get('debug_vad', False):
            print(f"[VAD] Using profile '{profile}' with config: {vad_config}")
            if hasattr(self, 'adaptive_vad') and self.adaptive_vad.adaptation_enabled:
                print(f"[VAD] Adaptive adjustments applied")
        
        return result
    
    def init_database(self):
        """Initialize SQLite database for transcription storage."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    raw_text TEXT,
                    enhanced_text TEXT,
                    processing_time_ms INTEGER,
                    word_count INTEGER,
                    confidence REAL,
                    model_used TEXT,
                    session_id TEXT
                )
            ''')
            conn.commit()
            conn.close()
            print(f"[DB] Database initialized: {self.db_path}")
        except Exception as e:
            print(f"[ERROR] Database initialization failed: {e}")
    
    def setup_browser_integration(self):
        """Setup browser integration engine."""
        if BROWSER_INTEGRATION:
            try:
                self.browser_engine = BrowserIntegrationEngine()
                
                # Get browser preference from config
                browser_type = self.config.get('browser_type', 'chrome')
                headless = self.config.get('browser_headless', False)
                
                browser_config = BrowserConfig(
                    browser_type=getattr(BrowserType, browser_type.upper(), BrowserType.CHROME),
                    headless=headless,
                    security_validation=True,
                    timeout=self.config.get('browser_timeout', 10)
                )
                
                # Don't initialize browser by default - only when needed
                print("[BROWSER] ✅ Browser integration configured (lazy initialization)")
                self.browser_integration_enabled = True
                
            except Exception as e:
                print(f"[ERROR] Browser integration setup failed: {e}")
                self.browser_integration_enabled = False
        else:
            print("[BROWSER] ⚠️  Browser integration disabled - install selenium for advanced features")
    
    def setup_ide_integration(self):
        """Setup IDE integration for intelligent text injection."""
        if IDE_INTEGRATION_AVAILABLE and self.smart_injection_enabled:
            try:
                # Initialize IDE manager
                self.ide_manager = create_ide_manager()
                self.code_analyzer = create_code_context_analyzer()
                self.code_formatter = create_code_formatter()
                
                print("[IDE] ✅ IDE integration initialized")
                
                # Detect currently running IDEs
                detected_ides = self.ide_manager.refresh_detection()
                if detected_ides:
                    active_ide = self.ide_manager.active_ide
                    if active_ide:
                        print(f"[IDE] Active IDE: {active_ide.ide_type.value}")
                        if active_ide.supports_api:
                            print(f"[IDE] API integration available for {active_ide.ide_type.value}")
                        if active_ide.supports_automation:
                            print(f"[IDE] Automation support available for {active_ide.ide_type.value}")
                else:
                    print("[IDE] No IDEs detected - will use fallback injection methods")
                
            except Exception as e:
                print(f"[ERROR] IDE integration setup failed: {e}")
                self.ide_manager = None
                self.code_analyzer = None
                self.code_formatter = None
        else:
            print("[IDE] ⚠️  IDE integration disabled - smart injection not available")
    
    def setup_audio_recorder(self):
        """Setup audio recorder with GPU/CPU fallback logic."""
        # Get model preference from config
        model = self.config.get('model', 'base')
        device = self.config.get('device', 'auto')
        
        # Enhanced VAD parameters with intelligent pause detection
        vad_profile = self.config.get('vad_profile', 'balanced')
        
        # Get context-aware VAD configuration if pause detection is enabled
        if self.pause_detection_enabled and self.vad_manager:
            current_context = self.config.get('context_type', ContextType.CHAT)
            if isinstance(current_context, str):
                try:
                    current_context = ContextType(current_context)
                except ValueError:
                    current_context = ContextType.CHAT
            
            # Set context in pause classifier
            self.pause_classifier.set_context(current_context)
            
            # Get adaptive VAD config and merge with base config
            base_config = self._get_vad_config(vad_profile)
            adaptive_config = self.vad_manager.get_config_for_context(current_context)
            
            # Merge configurations (adaptive takes precedence)
            common_params = {**base_config, **adaptive_config}
            print(f"[VAD] Using adaptive config for {current_context.value}")
        else:
            # Fallback to standard VAD configuration
            common_params = self._get_vad_config(vad_profile)
        
        # Add pause detection callbacks if enabled
        if self.pause_detection_enabled:
            common_params.update({
                "on_recording_start": self._on_recording_start,
                "on_recording_stop": self._on_recording_stop,
                "on_transcription_start": self._on_transcription_start
            })
        
        # Override with user configuration if provided
        audio_config = self.config.get('audio', {})
        for key in ['silero_sensitivity', 'webrtc_sensitivity', 'post_speech_silence_duration',
                   'min_length_of_recording', 'min_gap_between_recordings']:
            if key in audio_config:
                common_params[key] = audio_config[key]
        
        # Try GPU first, fallback to CPU
        if device == 'auto' or device == 'cuda':
            try:
                print(f"[STT] Initializing Whisper model '{model}' on GPU...")
                self.recorder = AudioToTextRecorder(
                    model=model,
                    device="cuda",
                    compute_type="int8",
                    **common_params
                )
                print("[STT] ✅ GPU acceleration active")
                return
            except Exception as e:
                print(f"[STT] GPU failed: {e}")
        
        # CPU fallback
        try:
            print(f"[STT] Falling back to CPU with model 'base'...")
            self.recorder = AudioToTextRecorder(
                model="base",
                device="cpu",
                compute_type="int8",
                **common_params
            )
            print("[STT] ✅ CPU mode active")
        except Exception as e:
            print(f"[ERROR] Failed to initialize STT: {e}")
            self.recorder = None
    
    def _on_recording_start(self):
        """Called when recording starts"""
        self.current_pause_start = None
        if self.context_manager:
            self.context_manager.add_context(
                "RECORDING_START", 
                speaker="system", 
                context_type="metadata",
                importance=0.3
            )
    
    def _on_recording_stop(self):
        """Called when recording stops - analyze pause"""
        if not self.pause_detection_enabled:
            return
            
        self.current_pause_start = time.time()
        self.last_speech_end = time.time()
        
        if self.context_manager:
            self.context_manager.add_context(
                "RECORDING_STOP", 
                speaker="system", 
                context_type="metadata",
                importance=0.3
            )
    
    def _on_transcription_start(self, text: str):
        """Called when transcription is ready - analyze and store"""
        if not text.strip():
            return
            
        # Add to speech buffer
        self.speech_buffer.append({
            'text': text,
            'timestamp': time.time(),
            'processed': False
        })
        
        # Analyze pause if we have one
        if self.current_pause_start and self.pause_detection_enabled:
            pause_duration = time.time() - self.current_pause_start
            
            # Get previous speech for context
            previous_speech = ""
            if len(self.speech_buffer) >= 2:
                previous_speech = self.speech_buffer[-2]['text']
            
            # Classify the pause
            pause_event = self.pause_classifier.classify_pause(
                duration=pause_duration,
                speech_before=previous_speech,
                speech_after=text,
                vad_sources=['silero', 'webrtc']  # Multiple VAD validation
            )
            
            # Log pause analysis
            print(f"[PAUSE] {pause_event.classification.value}: {pause_duration:.2f}s "
                  f"(confidence: {pause_event.confidence:.2f})")
            
            # Check if this indicates intentional completion
            if not self.pause_classifier.should_continue_listening(pause_event):
                print(f"[PAUSE] Detected intentional completion - stopping listening")
                # Could trigger completion callback here
            
            self.current_pause_start = None
        
        # Add to context manager
        if self.context_manager:
            self.context_manager.add_context(
                text, 
                speaker="user", 
                context_type="speech",
                importance=1.0
            )
    
    def process_speech(self) -> Optional[str]:
        """
        Process speech input and return transcription.
        Consolidated from multiple duplicate implementations.
        """
        if not self.recorder:
            print("[ERROR] STT recorder not initialized")
            return None
        
        # Enhanced timing control with pause detection
        current_time = time.time()
        
        # Adaptive timing based on context and user patterns
        min_gap = 1.0  # Default minimum gap
        if self.pause_detection_enabled and self.pause_classifier.user_patterns:
            # Use learned user patterns for timing
            user_gap = self.pause_classifier.user_patterns.avg_pause_duration * 0.5
            min_gap = max(0.5, min(2.0, user_gap))  # Clamp between 0.5-2.0 seconds
        
        if current_time - self.last_recording_time < min_gap:
            return None
        self.last_recording_time = current_time
        
        try:
            print("[STT] 🎤 Listening...")
            self.is_recording = True
            start_time = time.time()
            
            # Get transcription
            transcribed_text = self.recorder.text()
            
            processing_time = (time.time() - start_time) * 1000
            
            if transcribed_text:
                # Calculate recording duration and word count
                duration = time.time() - start_time
                word_count = len(transcribed_text.split())
                
                # Simple cutoff detection heuristic
                suspected_cutoff = self._detect_potential_cutoff(transcribed_text, duration)
                
                # Log VAD debug information
                if hasattr(self, 'vad_debug') and self.vad_debug.enabled:
                    self.vad_debug.log_speech_end(duration, self.config.get('post_speech_silence_duration', 1.3))
                    if suspected_cutoff:
                        cutoff_indicators = self._get_cutoff_indicators(transcribed_text, duration)
                        self.vad_debug.log_potential_cutoff(transcribed_text, cutoff_indicators)
                
                # Update adaptive VAD with speech event data
                if hasattr(self, 'adaptive_vad') and self.adaptive_vad:
                    self.adaptive_vad.record_speech_event(duration, word_count, suspected_cutoff)
                
                # Update statistics
                self.stats["total_transcriptions"] += 1
                self.stats["total_words"] += word_count
                self.stats["processing_times"].append(processing_time)
                
                # Store in database
                self.store_transcription(transcribed_text, processing_time)
                
                # Call callback if registered
                if self.on_transcription:
                    self.on_transcription(transcribed_text)
                
                # Add cutoff warning if detected
                cutoff_indicator = " ⚠️ CUTOFF?" if suspected_cutoff else ""
                print(f"[STT] ✅ Transcribed: '{transcribed_text}' ({processing_time:.0f}ms){cutoff_indicator}")
                return transcribed_text
            else:
                print("[STT] No speech detected")
                return None
                
        except KeyboardInterrupt:
            print("[INFO] Recording interrupted by user")
            return None
        except MemoryError:
            error_msg = "Out of memory during speech processing"
            print(f"[ERROR] {error_msg}")
            if self.on_error:
                self.on_error(error_msg)
            return None
        except PermissionError:
            error_msg = "Permission denied accessing microphone"
            print(f"[ERROR] {error_msg}")
            if self.on_error:
                self.on_error(error_msg)
            return None
        except Exception as e:
            error_msg = f"Speech processing error: {type(e).__name__}: {e}"
            print(f"[ERROR] {error_msg}")
            if self.on_error:
                self.on_error(error_msg)
            return None
        finally:
            self.is_recording = False
    
    def _detect_potential_cutoff(self, text: str, duration: float) -> bool:
        """
        Simple heuristic to detect potential speech cutoff.
        
        Args:
            text: Transcribed text
            duration: Recording duration in seconds
            
        Returns:
            True if cutoff is suspected, False otherwise
        """
        if not text:
            return False
        
        # Check for common cutoff indicators
        cutoff_indicators = [
            # Text ends abruptly without punctuation
            not text.strip().endswith(('.', '!', '?')),
            # Text ends with incomplete words (common artifacts)
            text.strip().endswith(('the', 'and', 'but', 'or', 'so', 'a', 'an', 'to')),
            # Very short duration for multiple words (might be cut off)
            duration < 1.0 and len(text.split()) > 3,
            # Text ends with partial sentences
            text.strip().endswith(('because', 'since', 'after', 'before', 'when', 'while')),
        ]
        
        # Return True if multiple indicators suggest cutoff
        return sum(cutoff_indicators) >= 2
    
    def _get_cutoff_indicators(self, text: str, duration: float) -> list:
        """Get list of cutoff indicators for debugging."""
        indicators = []
        
        if not text.strip().endswith(('.', '!', '?')):
            indicators.append("no_punctuation_ending")
        
        if text.strip().endswith(('the', 'and', 'but', 'or', 'so', 'a', 'an', 'to')):
            indicators.append("incomplete_word_ending")
        
        if duration < 1.0 and len(text.split()) > 3:
            indicators.append("short_duration_many_words")
        
        if text.strip().endswith(('because', 'since', 'after', 'before', 'when', 'while')):
            indicators.append("partial_sentence_ending")
        
        return indicators
    
    def inject_text(self, text: str, injection_method: str = "auto", 
                   code_context: Optional[str] = None) -> bool:
        """
        Inject text with intelligent IDE integration and context awareness.
        
        Args:
            text: Text to inject into active application
            injection_method: 'auto', 'ide', 'terminal', 'browser', 'system', or 'fallback'
            code_context: Optional programming context hint (e.g., 'python', 'comment')
            
        Returns:
            True if injection succeeded, False otherwise
        """
        if not text:
            return False
        
        safe_text = text[:50] + ('...' if len(text) > 50 else '')
        
        # Auto method selection with IDE priority
        if injection_method == "auto":
            injection_method = self._detect_best_injection_method()
        
        # Try smart IDE injection first if available
        if injection_method in ["auto", "ide"] and self.ide_manager:
            try:
                # Refresh IDE detection to get current state
                self.ide_manager.refresh_detection()
                
                if self.ide_manager.active_ide:
                    # Get current IDE context
                    ide_context = self.ide_manager.get_current_context()
                    
                    # Format text for code context if applicable
                    formatted_text = self._format_text_for_context(text, code_context, ide_context)
                    
                    # Use smart injection
                    if self.ide_manager.inject_text_smart(formatted_text, code_context):
                        print(f"[TEXT] ✅ IDE smart injected ({ide_context.get('ide', 'unknown')}): '{safe_text}'")
                        return True
                    else:
                        print("[TEXT] IDE injection failed, falling back")
                        if injection_method == "ide":
                            injection_method = "system"
                else:
                    print("[TEXT] No active IDE detected, falling back")
                    if injection_method == "ide":
                        injection_method = "system"
                        
            except Exception as e:
                print(f"[TEXT] IDE injection error: {e}")
                if injection_method == "ide":
                    injection_method = "system"
        
        # Try terminal injection
        if injection_method in ["auto", "terminal"] and self.terminal_integration_enabled:
            try:
                terminal_type, metadata = self.terminal_detector.detect_terminal_type()
                if terminal_type.value != 'unknown':
                    if self.terminal_injector.inject_enhanced_text(text, enable_command_processing=True):
                        print(f"[TEXT] ✅ Terminal injected ({terminal_type.value}): '{safe_text}'")
                        return True
                    else:
                        print(f"[TEXT] Terminal injection failed for {terminal_type.value}, falling back")
                        if injection_method == "terminal":
                            injection_method = "system"
            except Exception as e:
                print(f"[TEXT] Terminal injection error: {e}")
                if injection_method == "terminal":
                    injection_method = "system"
        
        # Try browser injection if enabled
        if injection_method == "browser" and self.browser_integration_enabled:
            try:
                if self._inject_text_browser(text):
                    print(f"[TEXT] ✅ Browser injected: '{safe_text}'")
                    return True
                else:
                    print("[TEXT] Browser injection failed, falling back to system")
                    injection_method = "system"
            except Exception as e:
                print(f"[TEXT] Browser injection error: {e}")
                injection_method = "system"
        
        # System injection fallback
        if injection_method == "system" and SYSTEM_INTEGRATION:
            try:
                pyautogui.typewrite(text)
                print(f"[TEXT] ✅ System injected: '{safe_text}'")
                return True
            except PermissionError:
                print("[ERROR] Permission denied for text injection")
                return False
            except Exception as e:
                print(f"[ERROR] System injection failed: {type(e).__name__}: {e}")
                return False
        
        # Final fallback - clipboard
        if injection_method == "fallback":
            try:
                import pyperclip
                pyperclip.copy(text)
                print(f"[TEXT] ✅ Copied to clipboard: '{safe_text}'")
                return True
            except Exception as e:
                print(f"[ERROR] Clipboard injection failed: {e}")
        
        print("[ERROR] All text injection methods failed")
        return False
    
    def _format_text_for_context(self, text: str, code_context: Optional[str], 
                                ide_context: Dict[str, Any]) -> str:
        """
        Format text based on programming context and IDE information.
        
        Args:
            text: Original text to format
            code_context: Optional context hint
            ide_context: IDE context information
            
        Returns:
            Formatted text appropriate for the context
        """
        if not self.code_formatter or not self.code_analyzer:
            return text
        
        try:
            # If we have explicit code context, use it
            if code_context:
                # Create a dummy code position for formatting
                from .code_context_analyzer import CodePosition, CodeContextType, LanguageType
                
                # Map context strings to enum values
                context_map = {
                    'comment': CodeContextType.COMMENT,
                    'string': CodeContextType.STRING,
                    'function': CodeContextType.FUNCTION_DEF,
                    'variable': CodeContextType.VARIABLE,
                    'code': CodeContextType.CODE
                }
                
                language_map = {
                    'python': LanguageType.PYTHON,
                    'javascript': LanguageType.JAVASCRIPT,
                    'typescript': LanguageType.TYPESCRIPT,
                    'java': LanguageType.JAVA,
                    'cpp': LanguageType.CPP,
                    'c': LanguageType.C,
                    'html': LanguageType.HTML,
                    'css': LanguageType.CSS
                }
                
                # Determine language from IDE context or code_context
                language = LanguageType.UNKNOWN
                if 'language' in ide_context and ide_context['language']:
                    language = language_map.get(ide_context['language'].lower(), LanguageType.UNKNOWN)
                elif code_context.lower() in language_map:
                    language = language_map[code_context.lower()]
                
                # Determine context type
                context_type = CodeContextType.CODE
                for key, value in context_map.items():
                    if key in code_context.lower():
                        context_type = value
                        break
                
                # Create position for formatting
                position = CodePosition(
                    line=0,
                    column=0,
                    context_type=context_type,
                    language=language,
                    indentation_level=0,
                    scope=None,
                    preceding_code="",
                    following_code=""
                )
                
                # Format the text
                formatted_text = self.code_formatter.format_for_context(text, position)
                return formatted_text
            
        except Exception as e:
            print(f"[FORMAT] Context formatting failed: {e}")
        
        return text
    
    def _detect_best_injection_method(self) -> str:
        """Detect the best injection method based on active window and application type."""
        try:
            # Check for IDE integration first (highest priority for coding environments)
            if self.ide_manager and self.smart_injection_enabled:
                # Refresh detection to get current IDE state
                detected_ides = self.ide_manager.refresh_detection()
                if detected_ides and self.ide_manager.active_ide:
                    return "ide"
            
            # Check for terminal (high priority for terminal environments)
            if self.terminal_integration_enabled:
                terminal_type, metadata = self.terminal_detector.detect_terminal_type()
                if terminal_type.value != 'unknown':
                    return "terminal"
            
            # Check for browser integration
            if self.browser_integration_enabled and self.browser_engine:
                # Check if there's an active browser session with input elements
                browser_info = self.browser_engine.get_browser_info()
                if browser_info and browser_info.get("current_url"):
                    return "browser"
            
            # Default to system injection
            return "system"
            
        except Exception as e:
            print(f"[DEBUG] Method detection error: {e}")
            return "system"
    
    def _inject_text_browser(self, text: str) -> bool:
        """Inject text using browser integration."""
        if not self.browser_engine:
            return False
        
        # Initialize browser if not already done
        if not self.browser_engine.browser_manager.get_driver():
            browser_config = BrowserConfig(
                browser_type=getattr(BrowserType, self.config.get('browser_type', 'chrome').upper(), BrowserType.CHROME),
                headless=self.config.get('browser_headless', False),
                security_validation=True
            )
            
            if not self.browser_engine.initialize(browser_config):
                return False
        
        return self.browser_engine.inject_text_to_browser(text)
    
    def open_browser_session(self, url: Optional[str] = None, browser_type: str = "chrome") -> bool:
        """
        Open a new browser session for enhanced text injection.
        
        Args:
            url: Optional URL to navigate to
            browser_type: Browser type ('chrome', 'firefox', 'edge', 'safari')
            
        Returns:
            True if browser session opened successfully
        """
        if not self.browser_integration_enabled:
            print("[ERROR] Browser integration not enabled")
            return False
        
        try:
            browser_config = BrowserConfig(
                browser_type=getattr(BrowserType, browser_type.upper(), BrowserType.CHROME),
                headless=self.config.get('browser_headless', False),
                security_validation=True
            )
            
            if self.browser_engine.initialize(browser_config):
                if url:
                    success = self.browser_engine.inject_text_to_browser("", target_url=url)
                    if success:
                        print(f"[BROWSER] ✅ Opened {browser_type} session: {url}")
                    else:
                        print(f"[BROWSER] ⚠️  Opened {browser_type} session but failed to navigate to {url}")
                else:
                    print(f"[BROWSER] ✅ Opened {browser_type} session")
                return True
            else:
                print(f"[ERROR] Failed to open {browser_type} session")
                return False
                
        except Exception as e:
            print(f"[ERROR] Browser session error: {e}")
            return False
    
    def close_browser_session(self):
        """Close the current browser session."""
        if self.browser_engine:
            self.browser_engine.cleanup()
            print("[BROWSER] ✅ Browser session closed")
    
    def get_browser_status(self) -> Dict[str, Any]:
        """Get current browser integration status."""
        status = {
            "integration_enabled": self.browser_integration_enabled,
            "selenium_available": BROWSER_INTEGRATION,
            "active_session": False,
            "browser_info": {}
        }
        
        if self.browser_engine:
            browser_info = self.browser_engine.get_browser_info()
            if browser_info:
                status["active_session"] = True
                status["browser_info"] = browser_info
        
        return status
    
    def detect_browser_inputs(self) -> List[Dict[str, Any]]:
        """Detect input elements in the current browser session."""
        if not self.browser_engine:
            return []
        
        try:
            elements = self.browser_engine.detect_browser_elements()
            return [{
                "type": elem.element_type.value,
                "framework": elem.framework.value,
                "is_focused": elem.is_focused,
                "is_visible": elem.is_visible,
                "selector": elem.selector
            } for elem in elements]
        except Exception as e:
            print(f"[ERROR] Input detection failed: {e}")
            return []
    
    def handle_interruption(self, interruption_type: str = "unknown"):
        """Handle external interruption (phone call, meeting, etc.)"""
        if not self.context_manager:
            return
            
        try:
            interruption_enum = InterruptionType(interruption_type)
        except ValueError:
            interruption_enum = InterruptionType.UNKNOWN
            
        self.context_manager.handle_interruption_start(interruption_enum)
        print(f"[CONTEXT] Handling interruption: {interruption_type}")
    
    def resume_after_interruption(self) -> Dict[str, Any]:
        """Resume after interruption and get recovery context"""
        if not self.context_manager:
            return {"status": "no_context_manager"}
            
        recovery_info = self.context_manager.handle_interruption_end()
        
        # Provide user with context restoration
        if recovery_info.get("pre_interruption_context"):
            suggestion = recovery_info.get("suggested_continuation", "")
            print(f"[CONTEXT] Resume suggestion: {suggestion}")
        
        return recovery_info
    
    def set_context_type(self, context_type: str):
        """Set the current conversation context for adaptive behavior"""
        if not self.pause_detection_enabled:
            return
            
        try:
            context_enum = ContextType(context_type)
            if self.pause_classifier:
                self.pause_classifier.set_context(context_enum)
            
            # Update VAD configuration for new context
            if self.vad_manager and self.recorder:
                new_config = self.vad_manager.get_config_for_context(context_enum)
                # Note: RealtimeSTT doesn't support runtime config changes
                # This would require recorder restart in a full implementation
                print(f"[CONTEXT] Context set to {context_type}. Restart recording for optimal settings.")
                
        except ValueError:
            print(f"[CONTEXT] Unknown context type: {context_type}")
    
    def get_pause_statistics(self) -> Dict[str, Any]:
        """Get comprehensive pause detection statistics"""
        stats = {"pause_detection_enabled": self.pause_detection_enabled}
        
        if self.pause_classifier:
            stats.update(self.pause_classifier.get_pause_statistics())
        
        if self.context_manager:
            stats["session_summary"] = self.context_manager.get_session_summary()
        
        return stats
    
    def setup_hotkeys(self, hotkey: str = 'ctrl+alt', callback: Optional[Callable] = None):
        """
        Setup global hotkeys for voice recording.
        Consolidated hotkey logic from multiple implementations.
        """
        if not SYSTEM_INTEGRATION:
            print("[WARNING] Hotkeys not available - system integration disabled")
            return
        
        def hotkey_handler():
            if callback:
                callback()
            else:
                # Default behavior: process speech and inject text
                result = self.process_speech()
                if result:
                    self.inject_text(result)
        
        try:
            keyboard.add_hotkey(hotkey, hotkey_handler)
            print(f"[HOTKEY] ✅ Registered: {hotkey}")
        except Exception as e:
            print(f"[ERROR] Hotkey registration failed: {e}")
    
    def store_transcription(self, text: str, processing_time: float):
        """Store transcription in secure encrypted database with session tracking."""
        try:
            word_count = len(text.split())
            
            # Get session ID from session manager if available
            session_id = str(self.stats["session_start"])
            if self.enable_long_sessions and self.session_manager:
                session_status = self.session_manager.get_session_status()
                if session_status.get('session_id'):
                    session_id = session_status['session_id']
                
                # Update session stats
                self.session_manager.update_session_stats(
                    transcriptions_delta=1,
                    words_delta=word_count
                )
            
            if self.secure_db:
                # Use encrypted storage
                success = self.secure_db.store_transcription(
                    text=text,
                    processing_time=processing_time,
                    word_count=word_count,
                    model_used=self.config.get('model', 'unknown'),
                    session_id=session_id
                )
                if not success:
                    print("[WARNING] Encrypted storage failed, falling back to plaintext")
                    self._store_fallback(text, processing_time)
            else:
                # Fallback to unencrypted storage
                self._store_fallback(text, processing_time)
                
        except Exception as e:
            print(f"[ERROR] Failed to store transcription: {e}")
    
    def _store_fallback(self, text: str, processing_time: float):
        """Fallback unencrypted storage method."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create legacy table if needed
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transcriptions_legacy (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_text TEXT NOT NULL,
                processing_time_ms INTEGER NOT NULL,
                word_count INTEGER NOT NULL,
                model_used TEXT NOT NULL,
                session_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO transcriptions_legacy 
            (raw_text, processing_time_ms, word_count, model_used, session_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            text,
            int(processing_time),
            len(text.split()),
            self.config.get('model', 'unknown'),
            str(self.stats["session_start"])
        ))
        
        conn.commit()
        conn.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current processing statistics."""
        avg_time = (
            sum(self.stats["processing_times"]) / len(self.stats["processing_times"])
            if self.stats["processing_times"] else 0
        )
        
        stats = {
            "total_transcriptions": self.stats["total_transcriptions"],
            "total_words": self.stats["total_words"],
            "session_duration": str(datetime.now() - self.stats["session_start"]),
            "average_processing_time_ms": round(avg_time, 1),
            "is_recording": self.is_recording
        }
        
        # Add IDE integration status
        if self.ide_manager:
            ide_status = self.ide_manager.get_status()
            stats["ide_integration"] = ide_status
        else:
            stats["ide_integration"] = {"enabled": False, "reason": "not_available"}
        
        # Add long session information
        if self.enable_long_sessions:
            stats["long_session"] = self.get_long_session_status()
        
        return stats
    
    def update_vad_profile(self, profile: str):
        """
        Update VAD profile at runtime.
        
        Args:
            profile: VAD profile ('conservative', 'balanced', 'aggressive')
        """
        if profile not in ['conservative', 'balanced', 'aggressive']:
            print(f"[ERROR] Invalid VAD profile: {profile}")
            return False
        
        try:
            print(f"[VAD] Switching to '{profile}' profile...")
            
            # Update config
            self.config['vad_profile'] = profile
            
            # Reinitialize recorder with new settings
            old_recorder = self.recorder
            self.setup_audio_recorder()
            
            # Clean up old recorder if it exists
            if old_recorder:
                try:
                    del old_recorder
                except:
                    pass
            
            print(f"[VAD] ✅ Profile updated to '{profile}'")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to update VAD profile: {e}")
            return False
    
    def get_vad_status(self) -> Dict[str, Any]:
        """Get current VAD configuration status."""
        profile = self.config.get('vad_profile', 'balanced')
        vad_config = self._get_vad_config(profile)
        
        status = {
            "current_profile": profile,
            "available_profiles": ['conservative', 'balanced', 'aggressive'],
            "current_settings": {
                "silero_sensitivity": vad_config.get('silero_sensitivity'),
                "webrtc_sensitivity": vad_config.get('webrtc_sensitivity'),
                "post_speech_silence_duration": vad_config.get('post_speech_silence_duration'),
                "min_length_of_recording": vad_config.get('min_length_of_recording'),
                "min_gap_between_recordings": vad_config.get('min_gap_between_recordings')
            },
            "cutoff_fix_applied": True
        }
        
        # Add adaptive VAD status if available
        if hasattr(self, 'adaptive_vad') and self.adaptive_vad:
            status["adaptive_vad"] = self.adaptive_vad.get_stats()
        
        return status
    
    def enable_adaptive_vad(self) -> bool:
        """Enable adaptive VAD learning."""
        if hasattr(self, 'adaptive_vad') and self.adaptive_vad:
            self.adaptive_vad.enable_adaptation()
            self.config['adaptive_vad'] = True
            return True
        return False
    
    def disable_adaptive_vad(self) -> bool:
        """Disable adaptive VAD learning."""
        if hasattr(self, 'adaptive_vad') and self.adaptive_vad:
            self.adaptive_vad.disable_adaptation()
            self.config['adaptive_vad'] = False
            return True
        return False
    
    def enable_vad_debug(self) -> bool:
        """Enable VAD debugging."""
        if hasattr(self, 'vad_debug') and self.vad_debug:
            self.vad_debug.enable_debug()
            self.config['enable_vad_debugging'] = True
            return True
        return False
    
    def disable_vad_debug(self) -> bool:
        """Disable VAD debugging."""
        if hasattr(self, 'vad_debug') and self.vad_debug:
            self.vad_debug.disable_debug()
            self.config['enable_vad_debugging'] = False
            return True
        return False
    
    def get_vad_debug_summary(self) -> Dict[str, Any]:
        """Get VAD debugging summary."""
        if hasattr(self, 'vad_debug') and self.vad_debug:
            return self.vad_debug.get_debug_summary()
        return {"status": "debug_not_available"}
    
    def _start_long_session(self):
        """Start long session management."""
        if not self.session_manager:
            return
        
        try:
            # Try to recover previous session first
            if not self.session_manager.recover_session():
                # Start new session
                session_id = self.session_manager.start_session({
                    'model': self.config.get('model', 'base'),
                    'engine_type': 'core',
                    'features': {
                        'pause_detection': getattr(self, 'pause_detection_enabled', False),
                        'noise_processing': getattr(self, 'noise_processing_enabled', False),
                        'ide_integration': getattr(self, 'ide_manager', None) is not None
                    }
                })
                print(f"[Core] Long session started: {session_id}")
            else:
                print("[Core] Previous session recovered")
            
            # Start memory monitoring
            if self.memory_monitor:
                self.memory_monitor.start_monitoring()
        
        except Exception as e:
            print(f"[Core] Long session start failed: {e}")
    
    def get_long_session_status(self) -> Dict[str, Any]:
        """Get long session status and metrics."""
        if not self.enable_long_sessions:
            return {'enabled': False}
        
        status = {'enabled': True}
        
        if self.session_manager:
            status['session'] = self.session_manager.get_session_status()
        
        if self.memory_monitor:
            status['memory'] = self.memory_monitor.get_current_status()
        
        return status
    
    def pause_long_session(self) -> bool:
        """Pause the current long session."""
        if self.enable_long_sessions and self.session_manager:
            return self.session_manager.pause_session()
        return False
    
    def resume_long_session(self) -> bool:
        """Resume a paused long session."""
        if self.enable_long_sessions and self.session_manager:
            return self.session_manager.resume_session()
        return False
    
    def force_memory_cleanup(self):
        """Force memory cleanup for long sessions."""
        if self.memory_monitor:
            # Trigger aggressive cleanup
            import gc
            gc.collect()
            print("[Core] Forced memory cleanup completed")
    
    def cleanup(self):
        """Clean up resources including long session components."""
        # Stop long session components first
        if self.enable_long_sessions:
            try:
                if self.session_manager:
                    self.session_manager.stop_session()
                    print("[Core] ✅ Long session stopped")
                
                if self.memory_monitor:
                    self.memory_monitor.stop_monitoring()
                    print("[Core] ✅ Memory monitoring stopped")
            except Exception as e:
                print(f"[ERROR] Long session cleanup failed: {e}")
        
        if self.recorder:
            try:
                # Stop any ongoing recording
                self.is_recording = False
                print("[STT] ✅ Engine stopped")
            except Exception as e:
                print(f"[ERROR] STT cleanup failed: {e}")
        
        # Clean up pause detection and context management
        if self.context_manager:
            try:
                self.context_manager.cleanup()
                print("[CONTEXT] ✅ Context manager cleaned up")
            except Exception as e:
                print(f"[ERROR] Context cleanup failed: {e}")
        
        # Clean up browser integration
        if self.browser_engine:
            try:
                self.browser_engine.cleanup()
                print("[BROWSER] ✅ Browser integration cleaned up")
            except Exception as e:
                print(f"[ERROR] Browser cleanup failed: {e}")
        
        # Clean up noise processing
        if self.quality_monitor:
            try:
                self.quality_monitor.stop_monitoring()
                print("[NOISE] ✅ Quality monitoring stopped")
            except Exception as e:
                print(f"[ERROR] Quality monitor cleanup failed: {e}")
    
    def add_audio_for_analysis(self, audio_data: np.ndarray):
        """Add audio data for noise analysis and quality monitoring"""
        if ADVANCED_NOISE_PROCESSING:
            if self.noise_analyzer:
                self.noise_analyzer.add_audio_frame(audio_data)
            if self.quality_monitor:
                self.quality_monitor.add_audio_data(audio_data)
    
    def process_audio_with_noise_reduction(self, audio_data: np.ndarray) -> np.ndarray:
        """Process audio data with noise reduction if enabled"""
        if not self.noise_processing_enabled or not self.noise_reducer:
            return audio_data
        
        if self.current_noise_profile is None:
            return audio_data
        
        try:
            # Apply noise gate first
            if self.noise_gate:
                gated_audio = self.noise_gate.process(audio_data)
            else:
                gated_audio = audio_data
            
            # Apply spectral subtraction
            clean_audio = self.noise_reducer.spectral_subtraction(gated_audio, self.current_noise_profile)
            
            # Apply Wiener filtering for additional cleaning
            final_audio = self.noise_reducer.adaptive_wiener_filter(clean_audio, self.current_noise_profile)
            
            return final_audio
            
        except Exception as e:
            print(f"[NOISE] Audio processing error: {e}")
            return audio_data
    
    def analyze_and_adapt_to_noise(self):
        """Analyze current noise conditions and adapt VAD settings"""
        if not self.adaptive_noise_vad_enabled or not self.noise_analyzer:
            return
        
        # Analyze current noise conditions
        noise_profile = self.noise_analyzer.analyze_current_noise()
        if noise_profile:
            self._adapt_to_noise_conditions(noise_profile)
    
    def _adapt_to_noise_conditions(self, noise_profile: NoiseProfile):
        """Adapt VAD and processing based on noise conditions"""
        if not self.adaptive_noise_vad_enabled or not self.noise_vad_manager:
            return
        
        # Store current noise profile
        self.current_noise_profile = noise_profile
        
        # Get adapted VAD configuration
        new_config = self.noise_vad_manager.adapt_config(noise_profile)
        
        # Log adaptation
        print(f"[NOISE-VAD] Adapted to {noise_profile.environment.value} environment (SNR: {noise_profile.snr_estimate:.1f}dB)")
        print(f"[NOISE-VAD] Silero sensitivity: {new_config.silero_sensitivity:.2f}, WebRTC: {new_config.webrtc_sensitivity}")
        
        # Update noise gate threshold
        if self.noise_gate:
            self.noise_gate.set_adaptive_threshold(noise_profile)
        
        # Update statistics
        if "noise_adaptations" not in self.stats:
            self.stats["noise_adaptations"] = 0
        self.stats["noise_adaptations"] += 1
    
    def get_noise_status(self) -> Dict[str, Any]:
        """Get current noise processing status"""
        if not ADVANCED_NOISE_PROCESSING:
            return {"status": "unavailable", "message": "Advanced noise processing not available"}
        
        status = {
            "noise_processing_enabled": self.noise_processing_enabled,
            "adaptive_noise_vad_enabled": self.adaptive_noise_vad_enabled,
            "current_environment": None,
            "current_snr_db": None,
            "noise_vad_sensitivity": None,
            "quality_score": None
        }
        
        if self.current_noise_profile:
            status.update({
                "current_environment": self.current_noise_profile.environment.value,
                "current_snr_db": round(self.current_noise_profile.snr_estimate, 1),
                "noise_floor_db": round(self.current_noise_profile.noise_floor, 1),
                "confidence": round(self.current_noise_profile.confidence, 2),
                "noise_type": self.current_noise_profile.noise_type.value
            })
        
        if self.noise_vad_manager:
            config = self.noise_vad_manager.current_config
            status["noise_vad_sensitivity"] = {
                "silero": config.silero_sensitivity,
                "webrtc": config.webrtc_sensitivity,
                "post_speech_silence": config.post_speech_silence_duration
            }
        
        if self.quality_monitor:
            summary = self.quality_monitor.analyzer.get_quality_summary(30.0)  # Last 30 seconds
            if summary.get('status') == 'ok':
                status["quality_score"] = round(summary.get('current_quality_score', 0), 1)
                status["quality_recommendations"] = summary.get('recommendations', [])
        
        return status
    
    def start_quality_monitoring(self):
        """Start audio quality monitoring"""
        if self.quality_monitor and not self.quality_monitor.is_monitoring:
            self.quality_monitor.start_monitoring()
            self.quality_monitor.on_quality_alert = self._handle_quality_alert
            print("[QUALITY] ✅ Audio quality monitoring started")
    
    def _handle_quality_alert(self, alert):
        """Handle audio quality alerts"""
        print(f"[QUALITY] {alert.severity.upper()}: {alert.message}")
        if alert.recommendations:
            print(f"[QUALITY] Recommendations: {', '.join(alert.recommendations[:2])}")
        
        if "quality_alerts" not in self.stats:
            self.stats["quality_alerts"] = 0
        self.stats["quality_alerts"] += 1
        
        # Auto-adapt to severe quality issues
        if alert.severity in ['critical', 'high'] and self.current_noise_profile:
            if alert.alert_type == 'low_snr':
                print("[NOISE-VAD] Auto-adjusting for low SNR conditions")
                # Could trigger automatic sensitivity adjustments
            elif alert.alert_type == 'clipping_risk':
                print("[QUALITY] Warning: Signal clipping detected - reduce input gain")


def create_engine(config: Optional[Dict[str, Any]] = None) -> VoiceFlowEngine:
    """Factory function to create a configured VoiceFlow engine."""
    default_config = {
        'model': os.getenv('VOICEFLOW_MODEL', 'base'),
        'device': os.getenv('VOICEFLOW_DEVICE', 'auto'),
        'enable_ai_enhancement': os.getenv('ENABLE_AI_ENHANCEMENT', 'true').lower() == 'true',
        'enable_noise_processing': os.getenv('ENABLE_NOISE_PROCESSING', 'true').lower() == 'true',
        'enable_adaptive_noise_vad': os.getenv('ENABLE_ADAPTIVE_NOISE_VAD', 'true').lower() == 'true'
    }
    
    if config:
        default_config.update(config)
    
    return VoiceFlowEngine(default_config)