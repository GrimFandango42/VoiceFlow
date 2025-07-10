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

# Import secure database utilities
try:
    from utils.secure_db import create_secure_database
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("[WARNING] Encryption not available - install cryptography package")

try:
    from RealtimeSTT import AudioToTextRecorder
    import pyautogui
    import keyboard
    SYSTEM_INTEGRATION = True
except ImportError:
    SYSTEM_INTEGRATION = False
    print("System integration packages not installed. Text injection disabled.")


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
        
        # Initialize components
        self.init_database()
        self.setup_audio_recorder()
    
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
    
    def setup_audio_recorder(self):
        """Setup audio recorder with GPU/CPU fallback logic."""
        # Get model preference from config
        model = self.config.get('model', 'base')
        device = self.config.get('device', 'auto')
        
        # Common recorder parameters extracted from duplicate implementations
        common_params = {
            "language": "en",
            "use_microphone": True,
            "spinner": False,
            "level": 0,
            "enable_realtime_transcription": True,
            "silero_sensitivity": 0.4,
            "webrtc_sensitivity": 3,
            "post_speech_silence_duration": 0.8,
            "min_length_of_recording": 0.2,
            "min_gap_between_recordings": 0.3
        }
        
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
    
    def process_speech(self) -> Optional[str]:
        """
        Process speech input and return transcription.
        Consolidated from multiple duplicate implementations.
        """
        if not self.recorder:
            print("[ERROR] STT recorder not initialized")
            return None
        
        # Prevent rapid successive recordings
        current_time = time.time()
        if current_time - self.last_recording_time < 1.0:
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
                # Update statistics
                self.stats["total_transcriptions"] += 1
                self.stats["total_words"] += len(transcribed_text.split())
                self.stats["processing_times"].append(processing_time)
                
                # Store in database
                self.store_transcription(transcribed_text, processing_time)
                
                # Call callback if registered
                if self.on_transcription:
                    self.on_transcription(transcribed_text)
                
                print(f"[STT] ✅ Transcribed: '{transcribed_text}' ({processing_time:.0f}ms)")
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
    
    def inject_text(self, text: str) -> bool:
        """
        Inject text into the active application.
        Consolidated text injection logic from multiple files.
        
        Args:
            text: Text to inject into active application
            
        Returns:
            True if injection succeeded, False otherwise
        """
        if not SYSTEM_INTEGRATION or not text:
            return False
        
        try:
            # Basic text injection using pyautogui
            pyautogui.typewrite(text)
            safe_text = text[:50] + ('...' if len(text) > 50 else '')
            print(f"[TEXT] ✅ Injected: '{safe_text}'")
            return True
        except PermissionError:
            print("[ERROR] Permission denied for text injection")
            return False
        except Exception as e:
            print(f"[ERROR] Text injection failed: {type(e).__name__}: {e}")
            return False
    
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
        """Store transcription in secure encrypted database."""
        try:
            if self.secure_db:
                # Use encrypted storage
                success = self.secure_db.store_transcription(
                    text=text,
                    processing_time=processing_time,
                    word_count=len(text.split()),
                    model_used=self.config.get('model', 'unknown'),
                    session_id=str(self.stats["session_start"])
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
        
        return {
            "total_transcriptions": self.stats["total_transcriptions"],
            "total_words": self.stats["total_words"],
            "session_duration": str(datetime.now() - self.stats["session_start"]),
            "average_processing_time_ms": round(avg_time, 1),
            "is_recording": self.is_recording
        }
    
    def cleanup(self):
        """Clean up resources."""
        if self.recorder:
            try:
                # Stop any ongoing recording
                self.is_recording = False
                print("[STT] ✅ Engine stopped")
            except Exception as e:
                print(f"[ERROR] Cleanup failed: {e}")


def create_engine(config: Optional[Dict[str, Any]] = None) -> VoiceFlowEngine:
    """Factory function to create a configured VoiceFlow engine."""
    default_config = {
        'model': os.getenv('VOICEFLOW_MODEL', 'base'),
        'device': os.getenv('VOICEFLOW_DEVICE', 'auto'),
        'enable_ai_enhancement': os.getenv('ENABLE_AI_ENHANCEMENT', 'true').lower() == 'true'
    }
    
    if config:
        default_config.update(config)
    
    return VoiceFlowEngine(default_config)