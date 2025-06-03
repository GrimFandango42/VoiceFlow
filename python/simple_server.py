"""
VoiceFlow Simple Server - FIXED VERSION
- No infinite loops with timeout protection
- Minimal logging (just timestamps and results)
- Clean session toggle functionality
"""

import time
import threading
from datetime import datetime
from pathlib import Path
import sqlite3
import signal
import sys

try:
    import requests
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

try:
    import pyautogui
    import keyboard
    SYSTEM_INTEGRATION = True
    pyautogui.FAILSAFE = False
except ImportError:
    SYSTEM_INTEGRATION = False

try:
    from RealtimeSTT import AudioToTextRecorder
    STT_AVAILABLE = True
except ImportError:
    STT_AVAILABLE = False

class SimpleVoiceFlowServer:
    def __init__(self):
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "transcriptions.db"
        
        # State management for clean sessions
        self.is_recording = False
        self.is_processing = False
        self.shutdown_flag = False
        self.last_recording_time = 0
        
        # Initialize database
        self.init_database()
        
        # Test Ollama
        self.use_ai_enhancement = False
        if OLLAMA_AVAILABLE:
            self.test_ollama_connection()
        
        # Initialize STT
        self.recorder = None
        if STT_AVAILABLE:
            self.init_recorder()
            
    def init_recorder(self):
        """Initialize STT recorder with timeout protection and minimal logging"""
        try:
            self.recorder = AudioToTextRecorder(
                model="tiny",
                language="en", 
                device="cpu",
                compute_type="int8",
                use_microphone=True,
                spinner=False,
                level=0,
                enable_realtime_transcription=False,
                silero_sensitivity=0.4,
                webrtc_sensitivity=3,
                post_speech_silence_duration=0.8,
                min_length_of_recording=0.5,
                min_gap_between_recordings=0.3,
                on_recording_start=self.on_recording_start,
                on_recording_stop=self.on_recording_stop
            )
            return True
        except Exception as e:
            print(f"[ERROR] STT initialization failed: {e}")
            return False
            
    def on_recording_start(self):
        """Called when recording starts - minimal logging"""
        self.is_recording = True
        self.start_time = datetime.now()
        print(f"Recording started: {self.start_time.strftime('%H:%M:%S')}")
        
    def on_recording_stop(self):
        """Called when recording stops - show duration"""
        self.is_recording = False
        if hasattr(self, 'start_time'):
            end_time = datetime.now()
            duration = (end_time - self.start_time).total_seconds()
            print(f"Recording stopped: {end_time.strftime('%H:%M:%S')} - {duration:.1f}s duration")
            
    def test_ollama_connection(self):
        """Test Ollama connection with short timeout"""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=1)
            if response.status_code == 200:
                self.use_ai_enhancement = True
                return True
        except:
            pass
        return False
        
    def init_database(self):
        """Initialize database for transcription history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    text TEXT,
                    duration REAL
                )
            ''')
            conn.commit()
            conn.close()
        except:
            pass
            
    def enhance_text(self, text):
        """Basic text enhancement - simple and fast"""
        if not text:
            return ""
            
        # Basic formatting only
        text = text.strip()
        if text:
            text = text[0].upper() + text[1:]
            if not text[-1] in '.!?':
                text += '.'
        return text
        
    def inject_text(self, text):
        """Inject text at cursor position"""
        if not SYSTEM_INTEGRATION or not text:
            return False
            
        try:
            pyautogui.typewrite(text)
            return True
        except Exception as e:
            print(f"[ERROR] Text injection failed: {e}")
            return False
            
    def save_transcription(self, text, duration):
        """Save transcription to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO transcriptions (text, duration)
                VALUES (?, ?)
            ''', (text, duration))
            conn.commit()
            conn.close()
        except:
            pass
            
    def process_speech_with_timeout(self):
        """Process speech with timeout protection to prevent infinite loops"""
        if not STT_AVAILABLE or not self.recorder:
            return False
            
        # Prevent concurrent processing
        if self.is_processing:
            return False
            
        self.is_processing = True
        
        try:
            # Set timeout protection
            start_process_time = time.time()
            
            # Use threading to implement timeout
            result_container = {'text': None, 'completed': False, 'error': None}
            
            def get_text():
                try:
                    result_container['text'] = self.recorder.text()
                    result_container['completed'] = True
                except Exception as e:
                    result_container['error'] = str(e)
                    result_container['completed'] = True
            
            # Start transcription in thread
            thread = threading.Thread(target=get_text, daemon=True)
            thread.start()
            
            # Wait with timeout (max 10 seconds to prevent infinite blocking)
            timeout = 10
            thread.join(timeout)
            
            if not result_container['completed']:
                print("[TIMEOUT] Speech processing timed out")
                return False
                
            if result_container['error']:
                print(f"[ERROR] {result_container['error']}")
                return False
                
            raw_text = result_container['text']
            
            if not raw_text or not raw_text.strip():
                return False
                
            # Process the text
            enhanced_text = self.enhance_text(raw_text)
            duration = time.time() - start_process_time
            
            # Output result (minimal logging)
            print(enhanced_text)
            
            # Save transcription
            self.save_transcription(enhanced_text, duration)
            
            # Inject text
            self.inject_text(enhanced_text)
            
            # Small delay to prevent rapid-fire recordings
            time.sleep(0.5)
            
            return True
            
        except Exception as e:
            print(f"[ERROR] {e}")
            return False
        finally:
            self.is_processing = False
            
    def start_hotkey_listener(self):
        """Start hotkey listener with debouncing to prevent rapid-fire"""
        if not SYSTEM_INTEGRATION:
            return False
            
        def hotkey_handler():
            current_time = time.time()
            
            # Debounce: prevent rapid-fire activations
            if current_time - self.last_recording_time < 1.0:
                return
                
            self.last_recording_time = current_time
            
            # Process in separate thread to avoid blocking
            threading.Thread(target=self.process_speech_with_timeout, daemon=True).start()
            
        try:
            keyboard.add_hotkey('ctrl+alt', hotkey_handler)
            return True
        except Exception as e:
            print(f"[ERROR] Hotkey registration failed: {e}")
            return False
            
    def cleanup(self):
        """Clean shutdown to prevent hanging"""
        self.shutdown_flag = True
        if self.recorder:
            try:
                self.recorder.shutdown()
            except:
                pass
                
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print("\n[SHUTDOWN] Stopping VoiceFlow...")
        self.cleanup()
        sys.exit(0)
        
    def run(self):
        """Run the server with clean session management"""
        print("\n" + "="*40)
        print("VoiceFlow Simple - READY")
        print("="*40)
        
        if not STT_AVAILABLE:
            print("[ERROR] RealtimeSTT not available")
            return
            
        if not SYSTEM_INTEGRATION:
            print("[ERROR] System integration not available")
            return
            
        # Register signal handler for clean exit
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Start hotkey listener
        if self.start_hotkey_listener():
            print("Press Ctrl+Alt and speak!")
            print("Press Ctrl+C to exit\n")
            
            try:
                # Keep running with proper exit conditions
                while not self.shutdown_flag:
                    time.sleep(0.1)  # Short sleep to reduce CPU usage
            except KeyboardInterrupt:
                self.cleanup()
        else:
            print("[ERROR] Could not start hotkey listener")

if __name__ == "__main__":
    try:
        server = SimpleVoiceFlowServer()
        server.run()
    except Exception as e:
        print(f"[FATAL] Server failed to start: {e}")
        sys.exit(1)
