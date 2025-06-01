"""
VoiceFlow Simple Server - WORKING VERSION
Focuses on core transcription functionality without complex WebSocket server
"""

import time
import threading
from datetime import datetime
from pathlib import Path
import sqlite3
try:
    import requests
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

try:
    import pyautogui
    import keyboard
    SYSTEM_INTEGRATION = True
    pyautogui.FAILSAFE = False  # Disable failsafe for automation
except ImportError:
    SYSTEM_INTEGRATION = False
    print("WARNING: System integration packages not installed. Text injection disabled.")

try:
    from RealtimeSTT import AudioToTextRecorder
    STT_AVAILABLE = True
except ImportError:
    STT_AVAILABLE = False
    print("ERROR: RealtimeSTT not available")

class SimpleVoiceFlowServer:
    def __init__(self):
        print("[INIT] Starting Simple VoiceFlow Server...")
        
        # Initialize paths
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "transcriptions.db"
        
        # Initialize database
        self.init_database()
        
        # Test Ollama connectivity
        self.ollama_url = None
        self.use_ai_enhancement = False
        if OLLAMA_AVAILABLE:
            self.test_ollama_connection()
        
        # Statistics
        self.stats = {
            "total_transcriptions": 0,
            "total_words": 0,
            "session_start": datetime.now(),
        }
        
        # Initialize STT recorder with STABLE settings
        if STT_AVAILABLE:
            self.init_recorder()
        else:
            print("[ERROR] Cannot initialize recorder - RealtimeSTT not available")
            
    def init_recorder(self):
        """Initialize the STT recorder with stable settings"""
        try:
            print("[INIT] Initializing STT recorder...")
            self.recorder = AudioToTextRecorder(
                model="tiny",  # Use tiny model for stability
                language="en",
                device="cpu",  # Force CPU to avoid GPU issues
                compute_type="int8",  # Force int8 for compatibility
                use_microphone=True,
                spinner=False,
                level=0,  # Minimal logging
                # Disable realtime for simplicity
                enable_realtime_transcription=False,
                # Conservative VAD settings
                silero_sensitivity=0.5,
                webrtc_sensitivity=3,
                post_speech_silence_duration=0.4,
                min_length_of_recording=0.5,
                min_gap_between_recordings=0.3,
            )
            print("[OK] STT recorder initialized successfully")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to initialize STT recorder: {e}")
            return False
            
    def test_ollama_connection(self):
        """Test Ollama connectivity"""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=2)
            if response.status_code == 200:
                self.ollama_url = "http://localhost:11434/api/generate"
                self.use_ai_enhancement = True
                models = response.json().get('models', [])
                print(f"[OK] Ollama connected, found {len(models)} models")
                return True
        except Exception:
            pass
        
        print("[WARNING] Ollama not available - using basic text formatting")
        return False
        
    def init_database(self):
        """Initialize SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    raw_text TEXT,
                    enhanced_text TEXT,
                    word_count INTEGER
                )
            ''')
            conn.commit()
            conn.close()
            print("[OK] Database initialized")
        except Exception as e:
            print(f"[WARNING] Database initialization failed: {e}")
            
    def enhance_text(self, text):
        """Enhance text with AI or basic formatting"""
        if not text:
            return ""
            
        if self.use_ai_enhancement and self.ollama_url:
            try:
                prompt = f"Format this speech with proper punctuation and capitalization: {text}"
                response = requests.post(self.ollama_url, json={
                    "model": "llama3.3:latest",
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3,
                }, timeout=10)
                
                if response.status_code == 200:
                    enhanced = response.json().get('response', text).strip()
                    if enhanced.startswith('"') and enhanced.endswith('"'):
                        enhanced = enhanced[1:-1]
                    return enhanced
            except Exception as e:
                print(f"[WARNING] AI enhancement failed: {e}")
        
        # Basic formatting fallback
        text = text.strip()
        if text:
            text = text[0].upper() + text[1:]
            if not text[-1] in '.!?':
                text += '.'
        return text
        
    def inject_text(self, text):
        """Inject text at cursor position"""
        if not SYSTEM_INTEGRATION:
            print(f"[TEXT] {text}")
            return False
            
        try:
            print(f"[INJECTING] {text}")
            pyautogui.typewrite(text)
            print("[SUCCESS] Text injected successfully")
            return True
        except Exception as e:
            print(f"[ERROR] Text injection failed: {e}")
            return False
            
    def save_transcription(self, raw_text, enhanced_text):
        """Save transcription to database"""
        try:
            word_count = len(enhanced_text.split()) if enhanced_text else 0
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO transcriptions (raw_text, enhanced_text, word_count)
                VALUES (?, ?, ?)
            ''', (raw_text, enhanced_text, word_count))
            conn.commit()
            conn.close()
            
            # Update stats
            self.stats["total_transcriptions"] += 1
            self.stats["total_words"] += word_count
            
        except Exception as e:
            print(f"[WARNING] Could not save transcription: {e}")
            
    def process_speech(self):
        """Process one speech input"""
        if not STT_AVAILABLE:
            print("[ERROR] STT not available")
            return False
            
        try:
            print("[LISTENING] Press Ctrl+Alt and speak...")
            
            # Wait for speech input
            raw_text = self.recorder.text()
            
            if not raw_text or not raw_text.strip():
                print("[WARNING] No speech detected")
                return False
                
            print(f"[RAW] {raw_text}")
            
            # Enhance the text
            enhanced_text = self.enhance_text(raw_text)
            print(f"[ENHANCED] {enhanced_text}")
            
            # Save to database
            self.save_transcription(raw_text, enhanced_text)
            
            # Inject text
            success = self.inject_text(enhanced_text)
            
            return success
            
        except Exception as e:
            print(f"[ERROR] Speech processing failed: {e}")
            return False
            
    def start_hotkey_listener(self):
        """Start hotkey listener"""
        if not SYSTEM_INTEGRATION:
            print("[WARNING] Hotkey listener not available")
            return False
            
        def hotkey_handler():
            print("[HOTKEY] Ctrl+Alt pressed - processing speech...")
            self.process_speech()
            
        try:
            keyboard.add_hotkey('ctrl+alt', hotkey_handler)
            print("[OK] Hotkey listener registered: Ctrl+Alt")
            return True
        except Exception as e:
            print(f"[ERROR] Could not register hotkey: {e}")
            return False
            
    def run(self):
        """Run the server"""
        print("\n" + "="*60)
        print("VoiceFlow Simple Server - READY")
        print("="*60)
        
        if not STT_AVAILABLE:
            print("[ERROR] RealtimeSTT not available - cannot run")
            return
            
        # Show configuration
        print(f"[CONFIG] STT Model: tiny (CPU/int8)")
        print(f"[CONFIG] AI Enhancement: {'Enabled' if self.use_ai_enhancement else 'Disabled'}")
        print(f"[CONFIG] Text Injection: {'Enabled' if SYSTEM_INTEGRATION else 'Disabled'}")
        print(f"[CONFIG] Data Directory: {self.data_dir}")
        
        # Start hotkey listener
        if self.start_hotkey_listener():
            print("\n[READY] Press Ctrl+Alt and speak to test VoiceFlow!")
            print("[INFO] Press Ctrl+C to exit")
            
            try:
                # Keep the server running
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[SHUTDOWN] Server stopped by user")
        else:
            print("\n[ERROR] Could not start hotkey listener")
            print("[MANUAL] You can test manually by calling process_speech()")

if __name__ == "__main__":
    try:
        server = SimpleVoiceFlowServer()
        server.run()
    except Exception as e:
        print(f"[FATAL] Server failed to start: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")
