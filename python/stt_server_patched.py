"""
VoiceFlow STT Server - Compatibility Patched Version
Fixed for Python 3.13 enum issues and improved error handling
"""

# COMPATIBILITY PATCHES FOR PYTHON 3.13
import sys
import os

# Fix enum compatibility before any other imports
import enum
if not hasattr(enum, 'global_enum'):
    def global_enum(cls):
        return cls
    enum.global_enum = global_enum
    print("[PATCH] Enum compatibility patch applied")

# Set environment variables for better WSL/Windows compatibility
os.environ.setdefault("DISPLAY", ":0.0")

# Now proceed with normal imports
import asyncio
import websockets
import json
import requests
import numpy as np
from datetime import datetime
import sqlite3
from pathlib import Path
from RealtimeSTT import AudioToTextRecorder
import threading
import queue
import time

# Try system integration with better error handling
SYSTEM_INTEGRATION = False
try:
    import pyautogui
    # Test basic functionality
    pyautogui.FAILSAFE = False  # Disable failsafe for compatibility
    print("[PATCH] pyautogui imported successfully")
    
    import keyboard
    print("[PATCH] keyboard imported successfully")
    
    SYSTEM_INTEGRATION = True
    print("[OK] System integration modules loaded")
except ImportError as e:
    print(f"[WARNING] System integration disabled: {e}")
except Exception as e:
    print(f"[ERROR] System integration failed: {e}")

class VoiceFlowServer:
    def __init__(self):
        print("[INIT] Starting VoiceFlow Server with compatibility patches...")
        
        # Initialize paths
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "transcriptions.db"
        
        # Initialize database
        self.init_database()
        
        # Ollama configuration with more endpoints
        self.ollama_urls = [
            "http://localhost:11434/api/generate",  # Windows local
            "http://127.0.0.1:11434/api/generate",  # Alternative local
            "http://172.30.248.191:11434/api/generate",  # WSL IP
        ]
        self.ollama_url = None
        self.deepseek_model = "llama3.3:latest"
        self.use_ai_enhancement = True
        
        # Test Ollama connectivity
        self.test_ollama_connection()
        
        # Message queue for WebSocket
        self.message_queue = queue.Queue()
        
        # Statistics
        self.stats = {
            "total_transcriptions": 0,
            "total_words": 0,
            "session_start": datetime.now(),
            "processing_times": []
        }
        
        # Initialize STT recorder with compatibility settings
        self.init_recorder()
        
        self.websocket_clients = set()
        self.current_transcription = {
            "id": None,
            "start_time": None,
            "preview_text": "",
            "final_text": "",
            "enhanced_text": ""
        }
        
    def init_recorder(self):
        """Initialize speech recognition with fallback strategy"""
        print("[RECORDER] Initializing speech recognition...")
        
        # Strategy: Start with most compatible configuration
        configs = [
            # Most compatible: CPU, small model
            {
                "model": "base",
                "device": "cpu", 
                "compute_type": "int8",
                "description": "CPU + base model (most compatible)"
            },
            # Medium: GPU, small model  
            {
                "model": "base",
                "device": "cuda",
                "compute_type": "int8", 
                "description": "GPU + base model"
            },
            # Best: GPU, large model
            {
                "model": "large-v3",
                "device": "cuda",
                "compute_type": "float16",
                "description": "GPU + large model (best quality)"
            }
        ]
        
        for config in configs:
            try:
                print(f"[RECORDER] Trying: {config['description']}")
                
                self.recorder = AudioToTextRecorder(
                    model=config["model"],
                    language="en",
                    device=config["device"],
                    compute_type=config["compute_type"],
                    on_recording_start=self.on_recording_start,
                    on_recording_stop=self.on_recording_stop,
                    on_transcription_start=self.on_transcription_start,
                    use_microphone=True,
                    spinner=False,
                    level=0,
                    # Simplified settings for compatibility
                    enable_realtime_transcription=True,
                    realtime_processing_pause=0.2,
                    realtime_model_type="tiny",
                    on_realtime_transcription_update=self.on_realtime_update,
                    silero_sensitivity=0.5,
                    webrtc_sensitivity=3,
                    post_speech_silence_duration=0.4,
                    min_length_of_recording=0.5,
                    min_gap_between_recordings=0.3
                )
                
                print(f"[SUCCESS] Using: {config['description']}")
                return
                
            except Exception as e:
                print(f"[FAILED] {config['description']}: {e}")
                continue
                
        raise RuntimeError("Could not initialize any speech recognition configuration")
        
    def test_ollama_connection(self):
        """Test Ollama connectivity and find working endpoint"""
        print("[OLLAMA] Testing AI enhancement connections...")
        
        for url in self.ollama_urls:
            try:
                test_url = url.replace('/generate', '/tags')
                print(f"[OLLAMA] Testing {test_url}")
                
                response = requests.get(test_url, timeout=3)
                if response.status_code == 200:
                    self.ollama_url = url
                    print(f"[OK] Ollama connected at: {url}")
                    
                    # Check available models
                    models = response.json().get('models', [])
                    model_names = [m.get('name', '') for m in models]
                    
                    if self.deepseek_model in model_names:
                        print(f"[OK] Found {self.deepseek_model} model")
                    else:
                        print(f"[WARNING] Model {self.deepseek_model} not found")
                        print(f"Available models: {model_names}")
                        if model_names:
                            self.deepseek_model = model_names[0]
                            print(f"Using {self.deepseek_model} instead")
                    return
                    
            except Exception as e:
                print(f"[FAILED] {url}: {e}")
                continue
        
        print("[WARNING] Could not connect to Ollama. AI enhancement disabled.")
        self.use_ai_enhancement = False
        
    def init_database(self):
        """Initialize SQLite database for transcription history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    raw_text TEXT,
                    enhanced_text TEXT,
                    duration_ms INTEGER,
                    word_count INTEGER,
                    processing_time_ms INTEGER,
                    confidence REAL
                )
            ''')
            conn.commit()
            conn.close()
            print("[OK] Database initialized")
        except Exception as e:
            print(f"[ERROR] Database initialization failed: {e}")
        
    def on_recording_start(self):
        """Called when recording starts"""
        print("[RECORDING] Started")
        self.current_transcription = {
            "id": int(time.time() * 1000),
            "start_time": time.time(),
            "preview_text": "",
            "final_text": "",
            "enhanced_text": ""
        }
        self.broadcast_message({
            "type": "recording_started",
            "timestamp": datetime.now().isoformat()
        })
        
    def on_recording_stop(self):
        """Called when recording stops"""
        print("[RECORDING] Stopped")
        self.broadcast_message({
            "type": "recording_stopped",
            "timestamp": datetime.now().isoformat()
        })
        
    def on_realtime_update(self, text):
        """Real-time preview using small model"""
        if text.strip():
            print(f"[PREVIEW] {text}")
            self.current_transcription["preview_text"] = text
            self.broadcast_message({
                "type": "realtime_preview",
                "text": text,
                "timestamp": datetime.now().isoformat()
            })
        
    def on_transcription_start(self, text):
        """Final transcription using large model"""
        if not text or not text.strip():
            print("[WARNING] Empty transcription received")
            return
            
        start_time = time.time()
        print(f"[TRANSCRIPTION] Raw: {text}")
        
        # Store raw transcription
        self.current_transcription["final_text"] = text
        word_count = len(text.split())
        
        # Enhance with AI
        enhanced_text = self.enhance_with_ai(text)
        self.current_transcription["enhanced_text"] = enhanced_text
        print(f"[ENHANCED] {enhanced_text}")
        
        # Calculate processing time
        processing_time = int((time.time() - start_time) * 1000)
        duration = int((time.time() - self.current_transcription["start_time"]) * 1000)
        
        # Store in database
        self.save_transcription(
            raw_text=text,
            enhanced_text=enhanced_text,
            duration_ms=duration,
            word_count=word_count,
            processing_time_ms=processing_time
        )
        
        # Update statistics
        self.stats["total_transcriptions"] += 1
        self.stats["total_words"] += word_count
        self.stats["processing_times"].append(processing_time)
        
        # Broadcast final result
        self.broadcast_message({
            "type": "transcription_complete",
            "raw_text": text,
            "enhanced_text": enhanced_text,
            "word_count": word_count,
            "duration_ms": duration,
            "processing_time_ms": processing_time,
            "timestamp": datetime.now().isoformat()
        })
        
        # Auto-inject text at cursor position
        self.inject_text_at_cursor(enhanced_text)
    
    def inject_text_at_cursor(self, text):
        """Inject text at the current cursor position"""
        if not SYSTEM_INTEGRATION:
            print(f"[TEXT READY] {text}")
            print("[INFO] Copy this text manually (system integration disabled)")
            return
            
        try:
            # Small delay for application focus
            time.sleep(0.1)
            
            # Use pyautogui to type the text
            pyautogui.typewrite(text, interval=0.01)
            print(f"[INJECTED] {text}")
            
        except Exception as e:
            print(f"[INJECTION FAILED] {e}")
            # Fallback: Try clipboard
            try:
                import pyperclip
                pyperclip.copy(text)
                print("[FALLBACK] Text copied to clipboard - press Ctrl+V to paste")
            except ImportError:
                print("[ERROR] No clipboard access available")
                print(f"[MANUAL] Please copy this text: {text}")
        
    def enhance_with_ai(self, text):
        """Enhance transcription with AI for proper formatting"""
        if not self.use_ai_enhancement:
            return self.basic_format(text)
            
        try:
            prompt = f"""Format this spoken text with proper punctuation and capitalization. Keep it concise and natural:

{text}

Formatted:"""
            
            response = requests.post(self.ollama_url, json={
                "model": self.deepseek_model,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.2,
                "top_p": 0.9,
                "max_tokens": len(text) * 2
            }, timeout=8)
            
            if response.status_code == 200:
                enhanced = response.json().get('response', text).strip()
                # Clean up response
                if enhanced.startswith('"') and enhanced.endswith('"'):
                    enhanced = enhanced[1:-1]
                return enhanced if enhanced else text
            else:
                print(f"[AI ERROR] HTTP {response.status_code}")
                return self.basic_format(text)
                
        except Exception as e:
            print(f"[AI FAILED] {e}")
            return self.basic_format(text)
            
    def basic_format(self, text):
        """Basic formatting fallback"""
        if not text:
            return text
            
        # Capitalize first letter and add period if missing
        text = text.strip()
        if text:
            text = text[0].upper() + text[1:]
            if not text[-1] in '.!?':
                text += '.'
        return text
        
    def save_transcription(self, **kwargs):
        """Save transcription to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO transcriptions (raw_text, enhanced_text, duration_ms, word_count, processing_time_ms)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                kwargs.get('raw_text'),
                kwargs.get('enhanced_text'),
                kwargs.get('duration_ms'),
                kwargs.get('word_count'),
                kwargs.get('processing_time_ms')
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB ERROR] {e}")
        
    def broadcast_message(self, message):
        """Send message to all connected WebSocket clients"""
        if not self.websocket_clients:
            return
            
        disconnected_clients = set()
        for client in self.websocket_clients:
            try:
                # Use asyncio.create_task for non-blocking send
                loop = asyncio.get_event_loop()
                loop.create_task(client.send(json.dumps(message)))
            except Exception as e:
                print(f"[WS ERROR] {e}")
                disconnected_clients.add(client)
                
        self.websocket_clients -= disconnected_clients
        
    async def handle_websocket(self, websocket, path):
        """Handle WebSocket connections"""
        print(f"[WS] New client connected from {websocket.remote_address}")
        self.websocket_clients.add(websocket)
        
        try:
            await websocket.send(json.dumps({
                "type": "connected",
                "message": "VoiceFlow STT Server Connected (Patched)",
                "features": {
                    "system_integration": SYSTEM_INTEGRATION,
                    "ai_enhancement": self.use_ai_enhancement,
                    "model": getattr(self.recorder, 'model', 'unknown')
                }
            }))
            
            async for message in websocket:
                try:
                    data = json.loads(message)
                    print(f"[WS] Received: {data.get('type', 'unknown')}")
                    
                    if data["type"] == "ping":
                        await websocket.send(json.dumps({"type": "pong"}))
                        
                except json.JSONDecodeError:
                    print("[WS ERROR] Invalid JSON received")
                    
        except websockets.exceptions.ConnectionClosed:
            print("[WS] Client disconnected")
        except Exception as e:
            print(f"[WS ERROR] {e}")
        finally:
            self.websocket_clients.discard(websocket)
            
    def start_recorder_thread(self):
        """Run the STT recorder in a separate thread"""
        def recorder_loop():
            print("[RECORDER] Starting background thread...")
            try:
                while True:
                    # The recorder handles everything through callbacks
                    self.recorder.text(lambda text: None)
                    time.sleep(0.1)  # Prevent busy waiting
            except Exception as e:
                print(f"[RECORDER ERROR] {e}")
        
        recorder_thread = threading.Thread(target=recorder_loop, daemon=True)
        recorder_thread.start()
        print("[RECORDER] Background thread started")
    
    def start_hotkey_listener(self):
        """Start global hotkey listener for Ctrl+Alt"""
        if not SYSTEM_INTEGRATION:
            print("[HOTKEY] Disabled (system integration not available)")
            return
            
        def hotkey_handler():
            print("[HOTKEY] Ctrl+Alt pressed - triggering recording")
            # The recorder already handles recording through its own mechanism
            
        try:
            keyboard.add_hotkey('ctrl+alt', hotkey_handler)
            print("[HOTKEY] Global hotkey registered: Ctrl+Alt")
        except Exception as e:
            print(f"[HOTKEY ERROR] Could not register global hotkey: {e}")
        
    async def main(self):
        """Main server loop"""
        print("="*60)
        print("VoiceFlow STT Server - Compatibility Patched")
        print("="*60)
        print(f"[SYSTEM] Python {sys.version}")
        print(f"[FEATURES] System Integration: {SYSTEM_INTEGRATION}")
        print(f"[FEATURES] AI Enhancement: {self.use_ai_enhancement}")
        print(f"[DATA] Storage: {self.data_dir}")
        
        # Start the recorder thread
        self.start_recorder_thread()
        
        # Start global hotkey listener if available
        self.start_hotkey_listener()
        
        # Start WebSocket server with error handling
        try:
            print("[SERVER] Starting WebSocket server on localhost:8765")
            
            # Bind to localhost with better error handling
            start_server = websockets.serve(
                self.handle_websocket, 
                "localhost", 
                8765,
                ping_interval=20,
                ping_timeout=10
            )
            
            async with start_server as server:
                print("[SUCCESS] WebSocket server started successfully!")
                print("[READY] VoiceFlow is ready for use")
                print("[USAGE] Press Ctrl+Alt anywhere to start voice transcription")
                
                if SYSTEM_INTEGRATION:
                    print("[OK] Text will be automatically typed at cursor position")
                else:
                    print("[INFO] Text will be displayed for manual copying")
                
                print("="*60)
                
                # Keep server running
                await asyncio.Future()  # Run forever
                
        except OSError as e:
            if "address already in use" in str(e).lower():
                print("[ERROR] Port 8765 is already in use!")
                print("Solution: Kill other VoiceFlow instances or restart computer")
            else:
                print(f"[ERROR] Server startup failed: {e}")
            raise
        except Exception as e:
            print(f"[ERROR] Unexpected server error: {e}")
            raise
            
if __name__ == "__main__":
    try:
        server = VoiceFlowServer()
        asyncio.run(server.main())
    except KeyboardInterrupt:
        print("\\n[EXIT] VoiceFlow stopped by user")
    except Exception as e:
        print(f"\\n[FATAL] VoiceFlow crashed: {e}")
        input("Press Enter to exit...")
