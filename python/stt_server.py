"""
VoiceFlow STT Server - Local Whisper + DeepSeek Integration
Zero-cost voice transcription with AI enhancement
"""

import asyncio
import websockets
import json
import requests
import numpy as np
from datetime import datetime
import sqlite3
import os
from pathlib import Path
from RealtimeSTT import AudioToTextRecorder
import threading
import queue
import time
try:
    import pyautogui
    import keyboard
    SYSTEM_INTEGRATION = True
except ImportError:
    SYSTEM_INTEGRATION = False
    print("System integration packages not installed. Text injection disabled.")

class VoiceFlowServer:
    def __init__(self):
        # Initialize paths
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "transcriptions.db"
        
        # Initialize database
        self.init_database()
        
        # Ollama configuration
        # Try multiple Ollama endpoints (WSL and local)
        self.ollama_urls = [
            "http://172.30.248.191:11434/api/generate",  # Your WSL IP
            "http://localhost:11434/api/generate",  # Windows local
            "http://127.0.0.1:11434/api/generate"  # Alternative local
        ]
        self.ollama_url = None  # Will be set when we find a working endpoint
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
        try:
            # Try GPU first with float16
            self.recorder = AudioToTextRecorder(
                model="large-v3",
                language="en",
                device="cuda",
                compute_type="float16",
                gpu_device_index=0,
                on_recording_start=self.on_recording_start,
                on_recording_stop=self.on_recording_stop,
                on_transcription_start=self.on_transcription_start,
                use_microphone=True,
                spinner=False,
                level=0,
                # Real-time transcription settings
                enable_realtime_transcription=True,
                realtime_processing_pause=0.1,
                realtime_model_type="small",  # Use small model for preview
                on_realtime_transcription_update=self.on_realtime_update,
                # VAD settings for better detection
                silero_sensitivity=0.5,
                webrtc_sensitivity=3,
                post_speech_silence_duration=0.4,
                min_length_of_recording=0.5,
                min_gap_between_recordings=0.3,
                # Wake word support (optional)
                wake_words="",
                on_wakeword_detected=None
            )
            print("[GPU] Using CUDA acceleration with float16")
        except Exception as e:
            print(f"[GPU] CUDA float16 failed: {e}")
            try:
                # Fallback to GPU with int8
                self.recorder = AudioToTextRecorder(
                    model="base",  # Use smaller model for compatibility
                    language="en",
                    device="cuda",
                    compute_type="int8",
                    gpu_device_index=0,
                    on_recording_start=self.on_recording_start,
                    on_recording_stop=self.on_recording_stop,
                    on_transcription_start=self.on_transcription_start,
                    use_microphone=True,
                    spinner=False,
                    level=0,
                    enable_realtime_transcription=True,
                    realtime_processing_pause=0.1,
                    realtime_model_type="tiny",
                    on_realtime_transcription_update=self.on_realtime_update,
                    silero_sensitivity=0.5,
                    webrtc_sensitivity=3,
                    post_speech_silence_duration=0.4,
                    min_length_of_recording=0.5,
                    min_gap_between_recordings=0.3,
                    wake_words="",
                    on_wakeword_detected=None
                )
                print("[GPU] Using CUDA acceleration with int8")
            except Exception as e2:
                print(f"[GPU] CUDA int8 failed: {e2}")
                # Final fallback to CPU
                self.recorder = AudioToTextRecorder(
                    model="base",
                    language="en",
                    device="cpu",
                    compute_type="int8",
                    on_recording_start=self.on_recording_start,
                    on_recording_stop=self.on_recording_stop,
                    on_transcription_start=self.on_transcription_start,
                    use_microphone=True,
                    spinner=False,
                    level=0,
                    enable_realtime_transcription=True,
                    realtime_processing_pause=0.2,
                    realtime_model_type="tiny",
                    on_realtime_transcription_update=self.on_realtime_update,
                    silero_sensitivity=0.5,
                    webrtc_sensitivity=3,
                    post_speech_silence_duration=0.4,
                    min_length_of_recording=0.5,
                    min_gap_between_recordings=0.3,
                    wake_words="",
                    on_wakeword_detected=None
                )
                print("[CPU] Using CPU fallback with int8")
        
        self.websocket_clients = set()
        self.current_transcription = {
            "id": None,
            "start_time": None,
            "preview_text": "",
            "final_text": "",
            "enhanced_text": ""
        }
        
    def test_ollama_connection(self):
        """Test Ollama connectivity and find working endpoint"""
        for url in self.ollama_urls:
            try:
                test_url = url.replace('/generate', '/tags')
                response = requests.get(test_url, timeout=2)
                if response.status_code == 200:
                    self.ollama_url = url
                    print(f"[OK] Ollama connected at: {url}")
                    # Check if our model exists
                    models = response.json().get('models', [])
                    model_names = [m.get('name', '') for m in models]
                    if self.deepseek_model in model_names:
                        print(f"[OK] Found {self.deepseek_model} model")
                    else:
                        print(f"[WARNING] Model {self.deepseek_model} not found. Available models: {model_names}")
                        if model_names:
                            self.deepseek_model = model_names[0]
                            print(f"  Using {self.deepseek_model} instead")
                    return
            except Exception as e:
                continue
        
        print("WARNING: Could not connect to Ollama. AI enhancement will be disabled.")
        self.use_ai_enhancement = False
        
    def init_database(self):
        """Initialize SQLite database for transcription history"""
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
        
    def on_recording_start(self):
        """Called when recording starts"""
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
        self.broadcast_message({
            "type": "recording_stopped",
            "timestamp": datetime.now().isoformat()
        })
        
    def on_realtime_update(self, text):
        """Real-time preview using small model"""
        self.current_transcription["preview_text"] = text
        self.broadcast_message({
            "type": "realtime_preview",
            "text": text,
            "timestamp": datetime.now().isoformat()
        })
        
    def on_transcription_start(self, text):
        """Final transcription using large model"""
        start_time = time.time()
        
        # Store raw transcription
        self.current_transcription["final_text"] = text
        word_count = len(text.split())
        
        # Enhance with DeepSeek
        enhanced_text = self.enhance_with_deepseek(text)
        self.current_transcription["enhanced_text"] = enhanced_text
        
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
        """Inject text at the current cursor position in any application"""
        if not SYSTEM_INTEGRATION:
            print(f"[Text ready to paste]: {text}")
            return
            
        try:
            # Method 1: Direct typing with pyautogui
            # This works in most applications
            pyautogui.typewrite(text)
            print(f"[Injected]: {text}")
            
        except Exception as e:
            print(f"[Injection failed]: {e}")
            # Fallback: Copy to clipboard
            try:
                import win32clipboard
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, text.encode('utf-8'))
                win32clipboard.CloseClipboard()
                print("[Copied to clipboard] Press Ctrl+V to paste")
            except:
                print("[Error] Could not access clipboard")
        
    def enhance_with_deepseek(self, text):
        """Enhance transcription with DeepSeek for proper formatting"""
        if not self.use_ai_enhancement:
            return self.basic_format(text)
            
        try:
            prompt = f"""You are a transcription formatter. Format the following spoken text with proper punctuation, capitalization, and paragraph breaks. Fix any obvious transcription errors. Keep the meaning exactly the same.

Raw transcription: {text}

Formatted text:"""
            
            response = requests.post(self.ollama_url, json={
                "model": self.deepseek_model,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.3,
                "top_p": 0.9,
                "max_tokens": len(text) * 2  # Allow some expansion
            }, timeout=10)
            
            if response.status_code == 200:
                enhanced = response.json().get('response', text).strip()
                # Remove any explanation text if DeepSeek added it
                if enhanced.startswith('"') and enhanced.endswith('"'):
                    enhanced = enhanced[1:-1]
                return enhanced
            else:
                print(f"DeepSeek error: {response.status_code}")
                return text
                
        except Exception as e:
            print(f"DeepSeek enhancement failed: {e}")
            # Fallback to basic formatting
            return self.basic_format(text)
            
    def basic_format(self, text):
        """Basic formatting fallback if DeepSeek is unavailable"""
        # Capitalize first letter
        if text:
            text = text[0].upper() + text[1:]
        # Add period if missing
        if text and not text[-1] in '.!?':
            text += '.'
        return text
        
    def save_transcription(self, **kwargs):
        """Save transcription to database"""
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
        
    def get_history(self, limit=50):
        """Get transcription history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM transcriptions 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        columns = [description[0] for description in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        conn.close()
        return results
        
    def get_statistics(self):
        """Get usage statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Today's stats
        cursor.execute('''
            SELECT COUNT(*), SUM(word_count), AVG(processing_time_ms)
            FROM transcriptions
            WHERE DATE(timestamp) = DATE('now')
        ''')
        today_count, today_words, avg_processing = cursor.fetchone()
        
        # All time stats
        cursor.execute('''
            SELECT COUNT(*), SUM(word_count), AVG(processing_time_ms)
            FROM transcriptions
        ''')
        total_count, total_words, total_avg_processing = cursor.fetchone()
        
        conn.close()
        
        return {
            "today": {
                "transcriptions": today_count or 0,
                "words": today_words or 0,
                "avg_processing_ms": avg_processing or 0
            },
            "all_time": {
                "transcriptions": total_count or 0,
                "words": total_words or 0,
                "avg_processing_ms": total_avg_processing or 0
            },
            "session": {
                "transcriptions": self.stats["total_transcriptions"],
                "words": self.stats["total_words"],
                "uptime_minutes": (datetime.now() - self.stats["session_start"]).seconds // 60
            }
        }
        
    def broadcast_message(self, message):
        """Send message to all connected WebSocket clients"""
        disconnected_clients = set()
        for client in self.websocket_clients:
            try:
                asyncio.create_task(client.send(json.dumps(message)))
            except:
                disconnected_clients.add(client)
        self.websocket_clients -= disconnected_clients
        
    async def handle_websocket(self, websocket, path):
        """Handle WebSocket connections"""
        self.websocket_clients.add(websocket)
        try:
            await websocket.send(json.dumps({
                "type": "connected",
                "message": "VoiceFlow STT Server Connected"
            }))
            
            async for message in websocket:
                data = json.loads(message)
                
                if data["type"] == "get_history":
                    history = self.get_history(data.get("limit", 50))
                    await websocket.send(json.dumps({
                        "type": "history",
                        "data": history
                    }))
                    
                elif data["type"] == "get_statistics":
                    stats = self.get_statistics()
                    await websocket.send(json.dumps({
                        "type": "statistics",
                        "data": stats
                    }))
                    
                elif data["type"] == "start_recording":
                    # Trigger recording manually if needed
                    pass
                    
                elif data["type"] == "toggle_recording":
                    # Toggle recording state
                    self.recorder.text(lambda text: None)
                    
                elif data["type"] == "set_language":
                    # Change language setting
                    language = data.get("language", "en")
                    self.recorder.language = language
                    await websocket.send(json.dumps({
                        "type": "language_changed",
                        "language": language
                    }))
                    
                elif data["type"] == "set_microphone":
                    # Change microphone setting
                    device = data.get("device", None)
                    # This would require reinitializing the recorder
                    await websocket.send(json.dumps({
                        "type": "microphone_changed",
                        "device": device
                    }))
                    
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.websocket_clients.remove(websocket)
            
    def start_recorder_thread(self):
        """Run the STT recorder in a separate thread"""
        def recorder_loop():
            while True:
                self.recorder.text(lambda text: None)  # Callbacks handle everything
        
        recorder_thread = threading.Thread(target=recorder_loop, daemon=True)
        recorder_thread.start()
    
    def start_hotkey_listener(self):
        """Start global hotkey listener for Ctrl+Alt+Space"""
        def hotkey_handler():
            # Trigger recording toggle
            print("[HOTKEY] Hotkey pressed!")
            # The recorder already has its own hotkey handling
            
        try:
            keyboard.add_hotkey('ctrl+alt', hotkey_handler)
            print("[HOTKEY] Global hotkey registered: Ctrl+Alt")
        except Exception as e:
            print(f"[WARNING] Could not register global hotkey: {e}")
        
    async def main(self):
        """Main server loop"""
        print("[STARTUP] VoiceFlow STT Server Starting...")
        print(f"[GPU] Using Whisper large-v3 on RTX 4080")
        print(f"[AI] DeepSeek enhancement via Ollama")
        print(f"[DATA] Data stored in: {self.data_dir}")
        
        # Start the recorder thread
        self.start_recorder_thread()
        
        # Start global hotkey listener if available
        if SYSTEM_INTEGRATION:
            self.start_hotkey_listener()
        
        # Start WebSocket server
        async with websockets.serve(self.handle_websocket, "localhost", 8765):
            print("[SERVER] Server running on ws://localhost:8765")
            print("[HOTKEY] Press Ctrl+Alt to start recording (configured in app)")
            if SYSTEM_INTEGRATION:
                print("[OK] System integration active - text will be typed at cursor")
            else:
                print("[WARNING] Install pyautogui and keyboard for automatic text injection")
            await asyncio.Future()  # Run forever
            
if __name__ == "__main__":
    server = VoiceFlowServer()
    asyncio.run(server.main())
