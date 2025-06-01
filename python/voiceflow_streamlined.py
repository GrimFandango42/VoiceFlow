"""
VoiceFlow Streamlined - Clean Wispr Flow Alternative
Simple, reliable global voice transcription with ctrl+alt hotkey
"""

import asyncio
import websockets
import json
import requests
import time
import threading
import tempfile
import wave
import os
from datetime import datetime
from pathlib import Path
from RealtimeSTT import AudioToTextRecorder
import pyaudio
import sqlite3

# Windows integration
try:
    import keyboard
    import pyautogui
    import win32api
    import win32con
    import win32gui
    import win32clipboard
    import win32process
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    print("Windows integration not available")

class VoiceFlowStreamlined:
    """Streamlined VoiceFlow - focused on core functionality"""
    
    def __init__(self):
        print("[VoiceFlow] Initializing streamlined voice transcription...")
        
        # Core state
        self.is_recording = False
        self.is_running = True
        self.hotkey_registered = False
        
        # Paths
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "transcriptions.db"
        
        # Initialize database
        self.init_database()
        
        # AI configuration - keep it simple
        self.ollama_urls = [
            "http://localhost:11434/api/generate",
            "http://172.30.248.191:11434/api/generate"
        ]
        self.ollama_url = None
        self.model = "llama3.3:latest"
        self.ai_available = self.test_ai_connection()
        
        # WebSocket clients
        self.websocket_clients = set()
        
        # Recording state
        self.current_recording = {
            'start_time': None,
            'target_app': None,
            'audio_frames': []
        }
        
        # Initialize speech processor
        self.init_speech_processor()
        
        print(f"[VoiceFlow] Initialized - AI: {'✅' if self.ai_available else '❌'}")
        print(f"[VoiceFlow] Data: {self.data_dir}")
    
    def init_database(self):
        """Simple database setup"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    text TEXT NOT NULL,
                    enhanced_text TEXT,
                    target_app TEXT,
                    word_count INTEGER,
                    processing_time_ms INTEGER
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Database] Error: {e}")
    
    def test_ai_connection(self):
        """Test if AI enhancement is available"""
        for url in self.ollama_urls:
            try:
                test_url = url.replace('/generate', '/tags')
                response = requests.get(test_url, timeout=2)
                if response.status_code == 200:
                    self.ollama_url = url
                    models = response.json().get('models', [])
                    model_names = [m.get('name', '') for m in models]
                    if self.model in model_names:
                        return True
                    elif model_names:
                        self.model = model_names[0]
                        return True
            except:
                continue
        return False
    
    def init_speech_processor(self):
        """Initialize Whisper with smart fallbacks"""
        configs = [
            {"model": "base", "device": "cuda", "compute_type": "int8"},
            {"model": "base", "device": "cpu", "compute_type": "int8"}
        ]
        
        for config in configs:
            try:
                self.recorder = AudioToTextRecorder(
                    model=config["model"],
                    language="en",
                    device=config["device"],
                    compute_type=config["compute_type"],
                    use_microphone=False,  # We handle audio ourselves
                    spinner=False,
                    level=0
                )
                print(f"[Speech] Ready: {config['device']} {config['model']}")
                return
            except Exception as e:
                print(f"[Speech] Config failed: {e}")
        
        raise Exception("Could not initialize speech processor")
    
    def setup_global_hotkey(self):
        """Setup ctrl+alt press-and-hold hotkey"""
        if not WINDOWS_AVAILABLE:
            print("[Hotkey] Windows integration required")
            return False
        
        try:
            # Register press and release handlers
            keyboard.add_hotkey('ctrl+alt', self.start_recording, suppress=False)
            
            # Stop recording when either key is released
            keyboard.on_release_key('ctrl', self.on_key_release)
            keyboard.on_release_key('alt', self.on_key_release)
            
            self.hotkey_registered = True
            print("[Hotkey] Ctrl+Alt registered (press and hold to record)")
            return True
            
        except Exception as e:
            print(f"[Hotkey] Failed: {e}")
            return False
    
    def on_key_release(self, key):
        """Stop recording when hotkey is released"""
        if self.is_recording:
            # Add buffer time to catch tail-end of speech (0.8 seconds)
            threading.Timer(0.8, self.stop_recording).start()
    
    def start_recording(self):
        """Start recording audio"""
        if self.is_recording:
            return
        
        self.is_recording = True
        print("[Record] Started")
        
        # Get target application info
        target_app = self.get_active_app()
        
        self.current_recording = {
            'start_time': time.time(),
            'target_app': target_app,
            'audio_frames': []
        }
        
        # Notify WebSocket clients
        self.broadcast_message({
            "type": "recording_started", 
            "app": target_app.get('name') if target_app else None
        })
        
        # Start recording in background thread
        threading.Thread(target=self._record_audio, daemon=True).start()
    
    def stop_recording(self):
        """Stop recording and process"""
        if not self.is_recording:
            return
        
        self.is_recording = False
        print("[Record] Stopped")
        
        self.broadcast_message({"type": "recording_stopped"})
    
    def _record_audio(self):
        """Record audio in background thread"""
        try:
            # Setup audio recording
            audio = pyaudio.PyAudio()
            stream = audio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=16000,
                input=True,
                frames_per_buffer=1024
            )
            
            frames = []
            start_time = time.time()
            
            # Record while hotkey held (max 30 seconds)
            while self.is_recording and (time.time() - start_time) < 30:
                data = stream.read(1024, exception_on_overflow=False)
                frames.append(data)
            
            # Cleanup
            stream.stop_stream()
            stream.close()
            audio.terminate()
            
            # Process if we have audio (reduced minimum duration for better responsiveness)
            if frames and (time.time() - start_time) > 0.2:  # Minimum duration
                self._process_audio(frames, time.time() - start_time)
            else:
                print("[Record] Too short, ignoring")
                
        except Exception as e:
            print(f"[Record] Error: {e}")
            self.is_recording = False
    
    def _process_audio(self, frames, duration):
        """Process recorded audio to text"""
        processing_start = time.time()
        
        try:
            # Save to temp file
            temp_path = self._save_temp_audio(frames)
            if not temp_path:
                return
            
            # Transcribe with Whisper
            raw_text = self.recorder.transcribe(temp_path)
            os.unlink(temp_path)  # Cleanup
            
            if not raw_text or not raw_text.strip():
                print("[Process] No speech detected")
                return
            
            raw_text = raw_text.strip()
            
            # Enhance with AI if available
            enhanced_text = self._enhance_text(raw_text)
            
            # Calculate metrics
            processing_time = int((time.time() - processing_start) * 1000)
            word_count = len(enhanced_text.split())
            
            # Inject text at cursor
            injection_success = self._inject_text(enhanced_text)
            
            # Save to database
            self._save_transcription(
                text=raw_text,
                enhanced_text=enhanced_text,
                target_app=self.current_recording['target_app'].get('name') if self.current_recording['target_app'] else None,
                word_count=word_count,
                processing_time_ms=processing_time
            )
            
            # Notify clients
            self.broadcast_message({
                "type": "transcription_complete",
                "text": enhanced_text,
                "word_count": word_count,
                "processing_time_ms": processing_time,
                "injection_success": injection_success
            })
            
            print(f"[Done] '{enhanced_text}' ({processing_time}ms)")
            
        except Exception as e:
            print(f"[Process] Error: {e}")
    
    def _save_temp_audio(self, frames):
        """Save audio frames to temporary WAV file"""
        try:
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as f:
                temp_path = f.name
            
            wf = wave.open(temp_path, 'wb')
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(16000)
            wf.writeframes(b''.join(frames))
            wf.close()
            
            return temp_path
        except Exception as e:
            print(f"[Audio] Save error: {e}")
            return None
    
    def _enhance_text(self, text):
        """Enhance text with AI or basic formatting"""
        if not self.ai_available:
            return self._basic_format(text)
        
        try:
            # Simple, effective prompt
            prompt = f"Fix punctuation and capitalization: {text}"
            
            response = requests.post(self.ollama_url, json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.2,
                "max_tokens": len(text) * 2
            }, timeout=3)
            
            if response.status_code == 200:
                enhanced = response.json().get('response', text).strip()
                # Remove quotes if AI added them
                if enhanced.startswith('"') and enhanced.endswith('"'):
                    enhanced = enhanced[1:-1]
                return enhanced
                
        except Exception as e:
            print(f"[AI] Enhancement failed: {e}")
        
        return self._basic_format(text)
    
    def _basic_format(self, text):
        """Basic text formatting fallback"""
        if not text:
            return text
        
        # Capitalize first letter and add period if needed
        formatted = text.strip()
        if formatted:
            formatted = formatted[0].upper() + formatted[1:]
            if not formatted.endswith(('.', '!', '?')):
                formatted += '.'
        
        return formatted
    
    def _inject_text(self, text):
        """Inject text at cursor using best available method"""
        if not WINDOWS_AVAILABLE or not text:
            return False
        
        try:
            # Method 1: Direct typing (fastest)
            keyboard.write(text)
            return True
        except:
            try:
                # Method 2: Clipboard fallback
                original = self._get_clipboard()
                self._set_clipboard(text)
                keyboard.send('ctrl+v')
                
                # Restore clipboard after delay
                def restore():
                    time.sleep(0.5)
                    if original:
                        self._set_clipboard(original)
                threading.Thread(target=restore, daemon=True).start()
                
                return True
            except Exception as e:
                print(f"[Inject] Failed: {e}")
                return False
    
    def _get_clipboard(self):
        """Get current clipboard content"""
        try:
            win32clipboard.OpenClipboard()
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                win32clipboard.CloseClipboard()
                return data.decode('utf-8') if isinstance(data, bytes) else data
        except:
            pass
        finally:
            try:
                win32clipboard.CloseClipboard()
            except:
                pass
        return None
    
    def _set_clipboard(self, text):
        """Set clipboard content"""
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, text.encode('utf-8'))
            win32clipboard.CloseClipboard()
        except:
            pass
        finally:
            try:
                win32clipboard.CloseClipboard()
            except:
                pass
    
    def get_active_app(self):
        """Get info about currently active application"""
        if not WINDOWS_AVAILABLE:
            return None
        
        try:
            hwnd = win32gui.GetForegroundWindow()
            window_title = win32gui.GetWindowText(hwnd)
            _, process_id = win32process.GetWindowThreadProcessId(hwnd)
            
            try:
                process_handle = win32api.OpenProcess(0x0400 | 0x0010, False, process_id)
                executable_path = win32process.GetModuleFileNameEx(process_handle, 0)
                app_name = os.path.basename(executable_path).lower()
                win32api.CloseHandle(process_handle)
            except:
                app_name = "unknown"
            
            return {
                'name': app_name,
                'title': window_title,
                'hwnd': hwnd
            }
        except:
            return None
    
    def _save_transcription(self, **kwargs):
        """Save transcription to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO transcriptions (text, enhanced_text, target_app, word_count, processing_time_ms)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                kwargs.get('text'),
                kwargs.get('enhanced_text'),
                kwargs.get('target_app'),
                kwargs.get('word_count'),
                kwargs.get('processing_time_ms')
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Database] Save error: {e}")
    
    def broadcast_message(self, message):
        """Send message to WebSocket clients"""
        if not self.websocket_clients:
            return
        
        disconnected = set()
        for client in self.websocket_clients:
            try:
                asyncio.create_task(client.send(json.dumps(message)))
            except:
                disconnected.add(client)
        
        self.websocket_clients -= disconnected
    
    async def handle_websocket(self, websocket, path):
        """Handle WebSocket connections for UI"""
        self.websocket_clients.add(websocket)
        try:
            await websocket.send(json.dumps({
                "type": "connected",
                "message": "VoiceFlow Streamlined Ready",
                "hotkey": "Ctrl+Alt (press and hold)"
            }))
            
            # Keep connection alive
            async for message in websocket:
                # Handle any UI commands here if needed
                pass
                
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.websocket_clients.discard(websocket)
    
    async def run_server(self):
        """Run the WebSocket server"""
        try:
            async with websockets.serve(self.handle_websocket, "localhost", 8765):
                print("[WebSocket] Server running on ws://localhost:8765")
                while self.is_running:
                    await asyncio.sleep(1)
        except Exception as e:
            print(f"[WebSocket] Error: {e}")
    
    def run(self):
        """Main entry point"""
        try:
            print("\n" + "="*50)
            print("VoiceFlow Streamlined")
            print("="*50)
            
            # Setup hotkey
            if not self.setup_global_hotkey():
                print("Failed to setup global hotkey")
                return
            
            print("Ready! Press and hold Ctrl+Alt anywhere to record")
            print("Release keys to stop and inject text")
            print("Press Ctrl+C to exit")
            
            # Run WebSocket server
            asyncio.run(self.run_server())
            
        except KeyboardInterrupt:
            print("\n[Exit] VoiceFlow stopped")
        except Exception as e:
            print(f"[Error] {e}")

if __name__ == "__main__":
    app = VoiceFlowStreamlined()
    app.run()