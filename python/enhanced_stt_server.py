"""
Enhanced VoiceFlow STT Server - Wispr Flow Compatible
Global voice transcription with invisible operation and instant text injection
"""

import asyncio
import websockets
import json
import requests
import numpy as np
from datetime import datetime
import sqlite3
import os
import time
import threading
import queue
import tempfile
import wave
from pathlib import Path
from RealtimeSTT import AudioToTextRecorder
import pyaudio

# Windows-specific imports for global hotkey and text injection
try:
    import pyautogui
    import keyboard
    import win32api
    import win32con
    import win32gui
    import win32clipboard
    import win32process
    WINDOWS_INTEGRATION = True
except ImportError:
    WINDOWS_INTEGRATION = False
    print("Windows integration packages not installed. Limited functionality.")

class EnhancedVoiceFlowServer:
    """Enhanced VoiceFlow Server with Wispr Flow compatibility"""
    
    def __init__(self):
        # Initialize paths
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "transcriptions.db"
        
        # Recording state
        self.is_recording = False
        self.is_server_running = True
        self.hotkey_registered = False
        
        # Initialize database
        self.init_database()
        
        # Ollama configuration with multiple endpoints
        self.ollama_urls = [
            "http://localhost:11434/api/generate",      # Windows local
            "http://172.30.248.191:11434/api/generate", # WSL
            "http://127.0.0.1:11434/api/generate"       # Alternative
        ]
        self.ollama_url = None
        self.deepseek_model = "llama3.3:latest"
        self.use_ai_enhancement = True
        
        # Test Ollama connectivity
        self.test_ollama_connection()
        
        # WebSocket clients
        self.websocket_clients = set()
        
        # Statistics
        self.stats = {
            "total_transcriptions": 0,
            "total_words": 0,
            "session_start": datetime.now(),
            "successful_injections": 0,
            "failed_injections": 0
        }
        
        # Current transcription tracking
        self.current_transcription = {
            "id": None,
            "start_time": None,
            "preview_text": "",
            "final_text": "",
            "enhanced_text": "",
            "target_app": None
        }
        
        # Initialize STT with fallback options
        self.init_stt_recorder()
        
        print("[ENHANCED] Enhanced VoiceFlow Server initialized")
        print(f"[CONFIG] Data directory: {self.data_dir}")
        print(f"[CONFIG] Windows integration: {'✅ Available' if WINDOWS_INTEGRATION else '❌ Limited'}")
    
    def init_stt_recorder(self):
        """Initialize STT recorder with GPU fallback options"""
        print("[STT] Initializing speech recognition...")
        
        # Try GPU configurations in order of preference
        configs = [
            # Best: GPU with float16
            {
                "model": "large-v3",
                "device": "cuda",
                "compute_type": "float16",
                "realtime_model_type": "small"
            },
            # Fallback: GPU with int8
            {
                "model": "base",
                "device": "cuda", 
                "compute_type": "int8",
                "realtime_model_type": "tiny"
            },
            # Last resort: CPU
            {
                "model": "base",
                "device": "cpu",
                "compute_type": "int8", 
                "realtime_model_type": "tiny"
            }
        ]
        
        for i, config in enumerate(configs):
            try:
                self.recorder = AudioToTextRecorder(
                    model=config["model"],
                    language="en",
                    device=config["device"],
                    compute_type=config["compute_type"],
                    gpu_device_index=0 if config["device"] == "cuda" else None,
                    on_recording_start=self.on_recording_start,
                    on_recording_stop=self.on_recording_stop,
                    on_transcription_start=self.on_transcription_complete,
                    use_microphone=True,
                    spinner=False,
                    level=0,
                    # Real-time settings
                    enable_realtime_transcription=True,
                    realtime_processing_pause=0.1,
                    realtime_model_type=config["realtime_model_type"],
                    on_realtime_transcription_update=self.on_realtime_update,
                    # VAD settings for better detection
                    silero_sensitivity=0.5,
                    webrtc_sensitivity=3,
                    post_speech_silence_duration=0.4,
                    min_length_of_recording=0.5,
                    min_gap_between_recordings=0.3,
                    # No wake words - we use global hotkey
                    wake_words="",
                    on_wakeword_detected=None
                )
                
                print(f"[STT] ✅ Using {config['device']} with {config['model']} model")
                break
                
            except Exception as e:
                print(f"[STT] ⚠️ Config {i+1} failed: {e}")
                if i == len(configs) - 1:
                    raise Exception("All STT configurations failed")
    
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
                target_app TEXT,
                duration_ms INTEGER,
                word_count INTEGER,
                processing_time_ms INTEGER,
                injection_success BOOLEAN,
                context_type TEXT
            )
        ''')
        conn.commit()
        conn.close()
        print("[DB] Database initialized")
    
    def test_ollama_connection(self):
        """Test Ollama connectivity"""
        for url in self.ollama_urls:
            try:
                test_url = url.replace('/generate', '/tags')
                response = requests.get(test_url, timeout=2)
                if response.status_code == 200:
                    self.ollama_url = url
                    models = response.json().get('models', [])
                    model_names = [m.get('name', '') for m in models]
                    if self.deepseek_model in model_names:
                        print(f"[AI] ✅ Connected to Ollama: {self.deepseek_model}")
                    else:
                        if model_names:
                            self.deepseek_model = model_names[0]
                            print(f"[AI] ✅ Using model: {self.deepseek_model}")
                    return
            except:
                continue
        
        print("[AI] ⚠️ Ollama not available - using basic formatting")
        self.use_ai_enhancement = False
    
    def get_active_window_info(self):
        """Get information about currently active window"""
        if not WINDOWS_INTEGRATION:
            return None
            
        try:
            hwnd = win32gui.GetForegroundWindow()
            if not hwnd:
                return None
            
            window_title = win32gui.GetWindowText(hwnd)
            _, process_id = win32process.GetWindowThreadProcessId(hwnd)
            
            try:
                process_handle = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, 
                    False, process_id
                )
                executable_path = win32process.GetModuleFileNameEx(process_handle, 0)
                app_name = os.path.basename(executable_path).lower()
                win32api.CloseHandle(process_handle)
            except:
                app_name = "unknown"
                executable_path = ""
            
            return {
                'hwnd': hwnd,
                'title': window_title,
                'app_name': app_name,
                'executable': executable_path,
                'process_id': process_id
            }
        except Exception as e:
            print(f"[WINDOW] Error getting window info: {e}")
            return None
    
    def detect_application_context(self, app_info):
        """Detect application type for context-aware formatting"""
        if not app_info:
            return 'general'
        
        app_name = app_info.get('app_name', '').lower()
        window_title = app_info.get('title', '').lower()
        
        # Email applications
        if any(email in app_name for email in ['outlook', 'thunderbird', 'mailbird']):
            return 'email'
        
        # Web browsers - check title for context
        if any(browser in app_name for browser in ['chrome', 'firefox', 'edge', 'msedge']):
            if any(site in window_title for site in ['gmail', 'outlook', 'yahoo mail']):
                return 'email'
            elif any(site in window_title for site in ['slack', 'discord', 'teams']):
                return 'chat'
            elif any(site in window_title for site in ['linkedin', 'twitter', 'facebook']):
                return 'social'
            return 'web'
        
        # Code editors
        if any(editor in app_name for editor in ['code', 'notepad++', 'sublime', 'atom', 'pycharm', 'visual studio']):
            return 'code'
        
        # Office applications
        if any(office in app_name for office in ['winword', 'excel', 'powerpoint']):
            return 'document'
        
        # Chat applications
        if any(chat in app_name for chat in ['slack', 'discord', 'teams', 'skype']):
            return 'chat'
        
        # Note-taking
        if any(notes in app_name for notes in ['notepad', 'onenote', 'notion', 'obsidian']):
            return 'notes'
        
        return 'general'
    
    def setup_global_hotkey(self):
        """Setup Windows global hotkey: Ctrl+Alt+Space"""
        if not WINDOWS_INTEGRATION:
            print("[HOTKEY] ❌ Windows integration not available")
            return False
        
        try:
            # Use keyboard library for global hotkey
            keyboard.add_hotkey(
                'ctrl+alt+space',
                self.toggle_recording,
                suppress=False,
                trigger_on_release=False
            )
            
            self.hotkey_registered = True
            print("[HOTKEY] ✅ Global hotkey registered: Ctrl+Alt+Space")
            return True
            
        except Exception as e:
            print(f"[HOTKEY] ❌ Failed to register: {e}")
            return False
    
    def toggle_recording(self):
        """Toggle recording state - called by global hotkey"""
        if not self.is_recording:
            self.start_recording()
        else:
            self.stop_recording()
    
    def start_recording(self):
        """Start voice recording"""
        if self.is_recording:
            return
        
        self.is_recording = True
        
        # Get current application context
        app_info = self.get_active_window_info()
        context = self.detect_application_context(app_info)
        
        self.current_transcription = {
            "id": int(time.time() * 1000),
            "start_time": time.time(),
            "preview_text": "",
            "final_text": "",
            "enhanced_text": "",
            "target_app": app_info
        }
        
        print(f"[REC] 🔴 Recording started (Context: {context})")
        if app_info:
            print(f"[REC] Target: {app_info.get('app_name')} - {app_info.get('title')[:50]}")
        
        # Broadcast to WebSocket clients
        self.broadcast_message({
            "type": "recording_started",
            "context": context,
            "target_app": app_info.get('app_name') if app_info else None,
            "timestamp": datetime.now().isoformat()
        })
        
        # Start actual recording in thread
        threading.Thread(target=self._recording_thread, daemon=True).start()
    
    def stop_recording(self):
        """Stop voice recording"""
        if not self.is_recording:
            return
        
        self.is_recording = False
        print("[REC] ⏹️ Recording stopped")
        
        self.broadcast_message({
            "type": "recording_stopped",
            "timestamp": datetime.now().isoformat()
        })
    
    def _recording_thread(self):
        """Handle recording in separate thread"""
        try:
            # Use the existing recorder's text method to get transcription
            def transcription_callback(text):
                if text and text.strip():
                    self.process_transcription(text)
            
            # Start transcription - this will block until recording stops
            self.recorder.text(transcription_callback)
            
        except Exception as e:
            print(f"[REC] Recording error: {e}")
            self.is_recording = False
    
    def on_recording_start(self):
        """Called when RealtimeSTT starts recording"""
        pass  # Already handled in start_recording()
    
    def on_recording_stop(self):
        """Called when RealtimeSTT stops recording"""
        pass  # Already handled in stop_recording()
    
    def on_realtime_update(self, text):
        """Real-time preview callback"""
        self.current_transcription["preview_text"] = text
        self.broadcast_message({
            "type": "realtime_preview",
            "text": text,
            "timestamp": datetime.now().isoformat()
        })
    
    def on_transcription_complete(self, text):
        """Called when final transcription is ready"""
        if text and text.strip():
            self.process_transcription(text)
    
    def process_transcription(self, raw_text):
        """Process and enhance transcription, then inject"""
        start_time = time.time()
        
        # Get application context
        app_info = self.current_transcription.get("target_app")
        context = self.detect_application_context(app_info)
        
        # Enhance text with AI
        enhanced_text = self.enhance_with_ai(raw_text, context)
        
        # Calculate metrics
        processing_time = int((time.time() - start_time) * 1000)
        duration = int((time.time() - self.current_transcription["start_time"]) * 1000)
        word_count = len(enhanced_text.split())
        
        # Inject text into active application
        injection_success = self.inject_text_universal(enhanced_text, app_info)
        
        # Save to database
        self.save_transcription(
            raw_text=raw_text,
            enhanced_text=enhanced_text,
            target_app=app_info.get('app_name') if app_info else None,
            duration_ms=duration,
            word_count=word_count,
            processing_time_ms=processing_time,
            injection_success=injection_success,
            context_type=context
        )
        
        # Update statistics
        self.stats["total_transcriptions"] += 1
        self.stats["total_words"] += word_count
        if injection_success:
            self.stats["successful_injections"] += 1
        else:
            self.stats["failed_injections"] += 1
        
        # Broadcast result
        self.broadcast_message({
            "type": "transcription_complete",
            "raw_text": raw_text,
            "enhanced_text": enhanced_text,
            "context": context,
            "word_count": word_count,
            "duration_ms": duration,
            "processing_time_ms": processing_time,
            "injection_success": injection_success,
            "timestamp": datetime.now().isoformat()
        })
        
        print(f"[DONE] ✅ '{enhanced_text}' ({processing_time}ms, {'✅' if injection_success else '❌'} injected)")
    
    def enhance_with_ai(self, text, context):
        """Enhance text with context-aware AI formatting"""
        if not self.use_ai_enhancement:
            return self.basic_format(text, context)
        
        try:
            # Context-specific prompts
            prompts = {
                'email': "Format this email text professionally with proper punctuation and grammar. Keep it formal but natural:",
                'chat': "Format this casual message with minimal punctuation, keeping it conversational:",
                'code': "Format this technical text preserving exact terminology and structure:",
                'document': "Format this formal document text with proper punctuation and grammar:",
                'social': "Format this social media text casually with appropriate tone:",
                'general': "Format this text with proper punctuation and capitalization:"
            }
            
            prompt = f"{prompts.get(context, prompts['general'])} {text}"
            
            response = requests.post(self.ollama_url, json={
                "model": self.deepseek_model,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.3,
                "top_p": 0.9,
                "max_tokens": len(text) * 2
            }, timeout=5)
            
            if response.status_code == 200:
                enhanced = response.json().get('response', text).strip()
                # Clean up any wrapper quotes
                if enhanced.startswith('"') and enhanced.endswith('"'):
                    enhanced = enhanced[1:-1]
                return enhanced
            else:
                return self.basic_format(text, context)
                
        except Exception as e:
            print(f"[AI] Enhancement failed: {e}")
            return self.basic_format(text, context)
    
    def basic_format(self, text, context):
        """Basic formatting fallback"""
        if not text:
            return text
        
        # Basic capitalization and punctuation
        formatted = text.strip()
        if formatted:
            formatted = formatted[0].upper() + formatted[1:]
        
        # Context-specific formatting
        if context in ['email', 'document']:
            if not formatted.endswith(('.', '!', '?')):
                formatted += '.'
        elif context == 'chat':
            # Keep casual - no automatic punctuation
            pass
        elif context == 'code':
            # Preserve exact formatting
            formatted = text.strip()
        
        return formatted
    
    def inject_text_universal(self, text, app_info=None):
        """Universal text injection using multiple methods"""
        if not WINDOWS_INTEGRATION or not text:
            print(f"[INJECT] Text ready: {text}")
            return False
        
        methods = [
            self._inject_sendkeys,
            self._inject_clipboard,
            self._inject_window_message
        ]
        
        for method in methods:
            try:
                if method(text, app_info):
                    return True
            except Exception as e:
                print(f"[INJECT] {method.__name__} failed: {e}")
                continue
        
        print(f"[INJECT] ❌ All methods failed for: {text[:50]}")
        return False
    
    def _inject_sendkeys(self, text, app_info):
        """Inject using keyboard simulation"""
        keyboard.write(text)
        time.sleep(0.1)  # Small delay to ensure completion
        return True
    
    def _inject_clipboard(self, text, app_info):
        """Inject using clipboard + Ctrl+V"""
        # Save current clipboard
        original_clipboard = self._get_clipboard()
        
        # Set our text
        self._set_clipboard(text)
        
        # Send Ctrl+V
        keyboard.send('ctrl+v')
        
        # Restore clipboard after delay
        def restore_clipboard():
            time.sleep(0.5)
            if original_clipboard:
                self._set_clipboard(original_clipboard)
        
        threading.Thread(target=restore_clipboard, daemon=True).start()
        return True
    
    def _inject_window_message(self, text, app_info):
        """Inject using Windows messaging"""
        if not app_info:
            return False
        
        hwnd = app_info.get('hwnd')
        if not hwnd:
            return False
        
        # Try sending characters directly to window
        for char in text:
            win32gui.SendMessage(hwnd, win32con.WM_CHAR, ord(char), 0)
            time.sleep(0.001)  # Small delay between characters
        
        return True
    
    def _get_clipboard(self):
        """Get current clipboard text"""
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
        """Set clipboard text"""
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, text.encode('utf-8'))
            win32clipboard.CloseClipboard()
            return True
        except Exception as e:
            print(f"[CLIPBOARD] Set failed: {e}")
            return False
        finally:
            try:
                win32clipboard.CloseClipboard()
            except:
                pass
    
    def save_transcription(self, **kwargs):
        """Save transcription to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO transcriptions 
                (raw_text, enhanced_text, target_app, duration_ms, word_count, 
                 processing_time_ms, injection_success, context_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                kwargs.get('raw_text'),
                kwargs.get('enhanced_text'),
                kwargs.get('target_app'),
                kwargs.get('duration_ms'),
                kwargs.get('word_count'),
                kwargs.get('processing_time_ms'),
                kwargs.get('injection_success'),
                kwargs.get('context_type')
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB] Save error: {e}")
    
    def broadcast_message(self, message):
        """Send message to all WebSocket clients"""
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
                "message": "Enhanced VoiceFlow Connected",
                "hotkey": "Ctrl+Alt+Space",
                "windows_integration": WINDOWS_INTEGRATION
            }))
            
            async for message in websocket:
                data = json.loads(message)
                await self.handle_websocket_command(websocket, data)
                
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.websocket_clients.discard(websocket)
    
    async def handle_websocket_command(self, websocket, data):
        """Handle WebSocket commands from UI"""
        command = data.get("type")
        
        if command == "get_statistics":
            uptime = (datetime.now() - self.stats["session_start"]).total_seconds()
            success_rate = 0
            total_attempts = self.stats["successful_injections"] + self.stats["failed_injections"]
            if total_attempts > 0:
                success_rate = (self.stats["successful_injections"] / total_attempts) * 100
            
            await websocket.send(json.dumps({
                "type": "statistics",
                "data": {
                    "session": {
                        "transcriptions": self.stats["total_transcriptions"],
                        "words": self.stats["total_words"],
                        "uptime_seconds": int(uptime),
                        "injection_success_rate": round(success_rate, 1)
                    },
                    "integration": {
                        "windows_available": WINDOWS_INTEGRATION,
                        "hotkey_registered": self.hotkey_registered,
                        "ollama_available": self.use_ai_enhancement
                    }
                }
            }))
        
        elif command == "toggle_recording":
            self.toggle_recording()
        
        elif command == "test_injection":
            test_text = data.get("text", "Test injection from VoiceFlow")
            app_info = self.get_active_window_info()
            success = self.inject_text_universal(test_text, app_info)
            await websocket.send(json.dumps({
                "type": "test_result",
                "success": success,
                "text": test_text
            }))
    
    async def main(self):
        """Main server entry point"""
        print("\n" + "="*60)
        print("🎙️  Enhanced VoiceFlow Server - Wispr Flow Compatible")
        print("="*60)
        print(f"[STATUS] Windows Integration: {'✅' if WINDOWS_INTEGRATION else '❌'}")
        print(f"[STATUS] AI Enhancement: {'✅' if self.use_ai_enhancement else '❌'}")
        print(f"[STATUS] Data Directory: {self.data_dir}")
        
        # Setup global hotkey
        if WINDOWS_INTEGRATION:
            if self.setup_global_hotkey():
                print("[HOTKEY] ✅ Press Ctrl+Alt+Space to record in ANY application")
            else:
                print("[HOTKEY] ❌ Failed to register global hotkey")
        else:
            print("[HOTKEY] ❌ Windows integration required for global hotkey")
        
        # Start WebSocket server for UI
        try:
            async with websockets.serve(self.handle_websocket, "localhost", 8765):
                print("[SERVER] ✅ WebSocket server running on ws://localhost:8765")
                print("[READY] 🚀 Enhanced VoiceFlow is ready!")
                print("\nPress Ctrl+Alt+Space anywhere to start voice transcription")
                print("Ctrl+C to exit")
                
                # Keep running
                while self.is_server_running:
                    await asyncio.sleep(1)
                    
        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Shutting down Enhanced VoiceFlow...")
            self.is_server_running = False
        except Exception as e:
            print(f"[ERROR] Server error: {e}")

if __name__ == "__main__":
    server = EnhancedVoiceFlowServer()
    try:
        asyncio.run(server.main())
    except KeyboardInterrupt:
        print("\n[EXIT] Enhanced VoiceFlow stopped by user")
    except Exception as e:
        print(f"[FATAL] {e}")
        input("Press Enter to exit...")