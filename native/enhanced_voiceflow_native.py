"""
Enhanced VoiceFlow Native - Complete Wispr Flow Alternative
True invisible global voice transcription for Windows with instant text injection
"""

import asyncio
import threading
import time
import sys
import os
import json
import logging
import tempfile
import wave
from pathlib import Path
from datetime import datetime
import sqlite3

# Windows-specific imports
try:
    import pyaudio
    import keyboard
    import pyautogui
    import win32api
    import win32con
    import win32gui
    import win32clipboard
    import win32process
    import win32file
    import win32event
    import pystray
    from PIL import Image, ImageDraw
    WINDOWS_INTEGRATION = True
except ImportError as e:
    print(f"Windows integration imports failed: {e}")
    WINDOWS_INTEGRATION = False

# AI and Speech Processing
try:
    from RealtimeSTT import AudioToTextRecorder
    import requests
    SPEECH_PROCESSING = True
except ImportError as e:
    print(f"Speech processing imports failed: {e}")
    SPEECH_PROCESSING = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('enhanced_voiceflow_native.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EnhancedVoiceFlowNative:
    """
    Enhanced VoiceFlow Native - Complete Wispr Flow replacement
    Features:
    - True global hotkey (Ctrl+Alt+Space)
    - Invisible operation
    - Instant text injection
    - Context-aware formatting
    - AI enhancement
    - System tray integration
    """
    
    def __init__(self):
        self.version = "2.1.0-enhanced"
        logger.info(f"Enhanced VoiceFlow Native {self.version} initializing...")
        
        # Core state
        self.is_running = True
        self.is_recording = False
        self.hotkey_registered = False
        
        # Configuration
        self.settings = self.load_settings()
        self.hotkey_combination = 'ctrl+alt+space'  # Wispr Flow compatible
        
        # Data paths
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "transcriptions.db"
        
        # Initialize database
        self.init_database()
        
        # AI Configuration
        self.ollama_urls = [
            "http://localhost:11434/api/generate",
            "http://172.30.248.191:11434/api/generate",
            "http://127.0.0.1:11434/api/generate"
        ]
        self.ollama_url = None
        self.deepseek_model = "llama3.3:latest"
        self.use_ai_enhancement = True
        self.test_ollama_connection()
        
        # Audio configuration
        self.audio_format = pyaudio.paInt16
        self.channels = 1
        self.sample_rate = 16000
        self.chunk_size = 1024
        
        # Statistics
        self.stats = {
            'session_start': datetime.now(),
            'total_transcriptions': 0,
            'total_words': 0,
            'successful_injections': 0,
            'failed_injections': 0,
            'average_latency_ms': 0
        }
        
        # Current transcription state
        self.current_transcription = {
            'start_time': None,
            'audio_frames': [],
            'target_app': None,
            'context': 'general'
        }
        
        # Initialize speech processor
        if SPEECH_PROCESSING:
            self.init_speech_processor()
        else:
            logger.error("Speech processing not available - install RealtimeSTT")
            
        logger.info("Enhanced VoiceFlow Native initialized successfully")
    
    def load_settings(self):
        """Load configuration settings"""
        settings_path = self.data_dir / 'enhanced_settings.json'
        
        default_settings = {
            'hotkey': 'ctrl+alt+space',
            'auto_start': True,
            'context_awareness': True,
            'ai_enhancement': True,
            'injection_method': 'smart',  # smart, sendkeys, clipboard, winapi
            'whisper_model': 'base',
            'processing_timeout': 10,
            'min_recording_duration': 0.5,
            'max_recording_duration': 30
        }
        
        try:
            if settings_path.exists():
                with open(settings_path, 'r') as f:
                    loaded = json.load(f)
                    default_settings.update(loaded)
        except Exception as e:
            logger.warning(f"Failed to load settings: {e}")
            
        return default_settings
    
    def save_settings(self):
        """Save current settings"""
        settings_path = self.data_dir / 'enhanced_settings.json'
        try:
            with open(settings_path, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
    
    def init_database(self):
        """Initialize SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS enhanced_transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    raw_text TEXT NOT NULL,
                    enhanced_text TEXT,
                    target_app TEXT,
                    context_type TEXT,
                    duration_ms INTEGER,
                    word_count INTEGER,
                    processing_time_ms INTEGER,
                    injection_success BOOLEAN,
                    injection_method TEXT,
                    ai_enhanced BOOLEAN
                )
            ''')
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    def test_ollama_connection(self):
        """Test Ollama AI enhancement connectivity"""
        for url in self.ollama_urls:
            try:
                test_url = url.replace('/generate', '/tags')
                response = requests.get(test_url, timeout=2)
                if response.status_code == 200:
                    self.ollama_url = url
                    models = response.json().get('models', [])
                    model_names = [m.get('name', '') for m in models]
                    
                    if self.deepseek_model in model_names:
                        logger.info(f"AI enhancement available: {self.deepseek_model}")
                        return
                    elif model_names:
                        self.deepseek_model = model_names[0]
                        logger.info(f"Using AI model: {self.deepseek_model}")
                        return
            except:
                continue
        
        logger.warning("AI enhancement unavailable - using basic formatting")
        self.use_ai_enhancement = False
    
    def init_speech_processor(self):
        """Initialize the speech recognition system"""
        logger.info("Initializing speech processor...")
        
        # Try different configurations for maximum compatibility
        configs = [
            {"model": "large-v3", "device": "cuda", "compute_type": "float16"},
            {"model": "base", "device": "cuda", "compute_type": "int8"},
            {"model": "base", "device": "cpu", "compute_type": "int8"}
        ]
        
        for i, config in enumerate(configs):
            try:
                self.recorder = AudioToTextRecorder(
                    model=config["model"],
                    language="en",
                    device=config["device"],
                    compute_type=config["compute_type"],
                    gpu_device_index=0 if config["device"] == "cuda" else None,
                    use_microphone=False,  # We'll handle audio ourselves
                    spinner=False,
                    level=0,
                    enable_realtime_transcription=False,  # We want final results only
                    silero_sensitivity=0.5,
                    webrtc_sensitivity=3,
                    post_speech_silence_duration=0.4,
                    min_length_of_recording=0.5,
                    min_gap_between_recordings=0.3
                )
                
                logger.info(f"Speech processor initialized: {config['device']} {config['model']}")
                return
                
            except Exception as e:
                logger.warning(f"Speech config {i+1} failed: {e}")
                if i == len(configs) - 1:
                    raise Exception("All speech processor configurations failed")
    
    def setup_global_hotkey(self):
        """Setup global hotkey: Ctrl+Alt+Space"""
        if not WINDOWS_INTEGRATION:
            logger.error("Windows integration required for global hotkey")
            return False
        
        try:
            # Register press and release handlers
            keyboard.add_hotkey(
                self.hotkey_combination,
                self.on_hotkey_press,
                suppress=False,
                trigger_on_release=False
            )
            
            # Register release handler for the space key
            keyboard.on_release_key('space', self.on_hotkey_release)
            
            self.hotkey_registered = True
            logger.info(f"Global hotkey registered: {self.hotkey_combination}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register global hotkey: {e}")
            return False
    
    def on_hotkey_press(self):
        """Called when Ctrl+Alt+Space is pressed"""
        if not self.is_recording:
            self.start_recording()
    
    def on_hotkey_release(self, key):
        """Called when space key is released (if recording)"""
        # Only stop if we're recording and the key release is from our hotkey
        if self.is_recording and keyboard.is_pressed('ctrl') and keyboard.is_pressed('alt'):
            # Small delay to avoid immediate stop
            threading.Timer(0.1, self.stop_recording).start()
    
    def start_recording(self):
        """Start voice recording"""
        if self.is_recording:
            return
        
        logger.info("🔴 Recording started")
        self.is_recording = True
        
        # Get current application context
        app_info = self.get_active_window_info()
        context = self.detect_application_context(app_info)
        
        self.current_transcription = {
            'start_time': time.time(),
            'audio_frames': [],
            'target_app': app_info,
            'context': context
        }
        
        if app_info:
            logger.info(f"Target: {app_info.get('app_name')} ({context})")
        
        # Start audio recording in background thread
        threading.Thread(target=self._record_audio_thread, daemon=True).start()
    
    def stop_recording(self):
        """Stop voice recording and process"""
        if not self.is_recording:
            return
        
        logger.info("⏹️ Recording stopped")
        self.is_recording = False
        
        # Processing will be handled by the recording thread
    
    def _record_audio_thread(self):
        """Record audio in background thread"""
        try:
            # Initialize PyAudio
            audio = pyaudio.PyAudio()
            
            stream = audio.open(
                format=self.audio_format,
                channels=self.channels,
                rate=self.sample_rate,
                input=True,
                frames_per_buffer=self.chunk_size
            )
            
            frames = []
            start_time = time.time()
            
            logger.info("Audio capture started")
            
            # Record while hotkey is held or until timeout
            while self.is_recording:
                try:
                    data = stream.read(self.chunk_size, exception_on_overflow=False)
                    frames.append(data)
                    
                    # Safety timeout
                    if time.time() - start_time > self.settings['max_recording_duration']:
                        logger.warning("Recording timeout")
                        break
                        
                except Exception as e:
                    logger.error(f"Audio read error: {e}")
                    break
            
            # Cleanup audio resources
            stream.stop_stream()
            stream.close()
            audio.terminate()
            
            # Check minimum duration
            duration = time.time() - start_time
            if duration < self.settings['min_recording_duration']:
                logger.info("Recording too short, ignoring")
                return
            
            if frames:
                # Save audio to temporary file
                temp_audio_file = self._save_audio_to_file(frames)
                if temp_audio_file:
                    # Process audio to text
                    self._process_audio_to_text(temp_audio_file, duration)
                    # Cleanup
                    try:
                        os.unlink(temp_audio_file)
                    except:
                        pass
            
        except Exception as e:
            logger.error(f"Recording thread error: {e}")
            self.is_recording = False
    
    def _save_audio_to_file(self, frames):
        """Save recorded audio frames to temporary WAV file"""
        try:
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
                temp_path = temp_file.name
            
            wf = wave.open(temp_path, 'wb')
            wf.setnchannels(self.channels)
            wf.setsampwidth(2)  # 16-bit audio
            wf.setframerate(self.sample_rate)
            wf.writeframes(b''.join(frames))
            wf.close()
            
            return temp_path
            
        except Exception as e:
            logger.error(f"Failed to save audio file: {e}")
            return None
    
    def _process_audio_to_text(self, audio_file_path, duration):
        """Process audio file to text using Whisper"""
        processing_start = time.time()
        
        try:
            # Use the recorder to transcribe the audio file
            text = self.recorder.transcribe(audio_file_path)
            
            if not text or not text.strip():
                logger.warning("No text transcribed")
                return
            
            # Clean up the text
            raw_text = text.strip()
            
            # Get application context
            app_info = self.current_transcription['target_app']
            context = self.current_transcription['context']
            
            # Enhance with AI
            enhanced_text = self.enhance_text_with_ai(raw_text, context)
            
            # Calculate metrics
            processing_time = int((time.time() - processing_start) * 1000)
            duration_ms = int(duration * 1000)
            word_count = len(enhanced_text.split())
            
            # Inject text into application
            injection_success, injection_method = self.inject_text_smart(enhanced_text, app_info)
            
            # Save to database
            self.save_transcription(
                raw_text=raw_text,
                enhanced_text=enhanced_text,
                target_app=app_info.get('app_name') if app_info else None,
                context_type=context,
                duration_ms=duration_ms,
                word_count=word_count,
                processing_time_ms=processing_time,
                injection_success=injection_success,
                injection_method=injection_method,
                ai_enhanced=self.use_ai_enhancement
            )
            
            # Update statistics
            self.update_statistics(word_count, processing_time, injection_success)
            
            logger.info(f"✅ '{enhanced_text}' ({processing_time}ms, {'✅' if injection_success else '❌'} {injection_method})")
            
        except Exception as e:
            logger.error(f"Audio processing failed: {e}")
    
    def get_active_window_info(self):
        """Get information about the currently active window"""
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
            logger.error(f"Failed to get window info: {e}")
            return None
    
    def detect_application_context(self, app_info):
        """Detect application context for formatting"""
        if not app_info:
            return 'general'
        
        app_name = app_info.get('app_name', '').lower()
        window_title = app_info.get('title', '').lower()
        
        # Email applications
        if any(email in app_name for email in ['outlook', 'thunderbird', 'mailbird']):
            return 'email'
        
        # Web browsers with email
        if any(browser in app_name for browser in ['chrome', 'firefox', 'edge', 'msedge']):
            if any(site in window_title for site in ['gmail', 'outlook', 'yahoo mail']):
                return 'email'
            elif any(site in window_title for site in ['slack', 'discord', 'teams']):
                return 'chat'
            elif any(site in window_title for site in ['linkedin', 'twitter', 'facebook']):
                return 'social'
            return 'web'
        
        # Development tools
        if any(dev in app_name for dev in ['code', 'notepad++', 'sublime', 'atom', 'pycharm', 'visual studio']):
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
    
    def enhance_text_with_ai(self, text, context):
        """Enhance text using AI based on context"""
        if not self.use_ai_enhancement or not text:
            return self.basic_text_formatting(text, context)
        
        try:
            context_prompts = {
                'email': "Format this email text professionally with proper punctuation and grammar:",
                'chat': "Format this casual message naturally with minimal punctuation:",
                'code': "Format this technical text preserving exact terminology:",
                'document': "Format this formal document text with proper punctuation:",
                'social': "Format this social media text casually:",
                'general': "Format this text with proper punctuation and capitalization:"
            }
            
            prompt = f"{context_prompts.get(context, context_prompts['general'])} {text}"
            
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
                # Clean up quotes if present
                if enhanced.startswith('"') and enhanced.endswith('"'):
                    enhanced = enhanced[1:-1]
                return enhanced
            
        except Exception as e:
            logger.warning(f"AI enhancement failed: {e}")
        
        return self.basic_text_formatting(text, context)
    
    def basic_text_formatting(self, text, context):
        """Basic text formatting fallback"""
        if not text:
            return text
        
        formatted = text.strip()
        
        # Capitalize first letter
        if formatted:
            formatted = formatted[0].upper() + formatted[1:]
        
        # Context-specific formatting
        if context in ['email', 'document']:
            # Formal contexts: ensure proper punctuation
            if not formatted.endswith(('.', '!', '?')):
                formatted += '.'
        elif context == 'chat':
            # Casual contexts: minimal punctuation
            pass
        elif context == 'code':
            # Technical contexts: preserve exact formatting
            formatted = text.strip()
        
        return formatted
    
    def inject_text_smart(self, text, app_info):
        """Smart text injection using multiple methods"""
        if not WINDOWS_INTEGRATION or not text:
            return False, "no_integration"
        
        # Try methods in order of reliability
        methods = [
            ('sendkeys', self._inject_sendkeys),
            ('clipboard', self._inject_clipboard),
            ('winapi', self._inject_winapi)
        ]
        
        for method_name, method_func in methods:
            try:
                if method_func(text, app_info):
                    return True, method_name
            except Exception as e:
                logger.debug(f"Injection method {method_name} failed: {e}")
                continue
        
        return False, "all_failed"
    
    def _inject_sendkeys(self, text, app_info):
        """Inject text using keyboard simulation"""
        keyboard.write(text)
        time.sleep(0.05)  # Small delay for completion
        return True
    
    def _inject_clipboard(self, text, app_info):
        """Inject text using clipboard + Ctrl+V"""
        # Save current clipboard
        original = self._get_clipboard_text()
        
        # Set our text to clipboard
        if self._set_clipboard_text(text):
            # Send Ctrl+V
            keyboard.send('ctrl+v')
            
            # Restore clipboard after delay
            def restore():
                time.sleep(0.5)
                if original:
                    self._set_clipboard_text(original)
            
            threading.Thread(target=restore, daemon=True).start()
            return True
        
        return False
    
    def _inject_winapi(self, text, app_info):
        """Inject text using Windows API"""
        if not app_info:
            return False
        
        hwnd = app_info.get('hwnd')
        if not hwnd:
            return False
        
        # Send characters using WM_CHAR messages
        for char in text:
            win32gui.SendMessage(hwnd, win32con.WM_CHAR, ord(char), 0)
            time.sleep(0.001)
        
        return True
    
    def _get_clipboard_text(self):
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
    
    def _set_clipboard_text(self, text):
        """Set clipboard text"""
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, text.encode('utf-8'))
            win32clipboard.CloseClipboard()
            return True
        except Exception as e:
            logger.debug(f"Clipboard set failed: {e}")
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
                INSERT INTO enhanced_transcriptions
                (raw_text, enhanced_text, target_app, context_type, duration_ms,
                 word_count, processing_time_ms, injection_success, injection_method, ai_enhanced)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                kwargs.get('raw_text'),
                kwargs.get('enhanced_text'),
                kwargs.get('target_app'),
                kwargs.get('context_type'),
                kwargs.get('duration_ms'),
                kwargs.get('word_count'),
                kwargs.get('processing_time_ms'),
                kwargs.get('injection_success'),
                kwargs.get('injection_method'),
                kwargs.get('ai_enhanced')
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database save failed: {e}")
    
    def update_statistics(self, word_count, processing_time, injection_success):
        """Update session statistics"""
        self.stats['total_transcriptions'] += 1
        self.stats['total_words'] += word_count
        
        if injection_success:
            self.stats['successful_injections'] += 1
        else:
            self.stats['failed_injections'] += 1
        
        # Update average latency
        total = self.stats['total_transcriptions']
        current_avg = self.stats['average_latency_ms']
        self.stats['average_latency_ms'] = ((current_avg * (total - 1)) + processing_time) / total
    
    def create_system_tray_icon(self):
        """Create system tray icon"""
        if not WINDOWS_INTEGRATION:
            return None
        
        # Create icon image
        image = Image.new('RGB', (64, 64), color=(0, 120, 255))
        draw = ImageDraw.Draw(image)
        draw.ellipse([8, 8, 56, 56], fill='white')
        draw.text((20, 20), "VF", fill='black')
        
        # Create menu
        menu = pystray.Menu(
            pystray.MenuItem("Enhanced VoiceFlow", None, enabled=False),
            pystray.MenuItem(f"Hotkey: {self.hotkey_combination}", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Statistics", self.show_statistics),
            pystray.MenuItem("Test Injection", self.test_text_injection),
            pystray.MenuItem("Open Data Folder", self.open_data_folder),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self.shutdown)
        )
        
        return pystray.Icon(
            "Enhanced VoiceFlow",
            image,
            "Enhanced VoiceFlow - Global Voice Transcription",
            menu
        )
    
    def show_statistics(self, icon, item):
        """Show statistics (placeholder - in full version would show UI)"""
        uptime = datetime.now() - self.stats['session_start']
        total_attempts = self.stats['successful_injections'] + self.stats['failed_injections']
        success_rate = (self.stats['successful_injections'] / max(1, total_attempts)) * 100
        
        stats_text = f"""Enhanced VoiceFlow Statistics:
Uptime: {uptime}
Transcriptions: {self.stats['total_transcriptions']}
Words: {self.stats['total_words']}
Success Rate: {success_rate:.1f}%
Avg Latency: {self.stats['average_latency_ms']:.0f}ms"""
        
        logger.info(f"Statistics:\n{stats_text}")
    
    def test_text_injection(self, icon, item):
        """Test text injection"""
        test_text = "Test from Enhanced VoiceFlow - Global text injection working!"
        app_info = self.get_active_window_info()
        success, method = self.inject_text_smart(test_text, app_info)
        logger.info(f"Test injection: {'✅' if success else '❌'} ({method})")
    
    def open_data_folder(self, icon, item):
        """Open data folder in Explorer"""
        os.startfile(str(self.data_dir))
    
    def shutdown(self, icon=None, item=None):
        """Shutdown Enhanced VoiceFlow"""
        logger.info("Shutting down Enhanced VoiceFlow...")
        self.is_running = False
        self.save_settings()
        
        if hasattr(self, 'tray_icon'):
            self.tray_icon.stop()
        
        sys.exit(0)
    
    def run(self):
        """Main entry point"""
        try:
            logger.info("Starting Enhanced VoiceFlow Native...")
            
            # Check dependencies
            if not WINDOWS_INTEGRATION:
                logger.error("Windows integration required. Install: pywin32, keyboard, pyautogui, pystray, PIL")
                return False
                
            if not SPEECH_PROCESSING:
                logger.error("Speech processing required. Install: RealtimeSTT, requests")
                return False
            
            # Setup global hotkey
            if not self.setup_global_hotkey():
                logger.error("Failed to setup global hotkey")
                return False
            
            # Create system tray
            self.tray_icon = self.create_system_tray_icon()
            if not self.tray_icon:
                logger.error("Failed to create system tray icon")
                return False
            
            logger.info("✅ Enhanced VoiceFlow is running!")
            logger.info(f"🎙️ Press {self.hotkey_combination} anywhere to record")
            logger.info("🔧 Right-click tray icon for options")
            
            # Run tray icon (blocks until exit)
            self.tray_icon.run()
            
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except Exception as e:
            logger.error(f"Fatal error: {e}")
        finally:
            self.shutdown()

def main():
    """Main entry point"""
    print("Enhanced VoiceFlow Native - Wispr Flow Alternative")
    print("=" * 60)
    
    if not WINDOWS_INTEGRATION:
        print("❌ Windows integration packages required:")
        print("   pip install pywin32 keyboard pyautogui pystray pillow")
        input("Press Enter to exit...")
        return
    
    if not SPEECH_PROCESSING:
        print("❌ Speech processing packages required:")
        print("   pip install RealtimeSTT requests")
        input("Press Enter to exit...")
        return
    
    try:
        app = EnhancedVoiceFlowNative()
        app.run()
    except Exception as e:
        logger.error(f"Failed to start: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()