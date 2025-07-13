"""
VoiceFlow Native - Invisible Voice Transcription for Windows
A truly invisible voice transcription system that works globally across all applications.

Architecture: Native Windows service with global hotkey support and universal text injection.
"""

import threading
import time
import sys
import os
import json
import logging
from pathlib import Path
from datetime import datetime
import win32api
import win32con
import win32gui
import win32clipboard
import win32process
import win32ui
import win32file
import win32event
import pystray
from PIL import Image, ImageDraw
import keyboard  # For global hotkey handling
import pyaudio
import wave
import tempfile
import asyncio
import queue

# Import terminal integration
try:
    from core.terminal_integration import create_terminal_injector, TerminalDetector
    TERMINAL_INTEGRATION_AVAILABLE = True
except ImportError:
    TERMINAL_INTEGRATION_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('voiceflow_native.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VoiceFlowNative:
    """
    Native Windows voice transcription service.
    Provides invisible, global voice-to-text with application context awareness.
    """
    
    def __init__(self):
        self.version = "2.0.0-native-terminal"
        self.is_running = True
        self.is_recording = False
        self.audio_queue = queue.Queue()
        self.settings = self.load_settings()
        
        # Application context detection
        self.current_app = None
        self.app_context = {}
        
        # Terminal integration
        if TERMINAL_INTEGRATION_AVAILABLE:
            self.terminal_injector = create_terminal_injector()
            self.terminal_detector = TerminalDetector()
            logger.info("Terminal integration enabled")
        else:
            self.terminal_injector = None
            self.terminal_detector = None
            logger.warning("Terminal integration not available")
        
        # Audio configuration
        self.audio_format = pyaudio.paInt16
        self.channels = 1
        self.sample_rate = 16000
        self.chunk_size = 1024
        self.audio_device = None
        
        # Hotkey configuration
        self.hotkey_combination = self.settings.get('hotkey', 'ctrl+alt')
        
        # Statistics
        self.stats = {
            'session_start': datetime.now(),
            'total_transcriptions': 0,
            'total_words': 0,
            'average_latency': 0,
            'successful_injections': 0,
            'failed_injections': 0,
            'terminal_injections': 0,
            'terminal_detections': 0
        }
        
        logger.info(f"VoiceFlow Native {self.version} initializing...")
        
    def load_settings(self):
        """Load user settings from configuration file."""
        settings_path = Path.home() / '.voiceflow' / 'native_settings.json'
        settings_path.parent.mkdir(exist_ok=True)
        
        default_settings = {
            'hotkey': 'ctrl+alt',
            'auto_start': True,
            'context_awareness': True,
            'audio_device': 'default',
            'whisper_model': 'base',
            'processing_timeout': 10,
            'inject_method': 'sendkeys',  # sendkeys, clipboard, accessibility
            'enhanced_processing': True
        }
        
        try:
            if settings_path.exists():
                with open(settings_path, 'r') as f:
                    loaded_settings = json.load(f)
                    # Merge with defaults
                    default_settings.update(loaded_settings)
            return default_settings
        except Exception as e:
            logger.warning(f"Failed to load settings: {e}. Using defaults.")
            return default_settings
    
    def save_settings(self):
        """Save current settings to configuration file."""
        settings_path = Path.home() / '.voiceflow' / 'native_settings.json'
        try:
            with open(settings_path, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
    
    def get_active_window_info(self):
        """
        Get information about the currently active window.
        Returns application name, window title, and process info.
        """
        try:
            # Get the foreground window
            hwnd = win32gui.GetForegroundWindow()
            if not hwnd:
                return None
            
            # Get window title
            window_title = win32gui.GetWindowText(hwnd)
            
            # Get process ID and executable name
            _, process_id = win32process.GetWindowThreadProcessId(hwnd)
            process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, process_id)
            executable_path = win32process.GetModuleFileNameEx(process_handle, 0)
            app_name = os.path.basename(executable_path).lower()
            
            win32api.CloseHandle(process_handle)
            
            return {
                'hwnd': hwnd,
                'title': window_title,
                'app_name': app_name,
                'executable': executable_path,
                'process_id': process_id
            }
            
        except Exception as e:
            logger.error(f"Failed to get active window info: {e}")
            return None
    
    def detect_application_context(self, app_info):
        """
        Detect the type of application and appropriate formatting context.
        """
        if not app_info:
            return 'general'
        
        app_name = app_info.get('app_name', '').lower()
        window_title = app_info.get('title', '').lower()
        
        # Email applications
        if any(email_app in app_name for email_app in ['outlook', 'thunderbird', 'mailbird']):
            return 'email'
        
        # Web browsers (could be email, social, etc.)
        if any(browser in app_name for browser in ['chrome', 'firefox', 'edge', 'safari']):
            # Try to detect website context from title
            if any(site in window_title for site in ['gmail', 'outlook', 'yahoo mail']):
                return 'email'
            elif any(site in window_title for site in ['slack', 'discord', 'teams']):
                return 'chat'
            elif any(site in window_title for site in ['linkedin', 'twitter', 'facebook']):
                return 'social'
            else:
                return 'web'
        
        # Code editors and terminals
        if any(editor in app_name for editor in ['code', 'notepad++', 'sublime', 'atom', 'pycharm', 'visual studio']):
            # Check if it's a terminal within VS Code
            if self.terminal_detector and 'code' in app_name:
                terminal_type, metadata = self.terminal_detector.detect_terminal_type(app_info)
                if terminal_type.value != 'unknown':
                    self.stats['terminal_detections'] += 1
                    return 'terminal'
            return 'code'
        
        # Terminal applications
        if self.terminal_detector:
            terminal_type, metadata = self.terminal_detector.detect_terminal_type(app_info)
            if terminal_type.value != 'unknown':
                self.stats['terminal_detections'] += 1
                return 'terminal'
        
        # Office applications
        if any(office in app_name for office in ['winword', 'excel', 'powerpoint']):
            return 'document'
        
        # Chat applications
        if any(chat in app_name for chat in ['slack', 'discord', 'teams', 'skype', 'zoom']):
            return 'chat'
        
        # Note-taking
        if any(notes in app_name for notes in ['notepad', 'onenote', 'notion', 'obsidian']):
            return 'notes'
        
        # Default
        return 'general'
    
    def format_text_for_context(self, text, context):
        """
        Format transcribed text based on application context.
        This is where we implement context-aware intelligence.
        """
        if not text or not text.strip():
            return text
        
        # Base formatting - ensure proper capitalization and punctuation
        formatted_text = text.strip()
        if formatted_text and not formatted_text[0].isupper():
            formatted_text = formatted_text[0].upper() + formatted_text[1:]
        
        # Context-specific formatting
        if context == 'email':
            # Professional tone, formal punctuation
            if not formatted_text.endswith(('.', '!', '?')):
                formatted_text += '.'
            # Remove filler words common in speech
            formatted_text = self.remove_speech_fillers(formatted_text)
            
        elif context == 'chat':
            # Casual tone, minimal punctuation
            formatted_text = formatted_text.lower()
            if len(formatted_text) > 50 and not formatted_text.endswith(('.', '!', '?')):
                formatted_text += '.'
                
        elif context == 'code':
            # Technical formatting, preserve exact speech
            # Don't auto-capitalize or add punctuation
            pass
        
        elif context == 'terminal':
            # Terminal-specific formatting - preserve exact commands
            # Don't modify capitalization or punctuation for commands
            pass
            
        elif context == 'document':
            # Formal document formatting
            if not formatted_text.endswith(('.', '!', '?')):
                formatted_text += '.'
            formatted_text = self.remove_speech_fillers(formatted_text)
            
        elif context == 'social':
            # Casual social media formatting
            formatted_text = formatted_text.lower()
            
        return formatted_text
    
    def remove_speech_fillers(self, text):
        """Remove common speech fillers for professional contexts."""
        fillers = ['um', 'uh', 'like', 'you know', 'so', 'basically', 'actually']
        words = text.split()
        filtered_words = []
        
        for word in words:
            clean_word = word.lower().strip('.,!?')
            if clean_word not in fillers:
                filtered_words.append(word)
                
        return ' '.join(filtered_words)
    
    def inject_text_universal(self, text, app_info=None):
        """
        Universal text injection that works across all Windows applications.
        Uses multiple fallback methods for maximum compatibility, with terminal-aware injection.
        """
        if not text:
            return False
        
        success = False
        method_used = None
        
        try:
            # Terminal-specific injection (highest priority for terminal apps)
            if self.terminal_injector and app_info:
                context = self.detect_application_context(app_info)
                if context == 'terminal':
                    success = self.terminal_injector.inject_enhanced_text(text, enable_command_processing=True)
                    if success:
                        method_used = 'terminal_enhanced'
                        self.stats['terminal_injections'] += 1
                        logger.info(f"Terminal injection successful: '{text[:50]}...'")
                        self.stats['successful_injections'] += 1
                        return True
            
            # Method 1: Direct SendKeys (fastest, works in most apps)
            if self.settings.get('inject_method') == 'sendkeys':
                success = self.inject_via_sendkeys(text)
                method_used = 'sendkeys'
            
            # Method 2: Clipboard + Paste (universal fallback)
            if not success:
                success = self.inject_via_clipboard(text)
                method_used = 'clipboard'
            
            # Method 3: Windows Accessibility API (for special cases)
            if not success and app_info:
                success = self.inject_via_accessibility(text, app_info)
                method_used = 'accessibility'
            
            # Update statistics
            if success:
                self.stats['successful_injections'] += 1
                logger.info(f"Text injected successfully via {method_used}: '{text[:50]}...'")
            else:
                self.stats['failed_injections'] += 1
                logger.warning(f"Failed to inject text: '{text[:50]}...'")
            
            return success
            
        except Exception as e:
            logger.error(f"Text injection error: {e}")
            self.stats['failed_injections'] += 1
            return False
    
    def inject_via_sendkeys(self, text):
        """Inject text using Windows SendKeys."""
        try:
            # Use keyboard library for reliable key sending
            keyboard.write(text)
            return True
        except Exception as e:
            logger.debug(f"SendKeys injection failed: {e}")
            return False
    
    def inject_via_clipboard(self, text):
        """Inject text via clipboard and Ctrl+V."""
        try:
            # Save current clipboard content
            original_clipboard = self.get_clipboard_text()
            
            # Set our text to clipboard
            self.set_clipboard_text(text)
            
            # Send Ctrl+V
            keyboard.send('ctrl+v')
            
            # Restore original clipboard after a delay
            threading.Timer(0.5, lambda: self.set_clipboard_text(original_clipboard or '')).start()
            
            return True
        except Exception as e:
            logger.debug(f"Clipboard injection failed: {e}")
            return False
    
    def inject_via_accessibility(self, text, app_info):
        """Inject text using Windows accessibility APIs."""
        try:
            hwnd = app_info.get('hwnd')
            if not hwnd:
                return False
            
            # Try to find the active text control
            # This is more complex and would require walking the window hierarchy
            # For now, fallback to SendMessage
            win32gui.SendMessage(hwnd, win32con.WM_CHAR, ord(text[0]), 0)
            return True
        except Exception as e:
            logger.debug(f"Accessibility injection failed: {e}")
            return False
    
    def get_clipboard_text(self):
        """Get current clipboard text content."""
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
    
    def set_clipboard_text(self, text):
        """Set clipboard text content."""
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, text.encode('utf-8'))
            win32clipboard.CloseClipboard()
            return True
        except Exception as e:
            logger.debug(f"Failed to set clipboard: {e}")
            return False
        finally:
            try:
                win32clipboard.CloseClipboard()
            except:
                pass
    
    def process_audio_to_text(self, audio_file_path):
        """
        Process audio file to text using integrated speech processor.
        """
        try:
            from speech_processor import process_audio_file_wrapper
            
            # Get current application context for processing
            app_info = self.get_active_window_info()
            context = self.detect_application_context(app_info)
            
            # Process audio with context awareness
            enhanced_text, metadata = process_audio_file_wrapper(audio_file_path, context)
            
            if enhanced_text:
                # Update statistics with processing metadata
                if 'total_time_ms' in metadata:
                    self.stats['average_latency'] = (
                        self.stats['average_latency'] * self.stats['total_transcriptions'] + 
                        metadata['total_time_ms']
                    ) / (self.stats['total_transcriptions'] + 1)
                
                logger.info(f"Speech processing complete: '{enhanced_text}' (Context: {context})")
                return enhanced_text, metadata
            else:
                logger.error("Speech processing failed")
                return None, metadata
            
        except ImportError:
            logger.error("Speech processor not available. Using fallback.")
            return self._fallback_processing(audio_file_path)
        except Exception as e:
            logger.error(f"Audio processing error: {e}")
            return None, {}
    
    def _fallback_processing(self, audio_file_path):
        """Fallback processing when speech processor is not available."""
        import time
        time.sleep(0.5)  # Simulate processing
        return "Fallback transcription - speech processor not available", {}
    
    def start_recording(self):
        """Start audio recording for voice input."""
        if self.is_recording:
            return
        
        self.is_recording = True
        logger.info("Recording started")
        
        # Get current application context
        app_info = self.get_active_window_info()
        context = self.detect_application_context(app_info)
        logger.info(f"Application context: {context} ({app_info.get('app_name') if app_info else 'Unknown'})")
        
        # Start audio recording in separate thread
        threading.Thread(target=self._record_audio_thread, args=(app_info, context), daemon=True).start()
    
    def stop_recording(self):
        """Stop audio recording and process the audio."""
        if not self.is_recording:
            return
        
        self.is_recording = False
        logger.info("Recording stopped")
    
    def _record_audio_thread(self, app_info, context):
        """Record audio in a separate thread."""
        try:
            # Initialize PyAudio
            audio = pyaudio.PyAudio()
            
            # Open audio stream
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
            
            # Record while hotkey is held
            while self.is_recording:
                data = stream.read(self.chunk_size, exception_on_overflow=False)
                frames.append(data)
                
                # Prevent extremely long recordings
                if time.time() - start_time > 30:
                    logger.warning("Recording timeout after 30 seconds")
                    break
            
            # Clean up audio resources
            stream.stop_stream()
            stream.close()
            audio.terminate()
            
            if frames:
                # Save audio to temporary file
                with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_audio:
                    temp_path = temp_audio.name
                    
                wf = wave.open(temp_path, 'wb')
                wf.setnchannels(self.channels)
                wf.setsampwidth(audio.get_sample_size(self.audio_format))
                wf.setframerate(self.sample_rate)
                wf.writeframes(b''.join(frames))
                wf.close()
                
                # Process audio to text with enhancement
                processing_start = time.time()
                result = self.process_audio_to_text(temp_path)
                
                if result and len(result) == 2:
                    enhanced_text, metadata = result
                    processing_time = metadata.get('total_time_ms', (time.time() - processing_start) * 1000)
                    
                    if enhanced_text:
                        # Inject text into active application
                        injection_success = self.inject_text_universal(enhanced_text, app_info)
                        
                        # Update statistics
                        self.stats['total_transcriptions'] += 1
                        self.stats['total_words'] += metadata.get('word_count', len(enhanced_text.split()))
                        
                        logger.info(f"Transcription complete: '{enhanced_text}' (Processing: {processing_time:.0f}ms)")
                    else:
                        logger.warning("No text transcribed from audio")
                else:
                    logger.warning("Audio processing returned invalid result")
                
                # Clean up temporary file
                try:
                    os.unlink(temp_path)
                except:
                    pass
            
        except Exception as e:
            logger.error(f"Recording thread error: {e}")
            self.is_recording = False
    
    def setup_global_hotkey(self):
        """Setup global hotkey for voice activation."""
        try:
            # Register hotkey using keyboard library
            logger.info(f"Registering global hotkey: {self.hotkey_combination}")
            
            keyboard.add_hotkey(
                self.hotkey_combination,
                self.start_recording,
                suppress=False,
                trigger_on_release=False
            )
            
            # Also register release event
            keyboard.on_release_key(
                self.hotkey_combination.split('+')[-1],
                lambda _: self.stop_recording()
            )
            
            logger.info("Global hotkey registered successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register global hotkey: {e}")
            return False
    
    def create_system_tray_icon(self):
        """Create system tray icon for VoiceFlow."""
        # Create a simple icon
        image = Image.new('RGB', (64, 64), color='blue')
        draw = ImageDraw.Draw(image)
        draw.ellipse([16, 16, 48, 48], fill='white')
        
        # Create menu
        menu = pystray.Menu(
            pystray.MenuItem("VoiceFlow Native", None, enabled=False),
            pystray.MenuItem("Status: Ready", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Settings", self.show_settings),
            pystray.MenuItem("Statistics", self.show_statistics),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self.shutdown)
        )
        
        # Create tray icon
        self.tray_icon = pystray.Icon(
            "VoiceFlow",
            image,
            "VoiceFlow Native - Invisible Voice Transcription",
            menu
        )
        
        return self.tray_icon
    
    def show_settings(self, icon, item):
        """Show settings dialog (placeholder)."""
        # For now, just log. In full implementation, this would open a settings window.
        logger.info("Settings requested - placeholder")
        
    def show_statistics(self, icon, item):
        """Show statistics dialog (placeholder)."""
        uptime = datetime.now() - self.stats['session_start']
        stats_text = f"""VoiceFlow Native Statistics:
Uptime: {uptime}
Transcriptions: {self.stats['total_transcriptions']}
Words: {self.stats['total_words']}
Successful Injections: {self.stats['successful_injections']}
Failed Injections: {self.stats['failed_injections']}
Terminal Injections: {self.stats['terminal_injections']}
Terminal Detections: {self.stats['terminal_detections']}
Success Rate: {(self.stats['successful_injections'] / max(1, self.stats['successful_injections'] + self.stats['failed_injections']) * 100):.1f}%"""
        
        logger.info(f"Statistics:\n{stats_text}")
    
    def shutdown(self, icon=None, item=None):
        """Shutdown VoiceFlow Native."""
        logger.info("Shutting down VoiceFlow Native...")
        self.is_running = False
        
        # Save settings
        self.save_settings()
        
        # Stop tray icon
        if hasattr(self, 'tray_icon'):
            self.tray_icon.stop()
        
        # Exit
        sys.exit(0)
    
    def run(self):
        """Main entry point for VoiceFlow Native."""
        try:
            logger.info("Starting VoiceFlow Native...")
            
            # Setup global hotkey
            if not self.setup_global_hotkey():
                logger.error("Failed to setup global hotkey. Exiting.")
                return
            
            # Create and run system tray
            tray_icon = self.create_system_tray_icon()
            
            logger.info("VoiceFlow Native is running. Press Ctrl+Alt to start recording.")
            logger.info("System tray icon created. Right-click for options.")
            
            # Run tray icon (this blocks)
            tray_icon.run()
            
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except Exception as e:
            logger.error(f"Fatal error: {e}")
        finally:
            self.shutdown()

def main():
    """Main entry point."""
    print("VoiceFlow Native - Invisible Voice Transcription")
    print("=" * 50)
    
    try:
        app = VoiceFlowNative()
        app.run()
    except Exception as e:
        logger.error(f"Failed to start VoiceFlow Native: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
