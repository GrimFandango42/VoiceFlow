#!/usr/bin/env python3
"""
Blazing Fast VoiceFlow - Based on CONFIRMED WORKING commit 9913ce2
Key differences from broken version:
1. Uses pyautogui.typewrite() not write()
2. Simple hotkey handler without complex state
3. Direct recorder.text() call like working version
4. Reduced post_speech_silence_duration for speed
"""

import time
import json
import threading
from datetime import datetime
from pathlib import Path
import sys

# Import with fallbacks EXACTLY like working simple_server.py
try:
    import pyautogui
    import keyboard
    SYSTEM_INTEGRATION = True
    pyautogui.FAILSAFE = False
except ImportError:
    print("ERROR: System integration modules not found!")
    SYSTEM_INTEGRATION = False

try:
    from RealtimeSTT import AudioToTextRecorder
    STT_AVAILABLE = True
except ImportError:
    print("ERROR: RealtimeSTT not found!")
    STT_AVAILABLE = False

# Only import if we have system integration
if SYSTEM_INTEGRATION:
    try:
        import win32gui
        import win32process
        import psutil
        WIN32_AVAILABLE = True
    except:
        WIN32_AVAILABLE = False
else:
    WIN32_AVAILABLE = False


class BlazingFastVoiceFlow:
    def __init__(self):
        print("\n🚀 Blazing Fast VoiceFlow (Working Version)")
        print("Based on confirmed working commit 9913ce2\n")
        
        # Simple state like working version
        self.is_processing = False
        self.last_recording_time = 0
        
        # Paths for personalization
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        
        # Load personal dictionary
        self.personal_dict_path = self.data_dir / "personal_dict.json"
        self.load_personal_dictionary()
        
        # Initialize recorder
        if STT_AVAILABLE:
            if self.init_recorder():
                print("✅ STT recorder initialized successfully")
            else:
                print("❌ Failed to initialize STT")
                sys.exit(1)
        else:
            print("❌ RealtimeSTT not available!")
            sys.exit(1)
            
        # Setup hotkeys
        if SYSTEM_INTEGRATION:
            self.setup_hotkeys()
            print("✅ Hotkeys registered (Ctrl+Alt)")
        else:
            print("❌ System integration not available!")
            sys.exit(1)
            
    def init_recorder(self):
        """Initialize EXACTLY like working version but with speed tweaks"""
        try:
            self.recorder = AudioToTextRecorder(
                model="tiny",
                language="en",
                device="cuda",  # Try GPU first
                compute_type="int8",
                use_microphone=True,
                spinner=False,
                level=0,  # No logging
                enable_realtime_transcription=False,  # Like working version
                
                # VAD settings - only change is reduced post_speech_silence
                silero_sensitivity=0.4,
                webrtc_sensitivity=3,
                post_speech_silence_duration=0.3,  # Reduced from 0.8 for speed
                min_length_of_recording=0.5,
                min_gap_between_recordings=0.3,
                
                # Simple callbacks
                on_recording_start=self.on_recording_start,
                on_recording_stop=self.on_recording_stop
            )
            return True
            
        except Exception as e:
            print(f"GPU init failed: {e}, trying CPU...")
            try:
                # Fallback to CPU exactly like working version
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
                    post_speech_silence_duration=0.3,
                    min_length_of_recording=0.5,
                    min_gap_between_recordings=0.3,
                    on_recording_start=self.on_recording_start,
                    on_recording_stop=self.on_recording_stop
                )
                print("✅ Using CPU mode")
                return True
            except Exception as e:
                print(f"❌ CPU init also failed: {e}")
                return False
                
    def on_recording_start(self):
        """Simple callback like working version"""
        self.start_time = datetime.now()
        print(f"🎤 Recording started: {self.start_time.strftime('%H:%M:%S')}")
        
    def on_recording_stop(self):
        """Simple callback with duration"""
        if hasattr(self, 'start_time'):
            end_time = datetime.now()
            duration = (end_time - self.start_time).total_seconds()
            print(f"⏹️  Recording stopped: {duration:.1f}s")
            
    def load_personal_dictionary(self):
        """Load personal corrections"""
        if self.personal_dict_path.exists():
            try:
                with open(self.personal_dict_path, 'r') as f:
                    self.personal_dict = json.load(f)
            except:
                self.personal_dict = {}
        else:
            # Default tech terms
            self.personal_dict = {
                "voiceflow": "VoiceFlow",
                "github": "GitHub", 
                "openai": "OpenAI",
                "claude": "Claude",
                "gpt": "GPT",
                "api": "API",
                "javascript": "JavaScript",
                "python": "Python",
                "vs code": "VS Code",
                "nithin": "Nithin",
            }
            self.save_personal_dictionary()
            
    def save_personal_dictionary(self):
        """Save dictionary"""
        try:
            with open(self.personal_dict_path, 'w') as f:
                json.dump(self.personal_dict, f, indent=2)
        except:
            pass
            
    def apply_corrections(self, text):
        """Apply personal vocabulary - simple and fast"""
        if not text:
            return text
            
        # Apply corrections
        for wrong, right in self.personal_dict.items():
            # Case insensitive replace
            import re
            pattern = re.compile(re.escape(wrong), re.IGNORECASE)
            text = pattern.sub(right, text)
            
        return text
        
    def inject_text(self, text):
        """Inject text EXACTLY like working version"""
        if not SYSTEM_INTEGRATION or not text:
            return False
            
        try:
            print(f"[INJECTING] {text}")
            pyautogui.typewrite(text)  # CRITICAL: Use typewrite() not write()
            print("[SUCCESS] Text injected")
            return True
        except Exception as e:
            print(f"[ERROR] Text injection failed: {e}")
            # Fallback to keyboard module
            try:
                keyboard.write(text)
                print("[SUCCESS] Text injected via keyboard module")
                return True
            except:
                return False
            
    def process_speech(self):
        """Process speech EXACTLY like working version but with speed improvements"""
        # Prevent concurrent processing
        if self.is_processing:
            print("[SKIP] Already processing")
            return
            
        self.is_processing = True
        
        try:
            # Start timing
            start_time = time.time()
            
            # Direct call like working version - no threading complexity
            raw_text = self.recorder.text()
            
            if not raw_text or not raw_text.strip():
                print("[EMPTY] No text captured")
                return
                
            # Quick enhancements
            text = self.apply_corrections(raw_text)
            
            # Simple formatting
            if text and text[0].islower():
                text = text[0].upper() + text[1:]
            
            # Add period for longer sentences
            if len(text.split()) > 3 and text[-1] not in ".!?,;:":
                text += "."
                
            # Performance timing
            elapsed = time.time() - start_time
            print(f"\n📝 Transcribed in {elapsed:.2f}s: '{text}'")
            
            # Inject text using working method
            self.inject_text(text)
            
            # Small delay like working version
            time.sleep(0.5)
            
        except Exception as e:
            print(f"[ERROR] {e}")
            
        finally:
            self.is_processing = False
            
    def setup_hotkeys(self):
        """Setup hotkeys EXACTLY like working version"""
        def hotkey_handler():
            current_time = time.time()
            
            # Debounce like working version
            if current_time - self.last_recording_time < 1.0:
                return
                
            self.last_recording_time = current_time
            
            # Process in thread like working version
            threading.Thread(target=self.process_speech, daemon=True).start()
            
        try:
            keyboard.add_hotkey('ctrl+alt', hotkey_handler)
            return True
        except Exception as e:
            print(f"[ERROR] Hotkey registration failed: {e}")
            return False
            
    def run(self):
        """Run main loop like working version"""
        print("\n" + "="*50)
        print("🎤 VoiceFlow is running!")
        print("📍 Press Ctrl+Alt to start recording")
        print("📍 Release to stop and transcribe") 
        print("📍 Press Ctrl+C to exit")
        print("="*50 + "\n")
        
        try:
            # Keep running
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n👋 Shutting down...")
            

if __name__ == "__main__":
    if not STT_AVAILABLE:
        print("\n❌ RealtimeSTT is required!")
        print("Install with: pip install RealtimeSTT")
        sys.exit(1)
        
    if not SYSTEM_INTEGRATION:
        print("\n❌ System integration modules required!")
        print("Install with: pip install keyboard pyautogui pywin32")
        sys.exit(1)
        
    try:
        app = BlazingFastVoiceFlow()
        app.run()
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")