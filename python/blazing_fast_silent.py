#!/usr/bin/env python3
"""
Blazing Fast VoiceFlow - Silent Version
Minimal console output to prevent focus stealing
"""

import time
import json
import threading
import os
from datetime import datetime
from pathlib import Path
import sys

# Suppress most output
SILENT_MODE = True

# Import with fallbacks
try:
    import pyautogui
    import keyboard
    SYSTEM_INTEGRATION = True
    pyautogui.FAILSAFE = False
except ImportError:
    print("ERROR: Required modules not found!")
    sys.exit(1)

try:
    from RealtimeSTT import AudioToTextRecorder
    STT_AVAILABLE = True
except ImportError:
    print("ERROR: RealtimeSTT not found!")
    sys.exit(1)

import win32gui
import win32process
import psutil


class BlazingFastVoiceFlow:
    def __init__(self):
        if not SILENT_MODE:
            print("\n🚀 Blazing Fast VoiceFlow (Silent Mode)")
        
        # State management
        self.is_processing = False
        self.last_recording_time = 0
        self.recording_count = 0
        
        # Paths
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        
        # Load personal dictionary
        self.personal_dict_path = self.data_dir / "personal_dict.json"
        self.load_personal_dictionary()
        
        # Initialize recorder
        if self.init_recorder():
            if not SILENT_MODE:
                print("✅ Ready")
        else:
            print("❌ Failed to initialize")
            sys.exit(1)
            
        # Setup hotkeys
        self.setup_hotkeys()
        
        # Minimal startup message
        print("\n🎤 VoiceFlow Ready - Ctrl+Alt to transcribe")
        print("📍 Hold keys while speaking, release when done")
        print("🔇 Silent mode enabled (minimal output)\n")
            
    def init_recorder(self):
        """Initialize with minimal output"""
        try:
            self.recorder = AudioToTextRecorder(
                model="tiny",
                language="en",
                device="cuda",
                compute_type="int8",
                use_microphone=True,
                
                # Disable ALL console output from recorder
                spinner=False,
                level=0,
                enable_realtime_transcription=False,
                
                # Optimized VAD
                silero_sensitivity=0.4,
                webrtc_sensitivity=3,
                post_speech_silence_duration=0.3,
                min_length_of_recording=0.3,
                min_gap_between_recordings=0.2,
                
                # No callbacks to reduce output
                on_recording_start=None,
                on_recording_stop=None,
                on_vad_detect_start=None,
                on_vad_detect_stop=None,
            )
            return True
            
        except:
            # Try CPU silently
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
                    post_speech_silence_duration=0.3,
                    min_length_of_recording=0.3,
                )
                return True
            except:
                return False
                
    def load_personal_dictionary(self):
        """Load corrections silently"""
        if self.personal_dict_path.exists():
            try:
                with open(self.personal_dict_path, 'r') as f:
                    self.personal_dict = json.load(f)
            except:
                self.personal_dict = {}
        else:
            self.personal_dict = {
                "voiceflow": "VoiceFlow",
                "github": "GitHub", 
                "openai": "OpenAI",
                "claude": "Claude",
                "python": "Python",
                "nithin": "Nithin",
            }
            self.save_personal_dictionary()
            
    def save_personal_dictionary(self):
        """Save silently"""
        try:
            with open(self.personal_dict_path, 'w') as f:
                json.dump(self.personal_dict, f, indent=2)
        except:
            pass
            
    def apply_corrections(self, text):
        """Apply corrections"""
        if not text:
            return text
            
        import re
        for wrong, right in self.personal_dict.items():
            pattern = re.compile(re.escape(wrong), re.IGNORECASE)
            text = pattern.sub(right, text)
            
        return text
        
    def inject_text(self, text):
        """Inject text silently"""
        if not text:
            return False
            
        try:
            pyautogui.typewrite(text)
            return True
        except:
            try:
                keyboard.write(text)
                return True
            except:
                return False
            
    def process_speech(self):
        """Process with minimal output"""
        if self.is_processing:
            return
            
        self.is_processing = True
        self.recording_count += 1
        
        try:
            # Show minimal indicator
            if SILENT_MODE:
                print(f"[{self.recording_count}] Recording...", end='', flush=True)
            
            # Get transcription
            raw_text = self.recorder.text()
            
            if not raw_text or not raw_text.strip():
                if SILENT_MODE:
                    print(" (empty)")
                return
                
            # Process text
            text = self.apply_corrections(raw_text)
            
            # Format
            if text and text[0].islower():
                text = text[0].upper() + text[1:]
            if len(text.split()) > 3 and text[-1] not in ".!?,;:":
                text += "."
                
            # Inject
            self.inject_text(text)
            
            # Minimal output
            if SILENT_MODE:
                print(f" ✓ {len(text)} chars")
            else:
                print(f"📝 {text}")
            
        except Exception as e:
            if not SILENT_MODE:
                print(f"\n❌ Error: {e}")
            
        finally:
            self.is_processing = False
            
    def setup_hotkeys(self):
        """Setup with debouncing"""
        def hotkey_handler():
            current_time = time.time()
            
            # Stronger debounce to prevent Windows search
            if current_time - self.last_recording_time < 1.5:
                return
                
            self.last_recording_time = current_time
            
            # Process in thread
            threading.Thread(target=self.process_speech, daemon=True).start()
            
        try:
            keyboard.add_hotkey('ctrl+alt', hotkey_handler)
            return True
        except:
            return False
            
    def run(self):
        """Run silently"""
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n\n✅ VoiceFlow stopped")
            

if __name__ == "__main__":
    try:
        # Optional: Set console title
        if os.name == 'nt':
            os.system('title VoiceFlow - Silent Mode')
            
        app = BlazingFastVoiceFlow()
        app.run()
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        input("\nPress Enter to exit...")