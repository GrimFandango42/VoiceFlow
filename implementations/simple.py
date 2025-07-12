#!/usr/bin/env python3
"""
Simple VoiceFlow Implementation

A straightforward implementation for testing and basic usage.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.voiceflow_core import VoiceFlowEngine, create_engine
from core.ai_enhancement import AIEnhancer, create_enhancer
from utils.config import get_config, get_audio_config, get_ai_config

try:
    import pyautogui
    import keyboard
    SYSTEM_INTEGRATION = True
except ImportError:
    SYSTEM_INTEGRATION = False
    print("[WARNING] System integration not available - install pyautogui and keyboard packages")


class SimpleVoiceFlow:
    """Simple VoiceFlow implementation for testing and basic usage."""
    
    def __init__(self):
        """Initialize Simple VoiceFlow application."""
        # Load configuration
        config = get_config()
        
        # Initialize core engine
        self.engine = create_engine(get_audio_config())
        
        # Initialize AI enhancer
        self.ai_enhancer = create_enhancer(get_ai_config())
        
        # Set up callbacks
        self.engine.on_transcription = self.on_transcription
        self.engine.on_error = self.on_error
    
    def on_transcription(self, text: str):
        """Handle transcription result."""
        print(f"[TRANSCRIPTION] {text}")
        
        # Enhance with AI if available
        if self.ai_enhancer and self.ai_enhancer.get_status().get('connected', False):
            try:
                enhanced = self.ai_enhancer.enhance_text(text)
                print(f"[ENHANCED] {enhanced}")
                text = enhanced
            except Exception as e:
                print(f"[WARNING] AI enhancement failed: {e}")
        
        # Inject text if system integration available
        if SYSTEM_INTEGRATION:
            try:
                pyautogui.write(text)
            except Exception as e:
                print(f"[WARNING] Text injection failed: {e}")
    
    def on_error(self, error):
        """Handle errors."""
        print(f"[ERROR] {error}")
    
    def start(self):
        """Start the application."""
        print("Simple VoiceFlow started")
        if SYSTEM_INTEGRATION:
            print("Press Ctrl+Alt to record")
        
        # Set up hotkeys if available
        if SYSTEM_INTEGRATION:
            try:
                self.engine.setup_hotkeys("ctrl+alt")
            except Exception as e:
                print(f"[WARNING] Hotkey setup failed: {e}")
    
    def cleanup(self):
        """Clean up resources."""
        if hasattr(self.engine, 'cleanup'):
            self.engine.cleanup()


if __name__ == "__main__":
    app = SimpleVoiceFlow()
    try:
        app.start()
        # Keep running
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        app.cleanup()