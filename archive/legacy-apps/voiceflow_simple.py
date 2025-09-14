#!/usr/bin/env python3
"""
VoiceFlow Simple - Default Voice Transcription

The simple, straightforward way to use VoiceFlow.
Perfect for daily usage and getting started.

Usage: python voiceflow_simple.py
"""

import sys
import signal
import threading
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from core.voiceflow_core import create_engine
    from core.ai_enhancement import create_enhancer
    from utils.config import get_config, get_audio_config, get_ai_config
except ImportError as e:
    print(f"Error importing VoiceFlow core modules: {e}")
    print("Make sure you're in the VoiceFlow directory and dependencies are installed.")
    sys.exit(1)


class VoiceFlowSimple:
    """Simple VoiceFlow implementation - the default way to use VoiceFlow."""
    
    def __init__(self):
        """Initialize VoiceFlow Simple."""
        print("=== VoiceFlow Simple ===")
        print("🎤 Local Voice Transcription")
        print()
        print("Getting started:")
        print("1. Position cursor in any text field")
        print("2. Press Ctrl+Alt and speak clearly") 
        print("3. Release when done - text appears instantly!")
        print()
        print("Press Ctrl+C to exit")
        print()
        
        # Load configuration
        self.config = get_config()
        
        # Initialize core components
        print("🔧 Initializing...")
        self.engine = create_engine(get_audio_config())
        self.ai_enhancer = create_enhancer(get_ai_config())
        
        # Set up callbacks
        self.engine.on_transcription = self.on_transcription
        self.engine.on_error = self.on_error
        
        # Setup signal handlers for clean shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def on_transcription(self, text: str):
        """Handle new transcription."""
        try:
            # Enhance with AI if available
            enhanced_text = self.ai_enhancer.enhance_text(text)
            
            # Inject enhanced text
            if enhanced_text:
                success = self.engine.inject_text(enhanced_text)
                if not success:
                    print(f"[INFO] Text ready: '{enhanced_text}'")
                    print("       (Text injection not available - text shown above)")
                
        except Exception as e:
            print(f"[ERROR] Processing failed: {e}")
    
    def on_error(self, error: str):
        """Handle errors gracefully."""
        print(f"[ERROR] {error}")
    
    def run(self):
        """Run VoiceFlow Simple."""
        try:
            # Print status
            self.print_status()
            
            # Setup hotkeys
            self.engine.setup_hotkeys('ctrl+alt')
            
            # Keep running
            print("✅ VoiceFlow is ready! Press Ctrl+Alt to start recording.")
            print()
            
            while True:
                threading.Event().wait(1)
                
        except KeyboardInterrupt:
            print("\n👋 Shutting down VoiceFlow...")
        except Exception as e:
            print(f"\n💥 Unexpected error: {e}")
        finally:
            self.cleanup()
    
    def print_status(self):
        """Print current system status."""
        print("System Status:")
        
        # STT Engine status
        engine_status = "✅ Ready" if self.engine.recorder else "❌ Failed"
        print(f"  🎤 Speech Recognition: {engine_status}")
        
        # AI Enhancement status  
        ai_status = self.ai_enhancer.get_status()
        ai_indicator = "✅ Connected" if ai_status['connected'] else "⚠️  Disabled"
        print(f"  🤖 AI Enhancement: {ai_indicator}")
        if ai_status['connected']:
            print(f"     Model: {ai_status['model']}")
        
        # Session stats
        stats = self.engine.get_stats()
        if stats['total_transcriptions'] > 0:
            print(f"  📊 This Session: {stats['total_transcriptions']} transcriptions, {stats['total_words']} words")
        
        print()
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\n🔄 Received shutdown signal, cleaning up...")
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Clean up resources."""
        if hasattr(self, 'engine'):
            self.engine.cleanup()
        print("✅ VoiceFlow Simple stopped cleanly")


def main():
    """Main entry point for VoiceFlow Simple."""
    try:
        app = VoiceFlowSimple()
        app.run()
    except Exception as e:
        print(f"💥 Failed to start VoiceFlow Simple: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure dependencies are installed: pip install -r python/requirements.txt")
        print("2. Check microphone permissions")
        print("3. Try running from the VoiceFlow project directory")
        sys.exit(1)


if __name__ == "__main__":
    main()