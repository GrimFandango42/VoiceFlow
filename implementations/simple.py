"""
Simple VoiceFlow Implementation

Lightweight wrapper around core VoiceFlow engine.
Replaces the former simple_server.py with consolidated core functionality.
"""

import sys
import signal
import threading
from pathlib import Path

# Add parent directory to path for core imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.voiceflow_core import create_engine
from core.ai_enhancement import create_enhancer
from utils.config import get_config, get_audio_config, get_ai_config


class SimpleVoiceFlow:
    """Simple VoiceFlow implementation using consolidated core modules."""
    
    def __init__(self):
        """Initialize simple VoiceFlow application."""
        print("=== VoiceFlow Simple ===")
        print("Local voice transcription with AI enhancement")
        print("Press Ctrl+Alt to record and inject text")
        print("Press Ctrl+C to exit")
        print()
        
        # Load configuration
        self.config = get_config()
        
        # Initialize core components
        self.engine = create_engine(get_audio_config())
        self.ai_enhancer = create_enhancer(get_ai_config())
        
        # Set up callbacks
        self.engine.on_transcription = self.on_transcription
        self.engine.on_error = self.on_error
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def on_transcription(self, text: str):
        """Handle new transcription."""
        try:
            # Enhance with AI if available
            enhanced_text = self.ai_enhancer.enhance_text(text)
            
            # Inject enhanced text
            if enhanced_text:
                self.engine.inject_text(enhanced_text)
                
        except Exception as e:
            print(f"[ERROR] Transcription processing failed: {e}")
    
    def on_error(self, error: str):
        """Handle errors."""
        print(f"[ERROR] {error}")
    
    def run(self):
        """Run the simple VoiceFlow application."""
        try:
            # Print status
            self.print_status()
            
            # Setup hotkeys
            self.engine.setup_hotkeys('ctrl+alt')
            
            # Keep running
            print("\n✅ VoiceFlow is ready! Press Ctrl+Alt to start recording.")
            while True:
                threading.Event().wait(1)
                
        except KeyboardInterrupt:
            print("\n\nShutting down...")
        except Exception as e:
            print(f"\n[ERROR] Application error: {e}")
        finally:
            self.cleanup()
    
    def print_status(self):
        """Print current status."""
        print("Status:")
        print(f"  🎤 STT Engine: {'✅ Ready' if self.engine.recorder else '❌ Failed'}")
        
        ai_status = self.ai_enhancer.get_status()
        print(f"  🤖 AI Enhancement: {'✅ Ready' if ai_status['connected'] else '❌ Disabled'}")
        if ai_status['connected']:
            print(f"     Model: {ai_status['model']}")
        
        stats = self.engine.get_stats()
        print(f"  📊 Session: {stats['total_transcriptions']} transcriptions, {stats['total_words']} words")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Clean up resources."""
        if hasattr(self, 'engine'):
            self.engine.cleanup()
        print("✅ Cleanup complete")


def main():
    """Main entry point."""
    try:
        app = SimpleVoiceFlow()
        app.run()
    except Exception as e:
        print(f"[FATAL] Failed to start VoiceFlow: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()