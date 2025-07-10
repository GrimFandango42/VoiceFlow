#!/usr/bin/env python3
"""
VoiceFlow Tray - Background Voice Transcription Service

Runs VoiceFlow in the background with system tray integration.
Perfect for all-day usage once you're confident it works well.

Usage: python voiceflow_tray.py
"""

import sys
import signal
import threading
import time
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

# Try to import system tray functionality
try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    print("System tray not available. Install with: pip install pystray pillow")


class VoiceFlowTray:
    """VoiceFlow background service with system tray integration."""
    
    def __init__(self):
        """Initialize VoiceFlow Tray service."""
        print("=== VoiceFlow Tray Service ===")
        print("🎤 Background Voice Transcription")
        print()
        
        # Load configuration
        self.config = get_config()
        
        # Initialize core components
        print("🔧 Initializing core components...")
        self.engine = create_engine(get_audio_config())
        self.ai_enhancer = create_enhancer(get_ai_config())
        
        # Set up callbacks
        self.engine.on_transcription = self.on_transcription
        self.engine.on_error = self.on_error
        
        # Service state
        self.running = True
        self.total_transcriptions = 0
        
        # System tray
        self.tray_icon = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def create_tray_icon(self):
        """Create system tray icon."""
        if not TRAY_AVAILABLE:
            return None
        
        # Create a simple microphone icon
        width = height = 64
        image = Image.new('RGB', (width, height), color='white')
        draw = ImageDraw.Draw(image)
        
        # Draw microphone shape
        # Microphone body (rounded rectangle)
        draw.ellipse([20, 15, 44, 35], fill='black')
        draw.rectangle([20, 25, 44, 40], fill='black')
        
        # Microphone stand
        draw.rectangle([30, 40, 34, 50], fill='black')
        draw.rectangle([25, 50, 39, 54], fill='black')
        
        return image
    
    def create_tray_menu(self):
        """Create system tray context menu."""
        if not TRAY_AVAILABLE:
            return None
        
        return pystray.Menu(
            item('VoiceFlow Status', self.show_status),
            item('Toggle Service', self.toggle_service),
            pystray.Menu.SEPARATOR,
            item('Statistics', self.show_statistics),
            item('Settings', self.show_settings),
            pystray.Menu.SEPARATOR,
            item('Exit', self.quit_service)
        )
    
    def on_transcription(self, text: str):
        """Handle new transcription."""
        try:
            # Enhance with AI if available
            enhanced_text = self.ai_enhancer.enhance_text(text)
            
            # Inject enhanced text
            if enhanced_text:
                success = self.engine.inject_text(enhanced_text)
                self.total_transcriptions += 1
                
                # Update tray tooltip
                if self.tray_icon:
                    self.tray_icon.title = f"VoiceFlow - {self.total_transcriptions} transcriptions"
                
        except Exception as e:
            print(f"[ERROR] Transcription processing failed: {e}")
    
    def on_error(self, error: str):
        """Handle errors."""
        print(f"[ERROR] {error}")
        if self.tray_icon:
            self.tray_icon.notify("VoiceFlow Error", error)
    
    def show_status(self, icon, item):
        """Show status notification."""
        if not TRAY_AVAILABLE:
            return
        
        # Get current status
        engine_status = "Working" if self.engine.recorder else "Error"
        ai_status = self.ai_enhancer.get_status()
        ai_indicator = "Connected" if ai_status['connected'] else "Disabled"
        
        status_msg = f"Speech: {engine_status}\nAI Enhancement: {ai_indicator}\nTranscriptions: {self.total_transcriptions}"
        icon.notify("VoiceFlow Status", status_msg)
    
    def toggle_service(self, icon, item):
        """Toggle service on/off."""
        # This is a placeholder - could implement pause/resume functionality
        icon.notify("VoiceFlow", "Service toggle not implemented yet")
    
    def show_statistics(self, icon, item):
        """Show session statistics."""
        if not TRAY_AVAILABLE:
            return
        
        stats = self.engine.get_stats()
        stats_msg = f"Session: {stats['total_transcriptions']} transcriptions\nWords: {stats['total_words']}\nAvg time: {stats['average_processing_time_ms']:.1f}ms"
        icon.notify("VoiceFlow Statistics", stats_msg)
    
    def show_settings(self, icon, item):
        """Show settings information."""
        if not TRAY_AVAILABLE:
            return
        
        icon.notify("VoiceFlow Settings", "Settings: Edit ~/.voiceflow/config.json\nHotkey: Ctrl+Alt")
    
    def quit_service(self, icon, item):
        """Quit the service."""
        print("🔄 Shutting down VoiceFlow Tray...")
        self.running = False
        if icon:
            icon.stop()
        self.cleanup()
    
    def run(self):
        """Run VoiceFlow Tray service."""
        try:
            # Print status
            self.print_status()
            
            # Setup hotkeys
            self.engine.setup_hotkeys('ctrl+alt')
            
            # Create system tray if available
            if TRAY_AVAILABLE:
                print("🖥️  Starting system tray service...")
                icon_image = self.create_tray_icon()
                menu = self.create_tray_menu()
                
                self.tray_icon = pystray.Icon(
                    "VoiceFlow",
                    icon_image,
                    "VoiceFlow - Ready",
                    menu
                )
                
                # Run tray in separate thread
                tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
                tray_thread.start()
                
                print("✅ VoiceFlow Tray is running in background")
                print("   Look for the microphone icon in your system tray")
                print("   Right-click the tray icon for options")
            else:
                print("✅ VoiceFlow is running in background (no tray - missing pystray)")
                print("   Press Ctrl+Alt to record")
                print("   Press Ctrl+C to stop")
            
            print()
            
            # Keep service running
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n👋 Shutting down VoiceFlow Tray...")
            self.running = False
        except Exception as e:
            print(f"\n💥 Service error: {e}")
        finally:
            self.cleanup()
    
    def print_status(self):
        """Print current system status."""
        print("Service Status:")
        
        # STT Engine status
        engine_status = "✅ Ready" if self.engine.recorder else "❌ Failed"
        print(f"  🎤 Speech Recognition: {engine_status}")
        
        # AI Enhancement status  
        ai_status = self.ai_enhancer.get_status()
        ai_indicator = "✅ Connected" if ai_status['connected'] else "⚠️  Disabled"
        print(f"  🤖 AI Enhancement: {ai_indicator}")
        if ai_status['connected']:
            print(f"     Model: {ai_status['model']}")
        
        # Tray status
        tray_status = "✅ Available" if TRAY_AVAILABLE else "⚠️  Not Available (install pystray)"
        print(f"  🖥️  System Tray: {tray_status}")
        
        print()
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print(f"\n🔄 Received shutdown signal...")
        self.running = False
        if self.tray_icon:
            self.tray_icon.stop()
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Clean up resources."""
        if hasattr(self, 'engine'):
            self.engine.cleanup()
        if self.tray_icon:
            self.tray_icon.stop()
        print("✅ VoiceFlow Tray stopped cleanly")


def main():
    """Main entry point for VoiceFlow Tray."""
    try:
        service = VoiceFlowTray()
        service.run()
    except Exception as e:
        print(f"💥 Failed to start VoiceFlow Tray: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure dependencies are installed: pip install -r python/requirements.txt")
        print("2. For system tray: pip install pystray pillow")
        print("3. Check microphone permissions")
        print("4. Try running from the VoiceFlow project directory")
        sys.exit(1)


if __name__ == "__main__":
    main()