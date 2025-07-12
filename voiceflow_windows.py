#!/usr/bin/env python3
"""
VoiceFlow Windows - Optimized for Windows platforms
Local voice transcription with system tray support
"""

import asyncio
import sys
import argparse
from pathlib import Path

# Add core modules to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from voiceflow_personal import PersonalVoiceFlow
    import pystray
    from PIL import Image, ImageDraw
    import threading
except ImportError as e:
    print(f"Missing dependencies: {e}")
    print("Install with: pip install -r requirements_windows.txt")
    sys.exit(1)


class VoiceFlowWindows:
    """Windows-optimized VoiceFlow with system tray support"""
    
    def __init__(self, tray_mode=False):
        self.tray_mode = tray_mode
        self.voiceflow = PersonalVoiceFlow()
        self.tray_icon = None
        self.running = True
    
    def create_tray_icon(self):
        """Create system tray icon"""
        # Create a simple icon
        width = height = 64
        image = Image.new('RGB', (width, height), color='blue')
        draw = ImageDraw.Draw(image)
        draw.ellipse([16, 16, width-16, height-16], fill='white')
        draw.text((24, 24), "VF", fill='blue')
        
        return image
    
    def on_tray_clicked(self, icon, item):
        """Handle tray icon clicks"""
        if item is None:  # Left click
            print("🎤 VoiceFlow ready - Speak or press Ctrl+Alt")
    
    def on_quit(self, icon, item):
        """Quit application from tray"""
        print("👋 VoiceFlow Windows stopping...")
        self.running = False
        if self.tray_icon:
            self.tray_icon.stop()
    
    def on_show_stats(self, icon, item):
        """Show session statistics"""
        stats = self.voiceflow.get_session_stats()
        print(f"""
📊 VoiceFlow Statistics:
   Transcriptions: {stats['transcriptions']}
   Words: {stats['words']}
   Uptime: {stats['uptime_seconds']}s
   Avg Processing: {stats['avg_processing_ms']}ms
        """)
    
    def run_tray_mode(self):
        """Run in system tray mode"""
        print("🚀 VoiceFlow Windows - System Tray Mode")
        
        # Create tray menu
        menu = pystray.Menu(
            pystray.MenuItem("VoiceFlow Ready", self.on_tray_clicked, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Show Statistics", self.on_show_stats),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self.on_quit)
        )
        
        # Create and run tray icon
        icon_image = self.create_tray_icon()
        self.tray_icon = pystray.Icon(
            "VoiceFlow",
            icon_image,
            "VoiceFlow - Voice Transcription",
            menu
        )
        
        # Start VoiceFlow in background thread
        voiceflow_thread = threading.Thread(
            target=lambda: asyncio.run(self.voiceflow.run_async()),
            daemon=True
        )
        voiceflow_thread.start()
        
        # Run tray icon
        print("📌 VoiceFlow running in system tray")
        print("💡 Right-click tray icon for options")
        self.tray_icon.run()
    
    def run_console_mode(self):
        """Run in console mode"""
        print("🚀 VoiceFlow Windows - Console Mode")
        asyncio.run(self.voiceflow.run_async())
    
    def run(self):
        """Main run method"""
        if self.tray_mode:
            self.run_tray_mode()
        else:
            self.run_console_mode()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="VoiceFlow Windows - Local Voice Transcription")
    parser.add_argument("--tray", action="store_true", help="Run in system tray mode")
    parser.add_argument("--console", action="store_true", help="Run in console mode")
    
    args = parser.parse_args()
    
    # Default to tray mode if no arguments
    tray_mode = args.tray or not args.console
    
    try:
        app = VoiceFlowWindows(tray_mode=tray_mode)
        app.run()
    except KeyboardInterrupt:
        print("\n👋 VoiceFlow Windows stopped")
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())