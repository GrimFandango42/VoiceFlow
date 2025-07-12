#!/usr/bin/env python3
"""
VoiceFlow Unix - Optimized for Linux/macOS platforms
Local voice transcription with system tray support
"""

import asyncio
import sys
import argparse
import signal
from pathlib import Path

# Add core modules to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from voiceflow_personal import PersonalVoiceFlow
    import threading
    import time
    
    # Try to import tray support (optional on Unix)
    try:
        import pystray
        from PIL import Image, ImageDraw
        TRAY_AVAILABLE = True
    except ImportError:
        TRAY_AVAILABLE = False
except ImportError as e:
    print(f"Missing dependencies: {e}")
    print("Install with: pip install -r requirements_unix.txt")
    sys.exit(1)


class VoiceFlowUnix:
    """Unix-optimized VoiceFlow with optional system tray support"""
    
    def __init__(self, tray_mode=False):
        self.tray_mode = tray_mode and TRAY_AVAILABLE
        self.voiceflow = PersonalVoiceFlow()
        self.tray_icon = None
        self.running = True
        
        # Setup signal handlers for clean shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n📨 Received signal {signum}, shutting down...")
        self.running = False
        if self.tray_icon:
            self.tray_icon.stop()
        sys.exit(0)
    
    def create_tray_icon(self):
        """Create system tray icon (if available)"""
        if not TRAY_AVAILABLE:
            return None
            
        # Create a simple icon
        width = height = 64
        image = Image.new('RGBA', (width, height), color=(0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        
        # Draw microphone icon
        draw.ellipse([20, 10, 44, 34], fill='blue', outline='darkblue', width=2)
        draw.rectangle([28, 34, 36, 44], fill='blue')
        draw.line([24, 50, 40, 50], fill='blue', width=3)
        
        return image
    
    def on_tray_clicked(self, icon, item):
        """Handle tray icon clicks"""
        if item is None:  # Left click
            print("🎤 VoiceFlow ready - Speak or press Ctrl+Alt")
    
    def on_quit(self, icon, item):
        """Quit application from tray"""
        print("👋 VoiceFlow Unix stopping...")
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
        """Run in system tray mode (if supported)"""
        if not TRAY_AVAILABLE:
            print("⚠️  System tray not available, falling back to console mode")
            print("   Install 'pystray' and 'pillow' for tray support")
            return self.run_console_mode()
        
        print("🚀 VoiceFlow Unix - System Tray Mode")
        
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
        try:
            self.tray_icon.run()
        except Exception as e:
            print(f"⚠️  Tray failed: {e}, falling back to console mode")
            self.run_console_mode()
    
    def run_console_mode(self):
        """Run in console mode"""
        print("🚀 VoiceFlow Unix - Console Mode")
        print("💡 Press Ctrl+C to stop")
        asyncio.run(self.voiceflow.run_async())
    
    def run_daemon_mode(self):
        """Run in background daemon mode"""
        print("🚀 VoiceFlow Unix - Daemon Mode")
        
        # Start VoiceFlow in background
        voiceflow_thread = threading.Thread(
            target=lambda: asyncio.run(self.voiceflow.run_async()),
            daemon=True
        )
        voiceflow_thread.start()
        
        # Keep alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    
    def run(self):
        """Main run method"""
        if self.tray_mode:
            self.run_tray_mode()
        else:
            self.run_console_mode()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="VoiceFlow Unix - Local Voice Transcription")
    parser.add_argument("--tray", action="store_true", help="Run in system tray mode")
    parser.add_argument("--console", action="store_true", help="Run in console mode")
    parser.add_argument("--daemon", action="store_true", help="Run in background daemon mode")
    
    args = parser.parse_args()
    
    # Determine mode
    if args.daemon:
        mode = "daemon"
    elif args.tray:
        mode = "tray"
    elif args.console:
        mode = "console"
    else:
        # Default to console mode on Unix
        mode = "console"
    
    try:
        app = VoiceFlowUnix(tray_mode=(mode == "tray"))
        
        if mode == "daemon":
            app.run_daemon_mode()
        else:
            app.run()
            
    except KeyboardInterrupt:
        print("\n👋 VoiceFlow Unix stopped")
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())