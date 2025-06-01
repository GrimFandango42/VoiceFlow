"""
VoiceFlow Simple System Tray - Python Implementation
More reliable than PowerShell for system tray functionality
"""

import sys
import os
import time
import subprocess
import threading
from pathlib import Path

# Try to import system tray components
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    print("Installing required system tray packages...")
    subprocess.run([sys.executable, "-m", "pip", "install", "pystray", "pillow"], check=True)
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True

# Try to import global hotkey
try:
    import keyboard
    HOTKEY_AVAILABLE = True
except ImportError:
    HOTKEY_AVAILABLE = False
    print("Global hotkey not available - use right-click menu to control")

class VoiceFlowTray:
    def __init__(self):
        self.server_process = None
        self.running = False
        self.project_dir = Path("C:/AI_Projects/VoiceFlow")
        
    def create_icon(self):
        """Create a simple microphone icon"""
        # Create a simple microphone icon
        image = Image.new('RGB', (64, 64), color='white')
        draw = ImageDraw.Draw(image)
        
        # Draw microphone shape
        draw.ellipse([20, 15, 44, 35], fill='black')  # Microphone head
        draw.rectangle([30, 35, 34, 50], fill='black')  # Microphone handle
        draw.arc([25, 45, 39, 55], 0, 180, fill='black', width=2)  # Stand
        
        return image
    
    def start_server(self):
        """Start the VoiceFlow STT server"""
        if self.server_process and self.server_process.poll() is None:
            print("Server already running")
            return True
            
        try:
            server_path = self.project_dir / "python" / "stt_server_patched.py"
            python_exe = self.project_dir / "python" / "venv" / "Scripts" / "python.exe"
            
            print("Starting VoiceFlow STT server...")
            self.server_process = subprocess.Popen(
                [str(python_exe), str(server_path)],
                cwd=str(self.project_dir),
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Give server time to start
            time.sleep(3)
            
            if self.server_process.poll() is None:
                print("✅ VoiceFlow server started successfully")
                return True
            else:
                print("❌ VoiceFlow server failed to start")
                return False
                
        except Exception as e:
            print(f"❌ Error starting server: {e}")
            return False
    
    def stop_server(self):
        """Stop the VoiceFlow STT server"""
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                print("✅ VoiceFlow server stopped")
            except subprocess.TimeoutExpired:
                self.server_process.kill()
                print("🔪 VoiceFlow server force-killed")
            except Exception as e:
                print(f"❌ Error stopping server: {e}")
    
    def test_text_injection(self):
        """Test text injection by opening notepad"""
        try:
            # Open notepad
            subprocess.Popen(["notepad.exe"])
            time.sleep(1)
            
            # Try to inject text using keyboard simulation
            if HOTKEY_AVAILABLE:
                import pyautogui
                time.sleep(0.5)  # Give notepad time to focus
                pyautogui.typewrite("VoiceFlow text injection test successful! " + time.strftime("%H:%M:%S"))
                print("✅ Text injection test completed - check Notepad")
            else:
                print("❌ Text injection not available - manual testing required")
                
        except Exception as e:
            print(f"❌ Text injection test failed: {e}")
    
    def show_instructions(self):
        """Show usage instructions"""
        instructions = """
VoiceFlow Usage Instructions:

1. VOICE TRANSCRIPTION:
   - Click in any text field (Notepad, Word, browser, etc.)
   - Press and hold Ctrl+Alt
   - Speak your text clearly
   - Release Ctrl+Alt
   - Text will appear automatically at cursor!

2. SYSTEM TRAY:
   - Right-click microphone icon for options
   - 'Test Text Injection' - Opens Notepad with test text
   - 'Restart Service' - If server stops working
   - 'Exit' - To stop VoiceFlow

3. TROUBLESHOOTING:
   - If hotkey doesn't work, try restarting service
   - Make sure microphone permissions are enabled
   - VoiceFlow works in most Windows applications

4. PRIVACY:
   - Everything processed locally on your computer
   - No internet connection required for transcription
   - No data sent to cloud services
        """
        print(instructions)
        
        # Also try to show a message box if available
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()  # Hide main window
            messagebox.showinfo("VoiceFlow Instructions", instructions)
            root.destroy()
        except:
            pass  # Fall back to console output
    
    def setup_hotkey(self):
        """Setup global hotkey if available"""
        if not HOTKEY_AVAILABLE:
            print("⚠️  Global hotkey not available")
            return False
            
        try:
            def hotkey_handler():
                print("🎤 Ctrl+Alt hotkey activated!")
                # The STT server handles the actual recording
                
            keyboard.add_hotkey('ctrl+alt', hotkey_handler)
            print("✅ Global hotkey registered: Ctrl+Alt")
            return True
            
        except Exception as e:
            print(f"❌ Hotkey registration failed: {e}")
            return False
    
    def create_menu(self):
        """Create system tray context menu"""
        menu_items = [
            pystray.MenuItem("VoiceFlow Active", lambda: None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("📖 Instructions", lambda icon, item: self.show_instructions()),
            pystray.MenuItem("🧪 Test Text Injection", lambda icon, item: self.test_text_injection()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("🔄 Restart Service", self.restart_service),
            pystray.MenuItem("❌ Exit VoiceFlow", self.quit_app)
        ]
        return pystray.Menu(*menu_items)
    
    def restart_service(self, icon=None, item=None):
        """Restart the VoiceFlow service"""
        print("🔄 Restarting VoiceFlow service...")
        self.stop_server()
        time.sleep(2)
        if self.start_server():
            print("✅ Service restarted successfully")
        else:
            print("❌ Service restart failed")
    
    def quit_app(self, icon=None, item=None):
        """Quit the application"""
        print("🛑 Stopping VoiceFlow...")
        self.running = False
        self.stop_server()
        if icon:
            icon.stop()
    
    def run(self):
        """Main application loop"""
        print("🚀 Starting VoiceFlow System Tray...")
        
        # Start the STT server
        if not self.start_server():
            print("❌ Failed to start server - exiting")
            return
        
        # Setup global hotkey
        self.setup_hotkey()
        
        # Create system tray icon
        icon_image = self.create_icon()
        menu = self.create_menu()
        
        icon = pystray.Icon(
            "VoiceFlow",
            icon_image,
            "VoiceFlow - Voice Transcription (Ctrl+Alt to use)",
            menu
        )
        
        self.running = True
        print("✅ VoiceFlow system tray started!")
        print("📍 Look for microphone icon in system tray")
        print("🎤 Press Ctrl+Alt anywhere to use voice transcription")
        print("🖱️  Right-click tray icon for options")
        
        try:
            # Run the system tray (this blocks)
            icon.run()
        except KeyboardInterrupt:
            print("\\n🛑 VoiceFlow stopped by user")
        finally:
            self.stop_server()

if __name__ == "__main__":
    try:
        app = VoiceFlowTray()
        app.run()
    except Exception as e:
        print(f"❌ VoiceFlow crashed: {e}")
        input("Press Enter to exit...")
