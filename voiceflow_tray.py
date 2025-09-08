#!/usr/bin/env python3
"""
VoiceFlow Tray Application for Windows
Provides a system tray icon for managing VoiceFlow.
"""

import pystray
from PIL import Image, ImageDraw
import base64
import io
import threading
import subprocess
import os
import sys
import signal

# Global variable to store the VoiceFlow process
voiceflow_process = None
voiceflow_config = None # To be loaded later

def create_placeholder_icon():
    """Creates a simple placeholder icon if icon.png is not found."""
    width = 64
    height = 64
    color1 = (100, 100, 255) # Blueish
    color2 = (200, 200, 255) # Lighter blue
    
    image = Image.new('RGB', (width, height), color1)
    dc = ImageDraw.Draw(image)
    dc.rectangle(
        (width // 4, height // 4, width * 3 // 4, height * 3 // 4),
        fill=color2)
    # Simple 'V' for VoiceFlow
    dc.text((width // 2 - 8, height // 2 - 8), "V", fill=(255,255,255))
    return image

def get_icon():
    """Loads the icon for the tray application, trying external then embedded fallback."""
    # Attempt to load external icon.png first
    icon_filename = "icon.png"
    # Check in script directory
    script_dir_icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), icon_filename)
    # Check in project root (one level up from script dir, common for src layouts)
    project_root_icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), icon_filename)

    for icon_path_candidate in [script_dir_icon_path, project_root_icon_path]:
        if os.path.exists(icon_path_candidate):
            try:
                print(f"Loading icon from: {icon_path_candidate}")
                return Image.open(icon_path_candidate)
            except Exception as e:
                print(f"Error loading icon from {icon_path_candidate}: {e}. Trying next option.")

    # Fallback to embedded base64 icon
    print("External icon.png not found or failed to load. Using embedded default icon.")
    try:
        base64_icon = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAABFSURBVDhPYxgFo2AUjIJBASMBOAOxKhA7A+L/A7E6EDsD4n8gVgBiJ0DsDMT/QGwAxE6A2AGI/wGZOkAWgLkGAAgAAQYAC5MDXcW2mmsAAAAASUVORK5CYII="
        image_data = base64.b64decode(base64_icon)
        return Image.open(io.BytesIO(image_data))
    except Exception as e:
        print(f"Error loading embedded icon: {e}. Using dynamically drawn placeholder.")
        return create_placeholder_icon() # Final fallback


def start_voiceflow(icon, item):
    """Starts the VoiceFlow main application."""
    global voiceflow_process
    if voiceflow_process is None or voiceflow_process.poll() is not None:
        try:
            # Determine the path to the voiceflow console script
            # This handles running from source vs. installed package
            if getattr(sys, 'frozen', False): # Running as a bundled exe
                # Assuming voiceflow.exe is in the same directory as voiceflow-tray.exe
                vf_executable = os.path.join(os.path.dirname(sys.executable), "voiceflow.exe")
                if not os.path.exists(vf_executable): # try voiceflow without .exe for non-windows bundled
                     vf_executable = os.path.join(os.path.dirname(sys.executable), "voiceflow")
            else: # Running as a script
                # Assuming venv is active or voiceflow is in PATH
                # For robustness, try to find it in Scripts dir of current venv
                venv_path = os.environ.get("VIRTUAL_ENV")
                if venv_path:
                    vf_executable = os.path.join(venv_path, "Scripts", "voiceflow.exe")
                    if not os.path.exists(vf_executable):
                         vf_executable = os.path.join(venv_path, "Scripts", "voiceflow") # for non-windows venv
                else: # Fallback to just 'voiceflow' hoping it's in PATH
                    vf_executable = "voiceflow.exe" if os.name == 'nt' else "voiceflow"


            print(f"Attempting to start VoiceFlow with: {vf_executable}")
            # Use CREATE_NO_WINDOW on Windows to prevent console window from popping up
            # and CREATE_NEW_PROCESS_GROUP to allow sending CTRL_BREAK_EVENT
            creationflags = 0
            if os.name == 'nt':
                creationflags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            voiceflow_process = subprocess.Popen([vf_executable], creationflags=creationflags)
            print("VoiceFlow started.")
            # We might want to update the icon or menu item text here
        except Exception as e:
            print(f"Error starting VoiceFlow: {e}")
            # Potentially show a notification to the user
    else:
        print("VoiceFlow is already running.")

def stop_voiceflow(icon, item):
    """Stops the VoiceFlow application."""
    global voiceflow_process
    if voiceflow_process and voiceflow_process.poll() is None:
        try:
            print("Attempting to stop VoiceFlow...")
            # More graceful termination if possible
            if os.name == 'nt':
                # Sending CTRL_C_EVENT to a process group on Windows is tricky.
                # subprocess.run(['taskkill', '/F', '/T', '/PID', str(voiceflow_process.pid)]) might be too aggressive.
                # For console apps, sending Ctrl+C is preferred.
                # Send CTRL_BREAK_EVENT to the process group on Windows for graceful shutdown of console apps
                voiceflow_process.send_signal(signal.CTRL_BREAK_EVENT)
                try:
                    voiceflow_process.wait(timeout=5) # Wait for graceful exit
                except subprocess.TimeoutExpired:
                    print("VoiceFlow did not respond to CTRL_BREAK_EVENT, trying terminate.")
                    voiceflow_process.terminate() # Try terminate next
                    try:
                        voiceflow_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        pass # Will be caught by poll() check below
            else:
                voiceflow_process.send_signal(signal.SIGINT) # Send SIGINT (Ctrl+C)
                voiceflow_process.wait(timeout=5)

            if voiceflow_process.poll() is None: # If still running
                print("VoiceFlow did not terminate gracefully, killing.")
                voiceflow_process.kill()

            voiceflow_process = None
            print("VoiceFlow stopped.")
        except Exception as e:
            print(f"Error stopping VoiceFlow: {e}")
    else:
        print("VoiceFlow is not running.")

def open_settings(icon, item):
    """Placeholder for opening a settings window."""
    print("Settings clicked. (Not yet implemented)")
    # Here, you could open a Tkinter window or a web page for settings.

def exit_action(icon, item):
    """Exits the tray application."""
    stop_voiceflow(icon, item) # Ensure VoiceFlow is stopped before exiting
    icon.stop()

def setup_tray_icon():
    """Creates and runs the system tray icon."""
    icon_image = get_icon()
    
    # Build menu as a list to be friendly with patched pystray in tests
    menu = [
        pystray.MenuItem("Start VoiceFlow", start_voiceflow, enabled=lambda item: voiceflow_process is None or voiceflow_process.poll() is not None),
        pystray.MenuItem("Stop VoiceFlow", stop_voiceflow, enabled=lambda item: voiceflow_process is not None and voiceflow_process.poll() is None),
        pystray.MenuItem("Settings", open_settings),
        getattr(pystray, 'Menu_SEP', '---'),
        pystray.MenuItem("Exit", exit_action),
    ]
    
    icon = pystray.Icon("voiceflow_tray", icon_image, "VoiceFlow", menu)
    
    # Update menu state periodically (optional, but good for dynamic enabling/disabling)
    def update_menu_state_loop(icon_instance):
        while icon_instance.visible:
            icon_instance.update_menu()
            threading.Event().wait(1) # Update every 1 second

    # Run update_menu_state_loop in a separate thread
    # This is not strictly necessary if pystray handles menu updates well on its own,
    # but can be useful for more complex dynamic menu item states.
    # For now, pystray's built-in enabled lambda should suffice for Start/Stop.

    icon.run()

def main():
    # Placeholder for loading VoiceFlowConfig if tray needs to pass settings
    # global voiceflow_config
    # from voiceflow.core.config import VoiceFlowConfig
    # voiceflow_config = VoiceFlowConfig.from_env()
    # voiceflow_config.validate()
    
    print("Starting VoiceFlow Tray Application...")
    setup_tray_icon()
    print("VoiceFlow Tray Application stopped.")

if __name__ == "__main__":
    main()
