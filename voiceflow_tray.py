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
voiceflow_config = None  # To be loaded later

def create_placeholder_icon():
    """Creates a simple placeholder icon if icon.png is not found."""
    width = 64
    height = 64
    color1 = (100, 100, 255)  # Blueish
    color2 = (200, 200, 255)  # Lighter blue

    image = Image.new('RGB', (width, height), color1)
    dc = ImageDraw.Draw(image)
    dc.rectangle((width // 4, height // 4, width * 3 // 4, height * 3 // 4), fill=color2)
    # Simple 'V' for VoiceFlow
    dc.text((width // 2 - 8, height // 2 - 8), "V", fill=(255, 255, 255))
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
        return create_placeholder_icon()  # Final fallback


def start_voiceflow(icon, item):
    """Starts the VoiceFlow main application."""
    global voiceflow_process
    if voiceflow_process is None or voiceflow_process.poll() is not None:
        try:
            # Determine the path to the voiceflow console script
            if getattr(sys, 'frozen', False):  # Running as a bundled exe
                vf_executable = os.path.join(os.path.dirname(sys.executable), "voiceflow.exe")
                if not os.path.exists(vf_executable):
                    vf_executable = os.path.join(os.path.dirname(sys.executable), "voiceflow")
            else:  # Running as a script
                venv_path = os.environ.get("VIRTUAL_ENV")
                if venv_path:
                    vf_executable = os.path.join(venv_path, "Scripts", "voiceflow.exe")
                    if not os.path.exists(vf_executable):
                        vf_executable = os.path.join(venv_path, "Scripts", "voiceflow")
                else:
                    vf_executable = "voiceflow.exe" if os.name == 'nt' else "voiceflow"

            print(f"Attempting to start VoiceFlow with: {vf_executable}")
            creationflags = 0
            if os.name == 'nt':
                creationflags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            voiceflow_process = subprocess.Popen([vf_executable], creationflags=creationflags)
            print("VoiceFlow started.")
        except Exception as e:
            print(f"Error starting VoiceFlow: {e}")
    else:
        print("VoiceFlow is already running.")

def stop_voiceflow(icon, item):
    """Stops the VoiceFlow application."""
    global voiceflow_process
    if voiceflow_process and voiceflow_process.poll() is None:
        try:
            print("Attempting to stop VoiceFlow...")
            if os.name == 'nt':
                voiceflow_process.send_signal(signal.CTRL_BREAK_EVENT)
                try:
                    voiceflow_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print("VoiceFlow did not respond to CTRL_BREAK_EVENT, trying terminate.")
                    voiceflow_process.terminate()
                    try:
                        voiceflow_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        pass
            else:
                voiceflow_process.send_signal(signal.SIGINT)
                voiceflow_process.wait(timeout=5)

            if voiceflow_process.poll() is None:
                print("VoiceFlow did not terminate gracefully, killing.")
                voiceflow_process.kill()
            voiceflow_process = None
            print("VoiceFlow stopped.")
        except Exception as e:
            print(f"Error stopping VoiceFlow: {e}")
    else:
        print("VoiceFlow is not running.")

def open_settings(icon, item):
    print("Settings clicked. (Not yet implemented)")

def exit_action(icon, item):
    stop_voiceflow(icon, item)
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
    icon.run()

def main():
    print("Starting VoiceFlow Tray Application...")
    setup_tray_icon()
    print("VoiceFlow Tray Application stopped.")

if __name__ == "__main__":
    main()
