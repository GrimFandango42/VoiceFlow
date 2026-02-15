"""
VoiceFlow 3.0 - Silent Launcher
Runs VoiceFlow without console window, logs to file only.
"""

import sys
import os
import ctypes

# CRITICAL: Add src directory to Python path BEFORE any imports
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(os.path.dirname(script_dir))  # Go up from ui -> voiceflow -> src
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

import logging

# Redirect stdout/stderr to log file
log_dir = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'LocalFlow', 'logs')
os.makedirs(log_dir, exist_ok=True)

log_file = os.path.join(log_dir, 'voiceflow_silent.log')

# Redirect all output to log file
sys.stdout = open(log_file, 'a', encoding='utf-8')
sys.stderr = sys.stdout

# Configure logging to file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(threadName)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

print("="*60)
print("VoiceFlow 3.0 - Silent Mode Started")
print(f"Python path: {src_dir}")
print("="*60)

# Prevent duplicate tray/background instances from competing for CPU/hotkeys.
kernel32 = ctypes.windll.kernel32
mutex_name = "Local\\VoiceFlow_Silent_Launcher"
mutex = kernel32.CreateMutexW(None, False, mutex_name)
ERROR_ALREADY_EXISTS = 183
if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
    print("VoiceFlow is already running. Exiting duplicate launcher instance.")
    sys.exit(0)

# Now run the main app
from voiceflow.ui.cli_enhanced import main
main()
