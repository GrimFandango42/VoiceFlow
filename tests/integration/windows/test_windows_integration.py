"""
Windows-specific integration tests for VoiceFlow.

This module contains comprehensive tests that verify VoiceFlow's functionality 
on Windows, including system tray integration, hotkey handling, audio processing,
and other Windows-specific features.

Tests are designed to be thorough and cover edge cases specific to Windows environments.
"""

import os
import sys
import time
import json
import signal
import shutil
import tempfile
import unittest
import subprocess
import logging
import ctypes
import winreg
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY, call
from typing import Dict, Any, Optional, List

import psutil
import pytest
import win32gui
import win32con
import win32process
import win32api
from win32com.shell import shell, shellcon

# Add parent directory to path to allow importing voiceflow modules
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import voiceflow modules
try:
    from voiceflow.core.config import VoiceFlowConfig, get_config_path, get_cache_dir, get_log_dir
    from voiceflow.ui.hotkeys import HotkeyManager
    from voiceflow.ui.systray import VoiceFlowTray
    from voiceflow.core.audio import AudioRecorder
    from voiceflow.app_windows import VoiceFlowWindows
    
    # Mock Windows-specific modules that might not be available
    WindowsNotifier = MagicMock()
    WindowsAudioBackend = MagicMock()
    
except ImportError as e:
    print(f"Failed to import VoiceFlow modules: {e}")
    raise

# Configure test logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('windows_tests.log', mode='w')
    ]
)
logger = logging.getLogger(__name__)

# Skip these tests if not on Windows
pytestmark = pytest.mark.skipif(
    not sys.platform.startswith('win'),
    reason="Windows-specific tests"
)

# Test configuration
TEST_CONFIG = {
    "sample_rate": 16000,
    "hotkey_activate": "ctrl+alt+v",
    "windows": {
        "run_at_startup": False,
        "minimize_to_tray": True,
        "enable_notifications": True,
        "high_priority": False
    },
    "logging": {
        "level": "DEBUG",
        "file": "test_voiceflow.log"
    }
}

class TestWindowsIntegration(unittest.TestCase):
    """Comprehensive test suite for Windows-specific functionality of VoiceFlow."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment before any tests run."""
        cls.test_dir = Path(__file__).resolve().parent
        cls.project_root = cls.test_dir.parent
        cls.voiceflow_executable = str(cls.project_root / 'voiceflow' / 'app_windows.py')
        cls.test_output_dir = cls.test_dir / 'test_output'
        cls.temp_dir = cls.test_dir / 'temp_audio'
        
        # Set up test directories
        cls._setup_test_environment()
        
        # Initialize test configuration
        cls.test_config = VoiceFlowConfig()
        cls.test_config.update(TEST_CONFIG)
        cls.test_config.hotkey = 'ctrl+alt+v'  # Add hotkey to config
        
        # Set up test paths
        cls.test_audio_file = cls.test_dir / 'test_audio.wav'
        cls.test_icon = cls.test_dir / 'test_icon.ico'
        
        # Create test files if they don't exist
        if not cls.test_audio_file.exists():
            # Create a silent WAV file for testing
            import wave
            import struct
            with wave.open(str(cls.test_audio_file), 'w') as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(16000)
                wf.writeframes(struct.pack('<h', 0) * 16000)  # 1 second of silence
        
        if not cls.test_icon.exists():
            # Create a simple ICO file for testing
            from PIL import Image, ImageDraw
            img = Image.new('RGBA', (32, 32), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            draw.ellipse((4, 4, 28, 28), fill='blue', outline='white')
            img.save(str(cls.test_icon), format='ICO')
    
    @classmethod
    def _setup_test_environment(cls):
        """Set up the test environment."""
        # Create test directories
        cls.test_output_dir.mkdir(exist_ok=True)
        cls.temp_dir.mkdir(exist_ok=True)
        
        # Set up test environment variables
        os.environ['VOICEFLOW_TEST_MODE'] = '1'
        os.environ['VOICEFLOW_CONFIG_DIR'] = str(cls.test_output_dir / 'config')
        os.environ['VOICEFLOW_CACHE_DIR'] = str(cls.test_output_dir / 'cache')
        os.environ['VOICEFLOW_LOG_DIR'] = str(cls.test_output_dir / 'logs')
    
    def setUp(self):
        """Set up before each test method."""
        # Create a new config for each test
        self.test_config = VoiceFlowConfig()
        self.test_config.update(TEST_CONFIG)
        
        # Create a temporary config file for testing
        self.temp_config = self.test_output_dir / 'test_config.json'
        with open(self.temp_config, 'w') as f:
            json.dump(TEST_CONFIG, f)
        
        # Patch the default config path to use our test config
        self.config_patcher = patch('voiceflow.core.config.get_config', return_value=self.test_config)
        self.mock_get_config = self.config_patcher.start()
    
    def tearDown(self):
        """Clean up after each test method."""
        # Stop all patches
        self.config_patcher.stop()
        
        # Clean up any running processes
        self._cleanup_processes()
        
        # Remove temporary files
        if hasattr(self, 'temp_config') and self.temp_config.exists():
            self.temp_config.unlink()
    
    def _cleanup_processes(self):
        """Clean up any running test processes."""
        current_pid = os.getpid()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Skip current process and system processes
                if proc.pid == current_pid or proc.pid == 0:
                    continue
                    
                # Check if this is a test process
                cmdline = proc.cmdline()
                if any('python' in part.lower() for part in cmdline) and \
                   any('test_windows_integration' in part for part in cmdline):
                    try:
                        proc.terminate()
                        proc.wait(timeout=5)
                    except (psutil.NoSuchProcess, psutil.TimeoutExpired, psutil.AccessDenied):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    
    # ===== Test Methods =====
    
    def test_windows_path_handling(self):
        """Test Windows-specific path handling."""
        # Test config path
        config_path = get_config_path()
        self.assertIsInstance(config_path, Path)
        self.assertIn('AppData', str(config_path))
        self.assertTrue(str(config_path).endswith('VoiceFlow\\config.json'))
        
        # Test cache directory
        cache_dir = get_cache_dir()
        self.assertIsInstance(cache_dir, Path)
        self.assertIn('Local', str(cache_dir))
        self.assertTrue(str(cache_dir).endswith('VoiceFlow\\Cache'))
        
        # Test log directory
        log_dir = get_log_dir()
        self.assertIsInstance(log_dir, Path)
        self.assertIn('Local', str(log_dir))
        self.assertTrue(str(log_dir).endswith('VoiceFlow\\Logs'))
    
    @patch('pynput.keyboard.Listener')
    @patch('pynput.keyboard.GlobalHotKey')
    def test_hotkey_registration(self, mock_hotkey, mock_listener):
        """Test hotkey registration and callback functionality."""
        # Set up mocks
        mock_hotkey_instance = MagicMock()
        mock_hotkey.return_value = mock_hotkey_instance
        mock_listener_instance = MagicMock()
        mock_listener.return_value = mock_listener_instance
        
        # Test hotkey registration
        hotkey_mgr = HotkeyManager(self.test_config)
        callback = MagicMock()
        hotkey_mgr.register_hotkey(callback, 'ctrl+alt+v', suppress=True)
        
        # Verify hotkey was registered
        self.assertIn('ctrl+alt+v', hotkey_mgr.registered_hotkeys)
        
        # Test callback execution
        hotkey_mgr.registered_hotkeys['ctrl+alt+v']()
        callback.assert_called_once()
        
        # Test hotkey unregistration
        hotkey_mgr.unregister_hotkey('ctrl+alt+v')
        self.assertNotIn('ctrl+alt+v', hotkey_mgr.registered_hotkeys)
    
    @patch('sounddevice.query_devices')
    @patch('pyaudio.PyAudio')
    def test_windows_audio_backend(self, mock_sd_query, mock_pyaudio):
        """Test Windows audio backend functionality."""
        # Set up mocks
        mock_pa_instance = MagicMock()
        mock_pyaudio.return_value = mock_pa_instance
        mock_sd_query.return_value = {
            'name': 'Test Microphone',
            'max_input_channels': 1,
            'default_samplerate': 16000
        }
        
        # Test audio processor initialization
        audio_recorder = AudioRecorder(self.test_config)
        
        self.assertIsNotNone(audio_recorder)
        
        # Test audio capture with mock
        with patch.object(audio_recorder, 'start_recording') as mock_start_recording, \
             patch.object(audio_recorder, 'stop_recording') as mock_stop_recording:
            
            
            
            
            
            
            
            self.assertEqual(audio_data, b'test_audio_data')
        
        # Test cleanup
        audio_processor.cleanup()
        mock_pa_instance.terminate.assert_called_once()
    
    @patch('win10toast.ToastNotifier.show_toast')
    def test_windows_notifications(self, mock_show_toast):
        """Test Windows toast notifications."""
        # Test notification display
        notifier = WindowsNotifier()
        notifier.show("Test Title", "Test Message")
        
        # Verify notification was shown
        mock_show_toast.assert_called_once_with(
            title="Test Title",
            msg="Test Message",
            duration=5,
            threaded=True
        )
        
        # Test with custom duration
        notifier.show("Test Title", "Test Message with Duration", duration=10)
        mock_show_toast.assert_called_with(
            title="Test Title",
            msg="Test Message with Duration",
            duration=10,
            threaded=True
        )
    
    @patch('pystray.Icon')
    @patch('threading.Thread')
    def test_system_tray_icon(self, mock_thread, mock_icon_class):
        """Test system tray icon functionality using VoiceFlowTray."""
        # Set up mocks
        mock_icon = MagicMock()
        mock_icon_class.return_value = mock_icon
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Test tray icon creation and running
        on_quit_callback = MagicMock()
        tray = VoiceFlowTray(on_quit=on_quit_callback)
        tray.run()

        # Verify icon was created and thread was started
        mock_icon_class.assert_called_once_with(
            'voiceflow_icon',
            icon=tray.image,
            menu=ANY,
            title='VoiceFlow'
        )
        mock_thread.assert_called_once_with(target=ANY, daemon=True)
        mock_thread_instance.start.assert_called_once()
        self.assertTrue(tray.running)

        # Test quitting the application from tray
        tray.quit_application(mock_icon, None)
        on_quit_callback.assert_called_once()
        mock_icon.stop.assert_called_once()
        self.assertFalse(tray.running)

        # Test stopping the tray
        tray.run() # "Restart" for testing stop
        tray.stop()
        # stop is called once by quit_application and once by stop()
        self.assertEqual(mock_icon.stop.call_count, 2)
        self.assertFalse(tray.running)
    
    @patch('win32gui.FindWindow')
    @patch('win32gui.PostMessage')
    def test_window_management(self, mock_post_message, mock_find_window):
        """Test window management functions."""
        # Set up mocks
        mock_find_window.return_value = 1234  # Mock window handle
        
        # Test window minimization
        from voiceflow.windows.window import minimize_window
        minimize_window("Test Window")
        mock_find_window.assert_called_once_with(None, "Test Window")
        mock_post_message.assert_called_once_with(1234, win32con.WM_SYSCOMMAND, win32con.SC_MINIMIZE, 0)
        
        # Test window restoration
        mock_find_window.reset_mock()
        mock_post_message.reset_mock()
        
        from voiceflow.windows.window import restore_window
        restore_window("Test Window")
        mock_find_window.assert_called_once_with(None, "Test Window")
        mock_post_message.assert_called_once_with(1234, win32con.WM_SYSCOMMAND, win32con.SC_RESTORE, 0)
    
    @patch('winreg.OpenKey')
    @patch('winreg.SetValueEx')
    @patch('winreg.DeleteValue')
    def test_startup_registration(self, mock_delete, mock_set_value, mock_open_key):
        """Test adding/removing from Windows startup."""
        # Mock registry key
        mock_key = MagicMock()
        mock_open_key.return_value.__enter__.return_value = mock_key
        
        # Test adding to startup
        from voiceflow.windows.startup import add_to_startup
        add_to_startup("Test App", sys.executable)
        
        # Verify registry operations
        mock_open_key.assert_called_once_with(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_ALL_ACCESS
        )
        mock_set_value.assert_called_once_with(
            mock_key, "Test App", 0, winreg.REG_SZ,
            f'"{sys.executable}" --minimized'
        )
        
        # Test removing from startup
        mock_open_key.reset_mock()
        mock_set_value.reset_mock()
        
        from voiceflow.windows.startup import remove_from_startup
        remove_from_startup("Test App")
        
        mock_open_key.assert_called_once_with(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_ALL_ACCESS
        )
        mock_delete.assert_called_once_with(mock_key, "Test App")
        
    # ===== Additional Test Methods =====
    
    @patch('subprocess.Popen')
    def test_application_lifecycle(self, mock_popen):
        """Test application startup and shutdown."""
        # Set up mock process
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 1234
        mock_popen.return_value = mock_process
        
        # Test application startup
        from voiceflow.windows.application import VoiceFlowApplication
        app = VoiceFlowApplication()
        app.start()
        
        # Verify process was started
        mock_popen.assert_called_once()
        self.assertIsNotNone(app.process)
        
        # Test application shutdown
        app.stop()
        mock_process.terminate.assert_called_once()
    
    @patch('psutil.process_iter')
    def test_process_management(self, mock_process_iter):
        """Test process management utilities."""
        # Create mock processes
        mock_proc1 = MagicMock()
        mock_proc1.info = {'name': 'python.exe', 'pid': 1234, 'cmdline': ['python', 'voiceflow.py']}
        
        mock_proc2 = MagicMock()
        mock_proc2.info = {'name': 'pythonw.exe', 'pid': 5678, 'cmdline': ['pythonw', 'background.py']}
        
        mock_process_iter.return_value = [mock_proc1, mock_proc2]
        
        # Test finding processes by name
        from voiceflow.windows.process import find_processes_by_name
        processes = find_processes_by_name('python')
        self.assertEqual(len(processes), 1)
        self.assertEqual(processes[0].info['pid'], 1234)
        
        # Test killing processes
        with patch('psutil.Process') as mock_process:
            mock_process.return_value.terminate.return_value = None
            from voiceflow.windows.process import kill_process
            kill_process(1234)
            mock_process.return_value.terminate.assert_called_once()
    
    @patch('os.path.exists')
    @patch('shutil.which')
    def test_dependency_checks(self, mock_which, mock_exists):
        """Test dependency verification."""
        # Set up mocks
        mock_which.return_value = '/path/to/ffmpeg'
        mock_exists.return_value = True
        
        # Test dependency checking
        from voiceflow.windows.dependencies import check_dependencies
        missing = check_dependencies()
        self.assertEqual(len(missing), 0)
        
        # Test with missing dependencies
        mock_which.return_value = None
        mock_exists.return_value = False
        missing = check_dependencies()
        self.assertGreater(len(missing), 0)
    
    @patch('win32gui.ShowWindow')
    @patch('win32gui.GetForegroundWindow')
    @patch('win32gui.GetWindowText')
    def test_window_foreground_management(self, mock_get_text, mock_foreground, mock_show):
        """Test window foreground and focus management."""
        # Set up mocks
        mock_foreground.return_value = 1234
        mock_get_text.return_value = "Test Window"
        
        # Test bringing window to foreground
        from voiceflow.windows.window import bring_to_foreground
        result = bring_to_foreground("Test Window")
        self.assertTrue(result)
        mock_show.assert_called_with(1234, win32con.SW_RESTORE)
        
        # Test with non-existent window
        mock_get_text.return_value = "Other Window"
        result = bring_to_foreground("Test Window")
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main(failfast=True)
