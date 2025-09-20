import pytest
pytestmark = [pytest.mark.integration, pytest.mark.windows]

"""
Windows integration tests for VoiceFlow.

This module contains tests to verify Windows-specific functionality.
"""

import os
import sys
import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY

# Add parent directory to path to allow importing voiceflow modules
sys.path.insert(0, str(Path(__file__).parent.parent))

class TestWindowsBasic(unittest.TestCase):
    """Test suite for Windows-specific functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_config = {
            "sample_rate": 16000,
            "hotkey_activate": "ctrl+alt+v",
            "hotkey_mute": "ctrl+alt+m",
            "hotkey_exit": "ctrl+alt+x"
        }
        self.config_file = Path(self.temp_dir.name) / "test_config.json"
        with open(self.config_file, 'w') as f:
            json.dump(self.test_config, f)
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.temp_dir.cleanup()

    def test_config_loading(self):
        """Test loading configuration from file."""
        from voiceflow.core.config import VoiceFlowConfig
        config = VoiceFlowConfig(self.config_file)
        
        # Check that values from file are loaded correctly
        self.assertEqual(config.sample_rate, self.test_config["sample_rate"])
        self.assertEqual(config.hotkey_activate, self.test_config["hotkey_activate"])
    
    def test_config_saving(self):
        """Test saving configuration to file."""
        from voiceflow.core.config import VoiceFlowConfig
        config = VoiceFlowConfig()
        
        # Modify a value and save
        new_hotkey = "ctrl+shift+v"
        config.hotkey_activate = new_hotkey
        config.save(self.config_file)
        
        # Verify the saved file
        with open(self.config_file, 'r') as f:
            saved_config = json.load(f)
        self.assertEqual(saved_config["hotkey_activate"], new_hotkey)
    
    def test_hotkey_registration(self):
        """Test hotkey registration and callback."""
        with patch('pynput.keyboard.Listener'), patch('pynput.keyboard.GlobalHotKey'):
            from voiceflow.ui.hotkeys import HotkeyManager
            
            callback_called = False
            def test_callback():
                nonlocal callback_called
                callback_called = True
            
            hotkey_mgr = HotkeyManager(MagicMock())
            hotkey_mgr.register_hotkey("test", "<ctrl>+t", test_callback)
            
            # Simulate hotkey press
            hotkey_mgr._on_activate("test")
            self.assertTrue(callback_called)
    
    def test_system_tray_menu(self):
        """Test system tray menu creation and interaction."""
        with patch('pystray.Icon') as mock_icon:
            from voiceflow.ui.systray import SystemTrayIcon, MenuItem
            
            # Create a test menu item
            clicked = False
            def on_click():
                nonlocal clicked
                clicked = True
            
            menu_items = [
                MenuItem("Test Item", on_click)
            ]
            
            tray = SystemTrayIcon("Test", "icon.ico", menu_items)
            
            # Simulate menu item click
            tray._on_clicked("Test Item")
            self.assertTrue(clicked)
    
    @patch('pyaudio.PyAudio')
    def test_audio_device_detection(self, mock_pyaudio):
        """Test audio device detection on Windows."""
        # Mock PyAudio device info
        mock_pa_instance = MagicMock()
        mock_pa_instance.get_default_input_device_info.return_value = {
            'name': 'Test Microphone',
            'maxInputChannels': 1,
            'defaultSampleRate': 16000.0
        }
        mock_pyaudio.return_value = mock_pa_instance
        
        from voiceflow.audio.device import AudioDeviceManager
        
        device_mgr = AudioDeviceManager()
        devices = device_mgr.list_input_devices()
        
        self.assertGreater(len(devices), 0)
        self.assertIn('name', devices[0])
        self.assertIn('index', devices[0])

    def test_windows_paths(self):
        """Test Windows-specific path handling."""
        from voiceflow.core.config import get_config_path, get_cache_dir, get_log_dir
        
        # Just verify these don't raise exceptions
        config_path = get_config_path()
        cache_dir = get_cache_dir()
        log_dir = get_log_dir()
        
        self.assertTrue(str(config_path).endswith("VoiceFlow\\config.json"))
        self.assertIn("VoiceFlow", str(cache_dir))
        self.assertIn("VoiceFlow", str(log_dir))

if __name__ == '__main__':
    unittest.main()

