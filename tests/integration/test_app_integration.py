import pytest
pytestmark = pytest.mark.integration

"""Integration tests for the complete VoiceFlow application."""

import os
import time
import pytest
import tempfile
import numpy as np
import soundfile as sf
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import patch, MagicMock, PropertyMock, call

# Test configuration
TEST_AUDIO_DIR = Path("tests/audio_samples")
SAMPLE_RATE = 16000
TEST_PHRASE = "This is a test phrase for VoiceFlow integration testing."

class TestVoiceFlowIntegration:
    """Integration test cases for the complete VoiceFlow application."""
    
    @classmethod
    def setup_class(cls):
        """Set up test class."""
        # Ensure test audio directory exists
        TEST_AUDIO_DIR.mkdir(parents=True, exist_ok=True)
        
        # Create a simple test audio file
        cls.test_audio = np.random.rand(SAMPLE_RATE * 3)  # 3 seconds of random audio
        cls.test_audio_path = TEST_AUDIO_DIR / "test_integration.wav"
        sf.write(cls.test_audio_path, cls.test_audio, SAMPLE_RATE)
    
    def test_complete_workflow(self, tmp_path):
        """Test the complete VoiceFlow workflow from recording to transcription."""
        from voiceflow.app import VoiceFlowApp
        from voiceflow.core.audio import AudioRecorder
        from voiceflow.core.transcription import TranscriptionEngine
        
        # Mock components
        mock_recorder = MagicMock(spec=AudioRecorder)
        mock_recorder.start_recording.return_value = None
        mock_recorder.stop_recording.return_value = self.test_audio
        type(mock_recorder).is_recording = PropertyMock(side_effect=[False, True, False])
        
        mock_engine = MagicMock(spec=TranscriptionEngine)
        mock_engine.transcribe.return_value = TEST_PHRASE
        
        # Create test config
        class TestConfig(MagicMock):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.activation_hotkey = "ctrl+alt+v"
                self.audio_sample_rate = SAMPLE_RATE
                self.audio_channels = 1
                self.audio_chunk_size = 1024
                self.model_name = "base.en" # Use model_name as in VoiceFlowConfig
                self.device = "cpu"
                self.compute_type = "int8"
                self.hotkey = "ctrl+alt"
                self.paste_hotkey = "ctrl+shift+alt"
                self.auto_paste = False
                self.log_level = "ERROR"
                self.enable_realtime_transcription = False
                self.save_debug_audio = False
                self.debug_audio_path = "debug_audio.wav"

            def validate(self):
                pass # Mock validation
        
        # Patch component creation
        with patch('voiceflow.app.create_audio_recorder', return_value=mock_recorder), \
             patch('voiceflow.app.create_transcription_engine', return_value=mock_engine), \
             patch('voiceflow.app.VoiceFlowConfig', TestConfig):
            
            # Initialize app
            app = VoiceFlowApp(config=TestConfig())
            
            # Start the app and simulate hotkey presses
            mock_hotkey_manager_instance = MockHotkeyManager.return_value
            mock_clipboard_manager_instance = MockClipboardManager.return_value

            def simulate_hotkey_press():
                # Simulate the first hotkey press to start recording
                app.toggle_recording()
                # Simulate some recording time
                time.sleep(0.1)
                # Simulate the second hotkey press to stop recording
                app.toggle_recording()

            mock_hotkey_manager_instance.wait_for_hotkey.side_effect = simulate_hotkey_press
            
            app.start()

            # Verify transcription was called with correct audio
            mock_engine.transcribe.assert_called_once_with(self.test_audio)
            # Verify clipboard was updated
            mock_clipboard_manager_instance.copy_and_paste.assert_called_once_with(TEST_PHRASE, app.hotkey_manager)
    
    @pytest.mark.skipif(os.name != 'nt', reason="Windows-specific test")
    def test_windows_integration(self):
        """Test Windows-specific integration with system tray."""
        from voiceflow.app_windows import VoiceFlowWindows
        from voiceflow.ui.systray import VoiceFlowTray
        
        # Mock system tray
        with patch('voiceflow.app_windows.VoiceFlowTray') as mock_tray_class, \
             patch('voiceflow.app_windows.VoiceFlowApp') as mock_app_class:
            
            # Set up mocks
            mock_tray = MagicMock(spec=VoiceFlowTray)
            mock_tray_class.return_value = mock_tray
            
            mock_app = MagicMock()
            mock_app_class.return_value = mock_app
            
            # Initialize Windows app
            windows_app = VoiceFlowWindows()
            
            # Test start
            windows_app.start()
            assert windows_app.running is True
            mock_app.start.assert_called_once()
            
            # Test stop
            windows_app.stop()
            assert windows_app.running is False
            mock_app.cleanup.assert_called_once()
    
    def test_clipboard_integration(self):
        """Test clipboard integration after transcription."""
        from voiceflow.app import VoiceFlowApp
        from voiceflow.ui.clipboard import ClipboardManager
        
        # Mock clipboard
        with patch('voiceflow.app.ClipboardManager') as MockClipboardManager:
            mock_clipboard = MockClipboardManager.return_value
            mock_clipboard = MockClipboardManager.return_value
            mock_clipboard = MockClipboardManager.return_value
            
            # Initialize app with mocked components
            app = VoiceFlowApp()
            app.transcription_engine = MagicMock()
            app.transcription_engine.transcribe.return_value = TEST_PHRASE
            app.audio_recorder = MagicMock()
            app.audio_recorder.stop_recording.return_value = self.test_audio
            
            # Test stop recording with clipboard
            app.stop_recording()
            
            # Verify clipboard was updated
            mock_clipboard.copy.assert_called_once_with(TEST_PHRASE)
    
    def test_error_handling(self):
        """Test error handling in the application workflow."""
        from voiceflow.app import VoiceFlowApp
        
        # Initialize app with error-throwing components
        app = VoiceFlowApp()
        app.audio_recorder = MagicMock()
        app.audio_recorder.start_recording.side_effect = Exception("Test error")
        
        # Test error handling
        with pytest.raises(Exception, match="Test error"):
            app.start_recording()
        
        # Verify state is cleaned up
        assert app.is_recording is False
        assert app.is_running is False
    



