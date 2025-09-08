import pytest
pytestmark = pytest.mark.integration

import unittest
from unittest.mock import patch, MagicMock
import numpy as np
import time
import os

from voiceflow.app import VoiceFlowApp
from voiceflow.core.config import VoiceFlowConfig

class TestVoiceFlowAppCore(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.mock_audio_recorder_instance = MagicMock()
        self.mock_transcription_engine_instance = MagicMock()

        self.patch_create_audio_recorder = patch('voiceflow.app.create_audio_recorder', return_value=self.mock_audio_recorder_instance)
        self.patch_create_transcription_engine = patch('voiceflow.app.create_transcription_engine', return_value=self.mock_transcription_engine_instance)
        
        self.mock_create_audio_recorder = self.patch_create_audio_recorder.start()
        self.mock_create_transcription_engine = self.patch_create_transcription_engine.start()

        self.mock_hotkey_manager_instance = MagicMock()
        self.mock_clipboard_manager_instance = MagicMock()
        
        self.patch_hotkey_manager = patch('voiceflow.app.HotkeyManager', return_value=self.mock_hotkey_manager_instance)
        self.patch_clipboard_manager = patch('voiceflow.app.ClipboardManager', return_value=self.mock_clipboard_manager_instance)

        self.mock_hotkey_manager = self.patch_hotkey_manager.start()
        self.mock_clipboard_manager = self.patch_clipboard_manager.start()

    def _get_default_test_config(self, **overrides):
        """
        Returns a VoiceFlowConfig instance with sensible defaults for testing.
        """
        base_config_params = {
            'model_name': 'tiny.en',
            'language': 'en',
            'sample_rate': 16000,
            'channels': 1,
            'device_index': None,
            'block_size': 1600,
            'flush_interval': 3,
            'vad_threshold': 0.5,
            'vad_min_silence_duration_ms': 100,
            'vad_speech_pad_ms': 100,
            'hotkey': 'ctrl+alt',
            'paste_hotkey': 'ctrl+shift+alt',
            'auto_paste': False,
            'log_level': 'ERROR',
            'use_realtime_stt': False,
            'rtstt_silence_limit': 1.0,
            'rtstt_chunk_s': 5.0,
            'audio_recorder_type': 'sounddevice',
            'transcription_engine_type': 'faster_whisper',
            'save_debug_audio': False,
            'debug_audio_path': "debug_audio.wav" 
        }
        base_config_params.update(overrides)
        
        with patch.dict(os.environ, {}, clear=True):
            config = VoiceFlowConfig(**base_config_params)
            config.validate()
        return config


    def tearDown(self):
        self.patch_create_audio_recorder.stop()
        self.patch_create_transcription_engine.stop()
        self.patch_hotkey_manager.stop()
        self.patch_clipboard_manager.stop()
        super().tearDown()

    def test_app_initialization(self):
        """Test VoiceFlowApp initializes correctly with mocked components."""
        config = self._get_default_test_config()
        app = VoiceFlowApp(config=config, audio_recorder_type="mock_audio", transcription_engine_type="mock_engine")
        
        self.assertIsNotNone(app)
        self.mock_create_audio_recorder.assert_called_once_with(config, "mock_audio")
        self.mock_create_transcription_engine.assert_called_once_with(config, "mock_engine")
        self.mock_hotkey_manager.assert_called_once_with(config.hotkey, config.paste_hotkey, app.toggle_recording, app.paste_transcription_from_hotkey)
        self.mock_clipboard_manager.assert_called_once()
        
        self.assertIs(app.audio_recorder, self.mock_audio_recorder_instance)
        self.assertIs(app.transcription_engine, self.mock_transcription_engine_instance)
        self.assertIs(app.hotkey_manager, self.mock_hotkey_manager_instance)
        self.assertIs(app.clipboard_manager, self.mock_clipboard_manager_instance)
        self.assertFalse(app.is_running)
        self.assertFalse(app.is_recording)

    def test_start_and_stop_app(self):
        """Test starting and stopping the application."""
        config = self._get_default_test_config()
        app = VoiceFlowApp(config=config)
        
        self.assertFalse(app.is_running)
        app.start()
        self.assertTrue(app.is_running)
        self.mock_hotkey_manager_instance.start_listening.assert_called_once()
        
        app.stop()
        self.assertFalse(app.is_running)
        self.mock_hotkey_manager_instance.stop_listening.assert_called_once()
        # app.cleanup() is called by app.stop()
        self.mock_audio_recorder_instance.cleanup.assert_called_once()
        self.mock_transcription_engine_instance.cleanup.assert_called_once()
        self.mock_hotkey_manager_instance.cleanup.assert_called_once()


    def test_toggle_recording_start(self):
        """Test starting recording via toggle_recording."""
        app = VoiceFlowApp(config=self.default_config)
        app.is_running = True # Simulate app is running
        
        self.mock_audio_recorder_instance.start_recording.return_value = True
        
        app.toggle_recording() # First call: start recording
        
        self.assertTrue(app.is_recording)
        self.mock_audio_recorder_instance.start_recording.assert_called_once()
        # Check if UI/console feedback is called (e.g., print) - might need to mock builtins.print

    def test_toggle_recording_stop_and_transcribe(self):
        """Test stopping recording and triggering transcription via toggle_recording."""
        app = VoiceFlowApp(config=self.default_config)
        app.is_running = True
        app.is_recording = True # Simulate already recording

        # Mock audio data returned by stop_recording
        mock_audio_data = np.array([0.1, 0.2, 0.3], dtype=np.float32)
        self.mock_audio_recorder_instance.stop_recording.return_value = mock_audio_data
        
        # Mock transcription engine's output
        self.mock_transcription_engine_instance.transcribe.return_value = "Hello world"
        
        # Mock clipboard manager
        self.mock_clipboard_manager_instance.copy_and_paste.return_value = True

        app.toggle_recording() # Second call: stop recording and transcribe

        self.assertFalse(app.is_recording)
        self.mock_audio_recorder_instance.stop_recording.assert_called_once()
        self.mock_transcription_engine_instance.transcribe.assert_called_once_with(mock_audio_data)
        self.mock_clipboard_manager_instance.copy_and_paste.assert_called_once_with("Hello world", app.hotkey_manager)

    def test_toggle_recording_stop_no_speech(self):
        """Test transcription when no speech is detected (empty string from engine)."""
        app = VoiceFlowApp(config=self.default_config)
        app.is_running = True
        app.is_recording = True 

        mock_audio_data = np.array([0.01, 0.02, 0.01], dtype=np.float32)
        self.mock_audio_recorder_instance.stop_recording.return_value = mock_audio_data
        self.mock_transcription_engine_instance.transcribe.return_value = "  " # Empty or whitespace only

        app.toggle_recording()

        self.assertFalse(app.is_recording)
        self.mock_transcription_engine_instance.transcribe.assert_called_once_with(mock_audio_data)
        self.mock_clipboard_manager_instance.copy_and_paste.assert_not_called() # Should not paste if no text

    def test_transcribe_and_paste_failure(self):
        """Test transcription and paste when clipboard fails."""
        app = VoiceFlowApp(config=self.default_config)
        app.is_running = True
        
        mock_audio_data = np.array([0.1, 0.2, 0.3], dtype=np.float32)
        self.mock_transcription_engine_instance.transcribe.return_value = "Test text"
        self.mock_clipboard_manager_instance.copy_and_paste.return_value = False # Simulate paste failure

        # Directly call transcribe_and_paste as it's called by toggle_recording
        app.transcribe_and_paste(mock_audio_data)
        
        self.mock_transcription_engine_instance.transcribe.assert_called_once_with(mock_audio_data)
        self.mock_clipboard_manager_instance.copy_and_paste.assert_called_once_with("Test text", app.hotkey_manager)
        # Add assertion for logging/printing "Failed to paste text" if possible (mock print)

    def test_paste_transcription_from_hotkey(self):
        """Test the paste_transcription_from_hotkey method."""
        app = VoiceFlowApp(config=self.default_config)
        app.last_transcription = "Previous text"
        
        self.mock_clipboard_manager_instance.copy_and_paste.return_value = True
        
        app.paste_transcription_from_hotkey()
        
        self.mock_clipboard_manager_instance.copy_and_paste.assert_called_once_with("Previous text", app.hotkey_manager)

    def test_paste_transcription_from_hotkey_no_last_transcription(self):
        """Test paste_transcription_from_hotkey when no previous transcription exists."""
        app = VoiceFlowApp(config=self.default_config)
        app.last_transcription = None
        
        app.paste_transcription_from_hotkey()
        
        self.mock_clipboard_manager_instance.copy_and_paste.assert_not_called()


if __name__ == '__main__':
    unittest.main()

