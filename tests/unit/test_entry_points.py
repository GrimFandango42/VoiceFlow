import unittest
from unittest.mock import patch, MagicMock, ANY
import sys
import os

class TestEntryPoints(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.mock_app_instance = MagicMock()
        self.patch_voiceflow_config_init = patch('voiceflow.core.config.VoiceFlowConfig')
        
        self.mock_voiceflow_config = self.patch_voiceflow_config_init.start()
        self.mock_config_instance = MagicMock()
        self.mock_config_instance.validate = MagicMock()
        self.mock_config_instance.audio_recorder_type = 'sounddevice'
        self.mock_config_instance.transcription_engine_type = 'faster_whisper'

        self.mock_voiceflow_config.return_value = self.mock_config_instance
        self.mock_voiceflow_config.from_env.return_value = self.mock_config_instance

    def tearDown(self):
        self.patch_voiceflow_config_init.stop()
        
        module_names = ['voiceflow_main', 'voiceflow_lite', 'voiceflow_debug']
        for name in module_names:
            if name in sys.modules:
                del sys.modules[name]
        super().tearDown()

    def test_voiceflow_main_entry_point(self):
        """Test that voiceflow_main.py can be imported and its main() runs."""
        # Patch VoiceFlowApp specifically for this test's import context
        with patch('voiceflow_main.VoiceFlowApp', return_value=self.mock_app_instance) as mock_app_in_main:
            with patch.dict(os.environ, {}, clear=True):
                import voiceflow_main
                voiceflow_main.main()

        self.mock_voiceflow_config.from_env.assert_called_once()
        self.mock_config_instance.validate.assert_called_once()
        
        mock_app_in_main.assert_called_once_with(
            config=self.mock_config_instance,
            audio_recorder_type=self.mock_config_instance.audio_recorder_type, # Uses default from config
            transcription_engine_type=self.mock_config_instance.transcription_engine_type # Uses default from config
        )
        self.mock_app_instance.start.assert_called_once()

    def test_voiceflow_lite_entry_point(self):
        """Test that voiceflow_lite.py can be imported and its main() runs."""
        with patch('voiceflow_lite.VoiceFlowApp', return_value=self.mock_app_instance) as mock_app_in_lite:
            with patch.dict(os.environ, {}, clear=True):
                import voiceflow_lite
                voiceflow_lite.main()

        self.mock_voiceflow_config.assert_called_once_with(
            model_name="tiny.en",
            compute_type="int8",
            device="cpu",
            enable_realtime_transcription=False,
            spinner=False
        )
        self.mock_config_instance.validate.assert_called_once()
        
        mock_app_in_lite.assert_called_once_with(
            config=self.mock_config_instance,
            audio_recorder_type=self.mock_config_instance.audio_recorder_type,
            transcription_engine_type=self.mock_config_instance.transcription_engine_type
        )
        self.mock_app_instance.start.assert_called_once()

    def test_voiceflow_debug_entry_point(self):
        """Test that voiceflow_debug.py can be imported and its main() runs."""
        with patch('voiceflow_debug.VoiceFlowApp', return_value=self.mock_app_instance) as mock_app_in_debug:
            with patch.dict(os.environ, {}, clear=True):
                # Need to also patch setup_debug_logging if it has side effects like file creation
                with patch('voiceflow_debug.setup_debug_logging'):
                    import voiceflow_debug
                    voiceflow_debug.main()

        self.mock_voiceflow_config.assert_called_once_with(
            model_name="base.en",
            compute_type="int8",
            device="cpu",
            enable_realtime_transcription=True,
            spinner=True
        )
        self.mock_config_instance.validate.assert_called_once()

        mock_app_in_debug.assert_called_once_with(
            config=self.mock_config_instance,
            audio_recorder_type=self.mock_config_instance.audio_recorder_type,
            transcription_engine_type=self.mock_config_instance.transcription_engine_type
        )
        self.mock_app_instance.start.assert_called_once()

if __name__ == '__main__':
    unittest.main()
