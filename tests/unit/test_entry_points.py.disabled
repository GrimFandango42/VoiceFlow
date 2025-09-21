import unittest
from unittest.mock import patch, MagicMock, ANY
import sys
import os

class TestEntryPoints(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.mock_app_instance = MagicMock()
        # Patch the create_engine factory function to control engine creation.
        self.patch_create_engine = patch('voiceflow.voiceflow_core.create_engine')
        
        self.mock_create_engine = self.patch_create_engine.start()
        self.mock_engine_instance = MagicMock()
        self.mock_create_engine.return_value = self.mock_engine_instance

    def tearDown(self):
        self.patch_create_engine.stop()
        
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

        # Assert that create_engine was called and the resulting engine was used.
        self.mock_create_engine.assert_called_once()
        mock_app_in_main.assert_called_once_with(engine=self.mock_engine_instance)
        self.mock_engine_instance.start.assert_called_once()

    def test_voiceflow_lite_entry_point(self):
        """Test that voiceflow_lite.py can be imported and its main() runs."""
        with patch('voiceflow_lite.VoiceFlowApp', return_value=self.mock_app_instance) as mock_app_in_lite:
            with patch.dict(os.environ, {}, clear=True):
                import voiceflow_lite
                voiceflow_lite.main()

        # Assert that the engine was initialized with the correct lite config
        self.mock_engine_class.assert_called_once()
        config_arg = self.mock_engine_class.call_args[1].get('config')
        self.assertEqual(config_arg.get('model'), "tiny.en")
        self.assertEqual(config_arg.get('device'), "cpu")

        mock_app_in_lite.assert_called_once_with(
            engine=self.mock_engine_instance
        )
        self.mock_engine_instance.start.assert_called_once()

    def test_voiceflow_debug_entry_point(self):
        """Test that voiceflow_debug.py can be imported and its main() runs."""
        with patch('voiceflow_debug.VoiceFlowApp', return_value=self.mock_app_instance) as mock_app_in_debug:
            with patch.dict(os.environ, {}, clear=True):
                # Need to also patch setup_debug_logging if it has side effects like file creation
                with patch('voiceflow_debug.setup_debug_logging'):
                    import voiceflow_debug
                    voiceflow_debug.main()

        # Assert that the engine was initialized with the correct debug config
        self.mock_engine_class.assert_called_once()
        config_arg = self.mock_engine_class.call_args[1].get('config')
        self.assertEqual(config_arg.get('model'), "base.en")
        self.assertTrue(config_arg.get('enable_realtime_transcription'))

        mock_app_in_debug.assert_called_once_with(
            engine=self.mock_engine_instance
        )
        self.mock_engine_instance.start.assert_called_once()

if __name__ == '__main__':
    unittest.main()
