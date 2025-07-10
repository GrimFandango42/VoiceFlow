"""
Unit tests for VoiceFlow Core Engine

Tests the consolidated speech processing engine functionality including:
- Engine initialization and configuration
- Database operations and transcription storage
- Audio recorder setup with GPU/CPU fallback
- Speech processing logic and error handling
- Text injection mechanisms
- Statistics tracking and reporting
"""

import pytest
import sqlite3
import tempfile
import shutil
import time
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime

# Import the module to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.voiceflow_core import VoiceFlowEngine, create_engine


class TestVoiceFlowEngine:
    """Test suite for VoiceFlowEngine class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    @pytest.fixture
    def mock_audio_recorder(self):
        """Mock AudioToTextRecorder."""
        with patch('core.voiceflow_core.AudioToTextRecorder') as mock:
            yield mock
    
    @pytest.fixture
    def engine_with_temp_dir(self, temp_dir, mock_audio_recorder):
        """Create engine instance with temporary directory."""
        with patch('core.voiceflow_core.Path.home', return_value=Path(temp_dir)):
            engine = VoiceFlowEngine()
            yield engine
            engine.cleanup()
    
    def test_initialization(self, temp_dir):
        """Test engine initialization with default configuration."""
        with patch('core.voiceflow_core.Path.home', return_value=Path(temp_dir)):
            with patch('core.voiceflow_core.AudioToTextRecorder'):
                engine = VoiceFlowEngine()
                
                # Check data directory creation
                assert (Path(temp_dir) / ".voiceflow").exists()
                
                # Check default values
                assert engine.is_recording is False
                assert engine.last_recording_time == 0
                assert engine.stats["total_transcriptions"] == 0
                assert engine.stats["total_words"] == 0
                assert isinstance(engine.stats["session_start"], datetime)
    
    def test_initialization_with_config(self, temp_dir, mock_audio_recorder):
        """Test engine initialization with custom configuration."""
        config = {
            'model': 'large',
            'device': 'cuda',
            'enable_ai_enhancement': False
        }
        
        with patch('core.voiceflow_core.Path.home', return_value=Path(temp_dir)):
            engine = VoiceFlowEngine(config)
            assert engine.config == config
    
    def test_database_initialization(self, engine_with_temp_dir):
        """Test database creation and schema."""
        db_path = engine_with_temp_dir.db_path
        assert db_path.exists()
        
        # Check table schema
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='transcriptions'")
        schema = cursor.fetchone()[0]
        
        # Verify required columns exist
        assert "id INTEGER PRIMARY KEY AUTOINCREMENT" in schema
        assert "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP" in schema
        assert "raw_text TEXT" in schema
        assert "enhanced_text TEXT" in schema
        assert "processing_time_ms INTEGER" in schema
        assert "word_count INTEGER" in schema
        assert "confidence REAL" in schema
        assert "model_used TEXT" in schema
        assert "session_id TEXT" in schema
        
        conn.close()
    
    def test_database_initialization_error(self, temp_dir):
        """Test database initialization error handling."""
        with patch('core.voiceflow_core.Path.home', return_value=Path(temp_dir)):
            with patch('core.voiceflow_core.AudioToTextRecorder'):
                with patch('sqlite3.connect', side_effect=Exception("DB Error")):
                    # Should not raise, just print error
                    engine = VoiceFlowEngine()
                    assert engine is not None
    
    @pytest.mark.parametrize("device,model,expected_device", [
        ("auto", "base", "cuda"),  # Should try GPU first
        ("cuda", "large", "cuda"),  # Explicit GPU
        ("cpu", "base", "cpu"),     # Explicit CPU
    ])
    def test_audio_recorder_setup(self, temp_dir, device, model, expected_device):
        """Test audio recorder setup with different configurations."""
        config = {'device': device, 'model': model}
        
        with patch('core.voiceflow_core.Path.home', return_value=Path(temp_dir)):
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder:
                if expected_device == "cuda":
                    # First call succeeds for GPU
                    mock_recorder.return_value = Mock()
                else:
                    # First call fails, second succeeds for CPU
                    mock_recorder.side_effect = [Exception("GPU not available"), Mock()]
                
                engine = VoiceFlowEngine(config)
                
                # Verify recorder was initialized with correct parameters
                if device == "cpu":
                    # CPU explicitly requested
                    mock_recorder.assert_called_with(
                        model="base",
                        device="cpu",
                        compute_type="int8",
                        language="en",
                        use_microphone=True,
                        spinner=False,
                        level=0,
                        enable_realtime_transcription=True,
                        silero_sensitivity=0.4,
                        webrtc_sensitivity=3,
                        post_speech_silence_duration=0.8,
                        min_length_of_recording=0.2,
                        min_gap_between_recordings=0.3
                    )
                assert engine.recorder is not None
    
    def test_audio_recorder_complete_failure(self, temp_dir):
        """Test handling when audio recorder fails completely."""
        with patch('core.voiceflow_core.Path.home', return_value=Path(temp_dir)):
            with patch('core.voiceflow_core.AudioToTextRecorder', side_effect=Exception("No audio")):
                engine = VoiceFlowEngine()
                assert engine.recorder is None
    
    def test_process_speech_success(self, engine_with_temp_dir):
        """Test successful speech processing."""
        mock_recorder = Mock()
        mock_recorder.text.return_value = "Hello world"
        engine_with_temp_dir.recorder = mock_recorder
        
        # Set up callback
        callback_called = False
        transcription_result = None
        
        def on_transcription(text):
            nonlocal callback_called, transcription_result
            callback_called = True
            transcription_result = text
        
        engine_with_temp_dir.on_transcription = on_transcription
        
        # Process speech
        result = engine_with_temp_dir.process_speech()
        
        assert result == "Hello world"
        assert callback_called
        assert transcription_result == "Hello world"
        assert engine_with_temp_dir.stats["total_transcriptions"] == 1
        assert engine_with_temp_dir.stats["total_words"] == 2
        assert len(engine_with_temp_dir.stats["processing_times"]) == 1
    
    def test_process_speech_no_recorder(self, engine_with_temp_dir):
        """Test speech processing when recorder is not initialized."""
        engine_with_temp_dir.recorder = None
        result = engine_with_temp_dir.process_speech()
        assert result is None
    
    def test_process_speech_rapid_calls(self, engine_with_temp_dir):
        """Test prevention of rapid successive recordings."""
        mock_recorder = Mock()
        mock_recorder.text.return_value = "Test"
        engine_with_temp_dir.recorder = mock_recorder
        
        # First call should succeed
        result1 = engine_with_temp_dir.process_speech()
        assert result1 == "Test"
        
        # Immediate second call should be blocked
        result2 = engine_with_temp_dir.process_speech()
        assert result2 is None
        
        # After waiting, should succeed
        time.sleep(1.1)
        result3 = engine_with_temp_dir.process_speech()
        assert result3 == "Test"
    
    def test_process_speech_empty_result(self, engine_with_temp_dir):
        """Test handling of empty transcription result."""
        mock_recorder = Mock()
        mock_recorder.text.return_value = ""
        engine_with_temp_dir.recorder = mock_recorder
        
        result = engine_with_temp_dir.process_speech()
        assert result is None
        assert engine_with_temp_dir.stats["total_transcriptions"] == 0
    
    def test_process_speech_error_handling(self, engine_with_temp_dir):
        """Test error handling during speech processing."""
        mock_recorder = Mock()
        mock_recorder.text.side_effect = Exception("Recording error")
        engine_with_temp_dir.recorder = mock_recorder
        
        # Set up error callback
        error_message = None
        def on_error(msg):
            nonlocal error_message
            error_message = msg
        
        engine_with_temp_dir.on_error = on_error
        
        result = engine_with_temp_dir.process_speech()
        assert result is None
        assert "Speech processing error: Recording error" in error_message
    
    @patch('core.voiceflow_core.SYSTEM_INTEGRATION', True)
    @patch('core.voiceflow_core.pyautogui')
    def test_inject_text_success(self, mock_pyautogui, engine_with_temp_dir):
        """Test successful text injection."""
        result = engine_with_temp_dir.inject_text("Hello world")
        
        assert result is True
        mock_pyautogui.typewrite.assert_called_once_with("Hello world")
    
    @patch('core.voiceflow_core.SYSTEM_INTEGRATION', False)
    def test_inject_text_no_integration(self, engine_with_temp_dir):
        """Test text injection when system integration is disabled."""
        result = engine_with_temp_dir.inject_text("Hello world")
        assert result is False
    
    @patch('core.voiceflow_core.SYSTEM_INTEGRATION', True)
    @patch('core.voiceflow_core.pyautogui')
    def test_inject_text_error(self, mock_pyautogui, engine_with_temp_dir):
        """Test text injection error handling."""
        mock_pyautogui.typewrite.side_effect = Exception("Injection error")
        
        result = engine_with_temp_dir.inject_text("Hello world")
        assert result is False
    
    @patch('core.voiceflow_core.SYSTEM_INTEGRATION', True)
    @patch('core.voiceflow_core.keyboard')
    def test_setup_hotkeys_success(self, mock_keyboard, engine_with_temp_dir):
        """Test hotkey setup."""
        callback = Mock()
        engine_with_temp_dir.setup_hotkeys('ctrl+shift', callback)
        
        mock_keyboard.add_hotkey.assert_called_once()
        args = mock_keyboard.add_hotkey.call_args
        assert args[0][0] == 'ctrl+shift'
        
        # Test the hotkey handler
        handler = args[0][1]
        handler()
        callback.assert_called_once()
    
    @patch('core.voiceflow_core.SYSTEM_INTEGRATION', True)
    @patch('core.voiceflow_core.keyboard')
    def test_setup_hotkeys_default_behavior(self, mock_keyboard, engine_with_temp_dir):
        """Test hotkey setup with default behavior."""
        mock_recorder = Mock()
        mock_recorder.text.return_value = "Test text"
        engine_with_temp_dir.recorder = mock_recorder
        
        with patch.object(engine_with_temp_dir, 'inject_text') as mock_inject:
            engine_with_temp_dir.setup_hotkeys('ctrl+alt')
            
            # Get and call the handler
            handler = mock_keyboard.add_hotkey.call_args[0][1]
            handler()
            
            # Should process speech and inject result
            mock_inject.assert_called_once_with("Test text")
    
    @patch('core.voiceflow_core.SYSTEM_INTEGRATION', False)
    def test_setup_hotkeys_no_integration(self, engine_with_temp_dir):
        """Test hotkey setup when system integration is disabled."""
        # Should not raise error, just print warning
        engine_with_temp_dir.setup_hotkeys('ctrl+alt')
    
    def test_store_transcription(self, engine_with_temp_dir):
        """Test storing transcription in database."""
        engine_with_temp_dir.config['model'] = 'test_model'
        engine_with_temp_dir.store_transcription("Test transcription", 150.5)
        
        # Verify data was stored
        conn = sqlite3.connect(engine_with_temp_dir.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM transcriptions")
        row = cursor.fetchone()
        
        assert row is not None
        assert row[2] == "Test transcription"  # raw_text
        assert row[4] == 150  # processing_time_ms
        assert row[5] == 2    # word_count
        assert row[7] == "test_model"  # model_used
        
        conn.close()
    
    def test_store_transcription_error(self, engine_with_temp_dir):
        """Test error handling when storing transcription fails."""
        with patch('sqlite3.connect', side_effect=Exception("DB Error")):
            # Should not raise, just print error
            engine_with_temp_dir.store_transcription("Test", 100)
    
    def test_get_stats(self, engine_with_temp_dir):
        """Test statistics retrieval."""
        # Process some speech to generate stats
        mock_recorder = Mock()
        mock_recorder.text.side_effect = ["First", "Second transcription"]
        engine_with_temp_dir.recorder = mock_recorder
        
        engine_with_temp_dir.process_speech()
        time.sleep(1.1)
        engine_with_temp_dir.process_speech()
        
        stats = engine_with_temp_dir.get_stats()
        
        assert stats["total_transcriptions"] == 2
        assert stats["total_words"] == 3  # "First" + "Second transcription"
        assert stats["is_recording"] is False
        assert stats["average_processing_time_ms"] > 0
        assert "session_duration" in stats
    
    def test_get_stats_empty(self, engine_with_temp_dir):
        """Test statistics when no processing has occurred."""
        stats = engine_with_temp_dir.get_stats()
        
        assert stats["total_transcriptions"] == 0
        assert stats["total_words"] == 0
        assert stats["average_processing_time_ms"] == 0
    
    def test_cleanup(self, engine_with_temp_dir):
        """Test cleanup method."""
        engine_with_temp_dir.is_recording = True
        engine_with_temp_dir.cleanup()
        
        assert engine_with_temp_dir.is_recording is False
    
    def test_cleanup_error(self, engine_with_temp_dir):
        """Test cleanup error handling."""
        engine_with_temp_dir.recorder = Mock()
        engine_with_temp_dir.recorder.side_effect = Exception("Cleanup error")
        
        # Should not raise
        engine_with_temp_dir.cleanup()


class TestCreateEngine:
    """Test suite for create_engine factory function."""
    
    @patch.dict(os.environ, {
        'VOICEFLOW_MODEL': 'large',
        'VOICEFLOW_DEVICE': 'cuda',
        'ENABLE_AI_ENHANCEMENT': 'false'
    })
    @patch('core.voiceflow_core.VoiceFlowEngine')
    def test_create_engine_with_env_vars(self, mock_engine_class):
        """Test engine creation with environment variables."""
        engine = create_engine()
        
        mock_engine_class.assert_called_once_with({
            'model': 'large',
            'device': 'cuda',
            'enable_ai_enhancement': False
        })
    
    @patch('core.voiceflow_core.VoiceFlowEngine')
    def test_create_engine_with_config(self, mock_engine_class):
        """Test engine creation with custom config."""
        config = {'model': 'tiny', 'custom_param': 'value'}
        engine = create_engine(config)
        
        expected_config = {
            'model': 'tiny',
            'device': 'auto',
            'enable_ai_enhancement': True,
            'custom_param': 'value'
        }
        mock_engine_class.assert_called_once_with(expected_config)
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('core.voiceflow_core.VoiceFlowEngine')
    def test_create_engine_defaults(self, mock_engine_class):
        """Test engine creation with default values."""
        engine = create_engine()
        
        mock_engine_class.assert_called_once_with({
            'model': 'base',
            'device': 'auto',
            'enable_ai_enhancement': True
        })


if __name__ == "__main__":
    pytest.main([__file__, "-v"])