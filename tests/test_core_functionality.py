"""
Core Functionality Tests

Tests core VoiceFlow functionality with proper mocking to avoid import issues.
"""

import pytest
import tempfile
import shutil
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call

# Add parent directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCoreVoiceFlowFunctionality:
    """Test core VoiceFlow functionality with proper mocking."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    @pytest.fixture
    def mock_dependencies(self):
        """Mock all external dependencies."""
        with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder:
            with patch('core.voiceflow_core.pyautogui') as mock_pyautogui:
                with patch('core.voiceflow_core.keyboard') as mock_keyboard:
                    with patch('core.voiceflow_core.SYSTEM_INTEGRATION', True):
                        yield {
                            'recorder': mock_recorder,
                            'pyautogui': mock_pyautogui,
                            'keyboard': mock_keyboard
                        }
    
    def test_complete_speech_to_text_flow(self, temp_dir, mock_dependencies):
        """Test complete speech-to-text processing flow."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            # Import after patching
            from core.voiceflow_core import VoiceFlowEngine
            
            # Setup mock recorder
            mock_recorder_instance = Mock()
            mock_recorder_instance.text.return_value = "Hello, this is a test transcription!"
            mock_dependencies['recorder'].return_value = mock_recorder_instance
            
            # Create engine
            engine = VoiceFlowEngine({'model': 'base', 'device': 'cpu'})
            
            # Process speech
            result = engine.process_speech()
            
            # Verify transcription
            assert result == "Hello, this is a test transcription!"
            assert engine.stats['total_transcriptions'] == 1
            assert engine.stats['total_words'] == 6
            
            # Verify database storage
            import sqlite3
            conn = sqlite3.connect(engine.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT raw_text FROM transcriptions")
            stored_text = cursor.fetchone()[0]
            conn.close()
            
            assert stored_text == "Hello, this is a test transcription!"
    
    def test_gpu_cpu_fallback(self, temp_dir, mock_dependencies):
        """Test GPU to CPU fallback mechanism."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            from core.voiceflow_core import VoiceFlowEngine
            
            # First call (GPU) fails, second call (CPU) succeeds
            mock_dependencies['recorder'].side_effect = [
                Exception("CUDA not available"),
                Mock()  # CPU initialization succeeds
            ]
            
            # Create engine with auto device selection
            engine = VoiceFlowEngine({'device': 'auto'})
            
            # Should have tried GPU first, then CPU
            assert mock_dependencies['recorder'].call_count == 2
            
            # First call should be GPU
            first_call = mock_dependencies['recorder'].call_args_list[0]
            assert first_call.kwargs['device'] == 'cuda'
            
            # Second call should be CPU
            second_call = mock_dependencies['recorder'].call_args_list[1]
            assert second_call.kwargs['device'] == 'cpu'
            assert second_call.kwargs['model'] == 'base'
    
    def test_text_injection_security(self, temp_dir, mock_dependencies):
        """Test text injection with security considerations."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            from core.voiceflow_core import VoiceFlowEngine
            
            engine = VoiceFlowEngine()
            
            # Test normal injection
            success = engine.inject_text("Normal text injection")
            assert success is True
            mock_dependencies['pyautogui'].typewrite.assert_called_with("Normal text injection")
            
            # Test empty text rejection
            success = engine.inject_text("")
            assert success is False
            
            # Test injection error handling
            mock_dependencies['pyautogui'].typewrite.side_effect = PermissionError("No permission")
            success = engine.inject_text("Test")
            assert success is False
    
    def test_hotkey_functionality(self, temp_dir, mock_dependencies):
        """Test hotkey setup and handling."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            from core.voiceflow_core import VoiceFlowEngine
            
            # Setup mock recorder
            mock_recorder_instance = Mock()
            mock_recorder_instance.text.return_value = "Hotkey triggered text"
            mock_dependencies['recorder'].return_value = mock_recorder_instance
            
            engine = VoiceFlowEngine()
            
            # Setup custom hotkey with callback
            callback_called = False
            def custom_callback():
                nonlocal callback_called
                callback_called = True
            
            engine.setup_hotkeys('ctrl+shift+v', custom_callback)
            
            # Verify hotkey registered
            mock_dependencies['keyboard'].add_hotkey.assert_called_once()
            hotkey, handler = mock_dependencies['keyboard'].add_hotkey.call_args[0]
            assert hotkey == 'ctrl+shift+v'
            
            # Trigger hotkey handler
            handler()
            assert callback_called is True
    
    def test_error_callbacks(self, temp_dir, mock_dependencies):
        """Test error callback functionality."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            from core.voiceflow_core import VoiceFlowEngine
            
            # Setup mock recorder that fails
            mock_recorder_instance = Mock()
            mock_recorder_instance.text.side_effect = MemoryError("Out of memory")
            mock_dependencies['recorder'].return_value = mock_recorder_instance
            
            engine = VoiceFlowEngine()
            
            # Setup error callback
            error_message = None
            def on_error(msg):
                nonlocal error_message
                error_message = msg
            
            engine.on_error = on_error
            
            # Process speech should fail
            result = engine.process_speech()
            
            assert result is None
            assert error_message == "Out of memory during speech processing"
    
    def test_statistics_tracking(self, temp_dir, mock_dependencies):
        """Test comprehensive statistics tracking."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            from core.voiceflow_core import VoiceFlowEngine
            
            # Setup mock recorder
            mock_recorder_instance = Mock()
            mock_recorder_instance.text.side_effect = [
                "First transcription",
                "Second longer transcription here",
                "Third"
            ]
            mock_dependencies['recorder'].return_value = mock_recorder_instance
            
            engine = VoiceFlowEngine()
            
            # Process multiple transcriptions
            for i in range(3):
                time.sleep(1.1)  # Avoid rapid call prevention
                engine.process_speech()
            
            # Check statistics
            stats = engine.get_stats()
            assert stats['total_transcriptions'] == 3
            assert stats['total_words'] == 7  # 2 + 4 + 1
            assert stats['average_processing_time_ms'] > 0
            assert stats['is_recording'] is False
            assert 'session_duration' in stats
    
    def test_secure_database_integration(self, temp_dir, mock_dependencies):
        """Test integration with secure database when available."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            # Mock secure database
            with patch('core.voiceflow_core.create_secure_database') as mock_create_db:
                with patch('core.voiceflow_core.ENCRYPTION_AVAILABLE', True):
                    mock_secure_db = Mock()
                    mock_secure_db.store_transcription.return_value = True
                    mock_create_db.return_value = mock_secure_db
                    
                    from core.voiceflow_core import VoiceFlowEngine
                    
                    # Setup recorder
                    mock_recorder_instance = Mock()
                    mock_recorder_instance.text.return_value = "Secure transcription"
                    mock_dependencies['recorder'].return_value = mock_recorder_instance
                    
                    engine = VoiceFlowEngine()
                    
                    # Process speech
                    result = engine.process_speech()
                    
                    # Verify secure storage was used
                    mock_secure_db.store_transcription.assert_called_once()
                    call_args = mock_secure_db.store_transcription.call_args[1]
                    assert call_args['text'] == "Secure transcription"
                    assert call_args['word_count'] == 2
    
    def test_configuration_propagation(self, temp_dir, mock_dependencies):
        """Test configuration propagates correctly through the system."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            from core.voiceflow_core import VoiceFlowEngine
            
            config = {
                'model': 'large',
                'device': 'cuda',
                'enable_ai_enhancement': True,
                'custom_param': 'test_value'
            }
            
            engine = VoiceFlowEngine(config)
            
            # Verify configuration stored
            assert engine.config == config
            
            # Verify model configuration used in recorder setup
            recorder_call = mock_dependencies['recorder'].call_args
            assert recorder_call.kwargs['model'] == 'large'
            assert recorder_call.kwargs['device'] == 'cuda'
    
    def test_cleanup_functionality(self, temp_dir, mock_dependencies):
        """Test cleanup releases resources properly."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            from core.voiceflow_core import VoiceFlowEngine
            
            engine = VoiceFlowEngine()
            engine.is_recording = True
            
            # Cleanup
            engine.cleanup()
            
            # Verify state reset
            assert engine.is_recording is False
    
    def test_concurrent_recording_prevention(self, temp_dir, mock_dependencies):
        """Test prevention of concurrent recordings."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            from core.voiceflow_core import VoiceFlowEngine
            
            # Setup mock recorder
            mock_recorder_instance = Mock()
            
            # Simulate slow transcription
            def slow_transcription():
                time.sleep(0.5)
                return "Slow result"
            
            mock_recorder_instance.text = slow_transcription
            mock_dependencies['recorder'].return_value = mock_recorder_instance
            
            engine = VoiceFlowEngine()
            
            # Start first recording in thread
            import threading
            result1 = None
            def record1():
                nonlocal result1
                result1 = engine.process_speech()
            
            thread1 = threading.Thread(target=record1)
            thread1.start()
            
            # Try immediate second recording
            time.sleep(0.1)  # Let first recording start
            result2 = engine.process_speech()
            
            thread1.join()
            
            # First should succeed, second should be blocked
            assert result1 == "Slow result"
            assert result2 is None


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_database_corruption_recovery(self, temp_dir):
        """Test recovery from database corruption."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            with patch('core.voiceflow_core.AudioToTextRecorder'):
                from core.voiceflow_core import VoiceFlowEngine
                
                # Create engine (creates database)
                engine = VoiceFlowEngine()
                
                # Corrupt database file
                with open(engine.db_path, 'wb') as f:
                    f.write(b'corrupted data')
                
                # Try to store transcription
                with patch('core.voiceflow_core.sqlite3.connect') as mock_connect:
                    mock_connect.side_effect = Exception("Database corrupted")
                    
                    # Should handle error gracefully
                    engine.store_transcription("Test", 100)
    
    def test_missing_dependencies_handling(self, temp_dir):
        """Test handling of missing dependencies."""
        with patch('core.voiceflow_core.Path.home', return_value=temp_dir):
            # Test with missing AudioToTextRecorder
            with patch.dict(sys.modules, {'RealtimeSTT': None}):
                # Force reload to trigger import error
                if 'core.voiceflow_core' in sys.modules:
                    del sys.modules['core.voiceflow_core']
                
                from core.voiceflow_core import VoiceFlowEngine
                
                engine = VoiceFlowEngine()
                
                # Should handle missing recorder
                result = engine.process_speech()
                assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])