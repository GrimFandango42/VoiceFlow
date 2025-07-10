"""
Integration tests for VoiceFlow components.

These tests verify that the core modules work together correctly.
"""

import pytest
import sqlite3
import time
from pathlib import Path
from unittest.mock import Mock, patch, call

# Import modules to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.voiceflow_core import VoiceFlowEngine, create_engine
from core.ai_enhancement import AIEnhancer, create_enhancer
from utils.config import VoiceFlowConfig, get_config


class TestVoiceFlowIntegration:
    """Integration tests for VoiceFlow components working together."""
    
    @pytest.mark.integration
    def test_engine_with_ai_enhancement(self, temp_home_dir, mock_audio_recorder, mock_requests):
        """Test VoiceFlow engine with AI enhancement enabled."""
        # Setup mock Ollama connection
        mock_requests.get.return_value.status_code = 200
        mock_requests.get.return_value.json.return_value = {
            'models': [{'name': 'llama3.3:latest'}]
        }
        
        # Setup mock enhancement response
        mock_requests.Session.return_value.post.return_value.status_code = 200
        mock_requests.Session.return_value.post.return_value.json.return_value = {
            'response': 'Enhanced text with proper formatting.'
        }
        
        # Create engine with AI enhancement
        config = {
            'enable_ai_enhancement': True,
            'model': 'base'
        }
        
        engine = create_engine(config)
        enhancer = create_enhancer(config)
        
        # Setup audio recorder mock
        engine.recorder = mock_audio_recorder
        mock_audio_recorder.text.return_value = "this is a test transcription"
        
        # Process speech
        result = engine.process_speech()
        
        assert result == "this is a test transcription"
        assert engine.stats["total_transcriptions"] == 1
        
        # Enhance the transcription
        enhanced = enhancer.enhance_text(result)
        assert enhanced == "Enhanced text with proper formatting."
    
    @pytest.mark.integration
    def test_configuration_flow(self, temp_home_dir):
        """Test configuration loading and usage across components."""
        # Create config file
        config_dir = temp_home_dir / ".voiceflow"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.json"
        
        import json
        config_data = {
            "audio": {
                "model": "large",
                "device": "cuda"
            },
            "ai": {
                "enabled": True,
                "model": "custom:latest",
                "temperature": 0.5
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f)
        
        # Load configuration
        config = VoiceFlowConfig()
        
        # Verify configuration is loaded correctly
        assert config.get('audio', 'model') == 'large'
        assert config.get('ai', 'temperature') == 0.5
        
        # Create components with configuration
        with patch('core.voiceflow_core.AudioToTextRecorder'):
            engine = VoiceFlowEngine(config.to_dict())
            assert engine.config['audio']['model'] == 'large'
        
        with patch('core.ai_enhancement.requests'):
            enhancer = AIEnhancer(config.get_section('ai'))
            assert enhancer.config['temperature'] == 0.5
    
    @pytest.mark.integration
    def test_full_speech_processing_pipeline(self, temp_home_dir, mock_system_integration):
        """Test complete speech processing pipeline from recording to injection."""
        with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
            with patch('core.ai_enhancement.requests') as mock_requests:
                # Setup mocks
                mock_recorder = Mock()
                mock_recorder_class.return_value = mock_recorder
                mock_recorder.text.return_value = "hello world test"
                
                # Mock Ollama connection
                mock_requests.get.return_value.status_code = 200
                mock_requests.get.return_value.json.return_value = {
                    'models': [{'name': 'llama3.3:latest'}]
                }
                
                # Mock AI enhancement
                mock_requests.Session.return_value.post.return_value.status_code = 200
                mock_requests.Session.return_value.post.return_value.json.return_value = {
                    'response': 'Hello world test.'
                }
                
                # Create engine
                engine = create_engine({'enable_ai_enhancement': True})
                enhancer = create_enhancer()
                
                # Setup hotkey with custom handler that includes enhancement
                def process_and_inject():
                    text = engine.process_speech()
                    if text:
                        enhanced = enhancer.enhance_text(text)
                        engine.inject_text(enhanced)
                
                engine.setup_hotkeys('ctrl+alt', process_and_inject)
                
                # Simulate hotkey press
                hotkey_handler = mock_system_integration['keyboard'].add_hotkey.call_args[0][1]
                hotkey_handler()
                
                # Verify the full pipeline
                mock_recorder.text.assert_called_once()
                mock_system_integration['pyautogui'].typewrite.assert_called_once_with('Hello world test.')
                
                # Check database storage
                conn = sqlite3.connect(engine.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT raw_text FROM transcriptions")
                stored_text = cursor.fetchone()[0]
                conn.close()
                
                assert stored_text == "hello world test"
    
    @pytest.mark.integration
    def test_error_handling_cascade(self, temp_home_dir):
        """Test error handling across integrated components."""
        with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
            with patch('core.ai_enhancement.requests') as mock_requests:
                # Setup recorder to fail
                mock_recorder = Mock()
                mock_recorder_class.return_value = mock_recorder
                mock_recorder.text.side_effect = Exception("Recording failed")
                
                # Mock Ollama to be unavailable
                mock_requests.get.side_effect = Exception("Connection refused")
                
                # Create components
                engine = create_engine()
                enhancer = create_enhancer()
                
                # Set up error tracking
                errors = []
                engine.on_error = lambda msg: errors.append(('engine', msg))
                
                # Try to process speech - should handle error gracefully
                result = engine.process_speech()
                assert result is None
                assert len(errors) == 1
                assert "Recording failed" in errors[0][1]
                
                # Try to enhance text - should fallback to basic formatting
                enhanced = enhancer.enhance_text("test input")
                assert enhanced == "Test input."
                assert enhancer.use_ai_enhancement is False
    
    @pytest.mark.integration
    @pytest.mark.slow
    def test_performance_tracking(self, temp_home_dir, mock_audio_recorder):
        """Test performance tracking across multiple operations."""
        with patch('core.voiceflow_core.AudioToTextRecorder'):
            engine = create_engine()
            engine.recorder = mock_audio_recorder
            
            # Simulate multiple transcriptions
            transcriptions = ["first test", "second longer test", "third"]
            for text in transcriptions:
                mock_audio_recorder.text.return_value = text
                engine.process_speech()
                time.sleep(1.1)  # Avoid rapid call blocking
            
            # Check statistics
            stats = engine.get_stats()
            assert stats["total_transcriptions"] == 3
            assert stats["total_words"] == 6  # 2 + 3 + 1
            assert len(engine.stats["processing_times"]) == 3
            assert stats["average_processing_time_ms"] > 0
            
            # Verify database entries
            conn = sqlite3.connect(engine.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM transcriptions")
            count = cursor.fetchone()[0]
            assert count == 3
            
            cursor.execute("SELECT raw_text, word_count FROM transcriptions ORDER BY id")
            rows = cursor.fetchall()
            assert rows[0] == ("first test", 2)
            assert rows[1] == ("second longer test", 3)
            assert rows[2] == ("third", 1)
            conn.close()
    
    @pytest.mark.integration
    def test_configuration_persistence(self, temp_home_dir):
        """Test configuration changes persist across component recreations."""
        # Create initial configuration
        config = VoiceFlowConfig()
        config.set('audio', 'model', 'custom-model')
        config.set('ai', 'temperature', 0.8)
        config.save()
        
        # Create new config instance - should load saved values
        new_config = VoiceFlowConfig()
        assert new_config.get('audio', 'model') == 'custom-model'
        assert new_config.get('ai', 'temperature') == 0.8
        
        # Create components with loaded config
        with patch('core.voiceflow_core.AudioToTextRecorder'):
            engine = VoiceFlowEngine(new_config.get_section('audio'))
            assert engine.config['model'] == 'custom-model'


class TestEnvironmentIntegration:
    """Test environment variable integration across components."""
    
    @pytest.mark.integration
    @patch.dict(os.environ, {
        'VOICEFLOW_MODEL': 'env-model',
        'AI_MODEL': 'env-ai-model',
        'ENABLE_AI_ENHANCEMENT': 'true',
        'OLLAMA_HOST': 'env-host',
        'OLLAMA_PORT': '9999'
    })
    def test_environment_variable_propagation(self, temp_home_dir):
        """Test that environment variables propagate correctly to all components."""
        with patch('core.voiceflow_core.AudioToTextRecorder'):
            with patch('core.ai_enhancement.requests') as mock_requests:
                # Mock Ollama connection
                mock_requests.get.side_effect = Exception("No connection")
                
                # Create components - should use env vars
                config = get_config()
                engine = create_engine()
                enhancer = create_enhancer()
                
                # Verify env vars were applied
                assert config.get('audio', 'model') == 'env-model'
                assert config.get('ai', 'model') == 'env-ai-model'
                assert engine.config['model'] == 'env-model'
                assert enhancer.deepseek_model == 'env-ai-model'
                assert enhancer.ollama_urls[0] == 'http://env-host:9999/api/generate'


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])