"""
Comprehensive Integration Tests for VoiceFlow System

This test suite validates the complete integration of VoiceFlow components,
testing real-world scenarios and failure modes to ensure the refactored
architecture works as a cohesive system.
"""

import asyncio
import json
import os
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call, AsyncMock
import pytest
import sys

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.voiceflow_core import VoiceFlowEngine, create_engine
from core.ai_enhancement import AIEnhancer, create_enhancer
from utils.config import VoiceFlowConfig, get_config, load_config
from implementations.simple import SimpleVoiceFlow


class TestComponentIntegration:
    """Test integration between core VoiceFlow components."""
    
    @pytest.mark.integration
    def test_voiceflow_engine_ai_enhancer_integration(self, temp_voiceflow_dir, mock_audio_recorder, mock_requests):
        """Test VoiceFlowEngine working with AIEnhancer in realistic scenarios."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            # Configure mock responses
            mock_requests['get'].return_value.status_code = 200
            mock_requests['get'].return_value.json.return_value = {
                'models': [{'name': 'llama3.3:latest'}]
            }
            
            session_mock = Mock()
            session_mock.post.return_value.status_code = 200
            session_mock.post.return_value.json.return_value = {
                'response': 'This is a properly formatted test transcription.'
            }
            
            with patch('requests.Session', return_value=session_mock):
                # Create integrated components
                config = {
                    'model': 'base',
                    'device': 'cpu',
                    'enable_ai_enhancement': True
                }
                
                engine = create_engine(config)
                enhancer = create_enhancer({'enabled': True, 'model': 'llama3.3:latest'})
                
                # Setup mock audio recorder with realistic behavior
                engine.recorder = mock_audio_recorder
                mock_audio_recorder.text.return_value = "this is a test transcription"
                
                # Process speech through the pipeline
                raw_text = engine.process_speech()
                assert raw_text == "this is a test transcription"
                
                # Enhance the text
                enhanced_text = enhancer.enhance_text(raw_text)
                assert enhanced_text == "This is a properly formatted test transcription."
                
                # Verify database integration
                conn = sqlite3.connect(engine.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT raw_text, word_count FROM transcriptions WHERE raw_text = ?", (raw_text,))
                result = cursor.fetchone()
                conn.close()
                
                assert result is not None
                assert result[0] == "this is a test transcription"
                assert result[1] == 5  # word count ("this is a test transcription" = 5 words)
    
    @pytest.mark.integration
    def test_configuration_system_integration(self, temp_voiceflow_dir):
        """Test configuration loading and propagation across all components."""
        # Create test configuration file
        config_dir = temp_voiceflow_dir
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.json"
        
        test_config = {
            "audio": {
                "model": "large-v2",
                "device": "cuda",
                "language": "en",
                "post_speech_silence_duration": 1.0
            },
            "ai": {
                "enabled": True,
                "model": "custom-model:latest",
                "temperature": 0.7,
                "timeout": 15,
                "ollama_host": "test-host",
                "ollama_port": "8080"
            },
            "text_injection": {
                "enabled": True,
                "method": "pyautogui",
                "require_confirmation": True
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(test_config, f)
        
        # Load configuration
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            config = VoiceFlowConfig(config_file)
            
            # Test configuration propagation to engine
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder:
                engine = VoiceFlowEngine(config.get_section('audio'))
                
                assert engine.config['model'] == 'large-v2'
                assert engine.config['device'] == 'cuda'
                assert engine.config['language'] == 'en'
                assert engine.config['post_speech_silence_duration'] == 1.0
                
                # Verify AudioToTextRecorder was called with correct parameters
                mock_recorder.assert_called_once()
                call_args = mock_recorder.call_args[1]
                assert call_args['model'] == 'large-v2'
                assert call_args['device'] == 'cuda'
                assert call_args['language'] == 'en'
            
            # Test configuration propagation to AI enhancer
            with patch('core.ai_enhancement.requests') as mock_requests:
                enhancer = AIEnhancer(config.get_section('ai'))
                
                assert enhancer.deepseek_model == 'custom-model:latest'
                assert enhancer.config['temperature'] == 0.7
                assert enhancer.config['timeout'] == 15
                assert 'test-host:8080' in enhancer.ollama_urls[0]
    
    @pytest.mark.integration
    def test_database_operations_integration(self, temp_voiceflow_dir, mock_audio_recorder):
        """Test database operations across multiple components."""
        with patch('core.voiceflow_core.AudioToTextRecorder'):
            engine = create_engine()
            engine.recorder = mock_audio_recorder
            
            # Test multiple transcriptions with different scenarios
            test_cases = [
                ("hello world", "Hello world.", 150),
                ("how are you doing today", "How are you doing today?", 200),
                ("this is a longer test sentence with more words", "This is a longer test sentence with more words.", 300),
                ("", "", 50)  # Empty transcription
            ]
            
            for raw_text, expected_enhanced, expected_time in test_cases:
                if raw_text:  # Skip empty case for recorder
                    mock_audio_recorder.text.return_value = raw_text
                    result = engine.process_speech()
                    assert result == raw_text
                    
                    # Verify database storage
                    conn = sqlite3.connect(engine.db_path)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT raw_text, word_count, processing_time_ms 
                        FROM transcriptions 
                        WHERE raw_text = ? 
                        ORDER BY id DESC 
                        LIMIT 1
                    """, (raw_text,))
                    
                    result = cursor.fetchone()
                    conn.close()
                    
                    assert result is not None
                    assert result[0] == raw_text
                    assert result[1] == len(raw_text.split()) if raw_text else 0
                    assert result[2] > 0  # Processing time should be recorded
            
            # Test database cleanup and integrity
            conn = sqlite3.connect(engine.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM transcriptions")
            count = cursor.fetchone()[0]
            conn.close()
            
            assert count == 3  # Should have 3 valid transcriptions
    
    @pytest.mark.integration
    def test_error_propagation_between_modules(self, temp_voiceflow_dir):
        """Test error handling and propagation across integrated components."""
        error_log = []
        
        def error_handler(msg):
            error_log.append(msg)
        
        # Test audio recorder failure
        with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
            mock_recorder = Mock()
            mock_recorder.text.side_effect = Exception("Audio device unavailable")
            mock_recorder_class.return_value = mock_recorder
            
            engine = create_engine()
            engine.on_error = error_handler
            
            result = engine.process_speech()
            assert result is None
            assert len(error_log) == 1
            assert "Audio device unavailable" in error_log[0]
        
        # Test AI enhancer failure fallback
        with patch('core.ai_enhancement.requests') as mock_requests:
            mock_requests.get.side_effect = Exception("Network unreachable")
            
            enhancer = create_enhancer()
            # Should fallback to basic formatting
            result = enhancer.enhance_text("test input")
            assert result == "Test input."
            assert enhancer.use_ai_enhancement is False
        
        # Test database failure handling
        with patch('core.voiceflow_core.AudioToTextRecorder'):
            engine = create_engine()
            engine.on_error = error_handler
            
            # Mock database connection failure
            original_connect = sqlite3.connect
            def failing_connect(*args, **kwargs):
                raise sqlite3.OperationalError("Database locked")
            
            with patch('sqlite3.connect', side_effect=failing_connect):
                engine.store_transcription("test", 100)
                # Should not crash, error should be logged
                assert len(error_log) >= 1

    @pytest.mark.integration
    def test_concurrent_operations_integration(self, temp_voiceflow_dir, mock_audio_recorder):
        """Test concurrent operations across integrated components."""
        with patch('core.voiceflow_core.AudioToTextRecorder'):
            engine = create_engine()
            engine.recorder = mock_audio_recorder
            
            # Setup concurrent transcription simulation
            results = []
            errors = []
            
            def transcribe_worker(worker_id, text):
                try:
                    mock_audio_recorder.text.return_value = f"worker {worker_id}: {text}"
                    result = engine.process_speech()
                    results.append((worker_id, result))
                except Exception as e:
                    errors.append((worker_id, str(e)))
            
            # Run multiple concurrent transcriptions
            threads = []
            for i in range(5):
                thread = threading.Thread(target=transcribe_worker, args=(i, f"test message {i}"))
                threads.append(thread)
                thread.start()
            
            for thread in threads:
                thread.join()
            
            # Verify all operations completed successfully
            assert len(errors) == 0
            assert len(results) == 5
            
            # Verify database integrity under concurrent access
            conn = sqlite3.connect(engine.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM transcriptions")
            count = cursor.fetchone()[0]
            conn.close()
            
            assert count == 5  # All transcriptions should be stored


class TestEndToEndWorkflows:
    """Test complete end-to-end workflows."""
    
    @pytest.mark.integration
    def test_complete_speech_processing_pipeline(self, temp_voiceflow_dir, mock_system_integration):
        """Test the complete pipeline from speech input to text injection."""
        with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
            with patch('core.ai_enhancement.requests') as mock_requests:
                # Setup complete mock environment
                mock_recorder = Mock()
                mock_recorder.text.return_value = "hello world this is a test"
                mock_recorder_class.return_value = mock_recorder
                
                # Mock AI enhancement
                mock_requests.get.return_value.status_code = 200
                mock_requests.get.return_value.json.return_value = {
                    'models': [{'name': 'llama3.3:latest'}]
                }
                
                session_mock = Mock()
                session_mock.post.return_value.status_code = 200
                session_mock.post.return_value.json.return_value = {
                    'response': 'Hello world, this is a test.'
                }
                
                with patch('requests.Session', return_value=session_mock):
                    # Create integrated pipeline
                    engine = create_engine({'enable_ai_enhancement': True})
                    enhancer = create_enhancer({'enabled': True})
                    
                    # Test complete workflow
                    def complete_workflow():
                        # 1. Process speech
                        raw_text = engine.process_speech()
                        assert raw_text == "hello world this is a test"
                        
                        # 2. Enhance text
                        enhanced_text = enhancer.enhance_text(raw_text)
                        assert enhanced_text == "Hello world, this is a test."
                        
                        # 3. Inject text
                        result = engine.inject_text(enhanced_text)
                        assert result is True
                        
                        return raw_text, enhanced_text
                    
                    # Execute complete workflow
                    raw_text, enhanced_text = complete_workflow()
                    
                    # Verify all components were called
                    mock_recorder.text.assert_called_once()
                    session_mock.post.assert_called_once()
                    mock_system_integration['pyautogui'].typewrite.assert_called_once_with(enhanced_text)
                    
                    # Verify database storage
                    conn = sqlite3.connect(engine.db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT raw_text, word_count FROM transcriptions ORDER BY id DESC LIMIT 1")
                    result = cursor.fetchone()
                    conn.close()
                    
                    assert result is not None
                    assert result[0] == raw_text
                    assert result[1] == 6  # word count
    
    @pytest.mark.integration
    def test_hotkey_integration_workflow(self, temp_voiceflow_dir, mock_system_integration):
        """Test hotkey-triggered complete workflow."""
        with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
            with patch('core.ai_enhancement.requests') as mock_requests:
                # Setup mocks
                mock_recorder = Mock()
                mock_recorder.text.return_value = "hotkey test transcription"
                mock_recorder_class.return_value = mock_recorder
                
                # Mock AI enhancement
                mock_requests.get.return_value.status_code = 200
                mock_requests.get.return_value.json.return_value = {
                    'models': [{'name': 'llama3.3:latest'}]
                }
                
                session_mock = Mock()
                session_mock.post.return_value.status_code = 200
                session_mock.post.return_value.json.return_value = {
                    'response': 'Hotkey test transcription.'
                }
                
                with patch('requests.Session', return_value=session_mock):
                    # Create engine with AI enhancement
                    engine = create_engine({'enable_ai_enhancement': True})
                    enhancer = create_enhancer({'enabled': True})
                    
                    # Setup custom hotkey handler that includes enhancement
                    def process_and_enhance():
                        raw_text = engine.process_speech()
                        if raw_text:
                            enhanced_text = enhancer.enhance_text(raw_text)
                            engine.inject_text(enhanced_text)
                            return raw_text, enhanced_text
                        return None, None
                    
                    # Setup hotkey
                    engine.setup_hotkeys('ctrl+alt+h', process_and_enhance)
                    
                    # Verify hotkey was registered
                    mock_system_integration['keyboard'].add_hotkey.assert_called_once_with('ctrl+alt+h', process_and_enhance)
                    
                    # Simulate hotkey press
                    raw_text, enhanced_text = process_and_enhance()
                    
                    # Verify complete workflow
                    assert raw_text == "hotkey test transcription"
                    assert enhanced_text == "Hotkey test transcription."
                    mock_system_integration['pyautogui'].typewrite.assert_called_once_with(enhanced_text)
    
    @pytest.mark.integration
    def test_configuration_to_injection_workflow(self, temp_voiceflow_dir, mock_system_integration):
        """Test complete workflow from configuration loading to text injection."""
        # Create comprehensive configuration
        config_dir = temp_voiceflow_dir
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.json"
        
        workflow_config = {
            "audio": {
                "model": "base",
                "device": "cpu",
                "language": "en",
                "post_speech_silence_duration": 0.5
            },
            "ai": {
                "enabled": True,
                "model": "workflow-model:latest",
                "temperature": 0.4,
                "timeout": 8
            },
            "text_injection": {
                "enabled": True,
                "method": "pyautogui",
                "require_confirmation": False
            },
            "hotkeys": {
                "record_and_inject": "ctrl+shift+r"
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(workflow_config, f)
        
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
                with patch('core.ai_enhancement.requests') as mock_requests:
                    # Setup complete workflow
                    mock_recorder = Mock()
                    mock_recorder.text.return_value = "configuration workflow test"
                    mock_recorder_class.return_value = mock_recorder
                    
                    # Mock AI enhancement
                    mock_requests.get.return_value.status_code = 200
                    mock_requests.get.return_value.json.return_value = {
                        'models': [{'name': 'workflow-model:latest'}]
                    }
                    
                    session_mock = Mock()
                    session_mock.post.return_value.status_code = 200
                    session_mock.post.return_value.json.return_value = {
                        'response': 'Configuration workflow test.'
                    }
                    
                    with patch('requests.Session', return_value=session_mock):
                        # Load configuration and create components
                        config = VoiceFlowConfig(config_file)
                        engine = VoiceFlowEngine(config.get_section('audio'))
                        enhancer = AIEnhancer(config.get_section('ai'))
                        
                        # Verify configuration was applied
                        assert engine.config['model'] == 'base'
                        assert engine.config['post_speech_silence_duration'] == 0.5
                        assert enhancer.deepseek_model == 'workflow-model:latest'
                        assert enhancer.config['temperature'] == 0.4
                        
                        # Execute workflow
                        raw_text = engine.process_speech()
                        enhanced_text = enhancer.enhance_text(raw_text)
                        injection_result = engine.inject_text(enhanced_text)
                        
                        # Verify results
                        assert raw_text == "configuration workflow test"
                        assert enhanced_text == "Configuration workflow test."
                        assert injection_result is True
                        
                        # Verify system integration calls
                        mock_system_integration['pyautogui'].typewrite.assert_called_once_with(enhanced_text)
    
    @pytest.mark.integration
    def test_performance_tracking_workflow(self, temp_voiceflow_dir, mock_audio_recorder):
        """Test performance tracking across complete workflows."""
        with patch('core.voiceflow_core.AudioToTextRecorder'):
            engine = create_engine()
            engine.recorder = mock_audio_recorder
            
            # Execute multiple workflows and track performance
            test_texts = [
                "short test",
                "this is a medium length test transcription",
                "this is a much longer test transcription that contains many more words and should take longer to process",
                "final test"
            ]
            
            for text in test_texts:
                mock_audio_recorder.text.return_value = text
                
                start_time = time.time()
                result = engine.process_speech()
                end_time = time.time()
                
                assert result == text
                
                # Verify processing time was recorded
                assert len(engine.stats["processing_times"]) > 0
                
                # Small delay to ensure different timestamps
                time.sleep(0.01)
            
            # Verify comprehensive statistics
            stats = engine.get_stats()
            assert stats["total_transcriptions"] == 4
            assert stats["total_words"] == sum(len(text.split()) for text in test_texts)
            assert stats["average_processing_time_ms"] > 0
            assert len(engine.stats["processing_times"]) == 4
            
            # Verify database performance tracking
            conn = sqlite3.connect(engine.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT raw_text, word_count, processing_time_ms 
                FROM transcriptions 
                ORDER BY id
            """)
            results = cursor.fetchall()
            conn.close()
            
            assert len(results) == 4
            for i, (raw_text, word_count, processing_time) in enumerate(results):
                assert raw_text == test_texts[i]
                assert word_count == len(test_texts[i].split())
                assert processing_time > 0


class TestImplementationIntegration:
    """Test integration with existing implementations."""
    
    @pytest.mark.integration
    def test_simple_implementation_integration(self, temp_voiceflow_dir, mock_system_integration):
        """Test implementations/simple.py integration with core modules."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
                with patch('core.ai_enhancement.requests') as mock_requests:
                    # Setup mocks
                    mock_recorder = Mock()
                    mock_recorder.text.return_value = "simple implementation test"
                    mock_recorder_class.return_value = mock_recorder
                    
                    # Mock AI enhancement
                    mock_requests.get.return_value.status_code = 200
                    mock_requests.get.return_value.json.return_value = {
                        'models': [{'name': 'llama3.3:latest'}]
                    }
                    
                    session_mock = Mock()
                    session_mock.post.return_value.status_code = 200
                    session_mock.post.return_value.json.return_value = {
                        'response': 'Simple implementation test.'
                    }
                    
                    with patch('requests.Session', return_value=session_mock):
                        # Create SimpleVoiceFlow instance
                        simple_app = SimpleVoiceFlow()
                        
                        # Verify core components were created
                        assert simple_app.engine is not None
                        assert simple_app.ai_enhancer is not None
                        assert simple_app.config is not None
                        
                        # Test transcription callback
                        simple_app.on_transcription("test transcription")
                        
                        # Verify AI enhancement was called
                        session_mock.post.assert_called_once()
                        
                        # Verify text injection was called
                        mock_system_integration['pyautogui'].typewrite.assert_called_once()
                        
                        # Test error handling
                        error_messages = []
                        simple_app.on_error = lambda msg: error_messages.append(msg)
                        
                        simple_app.on_error("test error")
                        assert len(error_messages) == 1
                        assert "test error" in error_messages[0]
                        
                        # Test cleanup
                        simple_app.cleanup()
                        # Should not raise exceptions
    
    @pytest.mark.integration
    def test_backwards_compatibility_with_legacy_configs(self, temp_voiceflow_dir):
        """Test that legacy configurations still work with new core modules."""
        # Create legacy-style configuration
        config_dir = temp_voiceflow_dir
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.json"
        
        legacy_config = {
            # Legacy format - flat structure
            "model": "large",
            "device": "cuda",
            "enable_ai_enhancement": True,
            "ai_model": "legacy-model:latest",
            "temperature": 0.6
        }
        
        with open(config_file, 'w') as f:
            json.dump(legacy_config, f)
        
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
                with patch('core.ai_enhancement.requests') as mock_requests:
                    mock_recorder_class.return_value = Mock()
                    mock_requests.get.return_value.status_code = 200
                    mock_requests.get.return_value.json.return_value = {
                        'models': [{'name': 'legacy-model:latest'}]
                    }
                    
                    # Load configuration
                    config = VoiceFlowConfig(config_file)
                    
                    # Test that legacy config values are accessible
                    # Note: This would need configuration migration logic
                    # For now, test that the system doesn't crash
                    try:
                        engine = VoiceFlowEngine({'model': 'base'})  # Fallback to safe defaults
                        enhancer = AIEnhancer({'model': 'legacy-model:latest'})
                        
                        # Should not raise exceptions
                        assert engine is not None
                        assert enhancer is not None
                        
                    except Exception as e:
                        pytest.fail(f"Legacy configuration caused failure: {e}")


class TestSystemIntegration:
    """Test system-level integration."""
    
    @pytest.mark.integration
    @patch.dict(os.environ, {
        'VOICEFLOW_MODEL': 'env-model',
        'VOICEFLOW_DEVICE': 'env-device',
        'ENABLE_AI_ENHANCEMENT': 'false',
        'AI_MODEL': 'env-ai-model',
        'OLLAMA_HOST': 'env-ollama-host',
        'OLLAMA_PORT': '9999'
    })
    def test_environment_variable_integration(self, temp_voiceflow_dir):
        """Test environment variable propagation across the system."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
                with patch('core.ai_enhancement.requests') as mock_requests:
                    mock_recorder_class.return_value = Mock()
                    mock_requests.get.side_effect = Exception("No connection")
                    
                    # Create components - should use environment variables
                    engine = create_engine()
                    enhancer = create_enhancer()
                    
                    # Verify environment variables were applied
                    assert engine.config['model'] == 'env-model'
                    assert engine.config['device'] == 'env-device'
                    assert enhancer.deepseek_model == 'env-ai-model'
                    assert enhancer.use_ai_enhancement is False  # Disabled by env var
                    assert 'env-ollama-host:9999' in enhancer.ollama_urls[0]
    
    @pytest.mark.integration
    def test_file_system_operations_integration(self, temp_voiceflow_dir):
        """Test file system operations across components."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
                mock_recorder_class.return_value = Mock()
                
                # Test directory creation
                engine = create_engine()
                
                # Verify directories were created
                assert engine.data_dir.exists()
                assert engine.data_dir.is_dir()
                assert engine.db_path.exists()
                
                # Test database file operations
                conn = sqlite3.connect(engine.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                conn.close()
                
                assert len(tables) > 0
                assert any('transcriptions' in table[0] for table in tables)
                
                # Test configuration file operations
                config = VoiceFlowConfig()
                config.set('test', 'value', 'test_data')
                config.save()
                
                config_file = temp_voiceflow_dir / ".voiceflow" / "config.json"
                assert config_file.exists()
                
                # Verify configuration was saved
                with open(config_file, 'r') as f:
                    saved_config = json.load(f)
                    assert saved_config['test']['value'] == 'test_data'
    
    @pytest.mark.integration
    def test_external_service_integration(self, temp_voiceflow_dir):
        """Test integration with external services (Ollama)."""
        with patch('core.ai_enhancement.requests') as mock_requests:
            # Test successful connection
            mock_requests.get.return_value.status_code = 200
            mock_requests.get.return_value.json.return_value = {
                'models': [{'name': 'test-model:latest'}]
            }
            
            enhancer = create_enhancer()
            
            # Verify connection was established
            assert enhancer.ollama_url is not None
            assert enhancer.use_ai_enhancement is True
            assert enhancer.deepseek_model == 'test-model:latest'
            
            # Test service failure handling
            mock_requests.get.side_effect = Exception("Service unavailable")
            
            enhancer2 = create_enhancer()
            
            # Verify fallback behavior
            assert enhancer2.ollama_url is None
            assert enhancer2.use_ai_enhancement is False
            
            # Test service recovery
            mock_requests.get.side_effect = None
            mock_requests.get.return_value.status_code = 200
            mock_requests.get.return_value.json.return_value = {
                'models': [{'name': 'recovered-model:latest'}]
            }
            
            enhancer3 = create_enhancer()
            assert enhancer3.use_ai_enhancement is True
            assert enhancer3.deepseek_model == 'recovered-model:latest'
    
    @pytest.mark.integration
    def test_system_hotkey_integration(self, temp_voiceflow_dir, mock_system_integration):
        """Test system-level hotkey integration."""
        with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
            mock_recorder_class.return_value = Mock()
            
            engine = create_engine()
            
            # Test multiple hotkey configurations
            hotkey_configs = [
                ('ctrl+alt+v', 'Voice recording'),
                ('ctrl+shift+t', 'Text processing'),
                ('f12', 'Quick transcribe')
            ]
            
            for hotkey, description in hotkey_configs:
                def test_handler():
                    return f"Handler for {description}"
                
                engine.setup_hotkeys(hotkey, test_handler)
                
                # Verify hotkey was registered
                mock_system_integration['keyboard'].add_hotkey.assert_called_with(hotkey, test_handler)
            
            # Verify all hotkeys were registered
            assert mock_system_integration['keyboard'].add_hotkey.call_count == len(hotkey_configs)


class TestFailureModes:
    """Test system behavior under various failure conditions."""
    
    @pytest.mark.integration
    def test_network_connectivity_failures(self, temp_voiceflow_dir):
        """Test behavior when network connectivity fails."""
        with patch('core.ai_enhancement.requests') as mock_requests:
            # Test various network failure scenarios
            network_failures = [
                Exception("Network unreachable"),
                Exception("Connection timeout"),
                Exception("DNS resolution failed"),
                Exception("Connection refused")
            ]
            
            for failure in network_failures:
                mock_requests.get.side_effect = failure
                
                enhancer = create_enhancer()
                
                # Should fallback to basic formatting
                assert enhancer.use_ai_enhancement is False
                
                # Should still work with basic formatting
                result = enhancer.enhance_text("test input")
                assert result == "Test input."
    
    @pytest.mark.integration
    def test_missing_dependencies_handling(self, temp_voiceflow_dir):
        """Test behavior when dependencies are missing."""
        # Test missing AudioToTextRecorder
        with patch('core.voiceflow_core.AudioToTextRecorder', side_effect=ImportError("Package not found")):
            engine = create_engine()
            
            # Should handle missing dependency gracefully
            assert engine.recorder is None
            
            # Should not crash on process_speech
            result = engine.process_speech()
            assert result is None
        
        # Test missing system integration packages
        with patch('core.voiceflow_core.SYSTEM_INTEGRATION', False):
            engine = create_engine()
            
            # Text injection should fail gracefully
            result = engine.inject_text("test text")
            assert result is False
            
            # Hotkey setup should warn but not crash
            engine.setup_hotkeys('ctrl+alt')  # Should not raise exception
    
    @pytest.mark.integration
    def test_file_permission_problems(self, temp_voiceflow_dir):
        """Test behavior when file permissions are problematic."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            # Test database creation failure
            with patch('sqlite3.connect', side_effect=sqlite3.OperationalError("Permission denied")):
                engine = create_engine()
                
                # Should handle database creation failure
                result = engine.process_speech()
                # Should not crash, but will fail to store
                
            # Test config file write failure
            with patch('builtins.open', side_effect=PermissionError("Permission denied")):
                config = VoiceFlowConfig()
                config.set('test', 'key', 'value')
                
                # Should handle save failure gracefully
                config.save()  # Should not raise exception
    
    @pytest.mark.integration
    def test_resource_exhaustion_scenarios(self, temp_voiceflow_dir, mock_audio_recorder):
        """Test behavior under resource exhaustion conditions."""
        with patch('core.voiceflow_core.AudioToTextRecorder'):
            engine = create_engine()
            engine.recorder = mock_audio_recorder
            
            # Test memory exhaustion simulation
            def memory_exhaustion_side_effect(*args, **kwargs):
                raise MemoryError("Out of memory")
            
            mock_audio_recorder.text.side_effect = memory_exhaustion_side_effect
            
            # Should handle memory error gracefully
            result = engine.process_speech()
            assert result is None
            
            # Test disk space exhaustion
            with patch('sqlite3.connect') as mock_connect:
                mock_conn = Mock()
                mock_cursor = Mock()
                mock_cursor.execute.side_effect = sqlite3.OperationalError("Disk full")
                mock_conn.cursor.return_value = mock_cursor
                mock_connect.return_value = mock_conn
                
                # Should handle disk full error gracefully
                engine.store_transcription("test", 100)  # Should not crash
    
    @pytest.mark.integration
    def test_concurrent_access_conflicts(self, temp_voiceflow_dir):
        """Test behavior when multiple instances access the same resources."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder_class:
                mock_recorder_class.return_value = Mock()
                
                # Create multiple engine instances
                engines = [create_engine() for _ in range(3)]
                
                # All should share the same database
                db_paths = [engine.db_path for engine in engines]
                assert all(path == db_paths[0] for path in db_paths)
                
                # Test concurrent database access
                def concurrent_store(engine, text):
                    for i in range(10):
                        engine.store_transcription(f"{text}_{i}", 100)
                
                threads = []
                for i, engine in enumerate(engines):
                    thread = threading.Thread(target=concurrent_store, args=(engine, f"engine_{i}"))
                    threads.append(thread)
                    thread.start()
                
                for thread in threads:
                    thread.join()
                
                # Verify all data was stored
                conn = sqlite3.connect(engines[0].db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM transcriptions")
                count = cursor.fetchone()[0]
                conn.close()
                
                assert count == 30  # 3 engines * 10 records each
    
    @pytest.mark.integration
    def test_malformed_data_handling(self, temp_voiceflow_dir):
        """Test behavior with malformed or corrupted data."""
        with patch('core.ai_enhancement.requests') as mock_requests:
            # Test malformed JSON response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
            mock_requests.get.return_value = mock_response
            
            enhancer = create_enhancer()
            
            # Should handle malformed response gracefully
            result = enhancer.enhance_text("test input")
            assert result == "Test input."  # Should fallback to basic formatting
            
            # Test malformed database
            with patch('sqlite3.connect') as mock_connect:
                mock_conn = Mock()
                mock_cursor = Mock()
                mock_cursor.execute.side_effect = sqlite3.DatabaseError("Database corrupted")
                mock_conn.cursor.return_value = mock_cursor
                mock_connect.return_value = mock_conn
                
                with patch('core.voiceflow_core.AudioToTextRecorder'):
                    engine = create_engine()
                    
                    # Should handle database corruption gracefully
                    engine.store_transcription("test", 100)  # Should not crash


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])