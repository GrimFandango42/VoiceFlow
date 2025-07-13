"""
Unit tests for Configuration Management

Tests the configuration handling functionality including:
- Configuration loading from files and environment
- Default value handling and overrides
- Section-based configuration access
- Configuration validation and error handling
"""

import pytest
import os
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, mock_open, Mock

# Import the module to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.config import (
    VoiceFlowConfig, get_config, load_config,
    get_audio_config, get_ai_config, get_security_config
)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


class TestVoiceFlowConfig:
    """Test suite for VoiceFlowConfig class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    @pytest.fixture
    def config_with_temp_dir(self, temp_dir):
        """Create config instance with temporary directory."""
        with patch('utils.config.Path.home', return_value=Path(temp_dir)):
            config = VoiceFlowConfig()
            yield config
    
    @pytest.fixture
    def sample_config_file(self, temp_dir):
        """Create a sample config file."""
        config_dir = Path(temp_dir) / ".voiceflow"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.json"
        
        sample_config = {
            "audio": {
                "model": "large",
                "device": "cuda"
            },
            "ai": {
                "enabled": False,
                "model": "custom:latest"
            },
            "custom_section": {
                "custom_key": "custom_value"
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(sample_config, f)
        
        return config_file
    
    def test_initialization_creates_directory(self, temp_dir):
        """Test that initialization creates config directory."""
        with patch('utils.config.Path.home', return_value=Path(temp_dir)):
            config = VoiceFlowConfig()
            assert (Path(temp_dir) / ".voiceflow").exists()
    
    def test_default_configuration(self, config_with_temp_dir):
        """Test default configuration values."""
        config = config_with_temp_dir
        
        # Audio defaults
        assert config.get('audio', 'model') == 'base'
        assert config.get('audio', 'device') == 'auto'
        assert config.get('audio', 'language') == 'en'
        assert config.get('audio', 'post_speech_silence_duration') == 1.3
        assert config.get('audio', 'silero_sensitivity') == 0.3
        
        # AI defaults
        assert config.get('ai', 'enabled') is True
        assert config.get('ai', 'model') == 'llama3.3:latest'
        assert config.get('ai', 'temperature') == 0.3
        assert config.get('ai', 'timeout') == 10
        assert config.get('ai', 'ollama_host') == 'localhost'
        assert config.get('ai', 'ollama_port') == '11434'
        
        # Text injection defaults
        assert config.get('text_injection', 'enabled') is True
        assert config.get('text_injection', 'method') == 'pyautogui'
        assert config.get('text_injection', 'require_confirmation') is False
        
        # Hotkeys defaults
        assert config.get('hotkeys', 'record_and_inject') == 'ctrl+alt'
        assert config.get('hotkeys', 'stop_recording') == 'esc'
        
        # Database defaults
        assert config.get('database', 'encrypt') is False
        assert config.get('database', 'retention_days') == 30
        
        # Security defaults
        assert config.get('security', 'log_transcriptions') is False
        assert config.get('security', 'max_audio_duration') == 30
        assert config.get('security', 'max_audio_file_size') == 10485760
        
        # Performance defaults
        assert config.get('performance', 'use_gpu') is True
        assert config.get('performance', 'max_concurrent_requests') == 5
    
    def test_load_config_file(self, temp_dir, sample_config_file):
        """Test loading configuration from file."""
        with patch('utils.config.Path.home', return_value=Path(temp_dir)):
            config = VoiceFlowConfig()
            
            # Should have loaded file config
            assert config.get('audio', 'model') == 'large'
            assert config.get('audio', 'device') == 'cuda'
            assert config.get('ai', 'enabled') is False
            assert config.get('ai', 'model') == 'custom:latest'
            assert config.get('custom_section', 'custom_key') == 'custom_value'
            
            # Other defaults should remain
            assert config.get('audio', 'language') == 'en'
            assert config.get('text_injection', 'enabled') is True
    
    def test_load_config_file_error(self, temp_dir):
        """Test handling of config file load errors."""
        config_dir = Path(temp_dir) / ".voiceflow"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.json"
        
        # Write invalid JSON
        with open(config_file, 'w') as f:
            f.write("{ invalid json")
        
        with patch('utils.config.Path.home', return_value=Path(temp_dir)):
            # Should not raise, just use defaults
            config = VoiceFlowConfig()
            assert config.get('audio', 'model') == 'base'
    
    def test_custom_config_path(self, temp_dir):
        """Test using custom config file path."""
        custom_path = Path(temp_dir) / "custom_config.json"
        custom_config = {"audio": {"model": "tiny"}}
        
        with open(custom_path, 'w') as f:
            json.dump(custom_config, f)
        
        with patch('utils.config.Path.home', return_value=Path(temp_dir)):
            config = VoiceFlowConfig(custom_path)
            assert config.get('audio', 'model') == 'tiny'
    
    @patch.dict(os.environ, {
        'VOICEFLOW_MODEL': 'whisper-large',
        'VOICEFLOW_DEVICE': 'mps',
        'VOICEFLOW_LANGUAGE': 'es',
        'ENABLE_AI_ENHANCEMENT': 'false',
        'AI_MODEL': 'llama2:latest',
        'AI_TEMPERATURE': '0.7',
        'AI_TIMEOUT': '30',
        'OLLAMA_HOST': 'remote-host',
        'OLLAMA_PORT': '8080',
        'OLLAMA_USE_HTTPS': 'true',
        'ENABLE_TEXT_INJECTION': 'false',
        'REQUIRE_USER_CONFIRMATION': 'true',
        'ENABLE_FAILSAFE': 'false',
        'ENABLE_DEBUG_LOGGING': 'true',
        'MAX_AUDIO_DURATION': '60',
        'MAX_AUDIO_FILE_SIZE': '20971520',
        'USE_GPU': 'false'
    })
    def test_environment_variables(self, temp_dir):
        """Test loading configuration from environment variables."""
        with patch('utils.config.Path.home', return_value=Path(temp_dir)):
            config = VoiceFlowConfig()
            
            # Audio from env
            assert config.get('audio', 'model') == 'whisper-large'
            assert config.get('audio', 'device') == 'mps'
            assert config.get('audio', 'language') == 'es'
            
            # AI from env
            assert config.get('ai', 'enabled') is False
            assert config.get('ai', 'model') == 'llama2:latest'
            assert config.get('ai', 'temperature') == 0.7
            assert config.get('ai', 'timeout') == 30
            assert config.get('ai', 'ollama_host') == 'remote-host'
            assert config.get('ai', 'ollama_port') == '8080'
            assert config.get('ai', 'ollama_use_https') is True
            
            # Text injection from env
            assert config.get('text_injection', 'enabled') is False
            assert config.get('text_injection', 'require_confirmation') is True
            assert config.get('text_injection', 'enable_failsafe') is False
            
            # Security from env
            assert config.get('security', 'enable_debug_logging') is True
            assert config.get('security', 'max_audio_duration') == 60
            assert config.get('security', 'max_audio_file_size') == 20971520
            
            # Performance from env
            assert config.get('performance', 'use_gpu') is False
    
    @patch.dict(os.environ, {
        'ENABLE_AI_ENHANCEMENT': 'invalid',
        'AI_TEMPERATURE': 'not_a_float',
        'AI_TIMEOUT': 'not_an_int'
    })
    def test_environment_variables_invalid_values(self, temp_dir):
        """Test handling of invalid environment variable values."""
        with patch('utils.config.Path.home', return_value=Path(temp_dir)):
            config = VoiceFlowConfig()
            
            # Should use defaults for invalid values
            assert config.get('ai', 'enabled') is False  # 'invalid' -> False
            assert config.get('ai', 'temperature') == 0.3  # Default
            assert config.get('ai', 'timeout') == 10  # Default
    
    def test_priority_order(self, temp_dir, sample_config_file):
        """Test configuration priority: env vars > file > defaults."""
        with patch('utils.config.Path.home', return_value=Path(temp_dir)):
            with patch.dict(os.environ, {'VOICEFLOW_MODEL': 'env-model'}):
                config = VoiceFlowConfig()
                
                # Env var should override file
                assert config.get('audio', 'model') == 'env-model'
                # File should override default
                assert config.get('audio', 'device') == 'cuda'
                # Default should be used when not in file or env
                assert config.get('audio', 'language') == 'en'
    
    def test_get_method(self, config_with_temp_dir):
        """Test get method with various inputs."""
        config = config_with_temp_dir
        
        # Normal get
        assert config.get('audio', 'model') == 'base'
        
        # With default
        assert config.get('audio', 'nonexistent', 'default_value') == 'default_value'
        
        # Nonexistent section
        assert config.get('nonexistent_section', 'key') is None
        assert config.get('nonexistent_section', 'key', 'default') == 'default'
    
    def test_set_method(self, config_with_temp_dir):
        """Test runtime configuration updates."""
        config = config_with_temp_dir
        
        # Set existing value
        config.set('audio', 'model', 'updated-model')
        assert config.get('audio', 'model') == 'updated-model'
        
        # Set new key in existing section
        config.set('audio', 'new_key', 'new_value')
        assert config.get('audio', 'new_key') == 'new_value'
        
        # Set in new section
        config.set('new_section', 'key', 'value')
        assert config.get('new_section', 'key') == 'value'
    
    def test_get_section(self, config_with_temp_dir):
        """Test getting entire configuration sections."""
        config = config_with_temp_dir
        
        audio_config = config.get_section('audio')
        assert isinstance(audio_config, dict)
        assert audio_config['model'] == 'base'
        assert audio_config['device'] == 'auto'
        assert 'language' in audio_config
        
        # Nonexistent section
        empty_section = config.get_section('nonexistent')
        assert empty_section == {}
        
        # Verify it's a copy
        audio_config['model'] = 'modified'
        assert config.get('audio', 'model') == 'base'
    
    def test_save_configuration(self, config_with_temp_dir):
        """Test saving configuration to file."""
        config = config_with_temp_dir
        
        # Modify config
        config.set('audio', 'model', 'saved-model')
        config.set('new_section', 'key', 'value')
        
        # Save
        config.save()
        
        # Verify file was created and contains correct data
        assert config.config_file.exists()
        
        with open(config.config_file, 'r') as f:
            saved_data = json.load(f)
        
        assert saved_data['audio']['model'] == 'saved-model'
        assert saved_data['new_section']['key'] == 'value'
    
    def test_save_configuration_error(self, config_with_temp_dir):
        """Test handling of save errors."""
        config = config_with_temp_dir
        
        # Make directory read-only to cause save error
        with patch('builtins.open', side_effect=PermissionError("No write access")):
            # Should not raise, just print error
            config.save()
    
    def test_to_dict(self, config_with_temp_dir):
        """Test getting complete configuration as dictionary."""
        config = config_with_temp_dir
        
        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)
        assert 'audio' in config_dict
        assert 'ai' in config_dict
        assert 'text_injection' in config_dict
        
        # Verify it's a copy
        config_dict['audio']['model'] = 'modified'
        assert config.get('audio', 'model') == 'base'
    
    def test_create_example_config(self, config_with_temp_dir):
        """Test creating example configuration file."""
        config = config_with_temp_dir
        
        config.create_example_config()
        
        example_file = config.config_dir / "config.example.json"
        assert example_file.exists()
        
        with open(example_file, 'r') as f:
            example_data = json.load(f)
        
        assert example_data['audio']['model'] == 'base'
        assert 'ai' in example_data
        assert 'text_injection' in example_data
    
    def test_merge_config(self, config_with_temp_dir):
        """Test configuration merging logic."""
        config = config_with_temp_dir
        
        # Test merging with existing section
        new_config = {
            'audio': {
                'model': 'merged-model',
                'new_audio_key': 'audio_value'
            },
            'completely_new': {
                'key': 'value'
            }
        }
        
        config._merge_config(new_config)
        
        # Should update existing keys
        assert config.get('audio', 'model') == 'merged-model'
        # Should add new keys to existing section
        assert config.get('audio', 'new_audio_key') == 'audio_value'
        # Should preserve other keys
        assert config.get('audio', 'device') == 'auto'
        # Should add new sections
        assert config.get('completely_new', 'key') == 'value'


class TestGlobalConfigFunctions:
    """Test suite for global configuration functions."""
    
    @pytest.fixture(autouse=True)
    def reset_global_config(self):
        """Reset global config before each test."""
        import utils.config
        utils.config._global_config = None
        yield
        utils.config._global_config = None
    
    def test_get_config_singleton(self):
        """Test that get_config returns singleton instance."""
        config1 = get_config()
        config2 = get_config()
        
        assert config1 is config2
    
    def test_load_config(self, temp_dir):
        """Test load_config function."""
        custom_path = Path(temp_dir) / "custom.json"
        custom_data = {"audio": {"model": "custom"}}
        
        with open(custom_path, 'w') as f:
            json.dump(custom_data, f)
        
        with patch('utils.config.Path.home', return_value=Path(temp_dir)):
            config = load_config(custom_path)
            
            assert config.get('audio', 'model') == 'custom'
            
            # Should update global instance
            assert get_config() is config
    
    def test_get_audio_config(self):
        """Test get_audio_config helper function."""
        with patch('utils.config.VoiceFlowConfig') as mock_config_class:
            mock_instance = Mock()
            mock_instance.get_section.return_value = {'model': 'test', 'device': 'cpu'}
            mock_config_class.return_value = mock_instance
            
            audio_config = get_audio_config()
            
            assert audio_config == {'model': 'test', 'device': 'cpu'}
            mock_instance.get_section.assert_called_once_with('audio')
    
    def test_get_ai_config(self):
        """Test get_ai_config helper function."""
        with patch('utils.config.VoiceFlowConfig') as mock_config_class:
            mock_instance = Mock()
            mock_instance.get_section.return_value = {'enabled': True, 'model': 'llama'}
            mock_config_class.return_value = mock_instance
            
            ai_config = get_ai_config()
            
            assert ai_config == {'enabled': True, 'model': 'llama'}
            mock_instance.get_section.assert_called_once_with('ai')
    
    def test_get_security_config(self):
        """Test get_security_config helper function."""
        with patch('utils.config.VoiceFlowConfig') as mock_config_class:
            mock_instance = Mock()
            mock_instance.get_section.return_value = {'log_transcriptions': False}
            mock_config_class.return_value = mock_instance
            
            security_config = get_security_config()
            
            assert security_config == {'log_transcriptions': False}
            mock_instance.get_section.assert_called_once_with('security')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])