"""
Unit tests for AI Enhancement Module

Tests the consolidated AI enhancement functionality including:
- AIEnhancer initialization and configuration
- Ollama connection testing and model validation
- Text enhancement with different contexts
- Error handling and fallback to basic formatting
- Prompt generation and response cleaning
"""

import pytest
import os
import requests
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Import the module to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.ai_enhancement import AIEnhancer, create_enhancer


class TestAIEnhancer:
    """Test suite for AIEnhancer class."""
    
    @pytest.fixture
    def mock_requests(self):
        """Mock requests module."""
        with patch('core.ai_enhancement.requests') as mock:
            yield mock
    
    @pytest.fixture
    def enhancer_no_connection(self, mock_requests):
        """Create enhancer instance with no connection test."""
        mock_requests.get.side_effect = Exception("Connection failed")
        enhancer = AIEnhancer({'enabled': True})
        yield enhancer
    
    @pytest.fixture
    def enhancer_with_connection(self, mock_requests):
        """Create enhancer instance with successful connection."""
        # Mock successful connection test
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'models': [
                {'name': 'llama3.3:latest'},
                {'name': 'deepseek-coder:latest'},
                {'name': 'mistral:latest'}
            ]
        }
        mock_requests.get.return_value = mock_response
        
        enhancer = AIEnhancer({'enabled': True})
        yield enhancer
    
    def test_initialization_default(self, mock_requests):
        """Test enhancer initialization with default configuration."""
        mock_requests.get.side_effect = Exception("No connection")
        
        enhancer = AIEnhancer()
        
        assert enhancer.use_ai_enhancement is True
        assert enhancer.deepseek_model == 'llama3.3:latest'
        assert enhancer.ollama_url is None
        assert len(enhancer.ollama_urls) == 3
    
    def test_initialization_with_config(self, mock_requests):
        """Test enhancer initialization with custom configuration."""
        mock_requests.get.side_effect = Exception("No connection")
        
        config = {
            'enabled': False,
            'model': 'custom-model:latest',
            'temperature': 0.5,
            'timeout': 20
        }
        
        enhancer = AIEnhancer(config)
        
        assert enhancer.use_ai_enhancement is False
        assert enhancer.deepseek_model == 'custom-model:latest'
        assert enhancer.config['temperature'] == 0.5
        assert enhancer.config['timeout'] == 20
    
    @patch.dict(os.environ, {
        'OLLAMA_HOST': 'custom-host',
        'OLLAMA_PORT': '12345',
        'OLLAMA_USE_HTTPS': 'true',
        'AI_MODEL': 'env-model:latest',
        'ENABLE_AI_ENHANCEMENT': 'false'
    })
    def test_initialization_with_env_vars(self, mock_requests):
        """Test enhancer initialization with environment variables."""
        mock_requests.get.side_effect = Exception("No connection")
        
        enhancer = AIEnhancer()
        
        assert enhancer.ollama_urls[0] == 'https://custom-host:12345/api/generate'
        assert enhancer.deepseek_model == 'env-model:latest'
        assert enhancer.use_ai_enhancement is False
    
    def test_ollama_connection_success(self, mock_requests):
        """Test successful Ollama connection."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'models': [
                {'name': 'llama3.3:latest'},
                {'name': 'deepseek-coder:latest'}
            ]
        }
        mock_requests.get.return_value = mock_response
        
        enhancer = AIEnhancer({'enabled': True})
        
        assert enhancer.ollama_url is not None
        assert enhancer.use_ai_enhancement is True
        # Should have tested with /tags endpoint
        mock_requests.get.assert_called()
        assert '/tags' in mock_requests.get.call_args[0][0]
    
    def test_ollama_connection_model_not_found(self, mock_requests):
        """Test Ollama connection when preferred model is not available."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'models': [
                {'name': 'mistral:latest'},
                {'name': 'codellama:latest'}
            ]
        }
        mock_requests.get.return_value = mock_response
        
        enhancer = AIEnhancer({'enabled': True, 'model': 'nonexistent:latest'})
        
        # Should fallback to first available model
        assert enhancer.ollama_url is not None
        assert enhancer.deepseek_model == 'mistral:latest'
        assert enhancer.use_ai_enhancement is True
    
    def test_ollama_connection_all_fail(self, mock_requests):
        """Test when all Ollama connections fail."""
        mock_requests.get.side_effect = Exception("Connection refused")
        
        enhancer = AIEnhancer({'enabled': True})
        
        assert enhancer.ollama_url is None
        assert enhancer.use_ai_enhancement is False
    
    def test_ollama_connection_partial_fail(self, mock_requests):
        """Test when some Ollama URLs fail but one succeeds."""
        # First two fail, third succeeds
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'models': [{'name': 'llama3.3:latest'}]}
        
        mock_requests.get.side_effect = [
            Exception("Connection refused"),
            Exception("Connection refused"),
            mock_response
        ]
        
        enhancer = AIEnhancer({'enabled': True})
        
        assert enhancer.ollama_url == "http://127.0.0.1:11434/api/generate"
        assert enhancer.use_ai_enhancement is True
    
    def test_enhance_text_disabled(self, enhancer_no_connection):
        """Test text enhancement when AI is disabled."""
        enhancer_no_connection.use_ai_enhancement = False
        
        result = enhancer_no_connection.enhance_text("hello world")
        assert result == "Hello world."
    
    def test_enhance_text_no_connection(self, enhancer_no_connection):
        """Test text enhancement when no connection is available."""
        result = enhancer_no_connection.enhance_text("hello world")
        assert result == "Hello world."
    
    def test_enhance_text_empty_input(self, enhancer_with_connection):
        """Test text enhancement with empty input."""
        result = enhancer_with_connection.enhance_text("")
        assert result == ""
        
        result = enhancer_with_connection.enhance_text("   ")
        assert result == ""
    
    def test_enhance_text_success(self, enhancer_with_connection, mock_requests):
        """Test successful text enhancement."""
        # Mock successful enhancement response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'response': 'Hello, world! This is enhanced text.'
        }
        mock_requests.Session.return_value.post.return_value = mock_response
        
        result = enhancer_with_connection.enhance_text("hello world this is enhanced text")
        
        assert result == "Hello, world! This is enhanced text."
        
        # Verify request was made correctly
        session = mock_requests.Session.return_value
        session.post.assert_called_once()
        
        call_args = session.post.call_args
        assert call_args[0][0] == enhancer_with_connection.ollama_url
        
        request_data = call_args[1]['json']
        assert request_data['model'] == 'llama3.3:latest'
        assert request_data['stream'] is False
        assert 'prompt' in request_data
    
    @pytest.mark.parametrize("context,expected_instruction", [
        ('email', 'This is email content, format appropriately for professional communication.'),
        ('code', 'This may contain technical terms or code. Preserve technical accuracy.'),
        ('document', 'This is document content, use formal writing style.'),
        ('chat', 'This is casual conversation, use natural informal style.'),
        ('general', 'Format naturally for general text input.'),
        ('unknown', 'Format naturally for general text input.')  # Default fallback
    ])
    def test_enhance_text_contexts(self, enhancer_with_connection, mock_requests, context, expected_instruction):
        """Test text enhancement with different contexts."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'Enhanced text.'}
        mock_requests.Session.return_value.post.return_value = mock_response
        
        result = enhancer_with_connection.enhance_text("test text", context)
        
        # Verify context-specific prompt was used
        call_args = mock_requests.Session.return_value.post.call_args
        prompt = call_args[1]['json']['prompt']
        assert expected_instruction in prompt
    
    def test_enhance_text_error_response(self, enhancer_with_connection, mock_requests):
        """Test text enhancement with error response."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        mock_requests.Session.return_value.post.return_value = mock_response
        
        result = enhancer_with_connection.enhance_text("hello world")
        
        # Should fallback to basic formatting
        assert result == "Hello world."
    
    def test_enhance_text_request_exception(self, enhancer_with_connection, mock_requests):
        """Test text enhancement when request raises exception."""
        mock_requests.Session.return_value.post.side_effect = Exception("Network error")
        
        result = enhancer_with_connection.enhance_text("hello world")
        
        # Should fallback to basic formatting
        assert result == "Hello world."
    
    def test_enhance_text_custom_parameters(self, enhancer_with_connection, mock_requests):
        """Test text enhancement with custom parameters."""
        enhancer_with_connection.config['temperature'] = 0.7
        enhancer_with_connection.config['top_p'] = 0.95
        enhancer_with_connection.config['timeout'] = 15
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'Enhanced.'}
        mock_requests.Session.return_value.post.return_value = mock_response
        
        result = enhancer_with_connection.enhance_text("test")
        
        call_args = mock_requests.Session.return_value.post.call_args
        request_data = call_args[1]['json']
        assert request_data['temperature'] == 0.7
        assert request_data['top_p'] == 0.95
        assert call_args[1]['timeout'] == 15
    
    def test_generate_prompt(self, enhancer_no_connection):
        """Test prompt generation for different contexts."""
        prompt = enhancer_no_connection._generate_prompt("test text", "email")
        
        assert "transcription formatter" in prompt
        assert "email content" in prompt
        assert "test text" in prompt
        assert "Formatted text:" in prompt
    
    @pytest.mark.parametrize("ai_response,expected", [
        ('"Formatted text"', 'Formatted text'),
        ('Formatted text:', ''),
        ('Here is the formatted text: Hello', 'Hello'),
        ('The formatted text is: Hello world', 'Hello world'),
        ('Formatted: Test', 'Test'),
        ('  Spaced text  ', 'Spaced text'),
        ('Regular text', 'Regular text')
    ])
    def test_clean_ai_response(self, enhancer_no_connection, ai_response, expected):
        """Test AI response cleaning logic."""
        result = enhancer_no_connection._clean_ai_response(ai_response)
        assert result == expected
    
    @pytest.mark.parametrize("input_text,expected", [
        ("hello world", "Hello world."),
        ("Hello world", "Hello world."),
        ("hello world!", "Hello world!"),
        ("question here", "Question here."),
        ("  spaced  ", "Spaced."),
        ("", ""),
        ("already has period.", "Already has period."),
        ("has question?", "Has question?"),
        ("exclamation!", "Exclamation!")
    ])
    def test_basic_format(self, enhancer_no_connection, input_text, expected):
        """Test basic formatting fallback."""
        result = enhancer_no_connection.basic_format(input_text)
        assert result == expected
    
    def test_basic_format_replacements(self, enhancer_no_connection):
        """Test basic format text replacements."""
        test_cases = [
            ("Add new line here", "Add\nhere"),
            ("Start new paragraph now", "Start\n\nnow"),
            ("End with period please", "End with. please"),
            ("Insert comma here", "Insert, here"),
            ("Is this question mark", "Is this?"),
            ("Wow exclamation mark", "Wow!"),
            ("scratch that I mean hello", " I mean hello"),
            ("Multiple new line and new paragraph markers", "Multiple\nand\n\nmarkers")
        ]
        
        for input_text, expected in test_cases:
            result = enhancer_no_connection.basic_format(input_text)
            assert result == expected.capitalize() + ('.' if expected and expected[-1] not in '.!?' else '')
    
    def test_get_status_connected(self, enhancer_with_connection):
        """Test status retrieval when connected."""
        status = enhancer_with_connection.get_status()
        
        assert status['enabled'] is True
        assert status['connected'] is True
        assert status['model'] == 'llama3.3:latest'
        assert 'ollama_url' in status
        assert status['ollama_url'] != "Not connected"
    
    def test_get_status_disconnected(self, enhancer_no_connection):
        """Test status retrieval when disconnected."""
        status = enhancer_no_connection.get_status()
        
        assert status['enabled'] is False  # Disabled due to no connection
        assert status['connected'] is False
        assert status['model'] == 'llama3.3:latest'
        assert status['ollama_url'] == "Not connected"


class TestCreateEnhancer:
    """Test suite for create_enhancer factory function."""
    
    @patch.dict(os.environ, {
        'ENABLE_AI_ENHANCEMENT': 'false',
        'AI_MODEL': 'custom:latest',
        'AI_TEMPERATURE': '0.5',
        'AI_TIMEOUT': '20'
    })
    @patch('core.ai_enhancement.AIEnhancer')
    def test_create_enhancer_with_env_vars(self, mock_enhancer_class):
        """Test enhancer creation with environment variables."""
        enhancer = create_enhancer()
        
        mock_enhancer_class.assert_called_once_with({
            'enabled': False,
            'model': 'custom:latest',
            'temperature': 0.5,
            'timeout': 20
        })
    
    @patch('core.ai_enhancement.AIEnhancer')
    def test_create_enhancer_with_config(self, mock_enhancer_class):
        """Test enhancer creation with custom config."""
        config = {'model': 'test:latest', 'custom_param': 'value'}
        enhancer = create_enhancer(config)
        
        expected_config = {
            'enabled': True,
            'model': 'test:latest',
            'temperature': 0.3,
            'timeout': 10,
            'custom_param': 'value'
        }
        mock_enhancer_class.assert_called_once_with(expected_config)
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('core.ai_enhancement.AIEnhancer')
    def test_create_enhancer_defaults(self, mock_enhancer_class):
        """Test enhancer creation with default values."""
        enhancer = create_enhancer()
        
        mock_enhancer_class.assert_called_once_with({
            'enabled': True,
            'model': 'llama3.3:latest',
            'temperature': 0.3,
            'timeout': 10
        })


if __name__ == "__main__":
    pytest.main([__file__, "-v"])