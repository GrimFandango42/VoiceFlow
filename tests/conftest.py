"""
Pytest configuration and shared fixtures for VoiceFlow testing.
"""

import os
import sys
import tempfile
import shutil
import sqlite3
import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import pytest

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(scope="session", autouse=True)
def clean_environment():
    """Clean environment variables before running tests."""
    env_vars_to_clean = [
        'VOICEFLOW_MODEL', 'VOICEFLOW_DEVICE', 'OLLAMA_HOST', 'OLLAMA_PORT',
        'ENABLE_AI_ENHANCEMENT', 'AI_MODEL', 'AI_TEMPERATURE'
    ]
    
    original_values = {}
    for var in env_vars_to_clean:
        original_values[var] = os.getenv(var)
        if var in os.environ:
            del os.environ[var]
    
    yield
    
    # Restore original environment
    for var, value in original_values.items():
        if value is not None:
            os.environ[var] = value
        elif var in os.environ:
            del os.environ[var]


@pytest.fixture
def temp_voiceflow_dir():
    """Create temporary VoiceFlow data directory."""
    temp_dir = tempfile.mkdtemp(prefix="voiceflow_test_")
    temp_path = Path(temp_dir)
    
    # Mock Path.home() to return our temp directory
    with patch('pathlib.Path.home', return_value=temp_path.parent):
        yield temp_path / ".voiceflow"
    
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_audio_recorder():
    """Mock AudioToTextRecorder for testing."""
    mock_recorder = Mock()
    mock_recorder.text.return_value = "test transcription"
    
    # Since AudioToTextRecorder is imported at module level, we need to mock it properly
    # We'll return the mock recorder directly and let tests set it manually
    yield mock_recorder


@pytest.fixture
def mock_requests():
    """Mock requests library for testing AI enhancement."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'response': 'Enhanced test text.',
        'models': [{'name': 'llama3.3:latest'}]
    }
    
    with patch('requests.post', return_value=mock_response) as mock_post, \
         patch('requests.get', return_value=mock_response) as mock_get:
        yield {'post': mock_post, 'get': mock_get, 'response': mock_response}


@pytest.fixture
def mock_system_integration():
    """Mock system integration components."""
    mocks = {}
    
    with patch('core.voiceflow_core.SYSTEM_INTEGRATION', True), \
         patch('core.voiceflow_core.pyautogui') as mock_pyautogui, \
         patch('core.voiceflow_core.keyboard') as mock_keyboard:
        
        mocks['pyautogui'] = mock_pyautogui
        mocks['keyboard'] = mock_keyboard
        
        # Configure pyautogui mock
        mock_pyautogui.typewrite = Mock()
        
        # Configure keyboard mock
        mock_keyboard.add_hotkey = Mock()
        
        yield mocks


@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return {
        'audio': {
            'model': 'base',
            'device': 'cpu',
            'language': 'en'
        },
        'ai': {
            'enabled': True,
            'model': 'test-model',
            'temperature': 0.5
        }
    }


@pytest.fixture
def test_database():
    """Create temporary test database."""
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(db_fd)
    
    yield Path(db_path)
    
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture
def populated_database(test_database):
    """Create test database with sample data."""
    conn = sqlite3.connect(test_database)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transcriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            raw_text TEXT,
            enhanced_text TEXT,
            processing_time_ms INTEGER,
            word_count INTEGER,
            confidence REAL,
            model_used TEXT,
            session_id TEXT
        )
    ''')
    
    # Insert sample data
    sample_data = [
        ("hello world", "Hello world.", 150, 2, 0.95, "base", "test-session-1"),
        ("how are you", "How are you?", 200, 3, 0.92, "base", "test-session-1"),
        ("test transcription", "Test transcription.", 175, 2, 0.98, "base", "test-session-2")
    ]
    
    cursor.executemany('''
        INSERT INTO transcriptions 
        (raw_text, enhanced_text, processing_time_ms, word_count, confidence, model_used, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', sample_data)
    
    conn.commit()
    conn.close()
    
    yield test_database


@pytest.fixture
def temp_home_dir():
    """Create temporary home directory for testing."""
    temp_dir = tempfile.mkdtemp(prefix="voiceflow_home_")
    temp_path = Path(temp_dir)
    
    # Create .voiceflow directory
    voiceflow_dir = temp_path / ".voiceflow"
    voiceflow_dir.mkdir(exist_ok=True)
    
    with patch('pathlib.Path.home', return_value=temp_path):
        yield temp_path
    
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_ollama_service():
    """Mock Ollama service for testing."""
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post, \
         patch('requests.Session') as mock_session_class:
        
        # Mock successful connection
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'models': [
                {'name': 'llama3.3:latest'},
                {'name': 'test-model:latest'}
            ]
        }
        
        # Mock session for AI enhancement
        mock_session = Mock()
        mock_session.post.return_value.status_code = 200
        mock_session.post.return_value.json.return_value = {
            'response': 'Enhanced text with proper formatting.'
        }
        mock_session_class.return_value = mock_session
        
        yield {
            'get': mock_get,
            'post': mock_post,
            'session': mock_session,
            'session_class': mock_session_class
        }


@pytest.fixture
def mock_mcp_server():
    """Mock MCP server components for testing."""
    with patch('voiceflow_mcp_server.MCP_AVAILABLE', True), \
         patch('voiceflow_mcp_server.Server') as mock_server_class, \
         patch('voiceflow_mcp_server.stdio_server') as mock_stdio:
        
        mock_server = Mock()
        mock_server_class.return_value = mock_server
        
        # Mock stdio server context manager
        mock_stdio.return_value.__aenter__ = AsyncMock(return_value=(Mock(), Mock()))
        mock_stdio.return_value.__aexit__ = AsyncMock(return_value=None)
        
        yield {
            'server': mock_server,
            'server_class': mock_server_class,
            'stdio': mock_stdio
        }


@pytest.fixture
def comprehensive_test_config():
    """Comprehensive test configuration for integration testing."""
    return {
        'audio': {
            'model': 'base',
            'device': 'cpu',
            'language': 'en',
            'post_speech_silence_duration': 0.8,
            'min_length_of_recording': 0.2,
            'silero_sensitivity': 0.4,
            'webrtc_sensitivity': 3
        },
        'ai': {
            'enabled': True,
            'model': 'test-model:latest',
            'temperature': 0.3,
            'timeout': 10,
            'ollama_host': 'localhost',
            'ollama_port': '11434',
            'ollama_use_https': False
        },
        'text_injection': {
            'enabled': True,
            'method': 'pyautogui',
            'require_confirmation': False,
            'enable_failsafe': True
        },
        'hotkeys': {
            'record_and_inject': 'ctrl+alt',
            'record_only': 'ctrl+shift+alt',
            'stop_recording': 'esc'
        },
        'database': {
            'encrypt': False,
            'retention_days': 30
        },
        'security': {
            'log_transcriptions': False,
            'enable_debug_logging': False,
            'max_audio_duration': 30,
            'max_audio_file_size': 10485760
        },
        'performance': {
            'use_gpu': False,  # Use CPU for testing
            'max_concurrent_requests': 5,
            'enable_caching': True
        }
    }


@pytest.fixture
def mock_audio_file():
    """Create mock audio file for testing."""
    with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
        # Create minimal WAV file header
        wav_header = b'RIFF' + b'\x24\x00\x00\x00' + b'WAVE' + b'fmt ' + b'\x10\x00\x00\x00'
        wav_header += b'\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00'
        wav_header += b'data' + b'\x00\x00\x00\x00'
        temp_file.write(wav_header)
        temp_file.flush()
        
        yield temp_file.name
        
        try:
            os.unlink(temp_file.name)
        except OSError:
            pass


@pytest.fixture
def integration_test_environment(temp_home_dir, mock_system_integration, mock_ollama_service):
    """Complete integration test environment."""
    # Set up test environment variables
    test_env = {
        'VOICEFLOW_MODEL': 'base',
        'VOICEFLOW_DEVICE': 'cpu',
        'ENABLE_AI_ENHANCEMENT': 'true',
        'AI_MODEL': 'test-model:latest',
        'OLLAMA_HOST': 'localhost',
        'OLLAMA_PORT': '11434'
    }
    
    original_env = {}
    for key, value in test_env.items():
        original_env[key] = os.getenv(key)
        os.environ[key] = value
    
    yield {
        'home_dir': temp_home_dir,
        'system_integration': mock_system_integration,
        'ollama_service': mock_ollama_service,
        'env_vars': test_env
    }
    
    # Restore original environment
    for key, value in original_env.items():
        if value is not None:
            os.environ[key] = value
        elif key in os.environ:
            del os.environ[key]


@pytest.fixture
def performance_test_data():
    """Test data for performance testing."""
    return [
        ("short", "Short.", 100),
        ("this is a medium length test", "This is a medium length test.", 200),
        ("this is a much longer test sentence that contains many more words and should take longer to process", "This is a much longer test sentence that contains many more words and should take longer to process.", 300),
        ("final performance test with various punctuation and numbers like 123 and symbols", "Final performance test with various punctuation and numbers like 123 and symbols.", 250)
    ]


@pytest.fixture
def failure_simulation():
    """Fixture for simulating various failure modes."""
    class FailureSimulator:
        def __init__(self):
            self.failures = {
                'network_error': Exception("Network unreachable"),
                'timeout_error': Exception("Connection timeout"),
                'permission_error': PermissionError("Permission denied"),
                'memory_error': MemoryError("Out of memory"),
                'database_error': sqlite3.OperationalError("Database locked"),
                'json_error': json.JSONDecodeError("Invalid JSON", "", 0)
            }
        
        def get_failure(self, failure_type):
            return self.failures.get(failure_type, Exception("Unknown failure"))
        
        def simulate_network_failure(self):
            return self.get_failure('network_error')
        
        def simulate_timeout(self):
            return self.get_failure('timeout_error')
        
        def simulate_permission_error(self):
            return self.get_failure('permission_error')
        
        def simulate_memory_error(self):
            return self.get_failure('memory_error')
        
        def simulate_database_error(self):
            return self.get_failure('database_error')
        
        def simulate_json_error(self):
            return self.get_failure('json_error')
    
    return FailureSimulator()


# Add async support for pytest
pytest_plugins = ('pytest_asyncio',)


@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()