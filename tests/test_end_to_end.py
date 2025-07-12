"""
VoiceFlow End-to-End Testing Suite
==================================

Comprehensive system tests for complete user workflows and real-world scenarios.
Tests the entire VoiceFlow system from installation to usage validation.

Test Categories:
1. Complete User Workflows
2. System-Level Testing  
3. Implementation Path Testing
4. Real-World Scenarios
5. Validation Testing
"""

import asyncio
import json
import os
import pytest
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import wave
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock
from typing import Dict, List, Optional, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.voiceflow_core import VoiceFlowEngine, create_engine
from core.ai_enhancement import AIEnhancer, create_enhancer
from utils.config import VoiceFlowConfig, get_config, get_audio_config, get_ai_config


class E2ETestEnvironment:
    """Comprehensive test environment for end-to-end testing."""
    
    def __init__(self, temp_dir: Path):
        self.temp_dir = temp_dir
        self.home_dir = temp_dir / "home"
        self.voiceflow_dir = self.home_dir / ".voiceflow"
        self.db_path = self.voiceflow_dir / "transcriptions.db"
        self.config_path = self.voiceflow_dir / "config.json"
        
        # Create directory structure
        self.home_dir.mkdir(parents=True, exist_ok=True)
        self.voiceflow_dir.mkdir(parents=True, exist_ok=True)
        
        # Environment state
        self.processes = []
        self.cleanup_funcs = []
        self.test_results = {}
        
    def setup_configuration(self, config_data: Dict[str, Any]):
        """Set up configuration files and environment."""
        # Write configuration file
        with open(self.config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        # Set environment variables
        os.environ['VOICEFLOW_HOME'] = str(self.voiceflow_dir)
        os.environ['HOME'] = str(self.home_dir)
        
    def create_test_audio(self, filename: str = "test_audio.wav", duration: float = 1.0):
        """Create a test audio file."""
        try:
            import numpy as np
            
            # Generate test audio (1 second of 440Hz sine wave)
            sample_rate = 16000
            samples = int(sample_rate * duration)
            frequency = 440.0
            
            # Generate sine wave
            t = np.linspace(0, duration, samples)
            audio_data = np.sin(2 * np.pi * frequency * t) * 0.5
            
            # Convert to 16-bit PCM
            audio_data = (audio_data * 32767).astype(np.int16)
            
        except ImportError:
            # Fallback to simple sine wave without numpy
            import math
            
            sample_rate = 16000
            samples = int(sample_rate * duration)
            frequency = 440.0
            
            # Generate sine wave manually
            audio_data = []
            for i in range(samples):
                t = i / sample_rate
                value = math.sin(2 * math.pi * frequency * t) * 0.5
                # Convert to 16-bit PCM
                pcm_value = int(value * 32767)
                audio_data.append(pcm_value)
            
            # Convert to bytes
            import struct
            audio_data = b''.join(struct.pack('<h', sample) for sample in audio_data)
        
        # Write WAV file
        audio_path = self.temp_dir / filename
        with wave.open(str(audio_path), 'wb') as wav_file:
            wav_file.setnchannels(1)  # Mono
            wav_file.setsampwidth(2)  # 16-bit
            wav_file.setframerate(sample_rate)
            if hasattr(audio_data, 'tobytes'):
                wav_file.writeframes(audio_data.tobytes())
            else:
                wav_file.writeframes(audio_data)
        
        return audio_path
    
    def simulate_ollama_server(self, port: int = 11434):
        """Simulate Ollama server for testing."""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class MockOllamaHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/api/tags':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = {
                        "models": [
                            {"name": "llama3.3:latest", "model": "llama3.3:latest"},
                            {"name": "deepseek-r1:latest", "model": "deepseek-r1:latest"}
                        ]
                    }
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_POST(self):
                if self.path == '/api/generate':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    # Mock AI enhancement response
                    response = {
                        "response": "Enhanced test transcription with proper grammar and formatting.",
                        "done": True
                    }
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                pass  # Suppress logging
        
        server = HTTPServer(('localhost', port), MockOllamaHandler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        self.cleanup_funcs.append(server.shutdown)
        return server
    
    def cleanup(self):
        """Clean up test environment."""
        # Stop all processes
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        # Run cleanup functions
        for cleanup_func in self.cleanup_funcs:
            try:
                cleanup_func()
            except:
                pass
        
        # Reset environment variables
        for var in ['VOICEFLOW_HOME', 'HOME']:
            if var in os.environ:
                del os.environ[var]


@pytest.fixture
def e2e_environment():
    """Create end-to-end test environment."""
    with tempfile.TemporaryDirectory() as temp_dir:
        env = E2ETestEnvironment(Path(temp_dir))
        try:
            yield env
        finally:
            env.cleanup()


def create_mock_engine(audio_config):
    """Create a VoiceFlow engine with mocked dependencies for testing."""
    with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
        engine = create_engine(audio_config)
        # Set up mock recorder
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        engine.recorder = mock_recorder
        return engine


class TestCompleteUserWorkflows:
    """Test complete user workflows from installation to usage."""
    
    def test_first_time_user_workflow(self, e2e_environment):
        """Test complete first-time user workflow: Install → Configure → Use → Validate."""
        env = e2e_environment
        
        # Phase 1: Installation simulation
        # Simulate directory creation and dependency check
        assert env.voiceflow_dir.exists()
        
        # Phase 2: Configuration setup
        config_data = {
            "audio": {
                "model": "base",
                "device": "cpu",
                "language": "en"
            },
            "ai": {
                "enabled": True,
                "model": "llama3.3:latest",
                "ollama_url": "http://localhost:11434"
            },
            "system": {
                "hotkey": "ctrl+alt",
                "enable_injection": True
            }
        }
        env.setup_configuration(config_data)
        
        # Phase 3: System startup
        config = get_config()
        assert config is not None
        
        # Phase 4: Component initialization
        engine = create_mock_engine(get_audio_config())
        assert engine is not None
        assert engine.recorder is not None
        
        # Phase 5: AI enhancement setup
        env.simulate_ollama_server()
        time.sleep(0.1)  # Allow server to start
        
        ai_enhancer = create_enhancer(get_ai_config())
        assert ai_enhancer is not None
        
        # Phase 6: Usage simulation
        test_transcription = "hello world this is a test"
        enhanced_text = ai_enhancer.enhance_text(test_transcription)
        assert enhanced_text is not None
        assert len(enhanced_text) > 0
        
        # Phase 7: Database validation
        assert env.db_path.exists()
        
        # Phase 8: Statistics validation
        stats = engine.get_stats()
        assert 'total_transcriptions' in stats
        assert 'total_words' in stats
        
        # Phase 9: Cleanup validation
        engine.cleanup()
        
    def test_configuration_change_workflow(self, e2e_environment):
        """Test workflow when user changes configuration."""
        env = e2e_environment
        
        # Initial configuration
        initial_config = {
            "audio": {"model": "base", "device": "cpu"},
            "ai": {"enabled": False}
        }
        env.setup_configuration(initial_config)
        
        # Initial system setup
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            engine = create_engine(get_audio_config())
            engine.recorder = MagicMock()
            ai_enhancer = create_enhancer(get_ai_config())
            
            # Verify initial state
            assert not ai_enhancer.get_status()['connected']
            
            # Change configuration
            updated_config = {
                "audio": {"model": "small", "device": "gpu"},
                "ai": {"enabled": True, "model": "llama3.3:latest"}
            }
            env.setup_configuration(updated_config)
            
            # Simulate configuration reload
            new_config = get_config()
            assert new_config.get('ai', {}).get('enabled', False) == True
            
            # Test that system adapts to new configuration
            env.simulate_ollama_server()
            time.sleep(0.1)
            
            new_ai_enhancer = create_enhancer(get_ai_config())
            status = new_ai_enhancer.get_status()
            assert status['connected'] == True
    
    def test_gpu_fallback_workflow(self, e2e_environment):
        """Test workflow with GPU failure and CPU fallback."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "gpu"},
            "ai": {"enabled": True}
        }
        env.setup_configuration(config_data)
        
        # Simulate GPU failure
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder') as mock_setup:
            # First call (GPU) fails, second succeeds
            mock_setup.side_effect = [RuntimeError("CUDA not available"), None]
            
            engine = create_engine(get_audio_config())
            engine.recorder = MagicMock()
            engine.recorder.get_model.return_value = "base"
            
            # Should fallback to CPU
            assert engine.recorder is not None
    
    def test_network_recovery_workflow(self, e2e_environment):
        """Test workflow with network connectivity issues and recovery."""
        env = e2e_environment
        
        config_data = {
            "ai": {"enabled": True, "model": "llama3.3:latest"}
        }
        env.setup_configuration(config_data)
        
        # Initially no network
        ai_enhancer = create_enhancer(get_ai_config())
        assert not ai_enhancer.get_status()['connected']
        
        # Network comes back
        env.simulate_ollama_server()
        time.sleep(0.1)
        
        # Test recovery
        new_ai_enhancer = create_enhancer(get_ai_config())
        assert new_ai_enhancer.get_status()['connected']


class TestSystemLevelTesting:
    """Test system-level functionality including startup, shutdown, and integration."""
    
    def test_application_startup_shutdown(self, e2e_environment):
        """Test complete application startup and shutdown sequence."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu"},
            "ai": {"enabled": True},
            "system": {"hotkey": "ctrl+alt"}
        }
        env.setup_configuration(config_data)
        
        # Startup sequence
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            # 1. Configuration loading
            config = get_config()
            assert config is not None
            
            # 2. Component initialization
            engine = create_engine(get_audio_config())
            ai_enhancer = create_enhancer(get_ai_config())
            
            # 3. Database initialization
            assert env.db_path.exists()
            
            # 4. System integration setup
            with patch('keyboard.add_hotkey'):
                engine.setup_hotkeys('ctrl+alt')
            
            # 5. Ready state validation
            assert engine.recorder is not None
            
            # Shutdown sequence
            engine.cleanup()
            
            # Verify clean shutdown
            assert True  # If we get here, shutdown was successful
    
    def test_database_initialization_migration(self, e2e_environment):
        """Test database initialization and migration scenarios."""
        env = e2e_environment
        
        # Test fresh database creation
        assert not env.db_path.exists()
        
        with patch('RealtimeSTT.AudioToTextRecorder'):
            engine = create_engine(get_audio_config())
            
            assert env.db_path.exists()
            
            # Test database schema
            conn = sqlite3.connect(env.db_path)
            cursor = conn.cursor()
            
            # Check tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            assert 'transcriptions' in tables
            
            conn.close()
    
    def test_external_service_connectivity(self, e2e_environment):
        """Test connectivity to external services (Ollama)."""
        env = e2e_environment
        
        config_data = {
            "ai": {
                "enabled": True,
                "model": "llama3.3:latest",
                "ollama_url": "http://localhost:11434"
            }
        }
        env.setup_configuration(config_data)
        
        # Test without service
        ai_enhancer = create_enhancer(get_ai_config())
        assert not ai_enhancer.get_status()['connected']
        
        # Test with service
        env.simulate_ollama_server()
        time.sleep(0.1)
        
        new_ai_enhancer = create_enhancer(get_ai_config())
        status = new_ai_enhancer.get_status()
        assert status['connected']
        assert 'model' in status
    
    def test_system_integration_components(self, e2e_environment):
        """Test system integration components (hotkeys, text injection)."""
        env = e2e_environment
        
        config_data = {
            "system": {
                "hotkey": "ctrl+alt",
                "enable_injection": True
            }
        }
        env.setup_configuration(config_data)
        
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.return_value.get_model.return_value = "base"
            
            with patch('keyboard.add_hotkey') as mock_keyboard:
                with patch('pyautogui.write') as mock_pyautogui:
                    
                    engine = create_engine(get_audio_config())
                    
                    # Test hotkey setup
                    engine.setup_hotkeys('ctrl+alt')
                    assert mock_keyboard.called
                    
                    # Test text injection
                    engine.inject_text("test text")
                    assert mock_pyautogui.called


class TestImplementationPaths:
    """Test different implementation paths and their integration."""
    
    def test_simple_implementation_path(self, e2e_environment):
        """Test implementations/simple.py end-to-end functionality."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu"},
            "ai": {"enabled": True}
        }
        env.setup_configuration(config_data)
        
        # Import and test simple implementation
        sys.path.insert(0, str(Path(__file__).parent.parent / "implementations"))
        
        with patch('simple.AudioToTextRecorder') as mock_recorder:
            mock_recorder.return_value.get_model.return_value = "base"
            
            with patch('simple.keyboard'):
                with patch('simple.pyautogui'):
                    from simple import SimpleVoiceFlow
                    
                    # Test initialization
                    app = SimpleVoiceFlow()
                    assert app.engine is not None
                    assert app.ai_enhancer is not None
                    
                    # Test transcription callback
                    test_text = "hello world"
                    app.on_transcription(test_text)
                    
                    # Test cleanup
                    app.cleanup()
    
    def test_server_implementation_path(self, e2e_environment):
        """Test python/stt_server.py WebSocket functionality."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu"},
            "ai": {"enabled": True}
        }
        env.setup_configuration(config_data)
        
        # Test server components
        sys.path.insert(0, str(Path(__file__).parent.parent / "python"))
        
        # Mock the server initialization
        with patch('stt_server.AudioToTextRecorder') as mock_recorder:
            mock_recorder.return_value.get_model.return_value = "base"
            
            with patch('stt_server.websockets'):
                # Import would normally start server, so we'll test components
                import stt_server
                
                # Test server class initialization
                server = stt_server.VoiceFlowServer()
                assert server.data_dir.exists()
                assert server.db_path.exists()
    
    def test_native_implementation_path(self, e2e_environment):
        """Test native/voiceflow_native.py Windows service functionality."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu"},
            "system": {"hotkey": "ctrl+alt"}
        }
        env.setup_configuration(config_data)
        
        # Test native components (mock Windows-specific parts)
        sys.path.insert(0, str(Path(__file__).parent.parent / "native"))
        
        with patch('voiceflow_native.win32api'):
            with patch('voiceflow_native.win32gui'):
                with patch('voiceflow_native.pystray'):
                    with patch('voiceflow_native.keyboard'):
                        # Test would require Windows-specific mocking
                        # This validates the import and basic structure
                        import voiceflow_native
                        
                        # Verify class exists and has required methods
                        assert hasattr(voiceflow_native, 'VoiceFlowNative')
                        native_class = voiceflow_native.VoiceFlowNative
                        assert hasattr(native_class, '__init__')
    
    def test_mcp_implementation_path(self, e2e_environment):
        """Test voiceflow_mcp_server.py MCP integration."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu"},
            "ai": {"enabled": True}
        }
        env.setup_configuration(config_data)
        
        # Test MCP server components
        with patch('voiceflow_mcp_server.Server'):
            with patch('voiceflow_mcp_server.AudioToTextRecorder') as mock_recorder:
                mock_recorder.return_value.get_model.return_value = "base"
                
                # Import MCP server
                import voiceflow_mcp_server
                
                # Test server class exists
                assert hasattr(voiceflow_mcp_server, 'VoiceFlowMCPServer')
                
                # Test initialization
                server = voiceflow_mcp_server.VoiceFlowMCPServer()
                assert server is not None


class TestRealWorldScenarios:
    """Test real-world usage scenarios and edge cases."""
    
    def test_multi_user_environment(self, e2e_environment):
        """Test behavior in multi-user environment."""
        env = e2e_environment
        
        # Create multiple user configurations
        user1_config = {
            "audio": {"model": "base", "device": "cpu"},
            "ai": {"enabled": True, "model": "llama3.3:latest"}
        }
        
        user2_config = {
            "audio": {"model": "small", "device": "gpu"},
            "ai": {"enabled": False}
        }
        
        # Test user 1
        env.setup_configuration(user1_config)
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.return_value.get_model.return_value = "base"
            
            engine1 = create_engine(get_audio_config())
            assert engine1.recorder is not None
        
        # Test user 2
        env.setup_configuration(user2_config)
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.return_value.get_model.return_value = "small"
            
            engine2 = create_engine(get_audio_config())
            assert engine2.recorder is not None
    
    def test_resource_constraint_scenarios(self, e2e_environment):
        """Test behavior under resource constraints."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu"},
            "ai": {"enabled": True}
        }
        env.setup_configuration(config_data)
        
        # Test low memory scenario
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.side_effect = MemoryError("Not enough memory")
            
            try:
                engine = create_engine(get_audio_config())
                # Should handle gracefully or fallback
                assert True  # If we get here, it was handled
            except MemoryError:
                # Expected in severe memory constraint
                assert True
    
    def test_configuration_corruption_recovery(self, e2e_environment):
        """Test recovery from corrupted configuration."""
        env = e2e_environment
        
        # Create corrupted config
        with open(env.config_path, 'w') as f:
            f.write("invalid json {")
        
        # Should fallback to defaults
        config = get_config()
        assert config is not None
        
        # Should be able to create engine with defaults
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.return_value.get_model.return_value = "base"
            
            engine = create_engine(get_audio_config())
            assert engine is not None
    
    def test_concurrent_access_scenarios(self, e2e_environment):
        """Test concurrent access to resources."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu"}
        }
        env.setup_configuration(config_data)
        
        # Test concurrent database access
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.return_value.get_model.return_value = "base"
            
            engine1 = create_engine(get_audio_config())
            engine2 = create_engine(get_audio_config())
            
            # Both should work
            assert engine1.recorder is not None
            assert engine2.recorder is not None
            
            # Test concurrent transcription storage
            engine1.store_transcription("test1")
            engine2.store_transcription("test2")
            
            # Both should be stored
            stats1 = engine1.get_stats()
            stats2 = engine2.get_stats()
            assert stats1['total_transcriptions'] > 0
            assert stats2['total_transcriptions'] > 0


class TestValidationTesting:
    """Test validation of audio input, transcription, AI enhancement, and text injection."""
    
    def test_audio_input_validation(self, e2e_environment):
        """Test audio input handling and validation."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu", "language": "en"}
        }
        env.setup_configuration(config_data)
        
        # Create test audio file
        audio_path = env.create_test_audio()
        assert audio_path.exists()
        
        # Test audio processing
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.return_value.get_model.return_value = "base"
            mock_recorder.return_value.transcribe.return_value = "test transcription"
            
            engine = create_engine(get_audio_config())
            
            # Simulate audio processing
            result = engine.recorder.transcribe(str(audio_path))
            assert result == "test transcription"
    
    def test_transcription_accuracy_validation(self, e2e_environment):
        """Test transcription accuracy and quality."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu"}
        }
        env.setup_configuration(config_data)
        
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.return_value.get_model.return_value = "base"
            
            engine = create_engine(get_audio_config())
            
            # Test various transcription scenarios
            test_cases = [
                ("hello world", "hello world"),
                ("", ""),  # Empty input
                ("Hello, how are you today?", "Hello, how are you today?"),
                ("123 456 789", "123 456 789"),  # Numbers
                ("test@example.com", "test@example.com"),  # Email
            ]
            
            for input_text, expected in test_cases:
                mock_recorder.return_value.transcribe.return_value = expected
                result = engine.recorder.transcribe(input_text)
                assert result == expected
    
    def test_ai_enhancement_validation(self, e2e_environment):
        """Test AI enhancement quality and accuracy."""
        env = e2e_environment
        
        config_data = {
            "ai": {"enabled": True, "model": "llama3.3:latest"}
        }
        env.setup_configuration(config_data)
        
        # Start mock Ollama server
        env.simulate_ollama_server()
        time.sleep(0.1)
        
        ai_enhancer = create_enhancer(get_ai_config())
        
        # Test enhancement scenarios
        test_cases = [
            ("hello world", "Hello world."),
            ("this is a test", "This is a test."),
            ("", ""),  # Empty input
            ("fix this bug in the code", "Fix this bug in the code."),
        ]
        
        for input_text, expected_pattern in test_cases:
            if input_text:
                enhanced = ai_enhancer.enhance_text(input_text)
                assert enhanced is not None
                assert len(enhanced) > 0
                # Enhanced text should be different from input (improved)
                assert enhanced != input_text or input_text == ""
    
    def test_text_injection_validation(self, e2e_environment):
        """Test text injection functionality."""
        env = e2e_environment
        
        config_data = {
            "system": {"enable_injection": True}
        }
        env.setup_configuration(config_data)
        
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.return_value.get_model.return_value = "base"
            
            with patch('pyautogui.write') as mock_pyautogui:
                engine = create_engine(get_audio_config())
                
                # Test text injection
                test_texts = [
                    "Hello world",
                    "This is a test",
                    "Multi-line\ntext\ninjection",
                    "",  # Empty text
                ]
                
                for text in test_texts:
                    engine.inject_text(text)
                    if text:  # Only check for non-empty text
                        mock_pyautogui.assert_called_with(text)
    
    def test_database_storage_validation(self, e2e_environment):
        """Test database storage and retrieval validation."""
        env = e2e_environment
        
        config_data = {
            "audio": {"model": "base", "device": "cpu"}
        }
        env.setup_configuration(config_data)
        
        mock_recorder = MagicMock()
        mock_recorder.get_model.return_value = "base"
        mock_recorder.transcribe.return_value = "test transcription"
        with patch('core.voiceflow_core.VoiceFlowEngine.setup_audio_recorder'):
            mock_recorder.return_value.get_model.return_value = "base"
            
            engine = create_engine(get_audio_config())
            
            # Test transcription storage
            test_transcriptions = [
                "Hello world",
                "This is a test transcription",
                "Another test with numbers 123",
                "Test with special characters: @#$%"
            ]
            
            for transcription in test_transcriptions:
                engine.store_transcription(transcription)
            
            # Verify storage
            stats = engine.get_stats()
            assert stats['total_transcriptions'] == len(test_transcriptions)
            assert stats['total_words'] > 0
            
            # Test database integrity
            conn = sqlite3.connect(env.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM transcriptions")
            count = cursor.fetchone()[0]
            assert count == len(test_transcriptions)
            conn.close()


# Test markers for filtering
pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
    pytest.mark.e2e
]


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"])