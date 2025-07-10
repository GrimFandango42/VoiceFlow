"""
Server Integration Tests for VoiceFlow

Tests WebSocket server, MCP server, and other server-based integrations
to ensure proper communication and data flow.
"""

import asyncio
import json
import tempfile
import websockets
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock
import pytest
import sys

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from voiceflow_mcp_server import VoiceFlowMCPServer


class TestMCPServerIntegration:
    """Test MCP server integration with core VoiceFlow components."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_server_initialization(self, temp_voiceflow_dir):
        """Test MCP server initialization and component integration."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    with patch('voiceflow_mcp_server.AudioToTextRecorder') as mock_recorder:
                        with patch('voiceflow_mcp_server.requests') as mock_requests:
                            # Setup mocks
                            mock_server = Mock()
                            mock_server_class.return_value = mock_server
                            mock_recorder.return_value = Mock()
                            
                            # Mock Ollama connection
                            mock_requests.get.return_value.status_code = 200
                            mock_requests.get.return_value.json.return_value = {
                                'models': [{'name': 'test-model:latest'}]
                            }
                            
                            # Create MCP server
                            mcp_server = VoiceFlowMCPServer()
                            
                            # Verify initialization
                            assert mcp_server.server is not None
                            assert mcp_server.data_dir.exists()
                            assert mcp_server.db_path.exists()
                            assert mcp_server.recorder is not None
                            assert mcp_server.use_ai_enhancement is True
                            assert mcp_server.deepseek_model == 'test-model:latest'
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_transcription_tool_integration(self, temp_voiceflow_dir):
        """Test MCP transcription tool integration with core components."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    with patch('voiceflow_mcp_server.AudioToTextRecorder') as mock_recorder_class:
                        with patch('voiceflow_mcp_server.requests') as mock_requests:
                            # Setup mocks
                            mock_server = Mock()
                            mock_server_class.return_value = mock_server
                            
                            mock_recorder = Mock()
                            mock_recorder.transcribe.return_value = "test transcription from audio file"
                            mock_recorder_class.return_value = mock_recorder
                            
                            # Mock AI enhancement
                            mock_requests.get.return_value.status_code = 200
                            mock_requests.get.return_value.json.return_value = {
                                'models': [{'name': 'test-model:latest'}]
                            }
                            
                            mock_requests.post.return_value.status_code = 200
                            mock_requests.post.return_value.json.return_value = {
                                'response': 'Test transcription from audio file.'
                            }
                            
                            # Create MCP server
                            mcp_server = VoiceFlowMCPServer()
                            
                            # Create test audio file
                            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
                                temp_audio_path = temp_file.name
                            
                            try:
                                # Test transcription tool
                                result = await mcp_server._transcribe_audio_file(
                                    temp_audio_path, 
                                    "general", 
                                    True
                                )
                                
                                # Verify results
                                assert result["success"] is True
                                assert result["raw_text"] == "test transcription from audio file"
                                assert result["enhanced_text"] == "Test transcription from audio file."
                                assert result["context"] == "general"
                                assert result["word_count"] == 6
                                assert result["ai_enhanced"] is True
                                
                                # Verify database storage
                                import sqlite3
                                conn = sqlite3.connect(mcp_server.db_path)
                                cursor = conn.cursor()
                                cursor.execute("SELECT raw_text, enhanced_text FROM mcp_transcriptions ORDER BY id DESC LIMIT 1")
                                db_result = cursor.fetchone()
                                conn.close()
                                
                                assert db_result is not None
                                assert db_result[0] == "test transcription from audio file"
                                assert db_result[1] == "Test transcription from audio file."
                                
                            finally:
                                # Cleanup
                                import os
                                try:
                                    os.unlink(temp_audio_path)
                                except:
                                    pass
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_text_enhancement_integration(self, temp_voiceflow_dir):
        """Test MCP text enhancement tool integration."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    with patch('voiceflow_mcp_server.requests') as mock_requests:
                        # Setup mocks
                        mock_server = Mock()
                        mock_server_class.return_value = mock_server
                        
                        # Mock AI enhancement
                        mock_requests.get.return_value.status_code = 200
                        mock_requests.get.return_value.json.return_value = {
                            'models': [{'name': 'test-model:latest'}]
                        }
                        
                        mock_requests.post.return_value.status_code = 200
                        mock_requests.post.return_value.json.return_value = {
                            'response': 'This is a properly enhanced text with correct punctuation.'
                        }
                        
                        # Create MCP server
                        mcp_server = VoiceFlowMCPServer()
                        
                        # Test text enhancement
                        result = await mcp_server._enhance_text(
                            "this is a test text that needs enhancement",
                            "general"
                        )
                        
                        # Verify results
                        assert result["success"] is True
                        assert result["original_text"] == "this is a test text that needs enhancement"
                        assert result["enhanced_text"] == "This is a properly enhanced text with correct punctuation."
                        assert result["context"] == "general"
                        assert result["ai_enhanced"] is True
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_text_injection_integration(self, temp_voiceflow_dir):
        """Test MCP text injection tool integration."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.VOICEFLOW_AVAILABLE', True):
                    with patch('voiceflow_mcp_server.Server') as mock_server_class:
                        with patch('voiceflow_mcp_server.keyboard') as mock_keyboard:
                            # Setup mocks
                            mock_server = Mock()
                            mock_server_class.return_value = mock_server
                            
                            # Create MCP server
                            mcp_server = VoiceFlowMCPServer()
                            
                            # Test text injection
                            result = await mcp_server._inject_text(
                                "test text injection",
                                "sendkeys"
                            )
                            
                            # Verify results
                            assert result["success"] is True
                            assert result["text"] == "test text injection"
                            assert result["method_used"] == "sendkeys"
                            assert result["length"] == 18
                            
                            # Verify keyboard.write was called
                            mock_keyboard.write.assert_called_once_with("test text injection")
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_statistics_integration(self, temp_voiceflow_dir):
        """Test MCP statistics tool integration with database."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    # Setup mocks
                    mock_server = Mock()
                    mock_server_class.return_value = mock_server
                    
                    # Create MCP server
                    mcp_server = VoiceFlowMCPServer()
                    
                    # Add some test data to database
                    import sqlite3
                    conn = sqlite3.connect(mcp_server.db_path)
                    cursor = conn.cursor()
                    
                    test_data = [
                        ("session1", "test one", "Test one.", "general", 150, 2, 1, "test_method", "{}"),
                        ("session1", "test two", "Test two.", "general", 200, 2, 1, "test_method", "{}"),
                        ("session2", "test three", "Test three.", "email", 175, 2, 0, "test_method", "{}")
                    ]
                    
                    cursor.executemany('''
                        INSERT INTO mcp_transcriptions
                        (session_id, raw_text, enhanced_text, context_info, processing_time_ms,
                         word_count, ai_enhanced, source_method, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', test_data)
                    
                    conn.commit()
                    conn.close()
                    
                    # Test statistics
                    result = await mcp_server._get_statistics()
                    
                    # Verify results
                    assert result["success"] is True
                    assert result["statistics"]["total"]["transcriptions"] == 3
                    assert result["statistics"]["total"]["words"] == 6
                    assert result["statistics"]["ai_enhancement"]["enhanced_count"] == 2
                    assert result["statistics"]["ai_enhancement"]["enhancement_rate"] == 66.7
                    assert result["system_status"]["speech_processor_available"] is False  # Mocked
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_history_integration(self, temp_voiceflow_dir):
        """Test MCP transcription history tool integration."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    # Setup mocks
                    mock_server = Mock()
                    mock_server_class.return_value = mock_server
                    
                    # Create MCP server
                    mcp_server = VoiceFlowMCPServer()
                    
                    # Add test data
                    import sqlite3
                    conn = sqlite3.connect(mcp_server.db_path)
                    cursor = conn.cursor()
                    
                    test_data = [
                        ("session1", "first transcription", "First transcription.", "general", 150, 2, 1, "test_method", "{}"),
                        ("session1", "second transcription", "Second transcription.", "general", 200, 2, 1, "test_method", "{}"),
                        ("session2", "third transcription", "Third transcription.", "email", 175, 2, 0, "test_method", "{}")
                    ]
                    
                    cursor.executemany('''
                        INSERT INTO mcp_transcriptions
                        (session_id, raw_text, enhanced_text, context_info, processing_time_ms,
                         word_count, ai_enhanced, source_method, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', test_data)
                    
                    conn.commit()
                    conn.close()
                    
                    # Test history retrieval
                    result = await mcp_server._get_transcription_history(5, None)
                    
                    # Verify results
                    assert result["success"] is True
                    assert result["count"] == 3
                    assert len(result["transcriptions"]) == 3
                    
                    # Test session-specific history
                    result = await mcp_server._get_transcription_history(10, "session1")
                    
                    assert result["success"] is True
                    assert result["count"] == 2
                    assert result["session_filter"] == "session1"
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_error_handling_integration(self, temp_voiceflow_dir):
        """Test MCP server error handling integration."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    # Setup mocks
                    mock_server = Mock()
                    mock_server_class.return_value = mock_server
                    
                    # Create MCP server
                    mcp_server = VoiceFlowMCPServer()
                    
                    # Test transcription with non-existent file
                    result = await mcp_server._transcribe_audio_file(
                        "/nonexistent/file.wav", 
                        "general", 
                        True
                    )
                    
                    assert "error" in result
                    assert "not found" in result["error"]
                    
                    # Test enhancement with empty text
                    result = await mcp_server._enhance_text("", "general")
                    
                    assert "error" in result
                    assert "No text provided" in result["error"]
                    
                    # Test injection with empty text
                    result = await mcp_server._inject_text("", "auto")
                    
                    assert "error" in result
                    assert "No text provided" in result["error"]


class TestWebSocketIntegration:
    """Test WebSocket server integration (if applicable)."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_websocket_server_basic_integration(self, temp_voiceflow_dir):
        """Test basic WebSocket server integration."""
        # Note: This test assumes a WebSocket server implementation exists
        # If not implemented, this test will be skipped
        
        try:
            # Try to import WebSocket server components
            from python.simple_server import SimpleServer
            websocket_available = True
        except ImportError:
            websocket_available = False
        
        if not websocket_available:
            pytest.skip("WebSocket server not available")
        
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('core.voiceflow_core.AudioToTextRecorder') as mock_recorder:
                with patch('core.ai_enhancement.requests') as mock_requests:
                    # Setup mocks
                    mock_recorder.return_value = Mock()
                    mock_requests.get.return_value.status_code = 200
                    mock_requests.get.return_value.json.return_value = {
                        'models': [{'name': 'test-model:latest'}]
                    }
                    
                    # Test would go here if WebSocket server exists
                    # For now, just verify the test infrastructure
                    assert True  # Placeholder
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_websocket_message_handling(self, temp_voiceflow_dir):
        """Test WebSocket message handling integration."""
        # This is a placeholder test for WebSocket message handling
        # Would test actual WebSocket message processing if implemented
        
        pytest.skip("WebSocket message handling not implemented")


class TestServerCommunication:
    """Test communication between different server components."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_core_component_communication(self, temp_voiceflow_dir):
        """Test communication between MCP server and core components."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    with patch('voiceflow_mcp_server.AudioToTextRecorder') as mock_recorder_class:
                        with patch('voiceflow_mcp_server.requests') as mock_requests:
                            # Setup mocks
                            mock_server = Mock()
                            mock_server_class.return_value = mock_server
                            
                            mock_recorder = Mock()
                            mock_recorder_class.return_value = mock_recorder
                            
                            # Mock AI enhancement
                            mock_requests.get.return_value.status_code = 200
                            mock_requests.get.return_value.json.return_value = {
                                'models': [{'name': 'test-model:latest'}]
                            }
                            
                            # Create MCP server
                            mcp_server = VoiceFlowMCPServer()
                            
                            # Test that MCP server can communicate with core components
                            # This verifies the integration points are working
                            
                            # Test AI enhancement communication
                            assert mcp_server.use_ai_enhancement is True
                            assert mcp_server.deepseek_model == 'test-model:latest'
                            assert mcp_server.ollama_url is not None
                            
                            # Test database communication
                            assert mcp_server.db_path.exists()
                            
                            # Test speech processor communication
                            assert mcp_server.recorder is not None
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_server_configuration_propagation(self, temp_voiceflow_dir):
        """Test configuration propagation to server components."""
        # Create test configuration
        config_dir = temp_voiceflow_dir
        config_dir.mkdir(exist_ok=True)
        
        # Set environment variables for server configuration
        import os
        original_env = {}
        test_env = {
            'OLLAMA_HOST': 'test-server',
            'OLLAMA_PORT': '8080',
            'ENABLE_AI_ENHANCEMENT': 'false',
            'AI_MODEL': 'server-test-model'
        }
        
        for key, value in test_env.items():
            original_env[key] = os.getenv(key)
            os.environ[key] = value
        
        try:
            with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
                with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                    with patch('voiceflow_mcp_server.Server') as mock_server_class:
                        with patch('voiceflow_mcp_server.requests') as mock_requests:
                            # Setup mocks
                            mock_server = Mock()
                            mock_server_class.return_value = mock_server
                            
                            # Mock failed connection (AI enhancement disabled)
                            mock_requests.get.side_effect = Exception("Connection failed")
                            
                            # Create MCP server
                            mcp_server = VoiceFlowMCPServer()
                            
                            # Verify configuration was applied
                            assert 'test-server:8080' in mcp_server.ollama_urls[0]
                            assert mcp_server.use_ai_enhancement is False  # Disabled due to connection failure
                            
        finally:
            # Restore original environment
            for key, value in original_env.items():
                if value is not None:
                    os.environ[key] = value
                elif key in os.environ:
                    del os.environ[key]
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_server_database_integration(self, temp_voiceflow_dir):
        """Test server database integration and data consistency."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    # Setup mocks
                    mock_server = Mock()
                    mock_server_class.return_value = mock_server
                    
                    # Create MCP server
                    mcp_server = VoiceFlowMCPServer()
                    
                    # Test database operations
                    await mcp_server._save_transcription(
                        session_id="test_session",
                        raw_text="test transcription",
                        enhanced_text="Test transcription.",
                        context_info="general",
                        processing_time_ms=150,
                        word_count=2,
                        ai_enhanced=True,
                        source_method="test_method",
                        metadata={"test": "data"}
                    )
                    
                    # Verify data was saved
                    import sqlite3
                    conn = sqlite3.connect(mcp_server.db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM mcp_transcriptions WHERE session_id = ?", ("test_session",))
                    result = cursor.fetchone()
                    conn.close()
                    
                    assert result is not None
                    assert result[2] == "test_session"  # session_id
                    assert result[3] == "test transcription"  # raw_text
                    assert result[4] == "Test transcription."  # enhanced_text
                    assert result[5] == "general"  # context_info
                    assert result[6] == 150  # processing_time_ms
                    assert result[7] == 2  # word_count
                    assert result[8] == 1  # ai_enhanced (boolean -> integer)
                    assert result[9] == "test_method"  # source_method
                    
                    # Test data consistency
                    metadata = json.loads(result[10])
                    assert metadata["test"] == "data"


class TestServerFailureModes:
    """Test server behavior under failure conditions."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_server_initialization_failures(self, temp_voiceflow_dir):
        """Test MCP server behavior when initialization fails."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            # Test MCP framework not available
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', False):
                with pytest.raises(ImportError):
                    VoiceFlowMCPServer()
            
            # Test database initialization failure
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    with patch('sqlite3.connect', side_effect=Exception("Database error")):
                        mock_server = Mock()
                        mock_server_class.return_value = mock_server
                        
                        # Should handle database error gracefully
                        mcp_server = VoiceFlowMCPServer()
                        # Should not crash, but database operations will fail
                        assert mcp_server.server is not None
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_server_service_failures(self, temp_voiceflow_dir):
        """Test MCP server behavior when external services fail."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    with patch('voiceflow_mcp_server.requests') as mock_requests:
                        # Setup mocks
                        mock_server = Mock()
                        mock_server_class.return_value = mock_server
                        
                        # Mock complete service failure
                        mock_requests.get.side_effect = Exception("Service unavailable")
                        
                        # Create MCP server
                        mcp_server = VoiceFlowMCPServer()
                        
                        # Should handle service failure gracefully
                        assert mcp_server.use_ai_enhancement is False
                        assert mcp_server.ollama_url is None
                        
                        # Should still work with basic functionality
                        result = await mcp_server._enhance_text("test text", "general")
                        assert result["success"] is True
                        assert result["enhanced_text"] == "Test text."  # Basic formatting
                        assert result["ai_enhanced"] is False
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_mcp_server_resource_limitations(self, temp_voiceflow_dir):
        """Test MCP server behavior under resource limitations."""
        with patch('pathlib.Path.home', return_value=temp_voiceflow_dir.parent):
            with patch('voiceflow_mcp_server.MCP_AVAILABLE', True):
                with patch('voiceflow_mcp_server.Server') as mock_server_class:
                    # Setup mocks
                    mock_server = Mock()
                    mock_server_class.return_value = mock_server
                    
                    # Create MCP server
                    mcp_server = VoiceFlowMCPServer()
                    
                    # Test database resource exhaustion
                    with patch('sqlite3.connect') as mock_connect:
                        mock_conn = Mock()
                        mock_cursor = Mock()
                        mock_cursor.execute.side_effect = Exception("Out of memory")
                        mock_conn.cursor.return_value = mock_cursor
                        mock_connect.return_value = mock_conn
                        
                        # Should handle resource exhaustion gracefully
                        result = await mcp_server._get_statistics()
                        assert "error" in result
                        assert "Failed to get statistics" in result["error"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])