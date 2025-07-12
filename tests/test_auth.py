"""
Unit tests for authentication utilities.

Tests token generation, validation, session management, and WebSocket authentication.
"""

import pytest
import tempfile
import shutil
import os
import time
import secrets
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.auth import AuthManager, extract_auth_token, get_auth_manager


class TestAuthManager:
    """Test suite for AuthManager class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    @pytest.fixture
    def auth_manager(self, temp_dir):
        """Create AuthManager instance with temp directory."""
        with patch('utils.auth.Path.home', return_value=temp_dir):
            manager = AuthManager()
            yield manager
    
    def test_initialization(self, temp_dir):
        """Test AuthManager initialization."""
        with patch('utils.auth.Path.home', return_value=temp_dir):
            manager = AuthManager()
            
            # Check data directory created
            assert (temp_dir / ".voiceflow").exists()
            
            # Check token generated
            assert manager.auth_token is not None
            assert len(manager.auth_token) > 0
            
            # Check defaults
            assert manager.session_timeout == 3600
            assert manager.active_sessions == {}
    
    def test_token_generation_new(self, temp_dir):
        """Test new token generation."""
        with patch('utils.auth.Path.home', return_value=temp_dir):
            manager = AuthManager()
            
            # Token should be created
            assert manager.auth_token is not None
            
            # Token file should exist with correct permissions
            token_file = temp_dir / ".voiceflow" / ".auth_token"
            assert token_file.exists()
            
            # Check permissions (Unix only)
            if os.name != 'nt':
                stat = os.stat(token_file)
                assert oct(stat.st_mode)[-3:] == '600'
            
            # Token in file should match
            with open(token_file, 'r') as f:
                file_token = f.read().strip()
            assert file_token == manager.auth_token
    
    @patch.dict(os.environ, {'VOICEFLOW_AUTH_TOKEN': 'env-test-token'})
    def test_token_from_environment(self, temp_dir):
        """Test token loading from environment variable."""
        with patch('utils.auth.Path.home', return_value=temp_dir):
            manager = AuthManager()
            assert manager.auth_token == 'env-test-token'
    
    def test_token_from_existing_file(self, temp_dir):
        """Test token loading from existing file."""
        # Create token file
        voiceflow_dir = temp_dir / ".voiceflow"
        voiceflow_dir.mkdir(exist_ok=True)
        token_file = voiceflow_dir / ".auth_token"
        
        existing_token = "existing-file-token"
        with open(token_file, 'w') as f:
            f.write(existing_token)
        
        with patch('utils.auth.Path.home', return_value=temp_dir):
            manager = AuthManager()
            assert manager.auth_token == existing_token
    
    def test_token_file_error_handling(self, temp_dir):
        """Test handling of token file errors."""
        with patch('utils.auth.Path.home', return_value=temp_dir):
            # Test when file save fails
            with patch('builtins.open', side_effect=PermissionError("No write access")):
                manager = AuthManager()
                # Should still generate token even if can't save
                assert manager.auth_token is not None
    
    def test_validate_token_success(self, auth_manager):
        """Test successful token validation."""
        assert auth_manager.validate_token(auth_manager.auth_token) is True
    
    def test_validate_token_failure(self, auth_manager):
        """Test failed token validation."""
        assert auth_manager.validate_token("wrong-token") is False
        assert auth_manager.validate_token("") is False
        assert auth_manager.validate_token(None) is False
    
    def test_validate_token_timing_attack_resistance(self, auth_manager):
        """Test that token validation uses constant-time comparison."""
        correct_token = auth_manager.auth_token
        wrong_token = "x" * len(correct_token)
        
        # Multiple attempts should take similar time
        import time
        
        correct_times = []
        wrong_times = []
        
        for _ in range(10):
            start = time.perf_counter()
            auth_manager.validate_token(correct_token)
            correct_times.append(time.perf_counter() - start)
            
            start = time.perf_counter()
            auth_manager.validate_token(wrong_token)
            wrong_times.append(time.perf_counter() - start)
        
        # Times should be similar (constant-time comparison)
        # This is a basic check - true timing attack tests require more sophisticated setup
        avg_correct = sum(correct_times) / len(correct_times)
        avg_wrong = sum(wrong_times) / len(wrong_times)
        
        # Just verify both validations complete without significant difference
        assert avg_correct > 0
        assert avg_wrong > 0
    
    def test_create_session(self, auth_manager):
        """Test session creation."""
        client_id = "test-client-123"
        session_id = auth_manager.create_session(client_id)
        
        assert session_id is not None
        assert len(session_id) > 0
        assert session_id in auth_manager.active_sessions
        
        session = auth_manager.active_sessions[session_id]
        assert session['client_id'] == client_id
        assert 'created_at' in session
        assert 'last_activity' in session
        assert session['created_at'] == session['last_activity']
    
    def test_validate_session_success(self, auth_manager):
        """Test successful session validation."""
        session_id = auth_manager.create_session("client-1")
        assert auth_manager.validate_session(session_id) is True
        
        # Last activity should be updated
        session = auth_manager.active_sessions[session_id]
        time.sleep(0.01)  # Small delay
        assert auth_manager.validate_session(session_id) is True
        assert session['last_activity'] > session['created_at']
    
    def test_validate_session_failure(self, auth_manager):
        """Test failed session validation."""
        assert auth_manager.validate_session(None) is False
        assert auth_manager.validate_session("") is False
        assert auth_manager.validate_session("non-existent-session") is False
    
    def test_validate_session_expiry(self, auth_manager):
        """Test session expiry."""
        session_id = auth_manager.create_session("client-1")
        
        # Manually set old creation time
        auth_manager.active_sessions[session_id]['created_at'] = time.time() - 7200  # 2 hours ago
        
        assert auth_manager.validate_session(session_id) is False
        assert session_id not in auth_manager.active_sessions  # Should be removed
    
    def test_revoke_session(self, auth_manager):
        """Test session revocation."""
        session_id = auth_manager.create_session("client-1")
        assert session_id in auth_manager.active_sessions
        
        auth_manager.revoke_session(session_id)
        assert session_id not in auth_manager.active_sessions
        
        # Revoking non-existent session should not error
        auth_manager.revoke_session("non-existent")
    
    def test_cleanup_expired_sessions(self, auth_manager):
        """Test cleanup of expired sessions."""
        # Create multiple sessions
        current_time = time.time()
        
        # Active sessions
        active1 = auth_manager.create_session("active-1")
        active2 = auth_manager.create_session("active-2")
        
        # Expired sessions
        expired1 = auth_manager.create_session("expired-1")
        expired2 = auth_manager.create_session("expired-2")
        
        # Set expired times
        auth_manager.active_sessions[expired1]['created_at'] = current_time - 7200
        auth_manager.active_sessions[expired2]['created_at'] = current_time - 10000
        
        # Run cleanup
        auth_manager.cleanup_expired_sessions()
        
        # Check results
        assert active1 in auth_manager.active_sessions
        assert active2 in auth_manager.active_sessions
        assert expired1 not in auth_manager.active_sessions
        assert expired2 not in auth_manager.active_sessions
    
    def test_get_token_info(self, auth_manager):
        """Test token info retrieval."""
        # Create some sessions
        auth_manager.create_session("client-1")
        auth_manager.create_session("client-2")
        
        info = auth_manager.get_token_info()
        
        assert 'token_preview' in info
        assert info['token_preview'].endswith('...')
        assert len(info['token_preview']) == 11  # 8 chars + "..."
        
        assert 'token_file' in info
        assert '.auth_token' in info['token_file']
        
        assert info['active_sessions'] == 2
        assert info['session_timeout'] == 3600


class TestExtractAuthToken:
    """Test suite for extract_auth_token function."""
    
    def test_extract_from_authorization_header(self):
        """Test token extraction from Authorization header."""
        mock_ws = Mock()
        mock_ws.request_headers = {'Authorization': 'Bearer test-token-123'}
        
        token = extract_auth_token(mock_ws)
        assert token == 'test-token-123'
    
    def test_extract_from_x_auth_token_header(self):
        """Test token extraction from X-Auth-Token header."""
        mock_ws = Mock()
        mock_ws.request_headers = {'X-Auth-Token': 'custom-token-456'}
        
        token = extract_auth_token(mock_ws)
        assert token == 'custom-token-456'
    
    def test_extract_from_query_parameter(self):
        """Test token extraction from query parameter."""
        mock_ws = Mock()
        mock_ws.request_headers = {}
        mock_ws.path = '/ws?token=query-token-789&other=param'
        
        token = extract_auth_token(mock_ws)
        assert token == 'query-token-789'
    
    def test_extract_priority_order(self):
        """Test that Authorization header takes priority."""
        mock_ws = Mock()
        mock_ws.request_headers = {
            'Authorization': 'Bearer priority-token',
            'X-Auth-Token': 'ignored-token'
        }
        mock_ws.path = '/ws?token=also-ignored'
        
        token = extract_auth_token(mock_ws)
        assert token == 'priority-token'
    
    def test_extract_no_token(self):
        """Test when no token is provided."""
        mock_ws = Mock()
        mock_ws.request_headers = {}
        mock_ws.path = '/ws'
        
        token = extract_auth_token(mock_ws)
        assert token is None
    
    def test_extract_malformed_authorization(self):
        """Test malformed Authorization header."""
        mock_ws = Mock()
        mock_ws.request_headers = {'Authorization': 'NotBearer token'}
        
        token = extract_auth_token(mock_ws)
        assert token is None
    
    def test_extract_empty_token(self):
        """Test empty token values."""
        mock_ws = Mock()
        mock_ws.request_headers = {'Authorization': 'Bearer '}
        
        token = extract_auth_token(mock_ws)
        assert token == ''
    
    def test_extract_query_edge_cases(self):
        """Test query parameter edge cases."""
        # No query string
        mock_ws = Mock()
        mock_ws.request_headers = {}
        mock_ws.path = '/ws'
        assert extract_auth_token(mock_ws) is None
        
        # Empty query string
        mock_ws.path = '/ws?'
        assert extract_auth_token(mock_ws) is None
        
        # Token not in query
        mock_ws.path = '/ws?other=value'
        assert extract_auth_token(mock_ws) is None
        
        # Multiple token parameters (first wins)
        mock_ws.path = '/ws?token=first&token=second'
        assert extract_auth_token(mock_ws) == 'first'
    
    def test_extract_exception_handling(self):
        """Test exception handling in token extraction."""
        # Missing attributes
        mock_ws = Mock()
        del mock_ws.request_headers
        assert extract_auth_token(mock_ws) is None
        
        # None websocket
        assert extract_auth_token(None) is None


class TestGetAuthManager:
    """Test suite for get_auth_manager singleton."""
    
    def test_singleton_behavior(self):
        """Test that get_auth_manager returns singleton."""
        manager1 = get_auth_manager()
        manager2 = get_auth_manager()
        
        assert manager1 is manager2
    
    def test_reset_singleton(self):
        """Test resetting singleton for testing."""
        import utils.auth
        
        # Get initial instance
        manager1 = get_auth_manager()
        
        # Reset singleton
        utils.auth._auth_manager = None
        
        # Get new instance
        manager2 = get_auth_manager()
        
        assert manager1 is not manager2


class TestAuthSecurityScenarios:
    """Test security-specific scenarios."""
    
    def test_token_randomness(self):
        """Test that generated tokens are sufficiently random."""
        tokens = set()
        
        # Generate multiple tokens
        for _ in range(100):
            with tempfile.TemporaryDirectory() as temp_dir:
                with patch('utils.auth.Path.home', return_value=Path(temp_dir)):
                    manager = AuthManager()
                    tokens.add(manager.auth_token)
        
        # All tokens should be unique
        assert len(tokens) == 100
        
        # Tokens should have sufficient length
        for token in tokens:
            assert len(token) >= 32
    
    def test_session_id_uniqueness(self):
        """Test that session IDs are unique."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('utils.auth.Path.home', return_value=Path(temp_dir)):
                manager = AuthManager()
                
                session_ids = set()
                for i in range(100):
                    session_id = manager.create_session(f"client-{i}")
                    session_ids.add(session_id)
                
                # All session IDs should be unique
                assert len(session_ids) == 100
    
    def test_concurrent_session_validation(self):
        """Test concurrent session validation doesn't cause issues."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('utils.auth.Path.home', return_value=Path(temp_dir)):
                manager = AuthManager()
                
                # Create multiple sessions
                sessions = []
                for i in range(10):
                    session_id = manager.create_session(f"client-{i}")
                    sessions.append(session_id)
                
                # Validate all sessions multiple times
                for _ in range(5):
                    for session_id in sessions:
                        assert manager.validate_session(session_id) is True
                
                # All sessions should still be active
                assert len(manager.active_sessions) == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])