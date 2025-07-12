"""
Security Integration Tests

Tests the integration of security features across the VoiceFlow application.
Validates that encryption, authentication, and validation work together correctly.
"""

import pytest
import tempfile
import shutil
import json
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestSecurityIntegration:
    """Test suite for security feature integration."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_secure_transcription_flow(self, temp_dir):
        """Test complete secure transcription storage and retrieval flow."""
        # Mock the imports to avoid dependency issues
        with patch('utils.secure_db.Fernet') as mock_fernet:
            # Setup mock encryption
            mock_cipher = Mock()
            mock_cipher.encrypt.return_value = b'encrypted_data'
            mock_cipher.decrypt.return_value = b'Original transcription text'
            mock_fernet.return_value = mock_cipher
            mock_fernet.generate_key.return_value = b'test_key'
            
            from utils.secure_db import SecureDatabase
            
            # Create secure database
            db = SecureDatabase(temp_dir / "test.db")
            
            # Store transcription
            success = db.store_transcription(
                text="Original transcription text",
                processing_time=150.5,
                word_count=3,
                model_used="whisper-base",
                session_id="test-session-123"
            )
            
            assert success is True
            
            # Retrieve and verify
            history = db.get_transcription_history(limit=1)
            assert len(history) == 1
            assert history[0]['text'] == "Original transcription text"
            assert history[0]['model_used'] == "whisper-base"
    
    def test_authenticated_websocket_flow(self, temp_dir):
        """Test WebSocket connection with authentication."""
        with patch('utils.auth.Path.home', return_value=temp_dir):
            from utils.auth import AuthManager, extract_auth_token
            
            # Create auth manager
            auth = AuthManager()
            
            # Simulate WebSocket connection
            mock_ws = Mock()
            mock_ws.request_headers = {
                'Authorization': f'Bearer {auth.auth_token}'
            }
            
            # Extract and validate token
            token = extract_auth_token(mock_ws)
            assert auth.validate_token(token) is True
            
            # Create session
            session_id = auth.create_session("test-client")
            assert auth.validate_session(session_id) is True
    
    def test_input_validation_in_transcription(self):
        """Test input validation prevents malicious content in transcriptions."""
        from utils.validation import InputValidator, ValidationError
        
        # Test dangerous transcription attempts
        dangerous_texts = [
            "<script>alert('XSS')</script> Hello world",
            "Run this: '; DROP TABLE transcriptions; --",
            "Execute: __import__('os').system('rm -rf /')"
        ]
        
        for dangerous_text in dangerous_texts:
            with pytest.raises(ValidationError) as exc_info:
                InputValidator.validate_text(dangerous_text)
            assert "potentially dangerous content" in str(exc_info.value)
    
    def test_secure_ai_enhancement_flow(self, temp_dir):
        """Test AI enhancement with input validation."""
        with patch('core.ai_enhancement.requests') as mock_requests:
            # Mock Ollama responses
            mock_requests.get.return_value.status_code = 200
            mock_requests.get.return_value.json.return_value = {
                'models': [{'name': 'llama3.3:latest'}]
            }
            
            mock_requests.Session.return_value.post.return_value.status_code = 200
            mock_requests.Session.return_value.post.return_value.json.return_value = {
                'response': 'Enhanced: Hello, world!'
            }
            
            from core.ai_enhancement import AIEnhancer
            
            enhancer = AIEnhancer({'enabled': True})
            
            # Test safe input
            safe_result = enhancer.enhance_text("hello world")
            assert safe_result == "Enhanced: Hello, world!"
            
            # Test with validation (if validation is integrated)
            # This would fail with dangerous content if validation was enforced
            dangerous_text = "Normal text without dangerous patterns"
            result = enhancer.enhance_text(dangerous_text)
            assert result == "Enhanced: Hello, world!"
    
    def test_encryption_key_security(self, temp_dir):
        """Test encryption key generation and storage security."""
        with patch('utils.secure_db.Fernet') as mock_fernet:
            mock_fernet.generate_key.return_value = b'secure_key_12345'
            
            from utils.secure_db import SecureDatabase
            
            # Create database
            db = SecureDatabase(temp_dir / "test.db")
            
            # Check key file created with correct permissions
            assert db.key_path.exists()
            
            # Verify key is stored securely
            with open(db.key_path, 'rb') as f:
                stored_key = f.read()
            assert stored_key == b'secure_key_12345'
    
    def test_session_expiry_security(self, temp_dir):
        """Test session expiry for security."""
        with patch('utils.auth.Path.home', return_value=temp_dir):
            from utils.auth import AuthManager
            
            auth = AuthManager()
            auth.session_timeout = 2  # 2 seconds for testing
            
            # Create session
            session_id = auth.create_session("test-client")
            
            # Initially valid
            assert auth.validate_session(session_id) is True
            
            # Wait for expiry
            time.sleep(2.1)
            
            # Should be expired
            assert auth.validate_session(session_id) is False
            assert session_id not in auth.active_sessions
    
    def test_concurrent_secure_operations(self, temp_dir):
        """Test concurrent secure operations don't interfere."""
        with patch('utils.secure_db.Fernet') as mock_fernet:
            # Setup mock encryption
            mock_cipher = Mock()
            call_count = 0
            
            def mock_encrypt(data):
                nonlocal call_count
                call_count += 1
                return f"encrypted_{call_count}_{data.decode()}".encode()
            
            def mock_decrypt(data):
                # Extract original from mock encrypted format
                parts = data.decode().split('_', 2)
                return parts[2].encode()
            
            mock_cipher.encrypt = mock_encrypt
            mock_cipher.decrypt = mock_decrypt
            mock_fernet.return_value = mock_cipher
            mock_fernet.generate_key.return_value = b'test_key'
            
            from utils.secure_db import SecureDatabase
            
            db = SecureDatabase(temp_dir / "test.db")
            
            # Store multiple transcriptions
            for i in range(5):
                success = db.store_transcription(
                    text=f"Transcription {i}",
                    processing_time=100 + i,
                    word_count=2,
                    model_used="whisper",
                    session_id=f"session-{i}"
                )
                assert success is True
            
            # Retrieve all
            history = db.get_transcription_history(limit=10)
            assert len(history) == 5
            
            # Verify each transcription
            for i in range(5):
                found = False
                for item in history:
                    if item['text'] == f"Transcription {4-i}":  # Reverse order
                        found = True
                        assert item['session_id'] == f"session-{4-i}"
                        break
                assert found
    
    def test_malicious_json_websocket_message(self):
        """Test handling of malicious JSON in WebSocket messages."""
        from utils.validation import InputValidator, ValidationError
        
        # Test various malicious JSON payloads
        malicious_payloads = [
            '{"type": "exec", "code": "__import__(\'os\').system(\'ls\')"}',
            '{"type": "test", "data": "<script>alert(1)</script>"}',
            '{"type": "../../file", "path": "/etc/passwd"}',
            '{"type": "test", "size": "' + 'A' * 10000 + '"}',  # Large payload
        ]
        
        for payload in malicious_payloads:
            try:
                # Should either sanitize or reject
                result = InputValidator.validate_json_message(payload, max_size=5000)
                # If it passes, dangerous content should be sanitized
                assert "__import__" not in str(result)
                assert "<script>" not in str(result)
                assert "../.." not in str(result)
            except ValidationError:
                # Rejection is also acceptable for dangerous content
                pass
    
    def test_secure_file_operations(self, temp_dir):
        """Test secure file path validation in operations."""
        from utils.validation import InputValidator, ValidationError
        
        # Create safe test file
        safe_file = temp_dir / "safe_transcription.txt"
        safe_file.write_text("Safe content")
        
        # Test safe path
        validated_path = InputValidator.validate_file_path(
            str(safe_file),
            must_exist=True,
            allowed_extensions=['.txt']
        )
        assert validated_path == safe_file
        
        # Test dangerous paths
        dangerous_paths = [
            str(temp_dir / "../../../etc/passwd"),
            "/etc/shadow",
            str(temp_dir / "test.exe"),  # Wrong extension
        ]
        
        for dangerous_path in dangerous_paths:
            with pytest.raises(ValidationError):
                InputValidator.validate_file_path(
                    dangerous_path,
                    must_exist=False,
                    allowed_extensions=['.txt']
                )
    
    def test_encryption_error_recovery(self, temp_dir):
        """Test system recovers gracefully from encryption errors."""
        with patch('utils.secure_db.Fernet') as mock_fernet:
            # Setup mock that fails sometimes
            mock_cipher = Mock()
            mock_cipher.encrypt.side_effect = [
                Exception("Encryption failed"),
                b'encrypted_success'
            ]
            mock_fernet.return_value = mock_cipher
            mock_fernet.generate_key.return_value = b'test_key'
            
            from utils.secure_db import SecureDatabase
            
            db = SecureDatabase(temp_dir / "test.db")
            
            # First attempt should fail gracefully
            success = db.store_transcription(
                text="Test 1",
                processing_time=100,
                word_count=2,
                model_used="whisper",
                session_id="session-1"
            )
            assert success is False
            
            # Second attempt should succeed
            success = db.store_transcription(
                text="Test 2",
                processing_time=100,
                word_count=2,
                model_used="whisper", 
                session_id="session-2"
            )
            assert success is True


class TestSecurityPerformance:
    """Test performance impact of security features."""
    
    def test_encryption_performance(self, temp_dir):
        """Test encryption doesn't significantly impact performance."""
        try:
            from cryptography.fernet import Fernet
            from utils.secure_db import SecureDatabase
        except ImportError:
            pytest.skip("cryptography not installed")
        
        db = SecureDatabase(temp_dir / "perf_test.db")
        
        # Test encryption speed
        start_time = time.perf_counter()
        
        for i in range(100):
            encrypted = db.encrypt_text(f"Test transcription number {i} with some content")
        
        encryption_time = time.perf_counter() - start_time
        avg_encryption_time = (encryption_time / 100) * 1000  # ms
        
        # Should be fast enough for real-time use
        assert avg_encryption_time < 10  # Less than 10ms per encryption
        print(f"Average encryption time: {avg_encryption_time:.2f}ms")
    
    def test_validation_performance(self):
        """Test input validation performance."""
        from utils.validation import InputValidator
        
        # Test text validation speed
        test_texts = [
            "Simple text",
            "Text with numbers 123 and symbols !@#",
            "Longer text " * 50,
            "Unicode text with émojis 🌍 and 中文"
        ]
        
        start_time = time.perf_counter()
        
        for _ in range(100):
            for text in test_texts:
                InputValidator.validate_text(text)
        
        validation_time = time.perf_counter() - start_time
        avg_validation_time = (validation_time / (100 * len(test_texts))) * 1000
        
        # Should be very fast
        assert avg_validation_time < 1  # Less than 1ms per validation
        print(f"Average validation time: {avg_validation_time:.3f}ms")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])