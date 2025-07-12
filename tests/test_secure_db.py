"""
Unit tests for secure database utilities.

Tests encryption/decryption functionality, key management, and database operations.
"""

import pytest
import tempfile
import shutil
import sqlite3
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import base64

# Add parent directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.secure_db import SecureDatabase, create_secure_database
from cryptography.fernet import Fernet


class TestSecureDatabase:
    """Test suite for SecureDatabase class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    @pytest.fixture
    def secure_db(self, temp_dir):
        """Create SecureDatabase instance."""
        db_path = temp_dir / "test.db"
        db = SecureDatabase(db_path)
        yield db
        # Cleanup
        if db_path.exists():
            os.remove(db_path)
        key_path = temp_dir / ".voiceflow_key"
        if key_path.exists():
            os.remove(key_path)
    
    def test_initialization(self, temp_dir):
        """Test database initialization."""
        db_path = temp_dir / "test.db"
        db = SecureDatabase(db_path)
        
        # Check database file created
        assert db_path.exists()
        
        # Check encryption key created
        assert db.key_path.exists()
        
        # Check key file permissions (Unix only)
        if os.name != 'nt':
            key_stat = os.stat(db.key_path)
            assert oct(key_stat.st_mode)[-3:] == '600'
    
    def test_initialization_with_custom_key(self, temp_dir):
        """Test initialization with custom encryption key."""
        db_path = temp_dir / "test.db"
        custom_key = Fernet.generate_key()
        
        db = SecureDatabase(db_path, encryption_key=custom_key)
        
        # Should use provided key
        test_text = "Test encryption"
        encrypted = db.encrypt_text(test_text)
        
        # Verify custom key works
        cipher = Fernet(custom_key)
        decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted))
        assert decrypted_bytes.decode('utf-8') == test_text
    
    def test_persistent_key(self, temp_dir):
        """Test that encryption key persists across instances."""
        db_path = temp_dir / "test.db"
        
        # Create first instance
        db1 = SecureDatabase(db_path)
        encrypted1 = db1.encrypt_text("Test message")
        
        # Create second instance (should load same key)
        db2 = SecureDatabase(db_path)
        decrypted2 = db2.decrypt_text(encrypted1)
        
        assert decrypted2 == "Test message"
    
    def test_database_schema(self, secure_db):
        """Test database schema creation."""
        conn = sqlite3.connect(secure_db.db_path)
        cursor = conn.cursor()
        
        # Check table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transcriptions'")
        assert cursor.fetchone() is not None
        
        # Check columns
        cursor.execute("PRAGMA table_info(transcriptions)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}
        
        expected_columns = {
            'id': 'INTEGER',
            'encrypted_text': 'TEXT',
            'processing_time_ms': 'INTEGER',
            'word_count': 'INTEGER',
            'model_used': 'TEXT',
            'session_id': 'TEXT',
            'timestamp': 'DATETIME'
        }
        
        for col_name, col_type in expected_columns.items():
            assert col_name in columns
            assert columns[col_name] == col_type
        
        conn.close()
    
    def test_encrypt_text(self, secure_db):
        """Test text encryption."""
        # Test normal text
        plain_text = "This is a test transcription"
        encrypted = secure_db.encrypt_text(plain_text)
        
        # Should be base64 encoded
        assert isinstance(encrypted, str)
        base64.b64decode(encrypted)  # Should not raise
        
        # Should be different from original
        assert encrypted != plain_text
        
        # Test empty string
        assert secure_db.encrypt_text("") == ""
        
        # Test Unicode
        unicode_text = "Hello 世界 🌍"
        encrypted_unicode = secure_db.encrypt_text(unicode_text)
        assert isinstance(encrypted_unicode, str)
    
    def test_decrypt_text(self, secure_db):
        """Test text decryption."""
        # Test round trip
        original = "Test message with punctuation!"
        encrypted = secure_db.encrypt_text(original)
        decrypted = secure_db.decrypt_text(encrypted)
        assert decrypted == original
        
        # Test empty string
        assert secure_db.decrypt_text("") == ""
        
        # Test invalid encrypted text
        invalid_encrypted = "InvalidBase64!!!"
        result = secure_db.decrypt_text(invalid_encrypted)
        assert result == "[ENCRYPTED_DATA]"
        
        # Test corrupted encrypted text
        encrypted = secure_db.encrypt_text("Valid text")
        corrupted = encrypted[:-4] + "XXXX"  # Corrupt the end
        result = secure_db.decrypt_text(corrupted)
        assert result == "[ENCRYPTED_DATA]"
    
    def test_store_transcription(self, secure_db):
        """Test storing encrypted transcription."""
        success = secure_db.store_transcription(
            text="Test transcription",
            processing_time=123.45,
            word_count=2,
            model_used="test-model",
            session_id="test-session"
        )
        
        assert success is True
        
        # Verify data was stored encrypted
        conn = sqlite3.connect(secure_db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM transcriptions")
        row = cursor.fetchone()
        
        assert row is not None
        assert row[1] != "Test transcription"  # Should be encrypted
        assert row[2] == 123  # processing_time_ms
        assert row[3] == 2    # word_count
        assert row[4] == "test-model"
        assert row[5] == "test-session"
        
        # Verify we can decrypt it
        decrypted = secure_db.decrypt_text(row[1])
        assert decrypted == "Test transcription"
        
        conn.close()
    
    def test_store_transcription_error(self, secure_db):
        """Test error handling in store_transcription."""
        # Test with database error
        with patch('sqlite3.connect', side_effect=Exception("DB Error")):
            success = secure_db.store_transcription(
                text="Test",
                processing_time=100,
                word_count=1,
                model_used="model",
                session_id="session"
            )
            assert success is False
    
    def test_get_transcription_history(self, secure_db):
        """Test retrieving decrypted transcription history."""
        # Store multiple transcriptions
        texts = ["First transcription", "Second one", "Third message"]
        for i, text in enumerate(texts):
            secure_db.store_transcription(
                text=text,
                processing_time=100 + i*10,
                word_count=len(text.split()),
                model_used=f"model-{i}",
                session_id=f"session-{i}"
            )
        
        # Retrieve history
        history = secure_db.get_transcription_history(limit=2)
        
        assert len(history) == 2
        # Should be in reverse chronological order
        assert history[0]['text'] == "Third message"
        assert history[1]['text'] == "Second one"
        
        # Check all fields
        assert history[0]['processing_time_ms'] == 120
        assert history[0]['word_count'] == 2
        assert history[0]['model_used'] == "model-2"
        assert history[0]['session_id'] == "session-2"
        assert 'timestamp' in history[0]
        assert 'id' in history[0]
    
    def test_get_transcription_history_error(self, secure_db):
        """Test error handling in get_transcription_history."""
        with patch('sqlite3.connect', side_effect=Exception("DB Error")):
            history = secure_db.get_transcription_history()
            assert history == []
    
    def test_get_statistics(self, secure_db):
        """Test statistics retrieval."""
        # Empty database
        stats = secure_db.get_statistics()
        assert stats['total_transcriptions'] == 0
        assert stats['total_words'] == 0
        assert stats['average_processing_time_ms'] == 0
        
        # Add some data
        for i in range(3):
            secure_db.store_transcription(
                text=f"Text with {i+2} words",
                processing_time=100 * (i+1),
                word_count=i+2,
                model_used="model",
                session_id="session"
            )
        
        stats = secure_db.get_statistics()
        assert stats['total_transcriptions'] == 3
        assert stats['total_words'] == 2 + 3 + 4  # 9
        assert stats['average_processing_time_ms'] == 200.0  # (100+200+300)/3
        assert stats['first_transcription'] is not None
        assert stats['last_transcription'] is not None
    
    def test_get_statistics_error(self, secure_db):
        """Test error handling in get_statistics."""
        with patch('sqlite3.connect', side_effect=Exception("DB Error")):
            stats = secure_db.get_statistics()
            assert stats == {}
    
    def test_cleanup_old_data(self, secure_db):
        """Test cleaning up old transcriptions."""
        # Insert old data (simulate old timestamps)
        conn = sqlite3.connect(secure_db.db_path)
        cursor = conn.cursor()
        
        # Insert data with different ages
        for days_ago in [40, 35, 25, 20, 10]:
            cursor.execute('''
                INSERT INTO transcriptions 
                (encrypted_text, processing_time_ms, word_count, model_used, session_id, timestamp)
                VALUES (?, ?, ?, ?, ?, datetime('now', '-{} days'))
            '''.format(days_ago), ("encrypted", 100, 1, "model", "session"))
        
        conn.commit()
        conn.close()
        
        # Clean up data older than 30 days
        deleted = secure_db.cleanup_old_data(days_to_keep=30)
        assert deleted == 2  # Should delete entries 40 and 35 days old
        
        # Verify remaining data
        history = secure_db.get_transcription_history()
        assert len(history) == 3
    
    def test_cleanup_old_data_error(self, secure_db):
        """Test error handling in cleanup_old_data."""
        with patch('sqlite3.connect', side_effect=Exception("DB Error")):
            deleted = secure_db.cleanup_old_data()
            assert deleted == 0
    
    def test_encryption_with_special_characters(self, secure_db):
        """Test encryption with special characters and edge cases."""
        test_cases = [
            "Simple text",
            "Text with\nnewlines\nand\ttabs",
            "Unicode: 你好世界 🌍 émojis",
            "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?",
            "Very " + "long " * 100 + "text",
            " " * 50,  # Just spaces
            "\n\n\n",  # Just newlines
        ]
        
        for original in test_cases:
            encrypted = secure_db.encrypt_text(original)
            decrypted = secure_db.decrypt_text(encrypted)
            assert decrypted == original
    
    def test_create_secure_database_factory(self, temp_dir):
        """Test the factory function."""
        db = create_secure_database(temp_dir)
        
        assert isinstance(db, SecureDatabase)
        assert db.db_path == temp_dir / "transcriptions.db"
        assert db.db_path.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])