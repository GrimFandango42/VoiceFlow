"""
Secure Database Utilities for VoiceFlow

Provides encrypted storage for sensitive transcription data.
Uses Fernet encryption for symmetric encryption of database content.
"""

import os
import sqlite3
import base64
from pathlib import Path
from typing import Optional, Dict, Any, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureDatabase:
    """Encrypted database wrapper for VoiceFlow transcriptions."""
    
    def __init__(self, db_path: Path, encryption_key: Optional[bytes] = None):
        """
        Initialize secure database with encryption.
        
        Args:
            db_path: Path to SQLite database file
            encryption_key: Optional encryption key (auto-generated if None)
        """
        self.db_path = db_path
        self.key_path = db_path.parent / ".voiceflow_key"
        
        # Initialize encryption
        if encryption_key:
            self.cipher = Fernet(encryption_key)
        else:
            self.cipher = self._get_or_create_cipher()
        
        # Initialize database
        self._init_database()
    
    def _get_or_create_cipher(self) -> Fernet:
        """Get or create encryption cipher with persistent key."""
        if self.key_path.exists():
            # Load existing key
            with open(self.key_path, 'rb') as f:
                key = f.read()
        else:
            # Generate new key from system entropy
            key = Fernet.generate_key()
            
            # Store key securely (600 permissions)
            with open(self.key_path, 'wb') as f:
                f.write(key)
            os.chmod(self.key_path, 0o600)  # Owner read/write only
        
        return Fernet(key)
    
    def _init_database(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transcriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_text TEXT NOT NULL,
                processing_time_ms INTEGER NOT NULL,
                word_count INTEGER NOT NULL,
                model_used TEXT NOT NULL,
                session_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def encrypt_text(self, text: str) -> str:
        """Encrypt text using Fernet encryption."""
        if not text:
            return ""
        
        encrypted_bytes = self.cipher.encrypt(text.encode('utf-8'))
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    
    def decrypt_text(self, encrypted_text: str) -> str:
        """Decrypt text using Fernet encryption."""
        if not encrypted_text:
            return ""
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            print(f"[WARNING] Failed to decrypt text: {e}")
            return "[ENCRYPTED_DATA]"
    
    def store_transcription(self, text: str, processing_time: float, 
                          word_count: int, model_used: str, session_id: str) -> bool:
        """Store encrypted transcription in database."""
        try:
            encrypted_text = self.encrypt_text(text)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO transcriptions 
                (encrypted_text, processing_time_ms, word_count, model_used, session_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                encrypted_text,
                int(processing_time),
                word_count,
                model_used,
                session_id
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to store encrypted transcription: {e}")
            return False
    
    def get_transcription_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get decrypted transcription history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, encrypted_text, processing_time_ms, word_count, 
                       model_used, session_id, timestamp
                FROM transcriptions
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            results = []
            for row in cursor.fetchall():
                decrypted_text = self.decrypt_text(row[1])
                results.append({
                    'id': row[0],
                    'text': decrypted_text,
                    'processing_time_ms': row[2],
                    'word_count': row[3],
                    'model_used': row[4],
                    'session_id': row[5],
                    'timestamp': row[6]
                })
            
            conn.close()
            return results
            
        except Exception as e:
            print(f"[ERROR] Failed to retrieve transcription history: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregated statistics (without exposing encrypted content)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_transcriptions,
                    SUM(word_count) as total_words,
                    AVG(processing_time_ms) as avg_processing_time,
                    MIN(timestamp) as first_transcription,
                    MAX(timestamp) as last_transcription
                FROM transcriptions
            ''')
            
            row = cursor.fetchone()
            conn.close()
            
            return {
                'total_transcriptions': row[0] or 0,
                'total_words': row[1] or 0,
                'average_processing_time_ms': round(row[2] or 0, 1),
                'first_transcription': row[3],
                'last_transcription': row[4]
            }
            
        except Exception as e:
            print(f"[ERROR] Failed to get statistics: {e}")
            return {}
    
    def cleanup_old_data(self, days_to_keep: int = 30) -> int:
        """Remove transcriptions older than specified days."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM transcriptions 
                WHERE datetime(timestamp) < datetime('now', '-{} days')
            '''.format(days_to_keep))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            print(f"[DB] Cleaned up {deleted_count} old transcriptions")
            return deleted_count
            
        except Exception as e:
            print(f"[ERROR] Failed to cleanup old data: {e}")
            return 0


def create_secure_database(data_dir: Path) -> SecureDatabase:
    """Factory function to create a secure database instance."""
    db_path = data_dir / "transcriptions.db"
    return SecureDatabase(db_path)