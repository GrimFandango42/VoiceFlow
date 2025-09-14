"""
Secure Database Utilities for VoiceFlow

Provides encrypted storage for sensitive transcription data.
Uses Fernet encryption for symmetric encryption of database content.
"""

import os
import sqlite3
import base64
import zlib
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureDatabase:
    """
    Enhanced encrypted database wrapper for VoiceFlow transcriptions.
    
    Features for long sessions:
    - Automatic compression for large transcriptions
    - Session-based table partitioning
    - Rolling cleanup and storage management
    - Storage quota enforcement
    """
    
    def __init__(self, 
                 db_path: Path, 
                 encryption_key: Optional[bytes] = None,
                 enable_compression: bool = True,
                 compression_threshold: int = 1024,
                 max_storage_mb: int = 500):
        """
        Initialize secure database with enhanced features.
        
        Args:
            db_path: Path to SQLite database file
            encryption_key: Optional encryption key (auto-generated if None)
            enable_compression: Whether to compress large transcriptions
            compression_threshold: Minimum text size (bytes) to trigger compression
            max_storage_mb: Maximum storage allowed before cleanup
        """
        self.db_path = db_path
        self.key_path = db_path.parent / ".voiceflow_key"
        
        # Compression settings
        self.enable_compression = enable_compression
        self.compression_threshold = compression_threshold
        self.max_storage_mb = max_storage_mb
        
        # Performance tracking
        self.compression_stats = {
            'compressed_count': 0,
            'original_bytes': 0,
            'compressed_bytes': 0,
            'compression_ratio': 0.0
        }
        
        # Initialize encryption
        if encryption_key:
            self.cipher = Fernet(encryption_key)
        else:
            self.cipher = self._get_or_create_cipher()
        
        # Initialize database with partitioning
        self._init_database_with_partitioning()
    
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
    
    def _init_database_with_partitioning(self):
        """Initialize database schema with partitioning and optimization features."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main transcriptions table with compression support
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transcriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_text TEXT NOT NULL,
                is_compressed BOOLEAN DEFAULT 0,
                original_size INTEGER DEFAULT 0,
                compressed_size INTEGER DEFAULT 0,
                processing_time_ms INTEGER NOT NULL,
                word_count INTEGER NOT NULL,
                model_used TEXT NOT NULL,
                session_id TEXT NOT NULL,
                partition_date TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Session metadata table for partitioning
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_metadata (
                session_id TEXT PRIMARY KEY,
                start_time DATETIME NOT NULL,
                end_time DATETIME,
                total_transcriptions INTEGER DEFAULT 0,
                total_words INTEGER DEFAULT 0,
                total_size_bytes INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Storage statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS storage_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total_size_mb REAL NOT NULL,
                compressed_count INTEGER DEFAULT 0,
                compression_ratio REAL DEFAULT 0.0,
                last_cleanup DATETIME,
                measurement_time DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_transcriptions_session 
            ON transcriptions(session_id)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_transcriptions_partition 
            ON transcriptions(partition_date)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_transcriptions_timestamp 
            ON transcriptions(timestamp)
        ''')
        
        # Enable WAL mode for better concurrent access
        cursor.execute('PRAGMA journal_mode=WAL')
        
        # Optimize for long sessions
        cursor.execute('PRAGMA synchronous=NORMAL')
        cursor.execute('PRAGMA cache_size=10000')
        cursor.execute('PRAGMA temp_store=MEMORY')
        
        conn.commit()
        conn.close()
    
    def encrypt_text(self, text: str, force_compression: bool = False) -> tuple[str, bool, int, int]:
        """
        Encrypt text with optional compression.
        
        Returns:
            (encrypted_text, is_compressed, original_size, compressed_size)
        """
        if not text:
            return "", False, 0, 0
        
        text_bytes = text.encode('utf-8')
        original_size = len(text_bytes)
        is_compressed = False
        compressed_size = original_size
        
        # Apply compression if enabled and text is large enough
        if (self.enable_compression and 
            (original_size >= self.compression_threshold or force_compression)):
            try:
                compressed_bytes = zlib.compress(text_bytes, level=6)  # Balanced compression
                if len(compressed_bytes) < original_size * 0.9:  # Only use if >10% reduction
                    text_bytes = compressed_bytes
                    is_compressed = True
                    compressed_size = len(compressed_bytes)
                    
                    # Update compression stats
                    self.compression_stats['compressed_count'] += 1
                    self.compression_stats['original_bytes'] += original_size
                    self.compression_stats['compressed_bytes'] += compressed_size
                    if self.compression_stats['original_bytes'] > 0:
                        self.compression_stats['compression_ratio'] = (
                            self.compression_stats['compressed_bytes'] / 
                            self.compression_stats['original_bytes']
                        )
            except Exception as e:
                print(f"[WARNING] Compression failed: {e}")
        
        # Encrypt the (possibly compressed) data
        encrypted_bytes = self.cipher.encrypt(text_bytes)
        encrypted_text = base64.b64encode(encrypted_bytes).decode('utf-8')
        
        return encrypted_text, is_compressed, original_size, compressed_size
    
    def decrypt_text(self, encrypted_text: str, is_compressed: bool = False) -> str:
        """Decrypt text with decompression support."""
        if not encrypted_text:
            return ""
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
            
            # Decompress if needed
            if is_compressed:
                try:
                    decrypted_bytes = zlib.decompress(decrypted_bytes)
                except Exception as e:
                    print(f"[WARNING] Decompression failed: {e}")
                    return "[CORRUPTED_COMPRESSED_DATA]"
            
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            print(f"[WARNING] Failed to decrypt text: {e}")
            return "[ENCRYPTED_DATA]"
    
    def store_transcription(self, text: str, processing_time: float, 
                          word_count: int, model_used: str, session_id: str) -> bool:
        """Store encrypted transcription with compression and partitioning."""
        try:
            # Encrypt with optional compression
            encrypted_text, is_compressed, original_size, compressed_size = self.encrypt_text(text)
            
            # Get partition date (YYYY-MM for monthly partitions)
            partition_date = datetime.now().strftime('%Y-%m')
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Store transcription
            cursor.execute('''
                INSERT INTO transcriptions 
                (encrypted_text, is_compressed, original_size, compressed_size,
                 processing_time_ms, word_count, model_used, session_id, partition_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                encrypted_text,
                is_compressed,
                original_size,
                compressed_size,
                int(processing_time),
                word_count,
                model_used,
                session_id,
                partition_date
            ))
            
            # Update session metadata
            cursor.execute('''
                INSERT OR REPLACE INTO session_metadata 
                (session_id, start_time, total_transcriptions, total_words, total_size_bytes, is_active)
                VALUES (?, ?, 
                    COALESCE((SELECT total_transcriptions FROM session_metadata WHERE session_id = ?), 0) + 1,
                    COALESCE((SELECT total_words FROM session_metadata WHERE session_id = ?), 0) + ?,
                    COALESCE((SELECT total_size_bytes FROM session_metadata WHERE session_id = ?), 0) + ?,
                    1)
            ''', (
                session_id, 
                datetime.now().isoformat(),
                session_id,
                session_id, word_count,
                session_id, compressed_size
            ))
            
            conn.commit()
            
            # Check storage quota and cleanup if needed
            if self._check_storage_quota(cursor):
                self._rolling_cleanup(cursor, conn)
            
            conn.close()
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to store encrypted transcription: {e}")
            return False
    
    def get_transcription_history(self, limit: int = 100, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get decrypted transcription history with compression support."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if session_id:
                cursor.execute('''
                    SELECT id, encrypted_text, is_compressed, original_size, compressed_size,
                           processing_time_ms, word_count, model_used, session_id, timestamp
                    FROM transcriptions
                    WHERE session_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (session_id, limit))
            else:
                cursor.execute('''
                    SELECT id, encrypted_text, is_compressed, original_size, compressed_size,
                           processing_time_ms, word_count, model_used, session_id, timestamp
                    FROM transcriptions
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))
            
            results = []
            for row in cursor.fetchall():
                decrypted_text = self.decrypt_text(row[1], row[2])  # Pass is_compressed flag
                results.append({
                    'id': row[0],
                    'text': decrypted_text,
                    'is_compressed': bool(row[2]),
                    'original_size': row[3],
                    'compressed_size': row[4],
                    'compression_ratio': row[4] / max(1, row[3]) if row[2] else 1.0,
                    'processing_time_ms': row[5],
                    'word_count': row[6],
                    'model_used': row[7],
                    'session_id': row[8],
                    'timestamp': row[9]
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
    
    def _check_storage_quota(self, cursor) -> bool:
        """Check if storage quota is exceeded."""
        try:
            # Get database file size
            db_size_mb = self.db_path.stat().st_size / (1024 * 1024)
            return db_size_mb > self.max_storage_mb
        except Exception:
            return False
    
    def _rolling_cleanup(self, cursor, conn):
        """Perform rolling cleanup based on age and size."""
        try:
            print(f"[DB] Storage quota exceeded ({self.max_storage_mb}MB), performing cleanup...")
            
            # Delete oldest partitions first
            cursor.execute('''
                DELETE FROM transcriptions 
                WHERE partition_date < date('now', '-3 months')
            ''')
            deleted_old = cursor.rowcount
            
            # If still over quota, delete oldest sessions
            if self._check_storage_quota(cursor):
                cursor.execute('''
                    DELETE FROM transcriptions 
                    WHERE session_id IN (
                        SELECT session_id FROM session_metadata 
                        WHERE is_active = 0 
                        ORDER BY end_time ASC 
                        LIMIT 10
                    )
                ''')
                deleted_sessions = cursor.rowcount
                
                # Mark those sessions as cleaned up
                cursor.execute('''
                    DELETE FROM session_metadata 
                    WHERE is_active = 0 
                    AND session_id NOT IN (SELECT DISTINCT session_id FROM transcriptions)
                ''')
            else:
                deleted_sessions = 0
            
            # Update storage stats
            cursor.execute('''
                INSERT INTO storage_stats (total_size_mb, last_cleanup)
                VALUES (?, ?)
            ''', (self.db_path.stat().st_size / (1024 * 1024), datetime.now().isoformat()))
            
            conn.commit()
            print(f"[DB] Cleanup completed: {deleted_old} old entries, {deleted_sessions} session entries")
            
        except Exception as e:
            print(f"[ERROR] Rolling cleanup failed: {e}")
    
    def get_storage_info(self) -> Dict[str, Any]:
        """Get storage usage information."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Database file size
            db_size_mb = self.db_path.stat().st_size / (1024 * 1024)
            
            # Count compressed vs uncompressed
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_entries,
                    SUM(CASE WHEN is_compressed = 1 THEN 1 ELSE 0 END) as compressed_entries,
                    SUM(original_size) as total_original_bytes,
                    SUM(compressed_size) as total_stored_bytes
                FROM transcriptions
            ''')
            
            stats = cursor.fetchone()
            
            # Active sessions
            cursor.execute('SELECT COUNT(*) FROM session_metadata WHERE is_active = 1')
            active_sessions = cursor.fetchone()[0]
            
            # Partition info
            cursor.execute('''
                SELECT partition_date, COUNT(*) as entries
                FROM transcriptions 
                GROUP BY partition_date 
                ORDER BY partition_date DESC
            ''')
            partitions = [{'date': row[0], 'entries': row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            compression_ratio = 0.0
            if stats[2] > 0:  # total_original_bytes
                compression_ratio = stats[3] / stats[2]  # total_stored_bytes / total_original_bytes
            
            return {
                'database_size_mb': round(db_size_mb, 2),
                'max_storage_mb': self.max_storage_mb,
                'usage_percent': round((db_size_mb / self.max_storage_mb) * 100, 1),
                'total_entries': stats[0] or 0,
                'compressed_entries': stats[1] or 0,
                'compression_ratio': round(compression_ratio, 3),
                'compression_enabled': self.enable_compression,
                'compression_threshold': self.compression_threshold,
                'active_sessions': active_sessions,
                'partitions': partitions,
                'compression_stats': self.compression_stats
            }
            
        except Exception as e:
            print(f"[ERROR] Failed to get storage info: {e}")
            return {}
    
    def force_compression_optimization(self) -> Dict[str, int]:
        """Force compression of existing uncompressed entries."""
        if not self.enable_compression:
            return {'error': 'Compression not enabled'}
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Find large uncompressed entries
            cursor.execute('''
                SELECT id, encrypted_text, original_size
                FROM transcriptions 
                WHERE is_compressed = 0 AND original_size >= ?
                ORDER BY original_size DESC
                LIMIT 100
            ''', (self.compression_threshold,))
            
            candidates = cursor.fetchall()
            compressed_count = 0
            bytes_saved = 0
            
            for entry_id, encrypted_text, original_size in candidates:
                try:
                    # Decrypt, then re-encrypt with compression
                    decrypted_text = self.decrypt_text(encrypted_text, False)
                    if decrypted_text and not decrypted_text.startswith('['):
                        new_encrypted, is_compressed, orig_size, comp_size = self.encrypt_text(
                            decrypted_text, force_compression=True)
                        
                        if is_compressed and comp_size < original_size:
                            cursor.execute('''
                                UPDATE transcriptions 
                                SET encrypted_text = ?, is_compressed = 1, compressed_size = ?
                                WHERE id = ?
                            ''', (new_encrypted, comp_size, entry_id))
                            
                            compressed_count += 1
                            bytes_saved += (original_size - comp_size)
                            
                except Exception as e:
                    print(f"[WARNING] Failed to compress entry {entry_id}: {e}")
                    continue
            
            conn.commit()
            conn.close()
            
            return {
                'compressed_count': compressed_count,
                'bytes_saved': bytes_saved,
                'candidates_processed': len(candidates)
            }
            
        except Exception as e:
            print(f"[ERROR] Compression optimization failed: {e}")
            return {'error': str(e)}


def create_secure_database(data_dir: Path, **kwargs) -> SecureDatabase:
    """Factory function to create a secure database instance with optimizations."""
    db_path = data_dir / "transcriptions.db"
    return SecureDatabase(db_path, **kwargs)