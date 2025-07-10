"""
Authentication utilities for VoiceFlow

Provides simple token-based authentication for WebSocket connections.
Uses environment variables for secure token management.
"""

import os
import secrets
import hashlib
import time
from typing import Optional
from pathlib import Path


class AuthManager:
    """Simple authentication manager for VoiceFlow."""
    
    def __init__(self):
        """Initialize authentication manager."""
        self.data_dir = Path.home() / ".voiceflow"
        self.token_file = self.data_dir / ".auth_token"
        self.session_timeout = 3600  # 1 hour
        self.active_sessions = {}
        
        # Get or generate auth token
        self.auth_token = self._get_or_create_token()
    
    def _get_or_create_token(self) -> str:
        """Get existing token or create new one."""
        # Check environment variable first
        env_token = os.getenv('VOICEFLOW_AUTH_TOKEN')
        if env_token:
            return env_token
        
        # Check for existing token file
        if self.token_file.exists():
            try:
                with open(self.token_file, 'r') as f:
                    return f.read().strip()
            except Exception:
                pass
        
        # Generate new token
        token = secrets.token_urlsafe(32)
        
        try:
            # Save token with secure permissions
            with open(self.token_file, 'w') as f:
                f.write(token)
            os.chmod(self.token_file, 0o600)  # Owner read/write only
            print(f"[AUTH] Generated new auth token: {token[:8]}...")
            print(f"[AUTH] Token saved to: {self.token_file}")
        except Exception as e:
            print(f"[WARNING] Could not save token: {e}")
        
        return token
    
    def validate_token(self, provided_token: Optional[str]) -> bool:
        """Validate provided authentication token."""
        if not provided_token:
            return False
        
        # Simple constant-time comparison
        return secrets.compare_digest(self.auth_token, provided_token)
    
    def create_session(self, client_id: str) -> str:
        """Create authenticated session for client."""
        session_id = secrets.token_urlsafe(16)
        self.active_sessions[session_id] = {
            'client_id': client_id,
            'created_at': time.time(),
            'last_activity': time.time()
        }
        return session_id
    
    def validate_session(self, session_id: Optional[str]) -> bool:
        """Validate active session."""
        if not session_id or session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        current_time = time.time()
        
        # Check if session expired
        if current_time - session['created_at'] > self.session_timeout:
            del self.active_sessions[session_id]
            return False
        
        # Update last activity
        session['last_activity'] = current_time
        return True
    
    def revoke_session(self, session_id: str):
        """Revoke active session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        current_time = time.time()
        expired_sessions = [
            session_id for session_id, session in self.active_sessions.items()
            if current_time - session['created_at'] > self.session_timeout
        ]
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
        
        if expired_sessions:
            print(f"[AUTH] Cleaned up {len(expired_sessions)} expired sessions")
    
    def get_token_info(self) -> dict:
        """Get token information for display."""
        return {
            'token_preview': f"{self.auth_token[:8]}...",
            'token_file': str(self.token_file),
            'active_sessions': len(self.active_sessions),
            'session_timeout': self.session_timeout
        }


def extract_auth_token(websocket) -> Optional[str]:
    """Extract auth token from WebSocket headers."""
    try:
        # Try Authorization header
        auth_header = websocket.request_headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Try X-Auth-Token header
        token_header = websocket.request_headers.get('X-Auth-Token')
        if token_header:
            return token_header
        
        # Try query parameter (less secure but more convenient)
        if hasattr(websocket, 'path') and '?' in websocket.path:
            query_params = websocket.path.split('?')[1]
            for param in query_params.split('&'):
                if param.startswith('token='):
                    return param[6:]  # Remove 'token=' prefix
        
        return None
        
    except Exception:
        return None


# Global auth manager instance
_auth_manager = None

def get_auth_manager() -> AuthManager:
    """Get global auth manager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager