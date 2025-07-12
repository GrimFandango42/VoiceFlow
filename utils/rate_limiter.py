"""
Rate Limiting utilities for VoiceFlow

Provides rate limiting functionality to prevent abuse and DoS attacks.
"""

import time
from typing import Dict, Optional
from collections import defaultdict, deque


class RateLimiter:
    """Simple rate limiter implementation."""
    
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)
    
    def is_allowed(self, client_id: str) -> bool:
        """
        Check if request is allowed for client.
        
        Args:
            client_id: Unique identifier for client
            
        Returns:
            True if request is allowed, False otherwise
        """
        current_time = time.time()
        client_requests = self.requests[client_id]
        
        # Remove old requests outside the time window
        while client_requests and current_time - client_requests[0] > self.window_seconds:
            client_requests.popleft()
        
        # Check if we're under the limit
        if len(client_requests) < self.max_requests:
            client_requests.append(current_time)
            return True
        
        return False
    
    def get_reset_time(self, client_id: str) -> Optional[float]:
        """
        Get time when rate limit resets for client.
        
        Args:
            client_id: Unique identifier for client
            
        Returns:
            Unix timestamp when limit resets, None if not limited
        """
        client_requests = self.requests[client_id]
        if not client_requests:
            return None
        
        oldest_request = client_requests[0]
        return oldest_request + self.window_seconds
    
    def cleanup_old_entries(self, max_age_hours: int = 24):
        """Clean up old client entries to prevent memory leaks."""
        current_time = time.time()
        cutoff_time = current_time - (max_age_hours * 3600)
        
        clients_to_remove = []
        for client_id, requests in self.requests.items():
            if not requests or requests[-1] < cutoff_time:
                clients_to_remove.append(client_id)
        
        for client_id in clients_to_remove:
            del self.requests[client_id]


class WebSocketRateLimiter:
    """Rate limiter specifically for WebSocket connections."""
    
    def __init__(self):
        """Initialize WebSocket rate limiter with sensible defaults."""
        # Connection rate limiting
        self.connection_limiter = RateLimiter(max_requests=10, window_seconds=60)
        
        # Message rate limiting
        self.message_limiter = RateLimiter(max_requests=100, window_seconds=60)
        
        # Authentication attempt limiting
        self.auth_limiter = RateLimiter(max_requests=5, window_seconds=300)  # 5 attempts per 5 minutes
    
    def can_connect(self, client_ip: str) -> bool:
        """Check if client can establish new connection."""
        return self.connection_limiter.is_allowed(f"conn_{client_ip}")
    
    def can_send_message(self, client_id: str) -> bool:
        """Check if client can send message."""
        return self.message_limiter.is_allowed(f"msg_{client_id}")
    
    def can_authenticate(self, client_ip: str) -> bool:
        """Check if client can attempt authentication."""
        return self.auth_limiter.is_allowed(f"auth_{client_ip}")
    
    def get_connection_reset_time(self, client_ip: str) -> Optional[float]:
        """Get when connection rate limit resets."""
        return self.connection_limiter.get_reset_time(f"conn_{client_ip}")
    
    def get_message_reset_time(self, client_id: str) -> Optional[float]:
        """Get when message rate limit resets."""
        return self.message_limiter.get_reset_time(f"msg_{client_id}")


# Global rate limiter instances
_websocket_limiter = None

def get_websocket_limiter() -> WebSocketRateLimiter:
    """Get global WebSocket rate limiter instance."""
    global _websocket_limiter
    if _websocket_limiter is None:
        _websocket_limiter = WebSocketRateLimiter()
    return _websocket_limiter