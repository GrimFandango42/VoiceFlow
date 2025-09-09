"""
Session Manager for VoiceFlow Long Sessions

Manages extended transcription sessions with checkpointing, pause/resume functionality,
and automatic session snapshots for recovery.
"""

import os
import json
import time
import uuid
import pickle
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List, Callable
from dataclasses import dataclass, asdict
from collections import deque

from .memory_monitor import MemoryMonitor, create_memory_monitor


@dataclass
class SessionState:
    """Represents the current state of a VoiceFlow session."""
    session_id: str
    start_time: datetime
    last_activity: datetime
    total_transcriptions: int
    total_words: int
    current_status: str  # active, paused, stopped
    cache_state: Dict[str, Any]
    memory_checkpoints: List[Dict]
    configuration: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'session_id': self.session_id,
            'start_time': self.start_time.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'total_transcriptions': self.total_transcriptions,
            'total_words': self.total_words,
            'current_status': self.current_status,
            'cache_state': self.cache_state,
            'memory_checkpoints': self.memory_checkpoints,
            'configuration': self.configuration
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'SessionState':
        """Create SessionState from dictionary."""
        return cls(
            session_id=data['session_id'],
            start_time=datetime.fromisoformat(data['start_time']),
            last_activity=datetime.fromisoformat(data['last_activity']),
            total_transcriptions=data['total_transcriptions'],
            total_words=data['total_words'],
            current_status=data['current_status'],
            cache_state=data['cache_state'],
            memory_checkpoints=data['memory_checkpoints'],
            configuration=data['configuration']
        )


class SessionCheckpoint:
    """Handles session checkpointing and recovery."""
    
    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self.session_dir.mkdir(exist_ok=True)
        
        # Checkpoint files
        self.state_file = session_dir / "session_state.json"
        self.cache_file = session_dir / "cache_checkpoint.pkl"
        self.recovery_file = session_dir / "recovery_info.json"
    
    def save_checkpoint(self, session_state: SessionState, cache_data: Any = None):
        """Save complete session checkpoint."""
        try:
            # Save session state
            with open(self.state_file, 'w') as f:
                json.dump(session_state.to_dict(), f, indent=2)
            
            # Save cache data if provided
            if cache_data is not None:
                with open(self.cache_file, 'wb') as f:
                    pickle.dump(cache_data, f)
            
            # Update recovery info
            recovery_info = {
                'last_checkpoint': datetime.now().isoformat(),
                'session_id': session_state.session_id,
                'status': session_state.current_status,
                'uptime_minutes': (datetime.now() - session_state.start_time).total_seconds() / 60
            }
            
            with open(self.recovery_file, 'w') as f:
                json.dump(recovery_info, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"[Session] Checkpoint save failed: {e}")
            return False
    
    def load_checkpoint(self) -> Optional[tuple[SessionState, Any]]:
        """Load session checkpoint."""
        try:
            if not self.state_file.exists():
                return None
            
            # Load session state
            with open(self.state_file, 'r') as f:
                state_data = json.load(f)
            
            session_state = SessionState.from_dict(state_data)
            
            # Load cache data if available
            cache_data = None
            if self.cache_file.exists():
                with open(self.cache_file, 'rb') as f:
                    cache_data = pickle.load(f)
            
            return session_state, cache_data
            
        except Exception as e:
            print(f"[Session] Checkpoint load failed: {e}")
            return None
    
    def cleanup_old_checkpoints(self, days_to_keep: int = 7):
        """Remove checkpoints older than specified days."""
        try:
            cutoff_time = datetime.now() - timedelta(days=days_to_keep)
            
            for file_path in self.session_dir.iterdir():
                if file_path.is_file():
                    file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_time < cutoff_time:
                        file_path.unlink()
                        print(f"[Session] Cleaned up old checkpoint: {file_path.name}")
        
        except Exception as e:
            print(f"[Session] Checkpoint cleanup failed: {e}")


class LongSessionManager:
    """
    Manages extended VoiceFlow sessions with advanced features:
    - 8+ hour session support
    - Automatic checkpointing
    - Pause/resume functionality
    - Memory optimization integration
    - Session recovery
    """
    
    def __init__(self, 
                 data_dir: Path,
                 checkpoint_interval_minutes: int = 30,
                 max_session_hours: int = 12,
                 auto_save_enabled: bool = True):
        """
        Initialize long session manager.
        
        Args:
            data_dir: Directory for session data
            checkpoint_interval_minutes: How often to create checkpoints
            max_session_hours: Maximum session duration before auto-pause
            auto_save_enabled: Whether to automatically save checkpoints
        """
        self.data_dir = data_dir
        self.data_dir.mkdir(exist_ok=True)
        
        self.checkpoint_interval = checkpoint_interval_minutes * 60  # Convert to seconds
        self.max_session_duration = timedelta(hours=max_session_hours)
        self.auto_save_enabled = auto_save_enabled
        
        # Session state
        self.current_session: Optional[SessionState] = None
        self.session_checkpoint = SessionCheckpoint(data_dir / "sessions")
        
        # Background tasks
        self.checkpoint_thread: Optional[threading.Thread] = None
        self.is_running = False
        
        # Memory integration
        self.memory_monitor: Optional[MemoryMonitor] = None
        
        # Callbacks for session events
        self.callbacks: Dict[str, List[Callable]] = {
            'session_start': [],
            'session_pause': [],
            'session_resume': [],
            'session_stop': [],
            'checkpoint_created': [],
            'session_timeout': []
        }
        
        # Session history
        self.session_history: deque = deque(maxlen=10)  # Keep last 10 sessions
    
    def register_callback(self, event: str, callback: Callable):
        """Register callback for session events."""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
    
    def _trigger_callbacks(self, event: str, *args, **kwargs):
        """Trigger all callbacks for an event."""
        for callback in self.callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                print(f"[Session] Callback error for {event}: {e}")
    
    def start_session(self, configuration: Optional[Dict] = None) -> str:
        """Start a new long session."""
        if self.current_session and self.current_session.current_status == 'active':
            print("[Session] Session already active")
            return self.current_session.session_id
        
        # Create new session
        session_id = str(uuid.uuid4())[:8]
        
        self.current_session = SessionState(
            session_id=session_id,
            start_time=datetime.now(),
            last_activity=datetime.now(),
            total_transcriptions=0,
            total_words=0,
            current_status='active',
            cache_state={},
            memory_checkpoints=[],
            configuration=configuration or {}
        )
        
        # Initialize memory monitoring for long sessions
        if not self.memory_monitor:
            self.memory_monitor = create_memory_monitor({
                'check_interval_seconds': 15.0,  # More frequent for long sessions
                'max_process_memory_mb': 1024.0,  # Conservative limit
                'enable_auto_cleanup': True
            })
            self.memory_monitor.optimize_for_long_session()
            self.memory_monitor.start_monitoring()
        
        # Start background tasks
        self.is_running = True
        if self.auto_save_enabled:
            self._start_checkpoint_thread()
        
        # Trigger callbacks
        self._trigger_callbacks('session_start', self.current_session)
        
        print(f"[Session] Started long session: {session_id}")
        return session_id
    
    def pause_session(self) -> bool:
        """Pause the current session."""
        if not self.current_session or self.current_session.current_status != 'active':
            print("[Session] No active session to pause")
            return False
        
        self.current_session.current_status = 'paused'
        self.current_session.last_activity = datetime.now()
        
        # Create checkpoint before pausing
        self._create_checkpoint()
        
        # Pause memory monitoring
        if self.memory_monitor:
            self.memory_monitor.stop_monitoring()
        
        # Trigger callbacks
        self._trigger_callbacks('session_pause', self.current_session)
        
        print(f"[Session] Paused session: {self.current_session.session_id}")
        return True
    
    def resume_session(self) -> bool:
        """Resume a paused session."""
        if not self.current_session or self.current_session.current_status != 'paused':
            print("[Session] No paused session to resume")
            return False
        
        self.current_session.current_status = 'active'
        self.current_session.last_activity = datetime.now()
        
        # Resume memory monitoring
        if self.memory_monitor:
            self.memory_monitor.start_monitoring()
        
        # Restart background tasks
        if self.auto_save_enabled and not self.checkpoint_thread:
            self._start_checkpoint_thread()
        
        # Trigger callbacks
        self._trigger_callbacks('session_resume', self.current_session)
        
        print(f"[Session] Resumed session: {self.current_session.session_id}")
        return True
    
    def stop_session(self) -> bool:
        """Stop the current session."""
        if not self.current_session:
            print("[Session] No active session to stop")
            return False
        
        # Final checkpoint
        self._create_checkpoint()
        
        # Add to history
        self.session_history.append({
            'session_id': self.current_session.session_id,
            'start_time': self.current_session.start_time.isoformat(),
            'end_time': datetime.now().isoformat(),
            'total_transcriptions': self.current_session.total_transcriptions,
            'total_words': self.current_session.total_words,
            'duration_minutes': (datetime.now() - self.current_session.start_time).total_seconds() / 60
        })
        
        # Stop background tasks
        self.is_running = False
        if self.checkpoint_thread:
            self.checkpoint_thread.join(timeout=5.0)
            self.checkpoint_thread = None
        
        # Stop memory monitoring
        if self.memory_monitor:
            self.memory_monitor.stop_monitoring()
        
        # Trigger callbacks
        self._trigger_callbacks('session_stop', self.current_session)
        
        print(f"[Session] Stopped session: {self.current_session.session_id}")
        
        self.current_session.current_status = 'stopped'
        self.current_session = None
        return True
    
    def recover_session(self) -> bool:
        """Attempt to recover the last session from checkpoint."""
        try:
            checkpoint_data = self.session_checkpoint.load_checkpoint()
            if not checkpoint_data:
                print("[Session] No checkpoint found for recovery")
                return False
            
            session_state, cache_data = checkpoint_data
            
            # Check if session is recent enough to recover
            time_since_checkpoint = datetime.now() - session_state.last_activity
            if time_since_checkpoint > timedelta(hours=24):
                print("[Session] Checkpoint too old for recovery")
                return False
            
            # Restore session
            self.current_session = session_state
            self.current_session.current_status = 'active'
            self.current_session.last_activity = datetime.now()
            
            # Restart background tasks
            self.is_running = True
            if self.auto_save_enabled:
                self._start_checkpoint_thread()
            
            # Restart memory monitoring
            if not self.memory_monitor:
                self.memory_monitor = create_memory_monitor()
                self.memory_monitor.optimize_for_long_session()
                self.memory_monitor.start_monitoring()
            
            print(f"[Session] Recovered session: {session_state.session_id}")
            return True
            
        except Exception as e:
            print(f"[Session] Recovery failed: {e}")
            return False
    
    def update_session_stats(self, transcriptions_delta: int = 0, words_delta: int = 0):
        """Update session statistics."""
        if not self.current_session or self.current_session.current_status != 'active':
            return
        
        self.current_session.total_transcriptions += transcriptions_delta
        self.current_session.total_words += words_delta
        self.current_session.last_activity = datetime.now()
        
        # Check for session timeout
        session_duration = datetime.now() - self.current_session.start_time
        if session_duration > self.max_session_duration:
            print(f"[Session] Maximum duration reached ({session_duration}), auto-pausing")
            self._trigger_callbacks('session_timeout', self.current_session)
            self.pause_session()
    
    def get_session_status(self) -> Dict[str, Any]:
        """Get current session status and metrics."""
        if not self.current_session:
            return {
                'status': 'no_session',
                'has_checkpoint': self.session_checkpoint.state_file.exists()
            }
        
        session_duration = datetime.now() - self.current_session.start_time
        time_until_timeout = self.max_session_duration - session_duration
        
        status = {
            'session_id': self.current_session.session_id,
            'status': self.current_session.current_status,
            'start_time': self.current_session.start_time.isoformat(),
            'duration_hours': session_duration.total_seconds() / 3600,
            'time_until_timeout_hours': max(0, time_until_timeout.total_seconds() / 3600),
            'total_transcriptions': self.current_session.total_transcriptions,
            'total_words': self.current_session.total_words,
            'last_activity': self.current_session.last_activity.isoformat(),
            'checkpoint_interval_minutes': self.checkpoint_interval / 60,
            'auto_save_enabled': self.auto_save_enabled
        }
        
        # Add memory status if available
        if self.memory_monitor:
            status['memory_status'] = self.memory_monitor.get_current_status()
        
        return status
    
    def get_session_history(self) -> List[Dict]:
        """Get history of recent sessions."""
        return list(self.session_history)
    
    def _start_checkpoint_thread(self):
        """Start background checkpoint thread."""
        if self.checkpoint_thread and self.checkpoint_thread.is_alive():
            return
        
        self.checkpoint_thread = threading.Thread(target=self._checkpoint_loop, daemon=True)
        self.checkpoint_thread.start()
    
    def _checkpoint_loop(self):
        """Background loop for creating periodic checkpoints."""
        while self.is_running and self.current_session:
            try:
                time.sleep(self.checkpoint_interval)
                
                if (self.current_session and 
                    self.current_session.current_status == 'active'):
                    self._create_checkpoint()
                    
            except Exception as e:
                print(f"[Session] Checkpoint loop error: {e}")
    
    def _create_checkpoint(self):
        """Create a session checkpoint."""
        if not self.current_session:
            return
        
        try:
            # Add memory checkpoint if monitor is available
            if self.memory_monitor:
                memory_checkpoint = self.memory_monitor.create_memory_checkpoint()
                self.current_session.memory_checkpoints.append(memory_checkpoint)
                
                # Keep only recent memory checkpoints
                if len(self.current_session.memory_checkpoints) > 20:
                    self.current_session.memory_checkpoints = self.current_session.memory_checkpoints[-10:]
            
            # Save checkpoint
            success = self.session_checkpoint.save_checkpoint(self.current_session)
            
            if success:
                self._trigger_callbacks('checkpoint_created', self.current_session)
                print(f"[Session] Checkpoint created for session {self.current_session.session_id}")
            
        except Exception as e:
            print(f"[Session] Checkpoint creation failed: {e}")
    
    def cleanup_old_sessions(self, days_to_keep: int = 7):
        """Clean up old session data."""
        try:
            self.session_checkpoint.cleanup_old_checkpoints(days_to_keep)
            print(f"[Session] Cleaned up sessions older than {days_to_keep} days")
        except Exception as e:
            print(f"[Session] Session cleanup failed: {e}")
    
    def export_session_report(self) -> Dict[str, Any]:
        """Export comprehensive session report."""
        if not self.current_session:
            return {'error': 'No active session'}
        
        session_duration = datetime.now() - self.current_session.start_time
        
        report = {
            'session_summary': {
                'session_id': self.current_session.session_id,
                'start_time': self.current_session.start_time.isoformat(),
                'duration_hours': session_duration.total_seconds() / 3600,
                'status': self.current_session.current_status,
                'total_transcriptions': self.current_session.total_transcriptions,
                'total_words': self.current_session.total_words,
                'words_per_hour': (self.current_session.total_words / 
                                 max(1, session_duration.total_seconds() / 3600))
            },
            'memory_analysis': (self.memory_monitor.get_current_status() 
                              if self.memory_monitor else {}),
            'memory_history': (self.memory_monitor.get_memory_history(hours=1) 
                             if self.memory_monitor else []),
            'checkpoints_created': len(self.current_session.memory_checkpoints),
            'configuration': self.current_session.configuration,
            'export_time': datetime.now().isoformat()
        }
        
        return report


def create_session_manager(data_dir: Path, config: Optional[Dict] = None) -> LongSessionManager:
    """Factory function to create a configured session manager."""
    default_config = {
        'checkpoint_interval_minutes': 30,
        'max_session_hours': 12,
        'auto_save_enabled': True
    }
    
    if config:
        default_config.update(config)
    
    return LongSessionManager(data_dir, **default_config)