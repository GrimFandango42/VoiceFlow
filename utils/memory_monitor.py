"""
Memory Monitor for VoiceFlow Long Sessions

Real-time memory tracking and optimization for extended transcription sessions.
Provides memory pressure detection, automatic cleanup, and performance metrics.
"""

import os
import gc
import time
import psutil
import threading
from typing import Dict, Optional, Callable, List, Tuple
from dataclasses import dataclass
from collections import deque
from datetime import datetime, timedelta


@dataclass
class MemorySnapshot:
    """Snapshot of memory usage at a point in time."""
    timestamp: datetime
    process_memory_mb: float
    system_memory_percent: float
    cache_size: int
    gc_collections: int
    session_uptime_minutes: float


class MemoryPressureDetector:
    """Detects memory pressure and recommends cleanup actions."""
    
    def __init__(self, 
                 memory_threshold_percent: float = 85.0,
                 process_threshold_mb: float = 1024.0):
        self.memory_threshold_percent = memory_threshold_percent
        self.process_threshold_mb = process_threshold_mb
        self.pressure_history = deque(maxlen=10)
        
    def check_pressure(self, snapshot: MemorySnapshot) -> Tuple[bool, str]:
        """
        Check if system is under memory pressure.
        
        Returns:
            (is_under_pressure, recommended_action)
        """
        reasons = []
        
        # Check system memory
        if snapshot.system_memory_percent > self.memory_threshold_percent:
            reasons.append(f"System memory at {snapshot.system_memory_percent:.1f}%")
        
        # Check process memory
        if snapshot.process_memory_mb > self.process_threshold_mb:
            reasons.append(f"Process using {snapshot.process_memory_mb:.1f}MB")
        
        # Check cache size growth
        if len(self.pressure_history) >= 3:
            recent_snapshots = list(self.pressure_history)[-3:]
            cache_growth = recent_snapshots[-1].cache_size - recent_snapshots[0].cache_size
            if cache_growth > 500:  # Cache grew by 500+ entries
                reasons.append(f"Cache grew by {cache_growth} entries")
        
        self.pressure_history.append(snapshot)
        
        if reasons:
            action = self._recommend_action(snapshot, reasons)
            return True, f"Memory pressure: {'; '.join(reasons)}. Action: {action}"
        
        return False, "Normal"
    
    def _recommend_action(self, snapshot: MemorySnapshot, reasons: List[str]) -> str:
        """Recommend cleanup action based on pressure reasons."""
        if snapshot.cache_size > 1000:
            return "Aggressive cache cleanup"
        elif snapshot.system_memory_percent > 90:
            return "Force garbage collection"
        else:
            return "Standard cache eviction"


class MemoryMonitor:
    """
    Real-time memory monitoring and optimization for long VoiceFlow sessions.
    """
    
    def __init__(self, 
                 check_interval_seconds: float = 30.0,
                 max_process_memory_mb: float = 2048.0,
                 enable_auto_cleanup: bool = True):
        """
        Initialize memory monitor.
        
        Args:
            check_interval_seconds: How often to check memory usage
            max_process_memory_mb: Maximum allowed process memory before cleanup
            enable_auto_cleanup: Whether to automatically trigger cleanup actions
        """
        self.check_interval = check_interval_seconds
        self.max_process_memory_mb = max_process_memory_mb
        self.enable_auto_cleanup = enable_auto_cleanup
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.session_start_time = datetime.now()
        
        # Memory tracking
        self.snapshots: deque[MemorySnapshot] = deque(maxlen=100)  # Last 100 snapshots
        self.pressure_detector = MemoryPressureDetector()
        
        # Callbacks for cleanup actions
        self.cleanup_callbacks: Dict[str, Callable] = {}
        
        # Performance metrics
        self.cleanup_count = 0
        self.gc_forced_count = 0
        self.last_cleanup_time: Optional[datetime] = None
        
        # Get process handle
        self.process = psutil.Process()
    
    def register_cleanup_callback(self, name: str, callback: Callable):
        """Register a cleanup callback function."""
        self.cleanup_callbacks[name] = callback
    
    def start_monitoring(self):
        """Start background memory monitoring."""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print(f"[Memory] Monitoring started (check interval: {self.check_interval}s)")
    
    def stop_monitoring(self):
        """Stop background memory monitoring."""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        print("[Memory] Monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop (runs in background thread)."""
        while self.is_monitoring:
            try:
                snapshot = self._take_snapshot()
                self.snapshots.append(snapshot)
                
                # Check for memory pressure
                is_pressure, message = self.pressure_detector.check_pressure(snapshot)
                
                if is_pressure:
                    print(f"[Memory] {message}")
                    
                    if self.enable_auto_cleanup:
                        self._trigger_cleanup(snapshot)
                
                # Log periodic status
                if len(self.snapshots) % 10 == 0:  # Every 10 checks
                    self._log_status(snapshot)
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                print(f"[Memory] Monitor error: {e}")
                time.sleep(self.check_interval)
    
    def _take_snapshot(self) -> MemorySnapshot:
        """Take a snapshot of current memory usage."""
        try:
            # Process memory info
            memory_info = self.process.memory_info()
            process_memory_mb = memory_info.rss / 1024 / 1024
            
            # System memory info
            system_memory = psutil.virtual_memory()
            system_memory_percent = system_memory.percent
            
            # Runtime info
            uptime_minutes = (datetime.now() - self.session_start_time).total_seconds() / 60
            
            # Get cache size from callbacks if available
            cache_size = 0
            if 'get_cache_size' in self.cleanup_callbacks:
                try:
                    cache_size = self.cleanup_callbacks['get_cache_size']()
                except Exception:
                    pass
            
            # GC info
            gc_collections = sum(gc.get_stats()[i]['collections'] for i in range(len(gc.get_stats())))
            
            return MemorySnapshot(
                timestamp=datetime.now(),
                process_memory_mb=process_memory_mb,
                system_memory_percent=system_memory_percent,
                cache_size=cache_size,
                gc_collections=gc_collections,
                session_uptime_minutes=uptime_minutes
            )
            
        except Exception as e:
            print(f"[Memory] Failed to take snapshot: {e}")
            # Return empty snapshot
            return MemorySnapshot(
                timestamp=datetime.now(),
                process_memory_mb=0,
                system_memory_percent=0,
                cache_size=0,
                gc_collections=0,
                session_uptime_minutes=0
            )
    
    def _trigger_cleanup(self, snapshot: MemorySnapshot):
        """Trigger appropriate cleanup actions based on memory pressure."""
        try:
            cleanup_triggered = False
            
            # Aggressive cache cleanup for high memory usage
            if (snapshot.process_memory_mb > self.max_process_memory_mb * 0.8 or
                snapshot.system_memory_percent > 90):
                
                if 'aggressive_cache_cleanup' in self.cleanup_callbacks:
                    self.cleanup_callbacks['aggressive_cache_cleanup']()
                    cleanup_triggered = True
                    print("[Memory] Triggered aggressive cache cleanup")
            
            # Standard cache eviction
            elif snapshot.cache_size > 1000:
                if 'cache_eviction' in self.cleanup_callbacks:
                    self.cleanup_callbacks['cache_eviction']()
                    cleanup_triggered = True
                    print("[Memory] Triggered cache eviction")
            
            # Force garbage collection as last resort
            if snapshot.system_memory_percent > 95:
                self._force_garbage_collection()
                cleanup_triggered = True
            
            if cleanup_triggered:
                self.cleanup_count += 1
                self.last_cleanup_time = datetime.now()
        
        except Exception as e:
            print(f"[Memory] Cleanup failed: {e}")
    
    def _force_garbage_collection(self):
        """Force garbage collection to free memory."""
        try:
            gc.collect()
            self.gc_forced_count += 1
            print("[Memory] Forced garbage collection")
        except Exception as e:
            print(f"[Memory] GC failed: {e}")
    
    def _log_status(self, snapshot: MemorySnapshot):
        """Log periodic memory status."""
        print(f"[Memory] Status: {snapshot.process_memory_mb:.1f}MB process, "
              f"{snapshot.system_memory_percent:.1f}% system, "
              f"{snapshot.cache_size} cache entries, "
              f"{snapshot.session_uptime_minutes:.1f}min uptime")
    
    def get_current_status(self) -> Dict:
        """Get current memory status and metrics."""
        if not self.snapshots:
            return {"status": "No data available"}
        
        latest = self.snapshots[-1]
        
        # Calculate trends
        memory_trend = "stable"
        if len(self.snapshots) >= 5:
            recent_memory = [s.process_memory_mb for s in list(self.snapshots)[-5:]]
            if recent_memory[-1] > recent_memory[0] * 1.2:
                memory_trend = "increasing"
            elif recent_memory[-1] < recent_memory[0] * 0.8:
                memory_trend = "decreasing"
        
        return {
            "process_memory_mb": latest.process_memory_mb,
            "system_memory_percent": latest.system_memory_percent,
            "cache_size": latest.cache_size,
            "session_uptime_hours": latest.session_uptime_minutes / 60,
            "memory_trend": memory_trend,
            "cleanup_count": self.cleanup_count,
            "gc_forced_count": self.gc_forced_count,
            "last_cleanup": self.last_cleanup_time.isoformat() if self.last_cleanup_time else None,
            "monitoring_active": self.is_monitoring
        }
    
    def get_memory_history(self, hours: int = 1) -> List[Dict]:
        """Get memory usage history for the specified time period."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        history = []
        for snapshot in self.snapshots:
            if snapshot.timestamp >= cutoff_time:
                history.append({
                    "timestamp": snapshot.timestamp.isoformat(),
                    "process_memory_mb": snapshot.process_memory_mb,
                    "system_memory_percent": snapshot.system_memory_percent,
                    "cache_size": snapshot.cache_size
                })
        
        return history
    
    def optimize_for_long_session(self):
        """Apply optimizations specifically for long-running sessions."""
        print("[Memory] Applying long session optimizations...")
        
        # More frequent but lighter monitoring
        self.check_interval = 15.0  # Check every 15 seconds
        
        # Lower memory thresholds for long sessions
        self.pressure_detector.memory_threshold_percent = 75.0
        self.pressure_detector.process_threshold_mb = 512.0
        
        # More aggressive cleanup
        self.max_process_memory_mb = 1024.0
        
        print("[Memory] Long session mode enabled")
    
    def create_memory_checkpoint(self) -> Dict:
        """Create a checkpoint of current memory state for session recovery."""
        if not self.snapshots:
            return {}
        
        latest = self.snapshots[-1]
        
        return {
            "checkpoint_time": datetime.now().isoformat(),
            "session_uptime_minutes": latest.session_uptime_minutes,
            "process_memory_mb": latest.process_memory_mb,
            "cache_size": latest.cache_size,
            "cleanup_count": self.cleanup_count,
            "gc_forced_count": self.gc_forced_count,
            "memory_trend": self._calculate_memory_trend()
        }
    
    def _calculate_memory_trend(self) -> str:
        """Calculate memory usage trend over recent snapshots."""
        if len(self.snapshots) < 3:
            return "insufficient_data"
        
        recent_snapshots = list(self.snapshots)[-5:]  # Last 5 snapshots
        memory_values = [s.process_memory_mb for s in recent_snapshots]
        
        # Simple trend calculation
        start_memory = memory_values[0]
        end_memory = memory_values[-1]
        
        change_percent = ((end_memory - start_memory) / start_memory) * 100
        
        if change_percent > 10:
            return "increasing"
        elif change_percent < -10:
            return "decreasing"
        else:
            return "stable"


def create_memory_monitor(config: Optional[Dict] = None) -> MemoryMonitor:
    """Factory function to create a configured memory monitor."""
    default_config = {
        'check_interval_seconds': 30.0,
        'max_process_memory_mb': 2048.0,
        'enable_auto_cleanup': True
    }
    
    if config:
        default_config.update(config)
    
    return MemoryMonitor(**default_config)