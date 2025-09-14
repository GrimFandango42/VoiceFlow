#!/usr/bin/env python3
"""
Production-Optimized Logging System for VoiceFlow
High-performance logging with minimal overhead and structured metrics.
"""

import time
import threading
from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass
from collections import deque
import json
import sys

class LogLevel(Enum):
    """Production logging levels optimized for performance"""
    CRITICAL = 0  # Only critical errors that stop the system
    ERROR = 1     # Errors that affect functionality but don't stop system  
    WARN = 2      # Performance issues or degraded functionality
    INFO = 3      # Key operational milestones
    DEBUG = 4     # Detailed diagnostic information

@dataclass
class LogEntry:
    """Structured log entry with minimal overhead"""
    timestamp: float
    level: LogLevel
    component: str
    message: str
    metrics: Optional[Dict[str, Any]] = None

class ProductionLogger:
    """High-performance logger with <0.1ms overhead per call"""
    
    def __init__(self, max_entries: int = 1000):
        self.max_entries = max_entries
        self.entries = deque(maxlen=max_entries)
        self.lock = threading.RLock()
        self.start_time = time.time()
        
        # Performance tracking
        self.call_count = 0
        self.total_log_time = 0.0
        
        # Production log level (INFO by default)
        self.log_level = LogLevel.INFO
        
        # Component performance tracking
        self.component_metrics: Dict[str, Dict[str, float]] = {}
    
    def set_level(self, level: LogLevel):
        """Set minimum logging level"""
        self.log_level = level
    
    def log(self, level: LogLevel, component: str, message: str, metrics: Dict[str, Any] = None):
        """High-performance logging with minimal overhead"""
        if level.value > self.log_level.value:
            return  # Skip if below log level
        
        start_time = time.perf_counter()
        
        try:
            with self.lock:
                entry = LogEntry(
                    timestamp=time.time(),
                    level=level,
                    component=component,
                    message=message,
                    metrics=metrics
                )
                self.entries.append(entry)
                
                # Update component metrics
                if component not in self.component_metrics:
                    self.component_metrics[component] = {
                        'total_logs': 0,
                        'last_activity': 0,
                        'error_count': 0
                    }
                
                self.component_metrics[component]['total_logs'] += 1
                self.component_metrics[component]['last_activity'] = entry.timestamp
                
                if level in [LogLevel.ERROR, LogLevel.CRITICAL]:
                    self.component_metrics[component]['error_count'] += 1
                
        finally:
            # Track logging performance
            log_time = time.perf_counter() - start_time
            self.call_count += 1
            self.total_log_time += log_time
    
    def critical(self, component: str, message: str, metrics: Dict[str, Any] = None):
        """Log critical system errors"""
        self.log(LogLevel.CRITICAL, component, message, metrics)
        # Also output to stderr for immediate visibility
        print(f"[CRITICAL] {component}: {message}", file=sys.stderr)
    
    def error(self, component: str, message: str, metrics: Dict[str, Any] = None):
        """Log errors that affect functionality"""
        self.log(LogLevel.ERROR, component, message, metrics)
    
    def warn(self, component: str, message: str, metrics: Dict[str, Any] = None):
        """Log performance warnings or degraded functionality"""
        self.log(LogLevel.WARN, component, message, metrics)
    
    def info(self, component: str, message: str, metrics: Dict[str, Any] = None):
        """Log key operational milestones"""
        self.log(LogLevel.INFO, component, message, metrics)
    
    def debug(self, component: str, message: str, metrics: Dict[str, Any] = None):
        """Log detailed diagnostic information"""
        self.log(LogLevel.DEBUG, component, message, metrics)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get logging system performance statistics"""
        with self.lock:
            avg_log_time = self.total_log_time / max(1, self.call_count)
            
            return {
                'total_calls': self.call_count,
                'avg_call_time_ms': avg_log_time * 1000,
                'total_entries': len(self.entries),
                'uptime_seconds': time.time() - self.start_time,
                'component_count': len(self.component_metrics),
                'performance_impact': 'EXCELLENT' if avg_log_time < 0.001 else 'GOOD' if avg_log_time < 0.01 else 'NEEDS_OPTIMIZATION'
            }
    
    def get_component_health(self) -> Dict[str, Dict[str, Any]]:
        """Get health status of all components"""
        with self.lock:
            health_report = {}
            current_time = time.time()
            
            for component, metrics in self.component_metrics.items():
                time_since_activity = current_time - metrics['last_activity']
                error_rate = metrics['error_count'] / max(1, metrics['total_logs'])
                
                health_status = 'HEALTHY'
                if error_rate > 0.1:
                    health_status = 'DEGRADED'
                elif error_rate > 0.05:
                    health_status = 'WARNING'
                
                health_report[component] = {
                    'status': health_status,
                    'total_logs': metrics['total_logs'],
                    'error_rate': error_rate,
                    'seconds_since_activity': time_since_activity,
                    'active': time_since_activity < 60  # Active if logged in last minute
                }
            
            return health_report
    
    def get_recent_entries(self, count: int = 50, level_filter: LogLevel = None) -> list:
        """Get recent log entries with optional level filtering"""
        with self.lock:
            entries = list(self.entries)
            
            if level_filter:
                entries = [e for e in entries if e.level.value <= level_filter.value]
            
            return entries[-count:]
    
    def export_diagnostics(self) -> Dict[str, Any]:
        """Export comprehensive diagnostic information"""
        with self.lock:
            return {
                'timestamp': time.time(),
                'performance_stats': self.get_performance_stats(),
                'component_health': self.get_component_health(),
                'recent_errors': [
                    {
                        'timestamp': e.timestamp,
                        'component': e.component,
                        'message': e.message,
                        'metrics': e.metrics
                    }
                    for e in self.entries 
                    if e.level in [LogLevel.ERROR, LogLevel.CRITICAL]
                ][-10:],  # Last 10 errors
                'system_health': self._assess_system_health()
            }
    
    def _assess_system_health(self) -> str:
        """Assess overall system health based on log patterns"""
        health_report = self.get_component_health()
        
        critical_components = ['AudioRecorder', 'BufferSafeWhisperASR', 'EnhancedApp']
        
        for component in critical_components:
            if component in health_report:
                status = health_report[component]['status']
                if status == 'DEGRADED':
                    return 'CRITICAL'
                elif status == 'WARNING':
                    return 'WARNING'
        
        # Check for recent critical errors
        recent_critical = sum(1 for e in list(self.entries)[-20:] if e.level == LogLevel.CRITICAL)
        if recent_critical > 0:
            return 'CRITICAL'
        
        return 'HEALTHY'

# Global production logger instance
_prod_logger = None

def get_production_logger() -> ProductionLogger:
    """Get the global production logger instance"""
    global _prod_logger
    if _prod_logger is None:
        _prod_logger = ProductionLogger()
    return _prod_logger

def set_production_log_level(level: LogLevel):
    """Set the global production log level"""
    get_production_logger().set_level(level)

# Convenience functions for global logging
def log_critical(component: str, message: str, metrics: Dict[str, Any] = None):
    get_production_logger().critical(component, message, metrics)

def log_error(component: str, message: str, metrics: Dict[str, Any] = None):
    get_production_logger().error(component, message, metrics)

def log_warn(component: str, message: str, metrics: Dict[str, Any] = None):
    get_production_logger().warn(component, message, metrics)

def log_info(component: str, message: str, metrics: Dict[str, Any] = None):
    get_production_logger().info(component, message, metrics)

def log_debug(component: str, message: str, metrics: Dict[str, Any] = None):
    get_production_logger().debug(component, message, metrics)

def get_system_diagnostics() -> Dict[str, Any]:
    """Get comprehensive system diagnostics"""
    return get_production_logger().export_diagnostics()

def print_system_health():
    """Print a concise system health report"""
    logger = get_production_logger()
    stats = logger.get_performance_stats()
    health = logger.get_component_health()
    
    print(f"\n=== VoiceFlow System Health ===")
    print(f"Overall Status: {logger._assess_system_health()}")
    print(f"Logging Performance: {stats['performance_impact']} ({stats['avg_call_time_ms']:.3f}ms avg)")
    print(f"Active Components: {sum(1 for h in health.values() if h['active'])}")
    print(f"Total Log Entries: {stats['total_entries']}")
    print(f"Uptime: {stats['uptime_seconds']:.1f}s")
    
    # Show component status
    for component, health_info in health.items():
        status_icon = "[OK]" if health_info['status'] == 'HEALTHY' else "[WARN]" if health_info['status'] == 'WARNING' else "[ERR]"
        print(f"  {status_icon} {component}: {health_info['status']}")
    
    print("=" * 32)

if __name__ == "__main__":
    # Demo the production logging system
    logger = get_production_logger()
    logger.set_level(LogLevel.INFO)
    
    print("Testing Production Logging System...")
    
    # Simulate some logging activity
    logger.info("AudioRecorder", "System initialized successfully")
    logger.info("BufferSafeWhisperASR", "Model loaded", {"model": "large-v3-turbo"})
    logger.warn("AudioRecorder", "High CPU usage detected", {"cpu_percent": 85})
    logger.error("BufferSafeWhisperASR", "Transcription failed", {"error_code": "TIMEOUT"})
    
    time.sleep(0.1)  # Brief pause
    
    print_system_health()
    
    # Performance test
    start_time = time.perf_counter()
    for i in range(1000):
        logger.debug("PerformanceTest", f"Test message {i}")
    
    test_time = time.perf_counter() - start_time
    print(f"\nPerformance Test: 1000 log calls in {test_time*1000:.2f}ms")
    print(f"Average per call: {test_time:.6f}s ({test_time*1000000:.1f}us)")