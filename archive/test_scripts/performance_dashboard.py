#!/usr/bin/env python3
"""
VoiceFlow Performance Monitoring Dashboard

Real-time performance monitoring and analysis dashboard for production VoiceFlow deployment.
Provides comprehensive metrics, alerts, and optimization recommendations.

Features:
- Real-time performance metrics
- Historical trend analysis
- Automatic degradation detection
- Resource usage monitoring
- Production optimization recommendations
- Export capabilities for reporting

Usage:
    python performance_dashboard.py --monitor
    python performance_dashboard.py --analyze logs/
    python performance_dashboard.py --web-dashboard
"""

import asyncio
import json
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import argparse
import logging
import statistics
import re
from collections import defaultdict, deque
import sys
import os

import psutil
import numpy as np

# Optional dependencies
try:
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

try:
    from flask import Flask, render_template, jsonify, request, send_from_directory
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from localflow.production_logging import get_production_logger, LogLevel
    PRODUCTION_LOGGING_AVAILABLE = True
except ImportError:
    PRODUCTION_LOGGING_AVAILABLE = False


@dataclass
class PerformanceMetrics:
    """Real-time performance metrics data structure"""
    timestamp: datetime
    transcription_id: str
    audio_duration: float
    processing_time: float
    speed_factor: float
    word_count: int
    memory_usage_mb: float
    cpu_usage_percent: float
    model_name: str
    session_id: str
    error_occurred: bool = False
    error_message: str = ""
    pre_buffer_effectiveness: float = 0.0
    
    @property
    def words_per_second(self) -> float:
        return self.word_count / self.processing_time if self.processing_time > 0 else 0
    
    @property
    def efficiency_score(self) -> float:
        """Calculate overall efficiency score (0-100)"""
        speed_score = min(self.speed_factor / 10.0, 1.0) * 30  # Up to 30 points for speed
        accuracy_score = min(self.words_per_second / 5.0, 1.0) * 25  # Up to 25 points for word rate
        memory_score = max(0, (500 - self.memory_usage_mb) / 500) * 25  # Up to 25 points for low memory
        error_score = 20 if not self.error_occurred else 0  # 20 points for no errors
        
        return speed_score + accuracy_score + memory_score + error_score


@dataclass
class SessionSummary:
    """Session-level performance summary"""
    session_id: str
    start_time: datetime
    end_time: Optional[datetime]
    total_recordings: int
    total_audio_seconds: float
    total_processing_seconds: float
    total_words: int
    average_speed_factor: float
    peak_memory_mb: float
    error_count: int
    model_reloads: int
    overall_efficiency: float


class PerformanceAnalyzer:
    """Advanced performance analysis engine"""
    
    def __init__(self, max_metrics: int = 1000):
        self.metrics: deque[PerformanceMetrics] = deque(maxlen=max_metrics)
        self.session_summaries: Dict[str, SessionSummary] = {}
        self.alerts: List[Dict[str, Any]] = []
        
        # Analysis thresholds
        self.thresholds = {
            'slow_processing': 2.0,  # Seconds
            'low_speed_factor': 1.0,  # Real-time ratio
            'high_memory': 300,  # MB
            'high_cpu': 80,  # Percentage
            'degradation_window': 10,  # Number of recordings to analyze
            'error_rate_threshold': 0.1  # 10% error rate
        }
        
        self.degradation_detector = DegradationDetector()
    
    def add_metrics(self, metrics: PerformanceMetrics):
        """Add new performance metrics and trigger analysis"""
        self.metrics.append(metrics)
        
        # Update session summary
        self._update_session_summary(metrics)
        
        # Check for performance issues
        self._check_performance_alerts(metrics)
        
        # Check for degradation patterns
        if len(self.metrics) >= self.thresholds['degradation_window']:
            recent_metrics = list(self.metrics)[-self.thresholds['degradation_window']:]
            degradation_alert = self.degradation_detector.check_degradation(recent_metrics)
            if degradation_alert:
                self.alerts.append(degradation_alert)
    
    def _update_session_summary(self, metrics: PerformanceMetrics):
        """Update session-level summary"""
        session_id = metrics.session_id
        
        if session_id not in self.session_summaries:
            self.session_summaries[session_id] = SessionSummary(
                session_id=session_id,
                start_time=metrics.timestamp,
                end_time=None,
                total_recordings=0,
                total_audio_seconds=0.0,
                total_processing_seconds=0.0,
                total_words=0,
                average_speed_factor=0.0,
                peak_memory_mb=0.0,
                error_count=0,
                model_reloads=0,
                overall_efficiency=0.0
            )
        
        summary = self.session_summaries[session_id]
        summary.end_time = metrics.timestamp
        summary.total_recordings += 1
        summary.total_audio_seconds += metrics.audio_duration
        summary.total_processing_seconds += metrics.processing_time
        summary.total_words += metrics.word_count
        summary.peak_memory_mb = max(summary.peak_memory_mb, metrics.memory_usage_mb)
        
        if metrics.error_occurred:
            summary.error_count += 1
        
        # Update averages
        summary.average_speed_factor = summary.total_audio_seconds / summary.total_processing_seconds
        summary.overall_efficiency = statistics.mean([m.efficiency_score for m in self.metrics if m.session_id == session_id])
    
    def _check_performance_alerts(self, metrics: PerformanceMetrics):
        """Check for performance alerts"""
        alerts = []
        
        # Processing time alert
        if metrics.processing_time > self.thresholds['slow_processing']:
            alerts.append({
                'type': 'performance',
                'severity': 'warning',
                'message': f"Slow processing: {metrics.processing_time:.2f}s for {metrics.audio_duration:.1f}s audio",
                'timestamp': metrics.timestamp,
                'metrics': metrics
            })
        
        # Speed factor alert
        if metrics.speed_factor < self.thresholds['low_speed_factor']:
            alerts.append({
                'type': 'performance',
                'severity': 'error',
                'message': f"Processing slower than realtime: {metrics.speed_factor:.1f}x",
                'timestamp': metrics.timestamp,
                'metrics': metrics
            })
        
        # Memory usage alert
        if metrics.memory_usage_mb > self.thresholds['high_memory']:
            alerts.append({
                'type': 'resource',
                'severity': 'warning',
                'message': f"High memory usage: {metrics.memory_usage_mb:.1f} MB",
                'timestamp': metrics.timestamp,
                'metrics': metrics
            })
        
        # CPU usage alert
        if metrics.cpu_usage_percent > self.thresholds['high_cpu']:
            alerts.append({
                'type': 'resource',
                'severity': 'warning',
                'message': f"High CPU usage: {metrics.cpu_usage_percent:.1f}%",
                'timestamp': metrics.timestamp,
                'metrics': metrics
            })
        
        # Error alert
        if metrics.error_occurred:
            alerts.append({
                'type': 'error',
                'severity': 'error',
                'message': f"Transcription error: {metrics.error_message}",
                'timestamp': metrics.timestamp,
                'metrics': metrics
            })
        
        self.alerts.extend(alerts)
        
        # Keep only recent alerts (last hour)
        cutoff_time = datetime.now() - timedelta(hours=1)
        self.alerts = [a for a in self.alerts if a['timestamp'] > cutoff_time]
    
    def get_performance_summary(self, window_minutes: int = 30) -> Dict[str, Any]:
        """Get performance summary for specified time window"""
        cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
        recent_metrics = [m for m in self.metrics if m.timestamp > cutoff_time]
        
        if not recent_metrics:
            return {'status': 'no_data', 'window_minutes': window_minutes}
        
        # Calculate statistics
        processing_times = [m.processing_time for m in recent_metrics if not m.error_occurred]
        speed_factors = [m.speed_factor for m in recent_metrics if not m.error_occurred]
        memory_usage = [m.memory_usage_mb for m in recent_metrics]
        efficiency_scores = [m.efficiency_score for m in recent_metrics]
        error_count = sum(1 for m in recent_metrics if m.error_occurred)
        
        return {
            'status': 'active',
            'window_minutes': window_minutes,
            'total_recordings': len(recent_metrics),
            'successful_recordings': len(processing_times),
            'error_rate': error_count / len(recent_metrics) if recent_metrics else 0,
            'performance': {
                'avg_processing_time': statistics.mean(processing_times) if processing_times else 0,
                'avg_speed_factor': statistics.mean(speed_factors) if speed_factors else 0,
                'min_speed_factor': min(speed_factors) if speed_factors else 0,
                'max_speed_factor': max(speed_factors) if speed_factors else 0,
                'processing_time_std': statistics.stdev(processing_times) if len(processing_times) > 1 else 0
            },
            'resources': {
                'avg_memory_mb': statistics.mean(memory_usage) if memory_usage else 0,
                'peak_memory_mb': max(memory_usage) if memory_usage else 0,
                'memory_growth': max(memory_usage) - min(memory_usage) if memory_usage else 0
            },
            'quality': {
                'avg_efficiency_score': statistics.mean(efficiency_scores) if efficiency_scores else 0,
                'min_efficiency_score': min(efficiency_scores) if efficiency_scores else 0,
                'total_words': sum(m.word_count for m in recent_metrics),
                'avg_words_per_recording': statistics.mean([m.word_count for m in recent_metrics]) if recent_metrics else 0
            },
            'alerts': {
                'total_alerts': len(self.alerts),
                'error_alerts': len([a for a in self.alerts if a['severity'] == 'error']),
                'warning_alerts': len([a for a in self.alerts if a['severity'] == 'warning'])
            }
        }
    
    def generate_optimization_recommendations(self) -> List[str]:
        """Generate specific optimization recommendations based on performance data"""
        recommendations = []
        
        if not self.metrics:
            return ["No performance data available for analysis"]
        
        recent_metrics = list(self.metrics)[-50:]  # Last 50 recordings
        
        # Processing speed analysis
        avg_speed = statistics.mean([m.speed_factor for m in recent_metrics if not m.error_occurred])
        if avg_speed < 2.0:
            recommendations.append("Consider switching to a faster Whisper model (base.en) for better real-time performance")
        elif avg_speed > 15.0:
            recommendations.append("Excellent processing speed - consider using a more accurate model (large-v3-turbo)")
        
        # Memory analysis
        memory_values = [m.memory_usage_mb for m in recent_metrics]
        if memory_values:
            memory_growth = max(memory_values) - min(memory_values)
            if memory_growth > 100:
                recommendations.append("Memory usage growing significantly - implement more frequent garbage collection")
            
            avg_memory = statistics.mean(memory_values)
            if avg_memory > 400:
                recommendations.append("High memory usage detected - consider model optimization or system upgrade")
        
        # Error rate analysis
        error_rate = sum(1 for m in recent_metrics if m.error_occurred) / len(recent_metrics)
        if error_rate > 0.05:
            recommendations.append("High error rate detected - review audio input validation and error handling")
        
        # Consistency analysis
        processing_times = [m.processing_time for m in recent_metrics if not m.error_occurred]
        if processing_times and len(processing_times) > 1:
            std_dev = statistics.stdev(processing_times)
            mean_time = statistics.mean(processing_times)
            if std_dev / mean_time > 0.5:  # High variability
                recommendations.append("High processing time variability - consider periodic model reinitialization")
        
        # Pre-buffer effectiveness
        pre_buffer_scores = [m.pre_buffer_effectiveness for m in recent_metrics if m.pre_buffer_effectiveness > 0]
        if pre_buffer_scores:
            avg_effectiveness = statistics.mean(pre_buffer_scores)
            if avg_effectiveness < 0.8:
                recommendations.append("Pre-buffer effectiveness is low - consider increasing buffer duration")
        
        if not recommendations:
            recommendations.append("Performance appears optimal - continue current configuration")
        
        return recommendations


class DegradationDetector:
    """Advanced degradation pattern detection"""
    
    def check_degradation(self, recent_metrics: List[PerformanceMetrics]) -> Optional[Dict[str, Any]]:
        """Check for various degradation patterns"""
        if len(recent_metrics) < 5:
            return None
        
        # Check processing time degradation
        processing_times = [m.processing_time for m in recent_metrics if not m.error_occurred]
        if len(processing_times) >= 5:
            early_avg = statistics.mean(processing_times[:len(processing_times)//2])
            recent_avg = statistics.mean(processing_times[len(processing_times)//2:])
            
            if recent_avg > early_avg * 1.5:  # 50% increase
                return {
                    'type': 'degradation',
                    'severity': 'warning',
                    'message': f"Processing time degradation detected: {early_avg:.2f}s -> {recent_avg:.2f}s",
                    'timestamp': recent_metrics[-1].timestamp,
                    'pattern': 'processing_time_increase',
                    'impact': (recent_avg / early_avg - 1) * 100
                }
        
        # Check memory leak patterns
        memory_values = [m.memory_usage_mb for m in recent_metrics]
        if len(memory_values) >= 5:
            # Linear regression to detect memory growth trend
            x_values = list(range(len(memory_values)))
            slope = self._calculate_slope(x_values, memory_values)
            
            if slope > 5:  # More than 5MB per recording
                return {
                    'type': 'degradation',
                    'severity': 'error',
                    'message': f"Memory leak detected: {slope:.1f} MB growth per recording",
                    'timestamp': recent_metrics[-1].timestamp,
                    'pattern': 'memory_leak',
                    'impact': slope
                }
        
        # Check transcription quality degradation
        word_counts = [m.word_count for m in recent_metrics if not m.error_occurred and m.audio_duration > 0]
        audio_durations = [m.audio_duration for m in recent_metrics if not m.error_occurred and m.audio_duration > 0]
        
        if len(word_counts) >= 5 and len(audio_durations) >= 5:
            word_rates = [w / d for w, d in zip(word_counts, audio_durations)]
            early_rate = statistics.mean(word_rates[:len(word_rates)//2])
            recent_rate = statistics.mean(word_rates[len(word_rates)//2:])
            
            if recent_rate < early_rate * 0.7:  # 30% decrease
                return {
                    'type': 'degradation',
                    'severity': 'warning',
                    'message': f"Transcription quality degradation: {early_rate:.1f} -> {recent_rate:.1f} words/sec",
                    'timestamp': recent_metrics[-1].timestamp,
                    'pattern': 'quality_degradation',
                    'impact': (1 - recent_rate / early_rate) * 100
                }
        
        return None
    
    def _calculate_slope(self, x_values: List[float], y_values: List[float]) -> float:
        """Calculate linear regression slope"""
        n = len(x_values)
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x2 = sum(x * x for x in x_values)
        
        return (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)


class RealTimeMonitor:
    """Real-time performance monitoring system"""
    
    def __init__(self, log_directory: Path):
        self.log_directory = Path(log_directory)
        self.analyzer = PerformanceAnalyzer()
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Integration with production logging system
        self.production_logger = None
        if PRODUCTION_LOGGING_AVAILABLE:
            try:
                self.production_logger = get_production_logger()
                print("[MONITOR] Integrated with production logging system")
            except Exception as e:
                print(f"[MONITOR] Could not connect to production logger: {e}")
        
        # Log parsing patterns
        self.log_patterns = {
            'transcription_complete': re.compile(
                r'TRANSCRIPTION_COMPLETE\s+(\{.*\})'
            ),
            'memory_usage': re.compile(
                r'MEMORY_USAGE\s+(\{.*\})'
            ),
            'error': re.compile(
                r'ERROR.*?(\{.*\})?'
            )
        }
        
        # Track processed log positions
        self.log_positions: Dict[str, int] = {}
    
    def start_monitoring(self):
        """Start real-time log monitoring"""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="PerformanceMonitor"
        )
        self.monitor_thread.start()
        print(f"[MONITOR] Started monitoring logs in {self.log_directory}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("[MONITOR] Stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Check production logger first
                if self.production_logger:
                    self._check_production_logger()
                
                # Then scan traditional log files
                self._scan_log_files()
                time.sleep(1)  # Check for new logs every second
            except Exception as e:
                print(f"[MONITOR] Error: {e}")
                time.sleep(5)  # Wait longer on error
    
    def _scan_log_files(self):
        """Scan log files for new entries"""
        if not self.log_directory.exists():
            return
        
        # Look for VoiceFlow log files
        log_files = list(self.log_directory.glob("*.log"))
        
        for log_file in log_files:
            try:
                self._process_log_file(log_file)
            except Exception as e:
                print(f"[MONITOR] Error processing {log_file}: {e}")
    
    def _process_log_file(self, log_file: Path):
        """Process new entries in a log file"""
        file_key = str(log_file)
        
        # Get current file size
        current_size = log_file.stat().st_size
        last_position = self.log_positions.get(file_key, 0)
        
        if current_size <= last_position:
            return  # No new data
        
        # Read new data
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(last_position)
            new_lines = f.readlines()
            self.log_positions[file_key] = f.tell()
        
        # Process new lines
        for line in new_lines:
            self._parse_log_line(line.strip(), log_file.stem)
    
    def _parse_log_line(self, line: str, log_source: str):
        """Parse a single log line for performance metrics"""
        try:
            # Look for transcription completion
            match = self.log_patterns['transcription_complete'].search(line)
            if match:
                data = json.loads(match.group(1))
                metrics = self._create_metrics_from_log(data, log_source)
                if metrics:
                    self.analyzer.add_metrics(metrics)
                return
            
            # Look for memory usage
            match = self.log_patterns['memory_usage'].search(line)
            if match:
                data = json.loads(match.group(1))
                # Handle memory usage data
                return
            
            # Look for errors
            if 'ERROR' in line and 'transcription' in line.lower():
                # Create error metrics
                error_metrics = PerformanceMetrics(
                    timestamp=datetime.now(),
                    transcription_id=f"error_{int(time.time())}",
                    audio_duration=0.0,
                    processing_time=0.0,
                    speed_factor=0.0,
                    word_count=0,
                    memory_usage_mb=0.0,
                    cpu_usage_percent=0.0,
                    model_name="unknown",
                    session_id=log_source,
                    error_occurred=True,
                    error_message=line
                )
                self.analyzer.add_metrics(error_metrics)
        
        except Exception as e:
            # Silently ignore parsing errors to avoid spam
            pass
    
    def _create_metrics_from_log(self, data: Dict[str, Any], session_id: str) -> Optional[PerformanceMetrics]:
        """Create PerformanceMetrics from log data"""
        try:
            # Get current system metrics
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            cpu_percent = process.cpu_percent()
            
            return PerformanceMetrics(
                timestamp=datetime.now(),
                transcription_id=str(data.get('timestamp', time.time())),
                audio_duration=data.get('audio_length', 0.0),
                processing_time=data.get('processing_time', 0.0),
                speed_factor=data.get('speed_factor', 0.0),
                word_count=data.get('words', 0),
                memory_usage_mb=memory_mb,
                cpu_usage_percent=cpu_percent,
                model_name=data.get('model', 'unknown'),
                session_id=session_id,
                error_occurred=False
            )
        except Exception as e:
            return None
    
    def _check_production_logger(self):
        """Check production logger for new metrics"""
        try:
            # Get recent performance entries from production logger
            recent_entries = self.production_logger.get_recent_entries(count=10, level_filter=LogLevel.INFO)
            
            for entry in recent_entries:
                if entry.metrics and 'transcription_complete' in entry.message.lower():
                    metrics = self._create_metrics_from_production_log(entry)
                    if metrics:
                        self.analyzer.add_metrics(metrics)
                        
        except Exception as e:
            # Silent fail to avoid spam
            pass
    
    def _create_metrics_from_production_log(self, log_entry) -> Optional[PerformanceMetrics]:
        """Create PerformanceMetrics from production log entry"""
        try:
            if not log_entry.metrics:
                return None
                
            # Get current system metrics
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            cpu_percent = process.cpu_percent()
            
            # Extract metrics from log entry
            metrics_data = log_entry.metrics
            
            return PerformanceMetrics(
                timestamp=datetime.fromtimestamp(log_entry.timestamp),
                transcription_id=str(log_entry.timestamp),
                audio_duration=metrics_data.get('audio_duration', 0.0),
                processing_time=metrics_data.get('processing_time', 0.0),
                speed_factor=metrics_data.get('speed_factor', 0.0),
                word_count=metrics_data.get('word_count', 0),
                memory_usage_mb=memory_mb,
                cpu_usage_percent=cpu_percent,
                model_name=metrics_data.get('model_name', 'unknown'),
                session_id=log_entry.component,
                error_occurred=log_entry.level.name in ['ERROR', 'CRITICAL'],
                error_message=log_entry.message if log_entry.level.name in ['ERROR', 'CRITICAL'] else ""
            )
        except Exception as e:
            return None
    
    def get_current_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        summary = self.analyzer.get_performance_summary(window_minutes=10)
        recent_alerts = self.analyzer.alerts[-5:]  # Last 5 alerts
        
        return {
            'monitoring': {
                'status': 'active' if self.running else 'stopped',
                'log_directory': str(self.log_directory),
                'files_monitored': len(self.log_positions),
                'metrics_collected': len(self.analyzer.metrics)
            },
            'performance': summary,
            'recent_alerts': recent_alerts,
            'recommendations': self.analyzer.generate_optimization_recommendations(),
            'production_system_health': self._get_production_system_health()
        }
    
    def _get_production_system_health(self) -> Dict[str, Any]:
        """Get health status from production logging system"""
        if not self.production_logger:
            return {'status': 'unavailable', 'message': 'Production logging not available'}
        
        try:
            health_report = self.production_logger.get_component_health()
            system_health = self.production_logger._assess_system_health()
            performance_stats = self.production_logger.get_performance_stats()
            
            return {
                'status': 'available',
                'overall_health': system_health,
                'component_count': len(health_report),
                'active_components': sum(1 for h in health_report.values() if h['active']),
                'logging_performance': performance_stats['performance_impact'],
                'components': health_report
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


class WebDashboard:
    """Web-based performance monitoring dashboard"""
    
    def __init__(self, monitor: RealTimeMonitor):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask not available - cannot create web dashboard")
        
        self.monitor = monitor
        self.app = Flask(__name__)
        if 'CORS' in globals():
            CORS(self.app)  # Enable CORS for frontend access
        
        self.setup_routes()
    
    def setup_routes(self):
        """Setup Flask routes for the web dashboard"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard page"""
            return self.render_dashboard_html()
        
        @self.app.route('/api/status')
        def api_status():
            """Get current system status"""
            return jsonify(self.monitor.get_current_status())
        
        @self.app.route('/api/metrics/recent/<int:minutes>')
        def api_recent_metrics(minutes):
            """Get recent metrics for specified time window"""
            summary = self.monitor.analyzer.get_performance_summary(window_minutes=minutes)
            return jsonify(summary)
        
        @self.app.route('/api/alerts')
        def api_alerts():
            """Get recent alerts"""
            return jsonify({
                'alerts': self.monitor.analyzer.alerts[-20:],  # Last 20 alerts
                'count': len(self.monitor.analyzer.alerts)
            })
        
        @self.app.route('/api/health')
        def api_health():
            """Get detailed health information"""
            status = self.monitor.get_current_status()
            return jsonify({
                'monitoring': status['monitoring'],
                'production_health': status.get('production_system_health', {}),
                'recommendations': status['recommendations']
            })
        
        @self.app.route('/api/export')
        def api_export():
            """Export performance data"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            status = self.monitor.get_current_status()
            
            # Add more detailed export data
            export_data = {
                'export_time': timestamp,
                'system_status': status,
                'raw_metrics': [
                    {
                        'timestamp': m.timestamp.isoformat(),
                        'transcription_id': m.transcription_id,
                        'audio_duration': m.audio_duration,
                        'processing_time': m.processing_time,
                        'speed_factor': m.speed_factor,
                        'word_count': m.word_count,
                        'memory_usage_mb': m.memory_usage_mb,
                        'cpu_usage_percent': m.cpu_usage_percent,
                        'model_name': m.model_name,
                        'session_id': m.session_id,
                        'error_occurred': m.error_occurred,
                        'efficiency_score': m.efficiency_score
                    }
                    for m in list(self.monitor.analyzer.metrics)[-100:]  # Last 100 metrics
                ]
            }
            
            return jsonify(export_data)
        
        @self.app.route('/api/control/<action>')
        def api_control(action):
            """Control monitoring system"""
            if action == 'start':
                self.monitor.start_monitoring()
                return jsonify({'status': 'started'})
            elif action == 'stop':
                self.monitor.stop_monitoring()
                return jsonify({'status': 'stopped'})
            elif action == 'clear':
                self.monitor.analyzer.metrics.clear()
                self.monitor.analyzer.alerts.clear()
                return jsonify({'status': 'cleared'})
            else:
                return jsonify({'error': 'Unknown action'}), 400
    
    def render_dashboard_html(self):
        """Render the main dashboard HTML"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VoiceFlow Performance Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 1rem; text-align: center; }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 1.5rem; }
        .card h3 { color: #2c3e50; margin-bottom: 1rem; font-size: 1.2rem; }
        .status-item { display: flex; justify-content: space-between; margin: 0.5rem 0; padding: 0.5rem; background: #f8f9fa; border-radius: 4px; }
        .status-label { font-weight: 600; color: #495057; }
        .status-value { font-weight: 500; }
        .status-good { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-error { color: #dc3545; }
        .metric-large { font-size: 2rem; font-weight: bold; text-align: center; margin: 1rem 0; }
        .chart-container { height: 300px; margin: 1rem 0; }
        .controls { display: flex; gap: 1rem; margin: 1rem 0; }
        .btn { padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; }
        .btn-primary { background: #007bff; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .alerts-container { max-height: 400px; overflow-y: auto; }
        .alert-item { padding: 0.75rem; margin: 0.5rem 0; border-radius: 4px; border-left: 4px solid; }
        .alert-error { background: #f8d7da; border-color: #dc3545; color: #721c24; }
        .alert-warning { background: #fff3cd; border-color: #ffc107; color: #856404; }
        .alert-info { background: #d1ecf1; border-color: #17a2b8; color: #0c5460; }
        .recommendations { background: #e7f3ff; padding: 1rem; border-radius: 4px; margin: 1rem 0; }
        .recommendations ul { margin-left: 1.5rem; }
        .recommendations li { margin: 0.5rem 0; }
        .loading { text-align: center; padding: 2rem; color: #6c757d; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
        .pulse { animation: pulse 2s infinite; }
    </style>
</head>
<body>
    <div class="header">
        <h1>[MIC] VoiceFlow Performance Dashboard</h1>
        <p>Real-time monitoring and performance analytics</p>
    </div>
    
    <div class="container">
        <div class="controls">
            <button class="btn btn-success" onclick="controlSystem('start')">Start Monitoring</button>
            <button class="btn btn-danger" onclick="controlSystem('stop')">Stop Monitoring</button>
            <button class="btn btn-secondary" onclick="controlSystem('clear')">Clear Data</button>
            <button class="btn btn-primary" onclick="exportData()">Export Report</button>
            <span id="lastUpdate" class="status-value">Loading...</span>
        </div>
        
        <div class="grid">
            <!-- System Status -->
            <div class="card">
                <h3>[STATS] System Status</h3>
                <div id="systemStatus" class="loading pulse">Loading...</div>
            </div>
            
            <!-- Performance Metrics -->
            <div class="card">
                <h3>⚡ Performance Metrics</h3>
                <div id="performanceMetrics" class="loading pulse">Loading...</div>
            </div>
            
            <!-- Resource Usage -->
            <div class="card">
                <h3>💾 Resource Usage</h3>
                <div id="resourceUsage" class="loading pulse">Loading...</div>
            </div>
            
            <!-- Recent Alerts -->
            <div class="card">
                <h3>🚨 Recent Alerts</h3>
                <div id="alertsContainer" class="alerts-container loading pulse">Loading...</div>
            </div>
            
            <!-- Performance Chart -->
            <div class="card" style="grid-column: span 2;">
                <h3>📈 Performance Trends</h3>
                <div class="chart-container">
                    <canvas id="performanceChart"></canvas>
                </div>
            </div>
            
            <!-- Health Status -->
            <div class="card">
                <h3>🏥 Component Health</h3>
                <div id="componentHealth" class="loading pulse">Loading...</div>
            </div>
            
            <!-- Recommendations -->
            <div class="card">
                <h3>💡 Optimization Recommendations</h3>
                <div id="recommendations" class="loading pulse">Loading...</div>
            </div>
        </div>
    </div>

    <script>
        let performanceChart;
        let chartData = {
            labels: [],
            datasets: [
                {
                    label: 'Speed Factor (x realtime)',
                    data: [],
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Memory Usage (MB)',
                    data: [],
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    yAxisID: 'y1',
                    tension: 0.4
                }
            ]
        };

        // Initialize chart
        function initChart() {
            const ctx = document.getElementById('performanceChart').getContext('2d');
            performanceChart = new Chart(ctx, {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: { intersect: false },
                    scales: {
                        y: { beginAtZero: true, position: 'left' },
                        y1: { type: 'linear', position: 'right', beginAtZero: true, grid: { drawOnChartArea: false } }
                    },
                    plugins: {
                        legend: { position: 'top' },
                        title: { display: true, text: 'Real-time Performance Metrics' }
                    }
                }
            });
        }

        // Update dashboard data
        async function updateDashboard() {
            try {
                const [status, alerts, health] = await Promise.all([
                    fetch('/api/status').then(r => r.json()),
                    fetch('/api/alerts').then(r => r.json()),
                    fetch('/api/health').then(r => r.json())
                ]);

                updateSystemStatus(status);
                updatePerformanceMetrics(status.performance);
                updateResourceUsage(status.performance);
                updateAlerts(alerts.alerts);
                updateComponentHealth(health);
                updateRecommendations(status.recommendations);
                updateChart(status);
                
                document.getElementById('lastUpdate').textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
            } catch (error) {
                console.error('Error updating dashboard:', error);
            }
        }

        function updateSystemStatus(status) {
            const monitoring = status.monitoring;
            const performance = status.performance;
            
            let statusHtml = `
                <div class="status-item">
                    <span class="status-label">Monitoring:</span>
                    <span class="status-value ${monitoring.status === 'active' ? 'status-good' : 'status-error'}">
                        ${monitoring.status.toUpperCase()}
                    </span>
                </div>
                <div class="status-item">
                    <span class="status-label">Files Monitored:</span>
                    <span class="status-value">${monitoring.files_monitored}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Metrics Collected:</span>
                    <span class="status-value">${monitoring.metrics_collected}</span>
                </div>
            `;
            
            if (performance.status === 'active') {
                statusHtml += `
                    <div class="status-item">
                        <span class="status-label">Recordings (10min):</span>
                        <span class="status-value">${performance.total_recordings}</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">Success Rate:</span>
                        <span class="status-value ${(1-performance.error_rate) > 0.95 ? 'status-good' : 'status-warning'}">
                            ${((1-performance.error_rate)*100).toFixed(1)}%
                        </span>
                    </div>
                `;
            }
            
            document.getElementById('systemStatus').innerHTML = statusHtml;
        }

        function updatePerformanceMetrics(performance) {
            if (performance.status !== 'active') {
                document.getElementById('performanceMetrics').innerHTML = '<p class="loading">No recent activity</p>';
                return;
            }
            
            const speedFactor = performance.performance.avg_speed_factor;
            const processingTime = performance.performance.avg_processing_time;
            
            const html = `
                <div class="metric-large ${speedFactor > 2 ? 'status-good' : speedFactor > 1 ? 'status-warning' : 'status-error'}">
                    ${speedFactor.toFixed(1)}x
                </div>
                <p style="text-align: center; margin-bottom: 1rem;">Average Speed Factor</p>
                
                <div class="status-item">
                    <span class="status-label">Processing Time:</span>
                    <span class="status-value">${processingTime.toFixed(2)}s</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Speed Range:</span>
                    <span class="status-value">${performance.performance.min_speed_factor.toFixed(1)}x - ${performance.performance.max_speed_factor.toFixed(1)}x</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Consistency:</span>
                    <span class="status-value">±${performance.performance.processing_time_std.toFixed(2)}s</span>
                </div>
            `;
            
            document.getElementById('performanceMetrics').innerHTML = html;
        }

        function updateResourceUsage(performance) {
            if (performance.status !== 'active') {
                document.getElementById('resourceUsage').innerHTML = '<p class="loading">No recent data</p>';
                return;
            }
            
            const avgMemory = performance.resources.avg_memory_mb;
            const peakMemory = performance.resources.peak_memory_mb;
            const memoryGrowth = performance.resources.memory_growth;
            
            const html = `
                <div class="metric-large ${avgMemory < 300 ? 'status-good' : avgMemory < 500 ? 'status-warning' : 'status-error'}">
                    ${avgMemory.toFixed(0)} MB
                </div>
                <p style="text-align: center; margin-bottom: 1rem;">Average Memory Usage</p>
                
                <div class="status-item">
                    <span class="status-label">Peak Memory:</span>
                    <span class="status-value">${peakMemory.toFixed(0)} MB</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Memory Growth:</span>
                    <span class="status-value ${memoryGrowth < 50 ? 'status-good' : memoryGrowth < 100 ? 'status-warning' : 'status-error'}">
                        ${memoryGrowth.toFixed(0)} MB
                    </span>
                </div>
                <div class="status-item">
                    <span class="status-label">Efficiency Score:</span>
                    <span class="status-value">${performance.quality.avg_efficiency_score.toFixed(0)}/100</span>
                </div>
            `;
            
            document.getElementById('resourceUsage').innerHTML = html;
        }

        function updateAlerts(alerts) {
            if (!alerts || alerts.length === 0) {
                document.getElementById('alertsContainer').innerHTML = '<p class="loading">No recent alerts</p>';
                return;
            }
            
            const html = alerts.slice(-10).reverse().map(alert => {
                const timestamp = new Date(alert.timestamp).toLocaleTimeString();
                const alertClass = alert.severity === 'error' ? 'alert-error' : 
                                 alert.severity === 'warning' ? 'alert-warning' : 'alert-info';
                
                return `
                    <div class="alert-item ${alertClass}">
                        <strong>[${timestamp}] ${alert.severity.toUpperCase()}</strong><br>
                        ${alert.message}
                    </div>
                `;
            }).join('');
            
            document.getElementById('alertsContainer').innerHTML = html;
        }

        function updateComponentHealth(health) {
            const productionHealth = health.production_health;
            
            if (productionHealth.status !== 'available') {
                document.getElementById('componentHealth').innerHTML = `
                    <p class="loading">Production health: ${productionHealth.status}</p>
                    <p>${productionHealth.message || ''}</p>
                `;
                return;
            }
            
            let html = `
                <div class="status-item">
                    <span class="status-label">Overall Health:</span>
                    <span class="status-value ${productionHealth.overall_health === 'HEALTHY' ? 'status-good' : 
                                                productionHealth.overall_health === 'WARNING' ? 'status-warning' : 'status-error'}">
                        ${productionHealth.overall_health}
                    </span>
                </div>
                <div class="status-item">
                    <span class="status-label">Active Components:</span>
                    <span class="status-value">${productionHealth.active_components}/${productionHealth.component_count}</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Logging Performance:</span>
                    <span class="status-value ${productionHealth.logging_performance === 'EXCELLENT' ? 'status-good' : 'status-warning'}">
                        ${productionHealth.logging_performance}
                    </span>
                </div>
            `;
            
            // Add individual component status
            if (productionHealth.components) {
                html += '<hr style="margin: 1rem 0;">';
                for (const [name, component] of Object.entries(productionHealth.components)) {
                    const statusClass = component.status === 'HEALTHY' ? 'status-good' : 
                                      component.status === 'WARNING' ? 'status-warning' : 'status-error';
                    html += `
                        <div class="status-item">
                            <span class="status-label">${name}:</span>
                            <span class="status-value ${statusClass}">${component.status}</span>
                        </div>
                    `;
                }
            }
            
            document.getElementById('componentHealth').innerHTML = html;
        }

        function updateRecommendations(recommendations) {
            if (!recommendations || recommendations.length === 0) {
                document.getElementById('recommendations').innerHTML = '<p class="loading">No recommendations</p>';
                return;
            }
            
            const html = `
                <div class="recommendations">
                    <ul>
                        ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                </div>
            `;
            
            document.getElementById('recommendations').innerHTML = html;
        }

        function updateChart(status) {
            if (status.performance.status !== 'active') return;
            
            const now = new Date().toLocaleTimeString();
            const performance = status.performance;
            
            // Keep only last 20 data points
            if (chartData.labels.length >= 20) {
                chartData.labels.shift();
                chartData.datasets[0].data.shift();
                chartData.datasets[1].data.shift();
            }
            
            chartData.labels.push(now);
            chartData.datasets[0].data.push(performance.performance.avg_speed_factor);
            chartData.datasets[1].data.push(performance.resources.avg_memory_mb);
            
            if (performanceChart) {
                performanceChart.update('none');
            }
        }

        // Control functions
        async function controlSystem(action) {
            try {
                const response = await fetch(`/api/control/${action}`);
                const result = await response.json();
                console.log(`System ${action}:`, result);
                
                // Immediate update after control action
                setTimeout(updateDashboard, 500);
            } catch (error) {
                console.error(`Error ${action} system:`, error);
            }
        }

        async function exportData() {
            try {
                const response = await fetch('/api/export');
                const data = await response.json();
                
                const blob = new Blob([JSON.stringify(data, null, 2)], {
                    type: 'application/json'
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `voiceflow_performance_${data.export_time}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            } catch (error) {
                console.error('Error exporting data:', error);
            }
        }

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initChart();
            updateDashboard();
            
            // Update every 3 seconds
            setInterval(updateDashboard, 3000);
        });
    </script>
</body>
</html>
        '''
    
    def run(self, host='localhost', port=5000, debug=False):
        """Run the web dashboard"""
        print(f"[WEB DASHBOARD] Starting on http://{host}:{port}")
        print(f"[WEB DASHBOARD] Dashboard URL: http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)


class PerformanceDashboardGUI:
    """GUI Dashboard for performance monitoring"""
    
    def __init__(self, monitor: RealTimeMonitor):
        if not TKINTER_AVAILABLE:
            raise ImportError("tkinter not available - cannot create GUI dashboard")
        
        self.monitor = monitor
        self.root = tk.Tk()
        self.root.title("VoiceFlow Performance Dashboard")
        self.root.geometry("1200x800")
        
        self.setup_gui()
        self.update_timer_running = True
        self.start_update_timer()
    
    def setup_gui(self):
        """Setup the GUI layout"""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Real-time tab
        self.realtime_frame = ttk.Frame(notebook)
        notebook.add(self.realtime_frame, text="Real-time Monitoring")
        self.setup_realtime_tab()
        
        # Analytics tab
        self.analytics_frame = ttk.Frame(notebook)
        notebook.add(self.analytics_frame, text="Performance Analytics")
        self.setup_analytics_tab()
        
        # Alerts tab
        self.alerts_frame = ttk.Frame(notebook)
        notebook.add(self.alerts_frame, text="Alerts & Issues")
        self.setup_alerts_tab()
        
        # Settings tab
        self.settings_frame = ttk.Frame(notebook)
        notebook.add(self.settings_frame, text="Settings")
        self.setup_settings_tab()
    
    def setup_realtime_tab(self):
        """Setup real-time monitoring tab"""
        # Status frame
        status_frame = ttk.LabelFrame(self.realtime_frame, text="System Status")
        status_frame.pack(fill='x', padx=5, pady=5)
        
        self.status_labels = {}
        status_items = [
            "Monitoring Status", "Recordings (10min)", "Avg Speed Factor", 
            "Memory Usage", "Error Rate", "Last Update"
        ]
        
        for i, item in enumerate(status_items):
            ttk.Label(status_frame, text=f"{item}:").grid(row=i//2, column=(i%2)*2, sticky='w', padx=5, pady=2)
            self.status_labels[item] = ttk.Label(status_frame, text="--", foreground='blue')
            self.status_labels[item].grid(row=i//2, column=(i%2)*2+1, sticky='w', padx=5, pady=2)
        
        # Performance metrics frame
        metrics_frame = ttk.LabelFrame(self.realtime_frame, text="Performance Metrics")
        metrics_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Metrics text area
        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, height=15)
        self.metrics_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Control buttons
        control_frame = ttk.Frame(self.realtime_frame)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(control_frame, text="Start Monitoring", 
                  command=self.start_monitoring).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Stop Monitoring", 
                  command=self.stop_monitoring).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Clear Metrics", 
                  command=self.clear_metrics).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Export Report", 
                  command=self.export_report).pack(side='right', padx=5)
    
    def setup_analytics_tab(self):
        """Setup analytics tab"""
        ttk.Label(self.analytics_frame, text="Performance Analytics", 
                 font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Analytics content will be populated dynamically
        self.analytics_text = scrolledtext.ScrolledText(self.analytics_frame, height=25)
        self.analytics_text.pack(fill='both', expand=True, padx=10, pady=10)
    
    def setup_alerts_tab(self):
        """Setup alerts tab"""
        ttk.Label(self.alerts_frame, text="Alerts & Issues", 
                 font=('Arial', 16, 'bold')).pack(pady=10)
        
        self.alerts_text = scrolledtext.ScrolledText(self.alerts_frame, height=25)
        self.alerts_text.pack(fill='both', expand=True, padx=10, pady=10)
    
    def setup_settings_tab(self):
        """Setup settings tab"""
        ttk.Label(self.settings_frame, text="Dashboard Settings", 
                 font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Settings will be added as needed
        settings_text = "Performance monitoring settings and configuration options will be added here."
        ttk.Label(self.settings_frame, text=settings_text, wraplength=400).pack(pady=20)
    
    def start_monitoring(self):
        """Start monitoring"""
        self.monitor.start_monitoring()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitor.stop_monitoring()
    
    def clear_metrics(self):
        """Clear collected metrics"""
        self.monitor.analyzer.metrics.clear()
        self.monitor.analyzer.alerts.clear()
        self.metrics_text.delete(1.0, tk.END)
    
    def export_report(self):
        """Export performance report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = Path(f"performance_report_{timestamp}.json")
        
        status = self.monitor.get_current_status()
        with open(report_file, 'w') as f:
            json.dump(status, f, indent=2, default=str)
        
        print(f"Performance report exported to {report_file}")
    
    def update_display(self):
        """Update the display with current data"""
        if not self.update_timer_running:
            return
        
        try:
            status = self.monitor.get_current_status()
            
            # Update status labels
            monitoring_status = status['monitoring']['status']
            self.status_labels["Monitoring Status"].config(
                text=monitoring_status.upper(),
                foreground='green' if monitoring_status == 'active' else 'red'
            )
            
            perf = status['performance']
            if perf['status'] == 'active':
                self.status_labels["Recordings (10min)"].config(text=str(perf['total_recordings']))
                self.status_labels["Avg Speed Factor"].config(
                    text=f"{perf['performance']['avg_speed_factor']:.1f}x"
                )
                self.status_labels["Memory Usage"].config(
                    text=f"{perf['resources']['avg_memory_mb']:.1f} MB"
                )
                self.status_labels["Error Rate"].config(
                    text=f"{perf['error_rate']:.1%}",
                    foreground='red' if perf['error_rate'] > 0.05 else 'green'
                )
            
            self.status_labels["Last Update"].config(text=datetime.now().strftime('%H:%M:%S'))
            
            # Update metrics display
            self.update_metrics_display(status)
            
            # Update alerts display
            self.update_alerts_display(status['recent_alerts'])
            
            # Update analytics
            self.update_analytics_display(status)
            
        except Exception as e:
            print(f"Error updating display: {e}")
        
        # Schedule next update
        self.root.after(2000, self.update_display)  # Update every 2 seconds
    
    def update_metrics_display(self, status: Dict[str, Any]):
        """Update metrics text display"""
        perf = status['performance']
        
        if perf['status'] != 'active':
            return
        
        # Build metrics text
        metrics_text = f"""PERFORMANCE SUMMARY (Last 10 minutes)
{'='*50}

PROCESSING PERFORMANCE:
  Total Recordings: {perf['total_recordings']}
  Successful: {perf['successful_recordings']}
  Error Rate: {perf['error_rate']:.1%}
  
  Average Processing Time: {perf['performance']['avg_processing_time']:.2f}s
  Average Speed Factor: {perf['performance']['avg_speed_factor']:.1f}x realtime
  Speed Range: {perf['performance']['min_speed_factor']:.1f}x - {perf['performance']['max_speed_factor']:.1f}x
  Processing Consistency: ±{perf['performance']['processing_time_std']:.2f}s

RESOURCE USAGE:
  Average Memory: {perf['resources']['avg_memory_mb']:.1f} MB
  Peak Memory: {perf['resources']['peak_memory_mb']:.1f} MB
  Memory Growth: {perf['resources']['memory_growth']:.1f} MB

TRANSCRIPTION QUALITY:
  Average Efficiency Score: {perf['quality']['avg_efficiency_score']:.1f}/100
  Minimum Efficiency: {perf['quality']['min_efficiency_score']:.1f}/100
  Total Words Transcribed: {perf['quality']['total_words']}
  Average Words per Recording: {perf['quality']['avg_words_per_recording']:.1f}

ALERTS SUMMARY:
  Total Alerts: {perf['alerts']['total_alerts']}
  Error Alerts: {perf['alerts']['error_alerts']}
  Warning Alerts: {perf['alerts']['warning_alerts']}
"""
        
        # Update text widget
        self.metrics_text.delete(1.0, tk.END)
        self.metrics_text.insert(1.0, metrics_text)
    
    def update_alerts_display(self, alerts: List[Dict[str, Any]]):
        """Update alerts display"""
        if not alerts:
            alerts_text = "No recent alerts.\n"
        else:
            alerts_text = "RECENT ALERTS:\n" + "="*50 + "\n\n"
            
            for alert in alerts[-10:]:  # Show last 10 alerts
                timestamp = alert['timestamp'].strftime('%H:%M:%S') if hasattr(alert['timestamp'], 'strftime') else str(alert['timestamp'])
                alerts_text += f"[{timestamp}] {alert['severity'].upper()}: {alert['message']}\n\n"
        
        self.alerts_text.delete(1.0, tk.END)
        self.alerts_text.insert(1.0, alerts_text)
    
    def update_analytics_display(self, status: Dict[str, Any]):
        """Update analytics display"""
        analytics_text = "PERFORMANCE ANALYTICS\n" + "="*50 + "\n\n"
        
        # Add recommendations
        analytics_text += "OPTIMIZATION RECOMMENDATIONS:\n" + "-"*30 + "\n"
        for i, rec in enumerate(status['recommendations'], 1):
            analytics_text += f"{i}. {rec}\n"
        
        analytics_text += "\n\nMONITORING STATUS:\n" + "-"*20 + "\n"
        monitoring = status['monitoring']
        analytics_text += f"Status: {monitoring['status']}\n"
        analytics_text += f"Log Directory: {monitoring['log_directory']}\n"
        analytics_text += f"Files Monitored: {monitoring['files_monitored']}\n"
        analytics_text += f"Metrics Collected: {monitoring['metrics_collected']}\n"
        
        self.analytics_text.delete(1.0, tk.END)
        self.analytics_text.insert(1.0, analytics_text)
    
    def start_update_timer(self):
        """Start the update timer"""
        self.root.after(1000, self.update_display)  # Start after 1 second
    
    def run(self):
        """Run the GUI"""
        try:
            self.root.mainloop()
        finally:
            self.update_timer_running = False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="VoiceFlow Performance Dashboard")
    parser.add_argument('--monitor', action='store_true', help='Start real-time monitoring')
    parser.add_argument('--analyze', type=str, help='Analyze log directory')
    parser.add_argument('--gui', action='store_true', help='Launch GUI dashboard')
    parser.add_argument('--web-dashboard', action='store_true', help='Start web dashboard')
    parser.add_argument('--log-dir', default='logs', help='Log directory to monitor')
    
    args = parser.parse_args()
    
    # Default log directory
    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        # Try common VoiceFlow log locations
        possible_dirs = [
            Path.home() / ".localflow" / "logs",
            Path(os.environ.get("LOCALAPPDATA", ".")) / "VoiceFlow" / "logs",
            Path("test_results")
        ]
        
        for possible_dir in possible_dirs:
            if possible_dir.exists():
                log_dir = possible_dir
                break
        else:
            log_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Using log directory: {log_dir}")
    
    # Create monitor
    monitor = RealTimeMonitor(log_dir)
    
    try:
        if args.gui:
            if not TKINTER_AVAILABLE:
                print("GUI not available - tkinter not installed")
                return 1
            
            print("Launching GUI dashboard...")
            dashboard = PerformanceDashboardGUI(monitor)
            monitor.start_monitoring()
            dashboard.run()
            
        elif args.web_dashboard:
            if not FLASK_AVAILABLE:
                print("Web dashboard not available - Flask not installed")
                return 1
            
            print("Starting web dashboard...")
            web_dashboard = WebDashboard(monitor)
            monitor.start_monitoring()
            web_dashboard.run(host='0.0.0.0', port=5000, debug=False)
            
        elif args.monitor:
            print("Starting console monitoring...")
            monitor.start_monitoring()
            
            try:
                while True:
                    time.sleep(10)
                    status = monitor.get_current_status()
                    
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Performance Summary:")
                    perf = status['performance']
                    if perf['status'] == 'active':
                        print(f"  Recordings: {perf['total_recordings']}")
                        print(f"  Avg Speed: {perf['performance']['avg_speed_factor']:.1f}x")
                        print(f"  Memory: {perf['resources']['avg_memory_mb']:.1f} MB")
                        print(f"  Errors: {perf['error_rate']:.1%}")
                        
                        if status['recent_alerts']:
                            print(f"  Alerts: {len(status['recent_alerts'])}")
                    else:
                        print("  No recent activity")
                        
            except KeyboardInterrupt:
                print("\nStopping monitor...")
                
        elif args.analyze:
            analyze_dir = Path(args.analyze)
            if not analyze_dir.exists():
                print(f"Analysis directory not found: {analyze_dir}")
                return 1
            
            print(f"Analyzing logs in {analyze_dir}...")
            # Analysis functionality would be implemented here
            print("Log analysis feature coming soon...")
            
        else:
            print("No action specified. Use --help for usage information.")
            print(f"Log directory: {log_dir}")
            print("Available actions:")
            print("  --monitor     Start console monitoring")
            print("  --gui         Launch GUI dashboard") 
            print("  --analyze DIR Analyze log directory")
            
    finally:
        monitor.stop_monitoring()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())