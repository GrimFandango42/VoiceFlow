"""
Audio Quality Monitor for VoiceFlow
Real-time SNR calculation, quality assessment, and audio stream monitoring.
"""

import numpy as np
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Callable, Any
import json
from datetime import datetime, timedelta
import sqlite3
from pathlib import Path


@dataclass
class AudioQualityMetrics:
    """Audio quality measurements"""
    timestamp: float
    snr_db: float
    noise_floor_db: float
    signal_level_db: float
    thd_percent: float  # Total Harmonic Distortion
    dynamic_range_db: float
    spectral_centroid_hz: float
    spectral_rolloff_hz: float
    zero_crossing_rate: float
    rms_energy: float
    peak_level_db: float
    crest_factor: float
    quality_score: float  # 0-100 overall quality score


@dataclass
class QualityAlert:
    """Quality alert information"""
    timestamp: float
    alert_type: str
    severity: str  # "low", "medium", "high", "critical"
    message: str
    metric_value: float
    threshold: float
    recommendations: List[str]


class AudioQualityAnalyzer:
    """
    Real-time audio quality analysis engine
    """
    
    def __init__(self, sample_rate: int = 16000, analysis_window: float = 1.0):
        self.sample_rate = sample_rate
        self.analysis_window = analysis_window
        self.window_samples = int(sample_rate * analysis_window)
        
        # Audio buffer for analysis
        self.audio_buffer = deque(maxlen=self.window_samples)
        
        # Quality thresholds
        self.quality_thresholds = {
            'snr_excellent': 20.0,     # > 20dB = excellent
            'snr_good': 15.0,          # 15-20dB = good
            'snr_fair': 10.0,          # 10-15dB = fair
            'snr_poor': 5.0,           # 5-10dB = poor
            'noise_floor_max': -30.0,  # Above -30dB = noisy
            'thd_max': 3.0,            # > 3% = high distortion
            'dynamic_range_min': 30.0, # < 30dB = compressed
            'clipping_threshold': -3.0  # Above -3dB = clipping risk
        }
        
        # History buffers
        self.metrics_history = deque(maxlen=300)  # 5 minutes at 1Hz
        self.alert_history = deque(maxlen=100)
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
    def add_audio_data(self, audio_data: np.ndarray):
        """Add audio data to analysis buffer"""
        with self.lock:
            self.audio_buffer.extend(audio_data.flatten())
    
    def calculate_snr(self, signal: np.ndarray) -> tuple[float, float, float]:
        """
        Calculate Signal-to-Noise Ratio using voice activity detection
        Returns: (snr_db, signal_level_db, noise_floor_db)
        """
        if len(signal) == 0:
            return 0.0, -80.0, -80.0
        
        # Frame-based analysis
        frame_length = int(self.sample_rate * 0.025)  # 25ms frames
        hop_length = int(self.sample_rate * 0.010)    # 10ms hop
        
        frame_energies = []
        for i in range(0, len(signal) - frame_length, hop_length):
            frame = signal[i:i + frame_length]
            energy = np.mean(frame ** 2)
            if energy > 0:
                energy_db = 10 * np.log10(energy)
                frame_energies.append(energy_db)
        
        if len(frame_energies) < 2:
            return 0.0, -80.0, -80.0
        
        frame_energies = np.array(frame_energies)
        
        # Separate speech and noise using energy distribution
        energy_sorted = np.sort(frame_energies)
        noise_threshold = np.percentile(energy_sorted, 25)  # Bottom 25% as noise
        signal_threshold = np.percentile(energy_sorted, 75)  # Top 25% as signal
        
        noise_frames = frame_energies[frame_energies <= noise_threshold]
        signal_frames = frame_energies[frame_energies >= signal_threshold]
        
        if len(noise_frames) == 0:
            noise_level = np.min(frame_energies)
        else:
            noise_level = np.mean(noise_frames)
            
        if len(signal_frames) == 0:
            signal_level = np.max(frame_energies)
        else:
            signal_level = np.mean(signal_frames)
        
        snr = signal_level - noise_level
        return max(snr, -20.0), signal_level, noise_level
    
    def calculate_thd(self, signal: np.ndarray) -> float:
        """
        Calculate Total Harmonic Distortion
        """
        if len(signal) < self.sample_rate // 10:  # Need at least 100ms
            return 0.0
        
        # Apply window to reduce spectral leakage
        windowed = signal * np.hanning(len(signal))
        
        # FFT
        fft_data = np.fft.fft(windowed)
        magnitude = np.abs(fft_data[:len(fft_data)//2])
        freqs = np.fft.fftfreq(len(signal), 1/self.sample_rate)[:len(magnitude)]
        
        # Find fundamental frequency (dominant peak in voice range)
        voice_range = (freqs >= 80) & (freqs <= 1000)
        if not np.any(voice_range):
            return 0.0
        
        voice_spectrum = magnitude[voice_range]
        voice_freqs = freqs[voice_range]
        
        if len(voice_spectrum) == 0:
            return 0.0
        
        # Find fundamental
        fundamental_idx = np.argmax(voice_spectrum)
        fundamental_freq = voice_freqs[fundamental_idx]
        fundamental_magnitude = voice_spectrum[fundamental_idx]
        
        if fundamental_freq == 0 or fundamental_magnitude == 0:
            return 0.0
        
        # Find harmonics (2f, 3f, 4f, 5f)
        harmonic_power = 0.0
        harmonics_found = 0
        
        for harmonic in range(2, 6):  # 2nd through 5th harmonics
            harmonic_freq = fundamental_freq * harmonic
            if harmonic_freq >= self.sample_rate / 2:
                break
            
            # Find closest frequency bin
            harmonic_idx = np.argmin(np.abs(freqs - harmonic_freq))
            if harmonic_idx < len(magnitude):
                harmonic_power += magnitude[harmonic_idx] ** 2
                harmonics_found += 1
        
        if harmonics_found == 0:
            return 0.0
        
        # THD calculation
        fundamental_power = fundamental_magnitude ** 2
        thd = np.sqrt(harmonic_power) / fundamental_magnitude * 100
        
        return min(thd, 50.0)  # Cap at 50%
    
    def calculate_spectral_features(self, signal: np.ndarray) -> Dict[str, float]:
        """
        Calculate spectral features for quality assessment
        """
        if len(signal) == 0:
            return {
                'spectral_centroid': 0.0,
                'spectral_rolloff': 0.0,
                'zero_crossing_rate': 0.0
            }
        
        # Apply window
        windowed = signal * np.hanning(len(signal))
        
        # FFT
        fft_data = np.fft.fft(windowed)
        magnitude = np.abs(fft_data[:len(fft_data)//2])
        freqs = np.fft.fftfreq(len(signal), 1/self.sample_rate)[:len(magnitude)]
        
        # Power spectrum
        power = magnitude ** 2
        power_sum = np.sum(power)
        
        if power_sum == 0:
            return {
                'spectral_centroid': 0.0,
                'spectral_rolloff': 0.0,
                'zero_crossing_rate': 0.0
            }
        
        # Spectral centroid
        spectral_centroid = np.sum(freqs * power) / power_sum
        
        # Spectral rolloff (95% of energy)
        cumsum_power = np.cumsum(power)
        rolloff_idx = np.where(cumsum_power >= 0.95 * power_sum)[0]
        spectral_rolloff = freqs[rolloff_idx[0]] if len(rolloff_idx) > 0 else self.sample_rate / 4
        
        # Zero crossing rate
        zero_crossings = np.sum(np.abs(np.diff(np.sign(signal))))
        zero_crossing_rate = zero_crossings / (2 * len(signal))
        
        return {
            'spectral_centroid': spectral_centroid,
            'spectral_rolloff': spectral_rolloff,
            'zero_crossing_rate': zero_crossing_rate
        }
    
    def calculate_dynamic_range(self, signal: np.ndarray) -> float:
        """
        Calculate dynamic range of the signal
        """
        if len(signal) == 0:
            return 0.0
        
        # RMS energy
        rms = np.sqrt(np.mean(signal ** 2))
        
        # Peak level
        peak = np.max(np.abs(signal))
        
        if peak == 0 or rms == 0:
            return 0.0
        
        # Dynamic range in dB
        dynamic_range = 20 * np.log10(peak / rms)
        return min(dynamic_range, 60.0)  # Cap at 60dB
    
    def calculate_quality_score(self, metrics: AudioQualityMetrics) -> float:
        """
        Calculate overall quality score (0-100)
        """
        score = 100.0
        
        # SNR component (40% weight)
        if metrics.snr_db >= self.quality_thresholds['snr_excellent']:
            snr_score = 100
        elif metrics.snr_db >= self.quality_thresholds['snr_good']:
            snr_score = 80
        elif metrics.snr_db >= self.quality_thresholds['snr_fair']:
            snr_score = 60
        elif metrics.snr_db >= self.quality_thresholds['snr_poor']:
            snr_score = 40
        else:
            snr_score = max(0, 20 + metrics.snr_db * 4)  # Linear below 5dB
        
        score = score * 0.4 + snr_score * 0.4
        
        # THD component (20% weight)
        if metrics.thd_percent <= 1.0:
            thd_score = 100
        elif metrics.thd_percent <= self.quality_thresholds['thd_max']:
            thd_score = 100 - (metrics.thd_percent - 1.0) * 33.3
        else:
            thd_score = max(0, 100 - metrics.thd_percent * 20)
        
        score = score * 0.8 + thd_score * 0.2
        
        # Dynamic range component (20% weight)
        if metrics.dynamic_range_db >= self.quality_thresholds['dynamic_range_min']:
            dr_score = 100
        else:
            dr_score = max(0, metrics.dynamic_range_db / self.quality_thresholds['dynamic_range_min'] * 100)
        
        score = score * 0.8 + dr_score * 0.2
        
        # Clipping penalty (20% weight)
        if metrics.peak_level_db <= self.quality_thresholds['clipping_threshold']:
            clipping_score = 100
        else:
            clipping_score = max(0, 100 - (metrics.peak_level_db - self.quality_thresholds['clipping_threshold']) * 20)
        
        score = score * 0.8 + clipping_score * 0.2
        
        return max(0.0, min(100.0, score))
    
    def analyze_quality(self) -> Optional[AudioQualityMetrics]:
        """
        Perform comprehensive quality analysis on current audio buffer
        """
        with self.lock:
            if len(self.audio_buffer) < self.window_samples // 4:
                return None
            
            signal = np.array(list(self.audio_buffer))
        
        # Calculate SNR
        snr_db, signal_level_db, noise_floor_db = self.calculate_snr(signal)
        
        # Calculate THD
        thd_percent = self.calculate_thd(signal)
        
        # Calculate spectral features
        spectral_features = self.calculate_spectral_features(signal)
        
        # Calculate dynamic range
        dynamic_range_db = self.calculate_dynamic_range(signal)
        
        # Calculate energy metrics
        rms_energy = np.sqrt(np.mean(signal ** 2))
        peak_level = np.max(np.abs(signal))
        peak_level_db = 20 * np.log10(peak_level) if peak_level > 0 else -80.0
        crest_factor = peak_level / rms_energy if rms_energy > 0 else 0.0
        
        # Create metrics object
        metrics = AudioQualityMetrics(
            timestamp=time.time(),
            snr_db=snr_db,
            noise_floor_db=noise_floor_db,
            signal_level_db=signal_level_db,
            thd_percent=thd_percent,
            dynamic_range_db=dynamic_range_db,
            spectral_centroid_hz=spectral_features['spectral_centroid'],
            spectral_rolloff_hz=spectral_features['spectral_rolloff'],
            zero_crossing_rate=spectral_features['zero_crossing_rate'],
            rms_energy=rms_energy,
            peak_level_db=peak_level_db,
            crest_factor=crest_factor,
            quality_score=0.0  # Will be calculated next
        )
        
        # Calculate overall quality score
        metrics.quality_score = self.calculate_quality_score(metrics)
        
        # Store in history
        self.metrics_history.append(metrics)
        
        # Check for quality alerts
        self.check_quality_alerts(metrics)
        
        return metrics
    
    def check_quality_alerts(self, metrics: AudioQualityMetrics):
        """
        Check for quality issues and generate alerts
        """
        alerts = []
        
        # SNR alerts
        if metrics.snr_db < self.quality_thresholds['snr_poor']:
            severity = "critical" if metrics.snr_db < 0 else "high"
            alerts.append(QualityAlert(
                timestamp=metrics.timestamp,
                alert_type="low_snr",
                severity=severity,
                message=f"Low signal-to-noise ratio: {metrics.snr_db:.1f}dB",
                metric_value=metrics.snr_db,
                threshold=self.quality_thresholds['snr_poor'],
                recommendations=[
                    "Move closer to microphone",
                    "Reduce background noise",
                    "Check microphone placement",
                    "Consider using noise cancellation"
                ]
            ))
        
        # High noise floor
        if metrics.noise_floor_db > self.quality_thresholds['noise_floor_max']:
            alerts.append(QualityAlert(
                timestamp=metrics.timestamp,
                alert_type="high_noise_floor",
                severity="medium",
                message=f"High noise floor: {metrics.noise_floor_db:.1f}dB",
                metric_value=metrics.noise_floor_db,
                threshold=self.quality_thresholds['noise_floor_max'],
                recommendations=[
                    "Reduce environmental noise",
                    "Check for electrical interference",
                    "Use noise gate or reduction"
                ]
            ))
        
        # High THD
        if metrics.thd_percent > self.quality_thresholds['thd_max']:
            severity = "high" if metrics.thd_percent > 10 else "medium"
            alerts.append(QualityAlert(
                timestamp=metrics.timestamp,
                alert_type="high_distortion",
                severity=severity,
                message=f"High distortion: {metrics.thd_percent:.1f}%",
                metric_value=metrics.thd_percent,
                threshold=self.quality_thresholds['thd_max'],
                recommendations=[
                    "Reduce input gain",
                    "Check microphone quality",
                    "Avoid overdriving the signal",
                    "Check for clipping"
                ]
            ))
        
        # Low dynamic range
        if metrics.dynamic_range_db < self.quality_thresholds['dynamic_range_min']:
            alerts.append(QualityAlert(
                timestamp=metrics.timestamp,
                alert_type="low_dynamic_range",
                severity="medium",
                message=f"Compressed signal: {metrics.dynamic_range_db:.1f}dB dynamic range",
                metric_value=metrics.dynamic_range_db,
                threshold=self.quality_thresholds['dynamic_range_min'],
                recommendations=[
                    "Reduce compression",
                    "Check audio processing chain",
                    "Avoid automatic gain control"
                ]
            ))
        
        # Clipping risk
        if metrics.peak_level_db > self.quality_thresholds['clipping_threshold']:
            severity = "critical" if metrics.peak_level_db > 0 else "high"
            alerts.append(QualityAlert(
                timestamp=metrics.timestamp,
                alert_type="clipping_risk",
                severity=severity,
                message=f"Signal too loud: {metrics.peak_level_db:.1f}dB peak",
                metric_value=metrics.peak_level_db,
                threshold=self.quality_thresholds['clipping_threshold'],
                recommendations=[
                    "Reduce input gain immediately",
                    "Move away from microphone",
                    "Lower speaking volume",
                    "Check gain staging"
                ]
            ))
        
        # Store alerts
        for alert in alerts:
            self.alert_history.append(alert)
    
    def get_quality_summary(self, time_window: float = 60.0) -> Dict[str, Any]:
        """
        Get quality summary for the specified time window
        """
        current_time = time.time()
        window_start = current_time - time_window
        
        # Filter metrics in time window
        recent_metrics = [m for m in self.metrics_history 
                         if m.timestamp >= window_start]
        
        if not recent_metrics:
            return {
                'status': 'no_data',
                'message': 'No audio quality data available'
            }
        
        # Calculate statistics
        snr_values = [m.snr_db for m in recent_metrics]
        quality_scores = [m.quality_score for m in recent_metrics]
        
        # Recent alerts
        recent_alerts = [a for a in self.alert_history 
                        if a.timestamp >= window_start]
        
        return {
            'status': 'ok',
            'time_window_seconds': time_window,
            'samples_analyzed': len(recent_metrics),
            'current_quality_score': recent_metrics[-1].quality_score if recent_metrics else 0,
            'average_quality_score': np.mean(quality_scores),
            'min_quality_score': np.min(quality_scores),
            'current_snr_db': recent_metrics[-1].snr_db if recent_metrics else 0,
            'average_snr_db': np.mean(snr_values),
            'min_snr_db': np.min(snr_values),
            'alert_count': len(recent_alerts),
            'critical_alerts': len([a for a in recent_alerts if a.severity == 'critical']),
            'high_alerts': len([a for a in recent_alerts if a.severity == 'high']),
            'medium_alerts': len([a for a in recent_alerts if a.severity == 'medium']),
            'recommendations': self.get_current_recommendations(recent_alerts)
        }
    
    def get_current_recommendations(self, alerts: List[QualityAlert]) -> List[str]:
        """
        Get prioritized recommendations based on current alerts
        """
        if not alerts:
            return ["Audio quality is good"]
        
        # Prioritize by severity
        critical_alerts = [a for a in alerts if a.severity == 'critical']
        high_alerts = [a for a in alerts if a.severity == 'high']
        
        recommendations = []
        
        # Add critical recommendations first
        for alert in critical_alerts:
            recommendations.extend(alert.recommendations[:2])  # Top 2 recommendations
        
        # Add high priority recommendations
        for alert in high_alerts:
            recommendations.extend(alert.recommendations[:1])  # Top recommendation
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                unique_recommendations.append(rec)
                seen.add(rec)
        
        return unique_recommendations[:5]  # Return top 5


class AudioQualityMonitor:
    """
    Continuous audio quality monitoring service
    """
    
    def __init__(self, sample_rate: int = 16000, 
                 analysis_interval: float = 1.0,
                 database_path: Optional[Path] = None):
        self.sample_rate = sample_rate
        self.analysis_interval = analysis_interval
        
        # Initialize analyzer
        self.analyzer = AudioQualityAnalyzer(sample_rate=sample_rate)
        
        # Database for storing quality metrics
        self.db_path = database_path or Path.home() / ".voiceflow" / "audio_quality.db"
        self.db_path.parent.mkdir(exist_ok=True)
        self.init_database()
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Callbacks
        self.on_quality_update: Optional[Callable[[AudioQualityMetrics], None]] = None
        self.on_quality_alert: Optional[Callable[[QualityAlert], None]] = None
        
    def init_database(self):
        """Initialize database for storing quality metrics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Quality metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quality_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                snr_db REAL,
                noise_floor_db REAL,
                signal_level_db REAL,
                thd_percent REAL,
                dynamic_range_db REAL,
                spectral_centroid_hz REAL,
                spectral_rolloff_hz REAL,
                zero_crossing_rate REAL,
                rms_energy REAL,
                peak_level_db REAL,
                crest_factor REAL,
                quality_score REAL
            )
        ''')
        
        # Quality alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quality_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                metric_value REAL,
                threshold_value REAL,
                recommendations TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_audio_data(self, audio_data: np.ndarray):
        """Add audio data for quality analysis"""
        self.analyzer.add_audio_data(audio_data)
    
    def start_monitoring(self):
        """Start continuous quality monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("[QUALITY] Audio quality monitoring started")
    
    def stop_monitoring(self):
        """Stop quality monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
        print("[QUALITY] Audio quality monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Analyze current quality
                metrics = self.analyzer.analyze_quality()
                
                if metrics:
                    # Store in database
                    self._store_metrics(metrics)
                    
                    # Call callback
                    if self.on_quality_update:
                        self.on_quality_update(metrics)
                    
                    # Check for new alerts
                    recent_alerts = list(self.analyzer.alert_history)[-10:]  # Last 10 alerts
                    for alert in recent_alerts:
                        if time.time() - alert.timestamp < self.analysis_interval * 2:
                            self._store_alert(alert)
                            if self.on_quality_alert:
                                self.on_quality_alert(alert)
                
                time.sleep(self.analysis_interval)
                
            except Exception as e:
                print(f"[QUALITY] Monitor error: {e}")
                time.sleep(1.0)
    
    def _store_metrics(self, metrics: AudioQualityMetrics):
        """Store quality metrics in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO quality_metrics (
                    timestamp, snr_db, noise_floor_db, signal_level_db,
                    thd_percent, dynamic_range_db, spectral_centroid_hz,
                    spectral_rolloff_hz, zero_crossing_rate, rms_energy,
                    peak_level_db, crest_factor, quality_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metrics.timestamp, metrics.snr_db, metrics.noise_floor_db,
                metrics.signal_level_db, metrics.thd_percent, metrics.dynamic_range_db,
                metrics.spectral_centroid_hz, metrics.spectral_rolloff_hz,
                metrics.zero_crossing_rate, metrics.rms_energy,
                metrics.peak_level_db, metrics.crest_factor, metrics.quality_score
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[QUALITY] Database error: {e}")
    
    def _store_alert(self, alert: QualityAlert):
        """Store quality alert in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO quality_alerts (
                    timestamp, alert_type, severity, message,
                    metric_value, threshold_value, recommendations
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.timestamp, alert.alert_type, alert.severity,
                alert.message, alert.metric_value, alert.threshold,
                json.dumps(alert.recommendations)
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[QUALITY] Alert storage error: {e}")
    
    def get_quality_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive quality report"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Time window
            start_time = time.time() - (hours * 3600)
            
            # Get metrics
            cursor.execute('''
                SELECT * FROM quality_metrics 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC
            ''', (start_time,))
            
            metrics_data = cursor.fetchall()
            
            # Get alerts
            cursor.execute('''
                SELECT * FROM quality_alerts 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC
            ''', (start_time,))
            
            alerts_data = cursor.fetchall()
            conn.close()
            
            if not metrics_data:
                return {'status': 'no_data', 'message': 'No quality data available'}
            
            # Process metrics
            quality_scores = [row[13] for row in metrics_data]  # quality_score column
            snr_values = [row[2] for row in metrics_data]       # snr_db column
            
            # Process alerts by severity
            critical_alerts = [row for row in alerts_data if row[3] == 'critical']
            high_alerts = [row for row in alerts_data if row[3] == 'high']
            medium_alerts = [row for row in alerts_data if row[3] == 'medium']
            
            report = {
                'time_period_hours': hours,
                'samples_analyzed': len(metrics_data),
                'quality': {
                    'current_score': quality_scores[0] if quality_scores else 0,
                    'average_score': np.mean(quality_scores) if quality_scores else 0,
                    'min_score': np.min(quality_scores) if quality_scores else 0,
                    'max_score': np.max(quality_scores) if quality_scores else 0
                },
                'snr': {
                    'current_db': snr_values[0] if snr_values else 0,
                    'average_db': np.mean(snr_values) if snr_values else 0,
                    'min_db': np.min(snr_values) if snr_values else 0,
                    'max_db': np.max(snr_values) if snr_values else 0
                },
                'alerts': {
                    'total': len(alerts_data),
                    'critical': len(critical_alerts),
                    'high': len(high_alerts),
                    'medium': len(medium_alerts)
                },
                'status': 'excellent' if np.mean(quality_scores) > 80 else
                         'good' if np.mean(quality_scores) > 60 else
                         'fair' if np.mean(quality_scores) > 40 else 'poor'
            }
            
            return report
            
        except Exception as e:
            return {'status': 'error', 'message': f'Report generation failed: {e}'}


def create_quality_monitor(sample_rate: int = 16000, 
                          analysis_interval: float = 1.0) -> AudioQualityMonitor:
    """Factory function to create audio quality monitor"""
    return AudioQualityMonitor(
        sample_rate=sample_rate,
        analysis_interval=analysis_interval
    )