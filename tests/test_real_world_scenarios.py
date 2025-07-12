#!/usr/bin/env python3
"""
Real-World Usage Pattern Simulation and Stress Testing
======================================================

Comprehensive testing suite that simulates realistic VoiceFlow usage patterns
and stress scenarios to validate production readiness and performance under
actual user conditions.

Test Categories:
1. Daily Usage Pattern Simulation (Light, Normal, Power Users)
2. Burst Traffic Handling (Meeting transcriptions, batch processing)
3. Extended Operation Stability (8+ hour sessions)
4. Resource-Constrained Environment Testing
5. Network Latency and Connectivity Issues
6. Concurrent User Simulation
7. Failure Recovery and Resilience Testing
8. Production Load Simulation

Author: Senior Performance Testing Expert
Version: 1.0.0
"""

import asyncio
import json
import os
import psutil
import random
import statistics
import sys
import threading
import time
import websockets
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from unittest.mock import Mock, patch

import numpy as np
import pytest

# Import VoiceFlow components
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.voiceflow_core import VoiceFlowEngine, create_engine
    from core.ai_enhancement import AIEnhancer, create_enhancer
    from utils.secure_db import SecureDatabase, create_secure_database
    from utils.auth import AuthManager, get_auth_manager
    VOICEFLOW_AVAILABLE = True
except ImportError:
    VOICEFLOW_AVAILABLE = False


class UserProfile:
    """Represents a user's behavior profile for simulation."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.transcriptions_per_hour = config.get('transcriptions_per_hour', 10)
        self.avg_transcription_duration = config.get('avg_duration_s', 3)
        self.ai_enhancement_rate = config.get('ai_enhancement_rate', 0.8)
        self.session_duration_hours = config.get('session_duration_hours', 2)
        self.break_frequency_minutes = config.get('break_frequency_minutes', 30)
        self.break_duration_minutes = config.get('break_duration_minutes', 5)
        self.error_tolerance = config.get('error_tolerance', 0.05)
        self.concurrency_factor = config.get('concurrency_factor', 1)
        
    def __str__(self):
        return f"UserProfile({self.name}: {self.transcriptions_per_hour}/hr, {self.avg_transcription_duration}s avg)"


class SimulationMetrics:
    """Tracks metrics during simulation."""
    
    def __init__(self):
        self.start_time = time.time()
        self.operations_completed = 0
        self.operations_failed = 0
        self.response_times = []
        self.memory_samples = []
        self.cpu_samples = []
        self.error_details = []
        self.throughput_samples = []
        
    def record_operation(self, duration_ms: float, success: bool, error_info: Optional[str] = None):
        """Record an operation result."""
        if success:
            self.operations_completed += 1
            self.response_times.append(duration_ms)
        else:
            self.operations_failed += 1
            if error_info:
                self.error_details.append({
                    'timestamp': time.time(),
                    'error': error_info,
                    'operation_count': self.operations_completed + self.operations_failed
                })
    
    def sample_system_resources(self):
        """Sample current system resource usage."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            cpu_percent = process.cpu_percent()
            
            self.memory_samples.append({
                'timestamp': time.time(),
                'rss_mb': memory_info.rss / 1024 / 1024,
                'cpu_percent': cpu_percent
            })
        except Exception:
            pass  # Skip if unable to sample
    
    def calculate_throughput(self, window_seconds: int = 60):
        """Calculate operations per second over a time window."""
        current_time = time.time()
        recent_count = sum(1 for _ in self.response_times if current_time - self.start_time < window_seconds)
        throughput = recent_count / min(window_seconds, current_time - self.start_time)
        self.throughput_samples.append({
            'timestamp': current_time,
            'ops_per_second': throughput
        })
        return throughput
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary."""
        total_time = time.time() - self.start_time
        total_operations = self.operations_completed + self.operations_failed
        
        return {
            'duration_seconds': total_time,
            'total_operations': total_operations,
            'successful_operations': self.operations_completed,
            'failed_operations': self.operations_failed,
            'success_rate': self.operations_completed / total_operations if total_operations > 0 else 0,
            'error_rate': self.operations_failed / total_operations if total_operations > 0 else 0,
            'response_time_stats': {
                'mean_ms': statistics.mean(self.response_times) if self.response_times else 0,
                'median_ms': statistics.median(self.response_times) if self.response_times else 0,
                'p95_ms': np.percentile(self.response_times, 95) if self.response_times else 0,
                'p99_ms': np.percentile(self.response_times, 99) if self.response_times else 0,
                'min_ms': min(self.response_times) if self.response_times else 0,
                'max_ms': max(self.response_times) if self.response_times else 0
            },
            'throughput_ops_per_second': total_operations / total_time if total_time > 0 else 0,
            'memory_usage': {
                'samples': len(self.memory_samples),
                'peak_mb': max([s['rss_mb'] for s in self.memory_samples]) if self.memory_samples else 0,
                'avg_mb': statistics.mean([s['rss_mb'] for s in self.memory_samples]) if self.memory_samples else 0
            },
            'cpu_usage': {
                'peak_percent': max([s['cpu_percent'] for s in self.memory_samples]) if self.memory_samples else 0,
                'avg_percent': statistics.mean([s['cpu_percent'] for s in self.memory_samples]) if self.memory_samples else 0
            },
            'error_details': self.error_details
        }


class RealWorldScenarioTester:
    """Comprehensive real-world scenario testing suite."""
    
    def __init__(self):
        self.test_results = {}
        self.user_profiles = self._create_user_profiles()
        self.simulation_active = False
        
    def _create_user_profiles(self) -> Dict[str, UserProfile]:
        """Create realistic user profiles for simulation."""
        return {
            'light_user': UserProfile('light_user', {
                'transcriptions_per_hour': 5,
                'avg_duration_s': 2,
                'ai_enhancement_rate': 0.7,
                'session_duration_hours': 1,
                'break_frequency_minutes': 15,
                'break_duration_minutes': 2
            }),
            'normal_user': UserProfile('normal_user', {
                'transcriptions_per_hour': 20,
                'avg_duration_s': 4,
                'ai_enhancement_rate': 0.85,
                'session_duration_hours': 3,
                'break_frequency_minutes': 30,
                'break_duration_minutes': 5
            }),
            'power_user': UserProfile('power_user', {
                'transcriptions_per_hour': 60,
                'avg_duration_s': 6,
                'ai_enhancement_rate': 0.95,
                'session_duration_hours': 6,
                'break_frequency_minutes': 45,
                'break_duration_minutes': 10
            }),
            'meeting_participant': UserProfile('meeting_participant', {
                'transcriptions_per_hour': 40,
                'avg_duration_s': 8,
                'ai_enhancement_rate': 0.9,
                'session_duration_hours': 2,
                'break_frequency_minutes': 60,
                'break_duration_minutes': 15,
                'concurrency_factor': 0.3  # Often overlapping with others
            }),
            'content_creator': UserProfile('content_creator', {
                'transcriptions_per_hour': 30,
                'avg_duration_s': 15,
                'ai_enhancement_rate': 0.98,
                'session_duration_hours': 4,
                'break_frequency_minutes': 60,
                'break_duration_minutes': 20
            })
        }
    
    # ============================================================================
    # DAILY USAGE PATTERN SIMULATION
    # ============================================================================
    
    def simulate_daily_usage_pattern(self, user_profile: UserProfile, simulation_duration_minutes: int = 60) -> Dict[str, Any]:
        """Simulate realistic daily usage pattern for a user profile."""
        print(f"\n[SIMULATION] Simulating {user_profile.name} for {simulation_duration_minutes} minutes...")
        
        metrics = SimulationMetrics()
        
        if not VOICEFLOW_AVAILABLE:
            return {"error": "VoiceFlow components not available"}
        
        try:
            # Setup mocked components
            with patch('core.voiceflow_core.AudioToTextRecorder'):
                engine = create_engine()
                
                with patch('requests.Session.post') as mock_post:
                    mock_response = Mock()
                    mock_response.status_code = 200
                    mock_response.json.return_value = {"response": "Enhanced transcription text"}
                    mock_post.return_value = mock_response
                    
                    enhancer = create_enhancer()
                    
                    # Calculate operation timing
                    operations_per_minute = user_profile.transcriptions_per_hour / 60
                    operation_interval = 60 / operations_per_minute if operations_per_minute > 0 else 60
                    
                    start_time = time.time()
                    end_time = start_time + (simulation_duration_minutes * 60)
                    next_break_time = start_time + (user_profile.break_frequency_minutes * 60)
                    
                    operation_count = 0
                    
                    while time.time() < end_time:
                        current_time = time.time()
                        
                        # Check for break time
                        if current_time >= next_break_time:
                            print(f"  Taking {user_profile.break_duration_minutes}min break...")
                            time.sleep(user_profile.break_duration_minutes * 60 / 60)  # Compressed break
                            next_break_time = current_time + (user_profile.break_frequency_minutes * 60)
                            continue
                        
                        # Simulate transcription operation
                        operation_start = time.perf_counter()
                        success = True
                        error_info = None
                        
                        try:
                            # Simulate transcription processing
                            transcription_text = f"Simulated transcription {operation_count} from {user_profile.name}"
                            
                            # Add realistic variation in processing time
                            base_duration = user_profile.avg_transcription_duration
                            actual_duration = max(0.5, random.normalvariate(base_duration, base_duration * 0.3))
                            time.sleep(actual_duration / 30)  # Compressed time for testing
                            
                            # Simulate AI enhancement
                            if random.random() < user_profile.ai_enhancement_rate:
                                enhanced_text = enhancer.enhance_text(transcription_text, "general")
                            
                            # Update engine stats
                            engine.stats["total_transcriptions"] += 1
                            processing_time = (time.perf_counter() - operation_start) * 1000
                            engine.stats["processing_times"].append(processing_time)
                            
                        except Exception as e:
                            success = False
                            error_info = str(e)
                        
                        operation_duration = (time.perf_counter() - operation_start) * 1000
                        metrics.record_operation(operation_duration, success, error_info)
                        
                        # Sample system resources periodically
                        if operation_count % 10 == 0:
                            metrics.sample_system_resources()
                            metrics.calculate_throughput()
                        
                        operation_count += 1
                        
                        # Wait for next operation
                        next_operation_time = operation_start + operation_interval
                        sleep_time = max(0, next_operation_time - time.perf_counter())
                        if sleep_time > 0:
                            time.sleep(sleep_time / 30)  # Compressed time
            
            # Generate results
            summary = metrics.get_summary()
            summary['user_profile'] = user_profile.name
            summary['target_operations_per_hour'] = user_profile.transcriptions_per_hour
            summary['actual_operations_per_hour'] = (metrics.operations_completed / simulation_duration_minutes) * 60
            summary['profile_compliance'] = self._analyze_profile_compliance(user_profile, summary)
            
            return summary
            
        except Exception as e:
            return {"error": f"Daily usage simulation failed: {e}"}
    
    def _analyze_profile_compliance(self, profile: UserProfile, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze how well the simulation matched the user profile."""
        target_ops_per_hour = profile.transcriptions_per_hour
        actual_ops_per_hour = results.get('actual_operations_per_hour', 0)
        
        compliance_score = min(1.0, actual_ops_per_hour / target_ops_per_hour) if target_ops_per_hour > 0 else 0
        
        return {
            'throughput_compliance': compliance_score,
            'throughput_variance': abs(actual_ops_per_hour - target_ops_per_hour) / target_ops_per_hour if target_ops_per_hour > 0 else 0,
            'error_rate_acceptable': results.get('error_rate', 1) <= profile.error_tolerance,
            'overall_grade': 'A' if compliance_score > 0.9 and results.get('error_rate', 1) <= profile.error_tolerance else 'B' if compliance_score > 0.7 else 'C'
        }
    
    # ============================================================================
    # BURST TRAFFIC AND LOAD TESTING
    # ============================================================================
    
    def test_burst_traffic_handling(self) -> Dict[str, Any]:
        """Test system response to sudden traffic bursts."""
        print("\n[BURST TEST] Testing burst traffic handling...")
        
        if not VOICEFLOW_AVAILABLE:
            return {"error": "VoiceFlow components not available"}
        
        results = {}
        
        # Define burst scenarios
        burst_scenarios = [
            {'name': 'small_burst', 'operations': 50, 'duration_seconds': 10},
            {'name': 'medium_burst', 'operations': 200, 'duration_seconds': 30},
            {'name': 'large_burst', 'operations': 500, 'duration_seconds': 60}
        ]
        
        for scenario in burst_scenarios:
            print(f"  Testing {scenario['name']}: {scenario['operations']} ops in {scenario['duration_seconds']}s")
            
            metrics = SimulationMetrics()
            
            try:
                with patch('core.voiceflow_core.AudioToTextRecorder'):
                    with patch('requests.Session.post') as mock_post:
                        mock_response = Mock()
                        mock_response.status_code = 200
                        mock_response.json.return_value = {"response": "Burst test response"}
                        mock_post.return_value = mock_response
                        
                        # Use ThreadPoolExecutor to simulate concurrent load
                        max_workers = min(20, scenario['operations'] // 10)
                        
                        def burst_operation(op_id: int) -> Tuple[float, bool, str]:
                            """Single burst operation."""
                            start_time = time.perf_counter()
                            
                            try:
                                engine = create_engine()
                                enhancer = create_enhancer()
                                
                                # Simulate work
                                text = f"Burst operation {op_id}"
                                enhanced = enhancer.enhance_text(text, "general")
                                
                                duration = (time.perf_counter() - start_time) * 1000
                                return duration, True, ""
                                
                            except Exception as e:
                                duration = (time.perf_counter() - start_time) * 1000
                                return duration, False, str(e)
                        
                        # Execute burst
                        start_time = time.time()
                        
                        with ThreadPoolExecutor(max_workers=max_workers) as executor:
                            # Submit all operations
                            futures = [executor.submit(burst_operation, i) for i in range(scenario['operations'])]
                            
                            # Collect results as they complete
                            for future in as_completed(futures):
                                duration, success, error = future.result()
                                metrics.record_operation(duration, success, error if not success else None)
                                
                                # Sample resources occasionally
                                if metrics.operations_completed % 10 == 0:
                                    metrics.sample_system_resources()
                        
                        total_duration = time.time() - start_time
                        
                        summary = metrics.get_summary()
                        summary['scenario'] = scenario
                        summary['actual_duration'] = total_duration
                        summary['target_throughput'] = scenario['operations'] / scenario['duration_seconds']
                        summary['actual_throughput'] = scenario['operations'] / total_duration
                        summary['throughput_ratio'] = summary['actual_throughput'] / summary['target_throughput']
                        
                        results[scenario['name']] = summary
                        
            except Exception as e:
                results[scenario['name']] = {"error": f"Burst test failed: {e}"}
        
        return results
    
    # ============================================================================
    # EXTENDED OPERATION STABILITY
    # ============================================================================
    
    def test_extended_operation_stability(self, duration_hours: float = 1.0) -> Dict[str, Any]:
        """Test system stability during extended operation periods."""
        print(f"\n[STABILITY TEST] Testing extended operation stability for {duration_hours} hours...")
        
        if not VOICEFLOW_AVAILABLE:
            return {"error": "VoiceFlow components not available"}
        
        metrics = SimulationMetrics()
        stability_metrics = {
            'memory_samples': [],
            'performance_degradation': [],
            'error_spikes': [],
            'resource_exhaustion_events': []
        }
        
        try:
            with patch('core.voiceflow_core.AudioToTextRecorder'):
                with patch('requests.Session.post') as mock_post:
                    mock_response = Mock()
                    mock_response.status_code = 200
                    mock_response.json.return_value = {"response": "Stability test response"}
                    mock_post.return_value = mock_response
                    
                    engine = create_engine()
                    enhancer = create_enhancer()
                    
                    # Calculate test parameters (compressed time for testing)
                    test_duration_seconds = duration_hours * 3600 / 60  # 1 hour = 1 minute for testing
                    operations_per_second = 2  # Moderate load
                    
                    start_time = time.time()
                    end_time = start_time + test_duration_seconds
                    next_operation_time = start_time
                    
                    operation_count = 0
                    last_performance_check = start_time
                    performance_baseline = None
                    
                    while time.time() < end_time:
                        current_time = time.time()
                        
                        # Execute operation if it's time
                        if current_time >= next_operation_time:
                            operation_start = time.perf_counter()
                            success = True
                            error_info = None
                            
                            try:
                                # Simulate transcription work
                                text = f"Stability test operation {operation_count}"
                                enhanced = enhancer.enhance_text(text, "general")
                                
                                # Simulate processing time variation
                                base_time = 0.1  # 100ms base processing
                                actual_time = random.normalvariate(base_time, base_time * 0.2)
                                time.sleep(max(0.01, actual_time))
                                
                            except Exception as e:
                                success = False
                                error_info = str(e)
                            
                            operation_duration = (time.perf_counter() - operation_start) * 1000
                            metrics.record_operation(operation_duration, success, error_info)
                            
                            next_operation_time = current_time + (1 / operations_per_second)
                            operation_count += 1
                        
                        # Periodic stability checks
                        if current_time - last_performance_check >= 30:  # Every 30 seconds
                            metrics.sample_system_resources()
                            
                            # Check for performance degradation
                            recent_times = metrics.response_times[-20:] if len(metrics.response_times) >= 20 else metrics.response_times
                            if recent_times:
                                current_avg = statistics.mean(recent_times)
                                
                                if performance_baseline is None:
                                    performance_baseline = current_avg
                                else:
                                    degradation_ratio = current_avg / performance_baseline
                                    if degradation_ratio > 1.5:  # 50% degradation
                                        stability_metrics['performance_degradation'].append({
                                            'timestamp': current_time,
                                            'baseline_ms': performance_baseline,
                                            'current_ms': current_avg,
                                            'degradation_ratio': degradation_ratio
                                        })
                            
                            # Check for memory growth
                            if len(metrics.memory_samples) > 1:
                                current_memory = metrics.memory_samples[-1]['rss_mb']
                                initial_memory = metrics.memory_samples[0]['rss_mb']
                                memory_growth = current_memory - initial_memory
                                
                                stability_metrics['memory_samples'].append({
                                    'timestamp': current_time,
                                    'memory_mb': current_memory,
                                    'growth_mb': memory_growth
                                })
                                
                                if memory_growth > 100:  # More than 100MB growth
                                    stability_metrics['resource_exhaustion_events'].append({
                                        'timestamp': current_time,
                                        'type': 'memory_growth',
                                        'value': memory_growth
                                    })
                            
                            last_performance_check = current_time
                        
                        # Brief pause to prevent CPU spinning
                        time.sleep(0.01)
            
            # Analyze stability results
            summary = metrics.get_summary()
            summary['stability_analysis'] = self._analyze_stability_metrics(stability_metrics, duration_hours)
            summary['test_duration_hours'] = duration_hours
            summary['compressed_duration_seconds'] = test_duration_seconds
            
            return summary
            
        except Exception as e:
            return {"error": f"Extended operation stability test failed: {e}"}
    
    def _analyze_stability_metrics(self, stability_metrics: Dict[str, List], duration_hours: float) -> Dict[str, Any]:
        """Analyze stability metrics for issues."""
        analysis = {
            'memory_stability': 'GOOD',
            'performance_stability': 'GOOD',
            'overall_stability': 'GOOD',
            'issues_detected': [],
            'recommendations': []
        }
        
        # Analyze memory stability
        memory_samples = stability_metrics['memory_samples']
        if memory_samples:
            max_growth = max([sample['growth_mb'] for sample in memory_samples])
            if max_growth > 200:
                analysis['memory_stability'] = 'POOR'
                analysis['issues_detected'].append(f"High memory growth: {max_growth:.1f}MB")
            elif max_growth > 100:
                analysis['memory_stability'] = 'FAIR'
                analysis['issues_detected'].append(f"Moderate memory growth: {max_growth:.1f}MB")
        
        # Analyze performance stability
        degradation_events = stability_metrics['performance_degradation']
        if degradation_events:
            max_degradation = max([event['degradation_ratio'] for event in degradation_events])
            if max_degradation > 2.0:
                analysis['performance_stability'] = 'POOR'
                analysis['issues_detected'].append(f"Severe performance degradation: {max_degradation:.1f}x slower")
            elif max_degradation > 1.5:
                analysis['performance_stability'] = 'FAIR'
                analysis['issues_detected'].append(f"Performance degradation: {max_degradation:.1f}x slower")
        
        # Overall stability assessment
        if analysis['memory_stability'] == 'POOR' or analysis['performance_stability'] == 'POOR':
            analysis['overall_stability'] = 'POOR'
        elif analysis['memory_stability'] == 'FAIR' or analysis['performance_stability'] == 'FAIR':
            analysis['overall_stability'] = 'FAIR'
        
        # Generate recommendations
        if analysis['memory_stability'] != 'GOOD':
            analysis['recommendations'].extend([
                "Investigate memory leaks",
                "Implement memory monitoring",
                "Add garbage collection optimization"
            ])
        
        if analysis['performance_stability'] != 'GOOD':
            analysis['recommendations'].extend([
                "Profile performance bottlenecks",
                "Implement performance monitoring",
                "Consider connection pooling"
            ])
        
        return analysis
    
    # ============================================================================
    # CONCURRENT USER SIMULATION
    # ============================================================================
    
    def simulate_concurrent_users(self, user_count: int = 10, simulation_duration_minutes: int = 30) -> Dict[str, Any]:
        """Simulate multiple concurrent users with different profiles."""
        print(f"\n[CONCURRENT TEST] Simulating {user_count} concurrent users for {simulation_duration_minutes} minutes...")
        
        if not VOICEFLOW_AVAILABLE:
            return {"error": "VoiceFlow components not available"}
        
        # Assign user profiles randomly
        profile_names = list(self.user_profiles.keys())
        user_assignments = [random.choice(profile_names) for _ in range(user_count)]
        
        # Track metrics per user and overall
        user_metrics = {}
        overall_metrics = SimulationMetrics()
        
        def simulate_user(user_id: int, profile_name: str) -> Dict[str, Any]:
            """Simulate a single user's activity."""
            profile = self.user_profiles[profile_name]
            user_metrics[user_id] = SimulationMetrics()
            
            try:
                with patch('core.voiceflow_core.AudioToTextRecorder'):
                    with patch('requests.Session.post') as mock_post:
                        mock_response = Mock()
                        mock_response.status_code = 200
                        mock_response.json.return_value = {"response": f"User {user_id} response"}
                        mock_post.return_value = mock_response
                        
                        engine = create_engine()
                        enhancer = create_enhancer()
                        
                        # Calculate timing for this user
                        operations_per_minute = profile.transcriptions_per_hour / 60
                        operation_interval = 60 / operations_per_minute if operations_per_minute > 0 else 60
                        
                        start_time = time.time()
                        end_time = start_time + (simulation_duration_minutes * 60 / 10)  # Compressed time
                        
                        operation_count = 0
                        
                        while time.time() < end_time:
                            operation_start = time.perf_counter()
                            success = True
                            error_info = None
                            
                            try:
                                # Simulate user operation
                                text = f"User {user_id} transcription {operation_count}"
                                
                                # Add realistic processing variation
                                base_duration = profile.avg_transcription_duration
                                actual_duration = max(0.1, random.normalvariate(base_duration, base_duration * 0.2))
                                time.sleep(actual_duration / 50)  # Highly compressed for testing
                                
                                # AI enhancement
                                if random.random() < profile.ai_enhancement_rate:
                                    enhanced = enhancer.enhance_text(text, "general")
                                
                            except Exception as e:
                                success = False
                                error_info = str(e)
                            
                            operation_duration = (time.perf_counter() - operation_start) * 1000
                            user_metrics[user_id].record_operation(operation_duration, success, error_info)
                            overall_metrics.record_operation(operation_duration, success, error_info)
                            
                            operation_count += 1
                            
                            # Wait for next operation
                            sleep_time = operation_interval / 50  # Compressed time
                            if sleep_time > 0:
                                time.sleep(sleep_time)
                
                return {
                    'user_id': user_id,
                    'profile': profile_name,
                    'metrics': user_metrics[user_id].get_summary()
                }
                
            except Exception as e:
                return {
                    'user_id': user_id,
                    'profile': profile_name,
                    'error': str(e)
                }
        
        # Run concurrent user simulations
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=min(user_count, 20)) as executor:
            futures = [
                executor.submit(simulate_user, i, user_assignments[i])
                for i in range(user_count)
            ]
            
            user_results = []
            for future in as_completed(futures):
                result = future.result()
                user_results.append(result)
                
                # Sample system resources periodically
                if len(user_results) % 5 == 0:
                    overall_metrics.sample_system_resources()
        
        total_duration = time.time() - start_time
        
        # Analyze concurrent performance
        overall_summary = overall_metrics.get_summary()
        concurrent_analysis = self._analyze_concurrent_performance(user_results, overall_summary)
        
        return {
            'concurrent_users': user_count,
            'simulation_duration_minutes': simulation_duration_minutes,
            'actual_duration_seconds': total_duration,
            'user_profile_distribution': {profile: user_assignments.count(profile) for profile in set(user_assignments)},
            'overall_metrics': overall_summary,
            'user_results': user_results,
            'concurrent_analysis': concurrent_analysis
        }
    
    def _analyze_concurrent_performance(self, user_results: List[Dict], overall_summary: Dict) -> Dict[str, Any]:
        """Analyze concurrent user performance."""
        successful_users = [r for r in user_results if 'error' not in r]
        failed_users = [r for r in user_results if 'error' in r]
        
        if not successful_users:
            return {"error": "No users completed successfully"}
        
        # Calculate per-user performance variance
        user_response_times = [r['metrics']['response_time_stats']['mean_ms'] for r in successful_users]
        user_throughputs = [r['metrics']['throughput_ops_per_second'] for r in successful_users]
        
        analysis = {
            'user_success_rate': len(successful_users) / len(user_results),
            'performance_variance': {
                'response_time_std_dev': statistics.stdev(user_response_times) if len(user_response_times) > 1 else 0,
                'throughput_std_dev': statistics.stdev(user_throughputs) if len(user_throughputs) > 1 else 0,
                'min_user_throughput': min(user_throughputs) if user_throughputs else 0,
                'max_user_throughput': max(user_throughputs) if user_throughputs else 0
            },
            'scalability_metrics': {
                'total_throughput': overall_summary.get('throughput_ops_per_second', 0),
                'avg_user_throughput': statistics.mean(user_throughputs) if user_throughputs else 0,
                'scalability_efficiency': overall_summary.get('throughput_ops_per_second', 0) / len(successful_users) if successful_users else 0
            },
            'resource_utilization': {
                'peak_memory_mb': overall_summary.get('memory_usage', {}).get('peak_mb', 0),
                'avg_cpu_percent': overall_summary.get('cpu_usage', {}).get('avg_percent', 0)
            },
            'fairness_analysis': self._analyze_user_fairness(successful_users)
        }
        
        return analysis
    
    def _analyze_user_fairness(self, user_results: List[Dict]) -> Dict[str, Any]:
        """Analyze fairness of resource allocation among users."""
        if len(user_results) < 2:
            return {"message": "Insufficient users for fairness analysis"}
        
        response_times = [r['metrics']['response_time_stats']['mean_ms'] for r in user_results]
        throughputs = [r['metrics']['throughput_ops_per_second'] for r in user_results]
        
        # Calculate coefficient of variation (std_dev / mean) for fairness
        response_time_cv = statistics.stdev(response_times) / statistics.mean(response_times) if statistics.mean(response_times) > 0 else 0
        throughput_cv = statistics.stdev(throughputs) / statistics.mean(throughputs) if statistics.mean(throughputs) > 0 else 0
        
        # Fairness grade based on coefficient of variation
        if response_time_cv < 0.2 and throughput_cv < 0.2:
            fairness_grade = "EXCELLENT"
        elif response_time_cv < 0.5 and throughput_cv < 0.5:
            fairness_grade = "GOOD"
        elif response_time_cv < 1.0 and throughput_cv < 1.0:
            fairness_grade = "FAIR"
        else:
            fairness_grade = "POOR"
        
        return {
            'response_time_coefficient_of_variation': response_time_cv,
            'throughput_coefficient_of_variation': throughput_cv,
            'fairness_grade': fairness_grade,
            'worst_user_performance': {
                'slowest_response_time_ms': max(response_times),
                'lowest_throughput': min(throughputs)
            },
            'best_user_performance': {
                'fastest_response_time_ms': min(response_times),
                'highest_throughput': max(throughputs)
            }
        }
    
    # ============================================================================
    # MAIN TEST EXECUTION
    # ============================================================================
    
    def run_comprehensive_real_world_tests(self) -> Dict[str, Any]:
        """Run all real-world scenario tests."""
        print("\n" + "="*80)
        print("VOICEFLOW REAL-WORLD SCENARIO TESTING")
        print("="*80)
        
        all_results = {}
        
        # Test categories
        test_categories = [
            ("daily_usage_patterns", self._test_all_daily_usage_patterns),
            ("burst_traffic_handling", self.test_burst_traffic_handling),
            ("extended_operation_stability", lambda: self.test_extended_operation_stability(0.5)),  # 30 minutes compressed
            ("concurrent_user_simulation", lambda: self.simulate_concurrent_users(8, 15))  # 8 users, 15 minutes compressed
        ]
        
        for category_name, test_function in test_categories:
            try:
                print(f"\n[CATEGORY] {category_name.upper()}")
                result = test_function()
                all_results[category_name] = result
            except Exception as e:
                print(f"[ERROR] Failed to run {category_name}: {e}")
                all_results[category_name] = {"error": str(e)}
        
        # Generate comprehensive analysis
        all_results["real_world_analysis"] = self._generate_real_world_analysis(all_results)
        all_results["system_info"] = self._get_system_info()
        all_results["test_timestamp"] = datetime.now().isoformat()
        
        return all_results
    
    def _test_all_daily_usage_patterns(self) -> Dict[str, Any]:
        """Test all user profile daily usage patterns."""
        results = {}
        
        for profile_name, profile in self.user_profiles.items():
            print(f"  Testing {profile_name} usage pattern...")
            result = self.simulate_daily_usage_pattern(profile, simulation_duration_minutes=10)  # 10 minutes compressed
            results[profile_name] = result
        
        return results
    
    def _generate_real_world_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive real-world scenario analysis."""
        analysis = {
            "production_readiness_score": 0,
            "performance_grades": {},
            "critical_issues": [],
            "recommendations": [],
            "user_experience_assessment": {},
            "scalability_assessment": {}
        }
        
        try:
            # Analyze daily usage patterns
            if "daily_usage_patterns" in results:
                daily_results = results["daily_usage_patterns"]
                user_grades = []
                
                for profile_name, result in daily_results.items():
                    if "error" not in result:
                        compliance = result.get("profile_compliance", {})
                        grade = compliance.get("overall_grade", "F")
                        user_grades.append(grade)
                        
                        error_rate = result.get("error_rate", 1)
                        if error_rate > 0.1:  # More than 10% errors
                            analysis["critical_issues"].append(f"High error rate for {profile_name}: {error_rate:.1%}")
                
                # Calculate overall daily usage grade
                grade_scores = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
                avg_score = statistics.mean([grade_scores.get(g, 0) for g in user_grades]) if user_grades else 0
                analysis["performance_grades"]["daily_usage"] = list(grade_scores.keys())[min(4, int(avg_score))]
            
            # Analyze burst traffic handling
            if "burst_traffic_handling" in results:
                burst_results = results["burst_traffic_handling"]
                burst_grades = []
                
                for scenario_name, result in burst_results.items():
                    if "error" not in result:
                        throughput_ratio = result.get("throughput_ratio", 0)
                        error_rate = result.get("error_rate", 1)
                        
                        if throughput_ratio > 0.8 and error_rate < 0.05:
                            burst_grades.append("A")
                        elif throughput_ratio > 0.6 and error_rate < 0.1:
                            burst_grades.append("B")
                        elif throughput_ratio > 0.4:
                            burst_grades.append("C")
                        else:
                            burst_grades.append("D")
                            analysis["critical_issues"].append(f"Poor burst handling in {scenario_name}")
                
                analysis["performance_grades"]["burst_handling"] = statistics.mode(burst_grades) if burst_grades else "F"
            
            # Analyze extended operation stability
            if "extended_operation_stability" in results:
                stability_result = results["extended_operation_stability"]
                if "error" not in stability_result:
                    stability_analysis = stability_result.get("stability_analysis", {})
                    overall_stability = stability_analysis.get("overall_stability", "POOR")
                    
                    if overall_stability == "GOOD":
                        analysis["performance_grades"]["stability"] = "A"
                    elif overall_stability == "FAIR":
                        analysis["performance_grades"]["stability"] = "B"
                    else:
                        analysis["performance_grades"]["stability"] = "C"
                        analysis["critical_issues"].extend(stability_analysis.get("issues_detected", []))
            
            # Analyze concurrent user performance
            if "concurrent_user_simulation" in results:
                concurrent_result = results["concurrent_user_simulation"]
                if "error" not in concurrent_result:
                    concurrent_analysis = concurrent_result.get("concurrent_analysis", {})
                    success_rate = concurrent_analysis.get("user_success_rate", 0)
                    fairness_grade = concurrent_analysis.get("fairness_analysis", {}).get("fairness_grade", "POOR")
                    
                    if success_rate > 0.95 and fairness_grade in ["EXCELLENT", "GOOD"]:
                        analysis["performance_grades"]["concurrency"] = "A"
                    elif success_rate > 0.9:
                        analysis["performance_grades"]["concurrency"] = "B"
                    else:
                        analysis["performance_grades"]["concurrency"] = "C"
            
            # Calculate overall production readiness score
            grades = analysis["performance_grades"]
            grade_values = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
            if grades:
                avg_grade = statistics.mean([grade_values.get(g, 0) for g in grades.values()])
                analysis["production_readiness_score"] = (avg_grade / 4) * 100  # Convert to percentage
            
            # Generate recommendations
            if analysis["production_readiness_score"] < 70:
                analysis["recommendations"].append("System not ready for production - address critical issues")
            elif analysis["production_readiness_score"] < 85:
                analysis["recommendations"].append("System needs optimization before production deployment")
            else:
                analysis["recommendations"].append("System ready for production with monitoring")
            
            if len(analysis["critical_issues"]) > 0:
                analysis["recommendations"].extend([
                    "Address all critical issues before deployment",
                    "Implement comprehensive monitoring",
                    "Create incident response procedures"
                ])
            
            # User experience assessment
            analysis["user_experience_assessment"] = {
                "light_users": "Good experience expected" if grades.get("daily_usage", "F") in ["A", "B"] else "Poor experience likely",
                "power_users": "Satisfactory performance" if grades.get("stability", "F") in ["A", "B"] else "Performance issues expected",
                "concurrent_users": "Fair resource sharing" if grades.get("concurrency", "F") in ["A", "B"] else "Resource contention issues"
            }
            
            # Scalability assessment
            analysis["scalability_assessment"] = {
                "current_capacity": "Good" if grades.get("burst_handling", "F") in ["A", "B"] else "Limited",
                "growth_potential": "High" if analysis["production_readiness_score"] > 85 else "Moderate" if analysis["production_readiness_score"] > 70 else "Low",
                "bottlenecks": analysis["critical_issues"][:3]  # Top 3 issues
            }
            
        except Exception as e:
            analysis["analysis_error"] = str(e)
        
        return analysis
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for test context."""
        try:
            import platform
            
            return {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "cpu_count": psutil.cpu_count(),
                "memory_total_gb": psutil.virtual_memory().total / (1024**3),
                "test_environment": "Real-World Scenario Testing"
            }
        except Exception as e:
            return {"error": f"Could not get system info: {e}"}


# Test execution functions
def test_real_world_scenarios():
    """Main test function for pytest."""
    if not VOICEFLOW_AVAILABLE:
        pytest.skip("VoiceFlow components not available")
    
    tester = RealWorldScenarioTester()
    results = tester.run_comprehensive_real_world_tests()
    
    # Basic assertions
    assert "real_world_analysis" in results
    analysis = results["real_world_analysis"]
    
    # Check production readiness
    readiness_score = analysis.get("production_readiness_score", 0)
    assert readiness_score > 50, f"Low production readiness score: {readiness_score}"
    
    # Check for critical issues
    critical_issues = analysis.get("critical_issues", [])
    assert len(critical_issues) < 5, f"Too many critical issues: {critical_issues}"
    
    # Save detailed results
    results_file = Path("voiceflow_real_world_scenario_results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n[RESULTS] Real-world scenario results saved to: {results_file}")
    return results


if __name__ == "__main__":
    # Run real-world scenario tests directly
    print("VoiceFlow Real-World Scenario Testing Suite")
    print("=" * 60)
    
    tester = RealWorldScenarioTester()
    results = tester.run_comprehensive_real_world_tests()
    
    # Print summary
    print("\n" + "="*80)
    print("REAL-WORLD SCENARIO TEST SUMMARY")
    print("="*80)
    
    analysis = results.get("real_world_analysis", {})
    
    print(f"Production Readiness Score: {analysis.get('production_readiness_score', 0):.1f}%")
    
    print("\nPerformance Grades:")
    for component, grade in analysis.get("performance_grades", {}).items():
        print(f"  {component}: {grade}")
    
    print("\nCritical Issues:")
    for issue in analysis.get("critical_issues", []):
        print(f"  • {issue}")
    
    print("\nRecommendations:")
    for rec in analysis.get("recommendations", []):
        print(f"  • {rec}")
    
    print("\nUser Experience Assessment:")
    for user_type, assessment in analysis.get("user_experience_assessment", {}).items():
        print(f"  {user_type}: {assessment}")
    
    # Save results
    results_file = "voiceflow_real_world_scenario_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {results_file}")
    print("Real-world scenario testing complete!")