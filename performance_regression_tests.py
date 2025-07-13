#!/usr/bin/env python3
"""
VoiceFlow Performance Regression Testing Framework

This module provides comprehensive performance regression testing to ensure
that system performance doesn't degrade with new changes and validates
performance against established benchmarks.

Features:
- Baseline performance measurement and tracking
- Performance regression detection
- Memory usage profiling and leak detection
- CPU utilization monitoring
- Latency and throughput benchmarking
- Performance trend analysis
- Automated performance alerts
- Resource consumption validation
"""

import asyncio
import json
import logging
import os
import psutil
import sqlite3
import sys
import threading
import time
import tracemalloc
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from unittest.mock import Mock, patch
import pytest
import statistics
import gc

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.voiceflow_core import VoiceFlowEngine, create_engine
from core.ai_enhancement import AIEnhancer, create_enhancer
from utils.config import VoiceFlowConfig

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Individual performance metric."""
    name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'value': self.value,
            'unit': self.unit,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }


@dataclass
class PerformanceBenchmark:
    """Performance benchmark definition."""
    name: str
    target_value: float
    tolerance: float
    unit: str
    comparison: str = "less_than"  # less_than, greater_than, equal_to
    critical: bool = False
    
    def evaluate(self, actual_value: float) -> Tuple[bool, str]:
        """Evaluate if actual value meets benchmark."""
        if self.comparison == "less_than":
            passed = actual_value <= (self.target_value * (1 + self.tolerance))
            message = f"Expected ≤ {self.target_value * (1 + self.tolerance):.3f}, got {actual_value:.3f}"
        elif self.comparison == "greater_than":
            passed = actual_value >= (self.target_value * (1 - self.tolerance))
            message = f"Expected ≥ {self.target_value * (1 - self.tolerance):.3f}, got {actual_value:.3f}"
        else:  # equal_to
            lower_bound = self.target_value * (1 - self.tolerance)
            upper_bound = self.target_value * (1 + self.tolerance)
            passed = lower_bound <= actual_value <= upper_bound
            message = f"Expected {lower_bound:.3f}-{upper_bound:.3f}, got {actual_value:.3f}"
        
        return passed, message


class PerformanceMonitor:
    """Real-time performance monitoring."""
    
    def __init__(self, sample_interval: float = 0.1):
        self.sample_interval = sample_interval
        self.monitoring = False
        self.metrics = defaultdict(list)
        self.start_time = None
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start performance monitoring."""
        self.monitoring = True
        self.start_time = time.time()
        self.metrics.clear()
        tracemalloc.start()
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self) -> Dict[str, List[float]]:
        """Stop monitoring and return collected metrics."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        
        tracemalloc.stop()
        return dict(self.metrics)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        process = psutil.Process()
        
        while self.monitoring:
            try:
                # CPU usage
                cpu_percent = process.cpu_percent()
                self.metrics['cpu_percent'].append(cpu_percent)
                
                # Memory usage
                memory_info = process.memory_info()
                self.metrics['memory_rss_mb'].append(memory_info.rss / 1024 / 1024)
                self.metrics['memory_vms_mb'].append(memory_info.vms / 1024 / 1024)
                
                # Memory percentage
                memory_percent = process.memory_percent()
                self.metrics['memory_percent'].append(memory_percent)
                
                # Thread count
                thread_count = process.num_threads()
                self.metrics['thread_count'].append(thread_count)
                
                # File descriptors (on Unix systems)
                try:
                    fd_count = process.num_fds()
                    self.metrics['file_descriptors'].append(fd_count)
                except (AttributeError, psutil.AccessDenied):
                    pass
                
                # System-wide metrics
                system_cpu = psutil.cpu_percent()
                self.metrics['system_cpu_percent'].append(system_cpu)
                
                system_memory = psutil.virtual_memory().percent
                self.metrics['system_memory_percent'].append(system_memory)
                
                time.sleep(self.sample_interval)
                
            except Exception as e:
                logger.warning(f"Error in performance monitoring: {e}")
                break
    
    def get_summary_stats(self) -> Dict[str, Dict[str, float]]:
        """Get summary statistics for all metrics."""
        summary = {}
        
        for metric_name, values in self.metrics.items():
            if values:
                summary[metric_name] = {
                    'min': min(values),
                    'max': max(values),
                    'mean': statistics.mean(values),
                    'median': statistics.median(values),
                    'stdev': statistics.stdev(values) if len(values) > 1 else 0.0,
                    'count': len(values)
                }
        
        return summary


class MemoryProfiler:
    """Memory usage profiling and leak detection."""
    
    def __init__(self):
        self.snapshots = []
        self.baseline_snapshot = None
        
    def take_snapshot(self, label: str = None) -> tracemalloc.Snapshot:
        """Take a memory snapshot."""
        if not tracemalloc.is_tracing():
            tracemalloc.start()
        
        snapshot = tracemalloc.take_snapshot()
        self.snapshots.append((label or f"snapshot_{len(self.snapshots)}", snapshot))
        
        if self.baseline_snapshot is None:
            self.baseline_snapshot = snapshot
            
        return snapshot
    
    def analyze_memory_growth(self) -> Dict[str, Any]:
        """Analyze memory growth between snapshots."""
        if len(self.snapshots) < 2:
            return {"error": "Need at least 2 snapshots to analyze growth"}
        
        first_label, first_snapshot = self.snapshots[0]
        last_label, last_snapshot = self.snapshots[-1]
        
        # Compare snapshots
        top_stats = last_snapshot.compare_to(first_snapshot, 'lineno')
        
        # Get top memory allocations
        top_allocations = []
        for stat in top_stats[:10]:
            top_allocations.append({
                'file': stat.traceback.format()[-1] if stat.traceback.format() else "Unknown",
                'size_diff_mb': stat.size_diff / 1024 / 1024,
                'count_diff': stat.count_diff,
                'size_mb': stat.size / 1024 / 1024
            })
        
        # Calculate total memory growth
        total_growth = sum(stat.size_diff for stat in top_stats) / 1024 / 1024
        
        return {
            'first_snapshot': first_label,
            'last_snapshot': last_label,
            'total_growth_mb': total_growth,
            'top_allocations': top_allocations,
            'snapshot_count': len(self.snapshots)
        }
    
    def detect_memory_leaks(self, threshold_mb: float = 10.0) -> Dict[str, Any]:
        """Detect potential memory leaks."""
        analysis = self.analyze_memory_growth()
        
        if 'error' in analysis:
            return analysis
        
        # Check if growth exceeds threshold
        leak_detected = analysis['total_growth_mb'] > threshold_mb
        
        # Find persistent allocations
        persistent_allocations = [
            alloc for alloc in analysis['top_allocations']
            if alloc['size_diff_mb'] > 1.0  # More than 1MB growth
        ]
        
        return {
            **analysis,
            'leak_detected': leak_detected,
            'threshold_mb': threshold_mb,
            'persistent_allocations': persistent_allocations,
            'leak_severity': 'high' if analysis['total_growth_mb'] > threshold_mb * 2 else 
                           'medium' if leak_detected else 'low'
        }


class PerformanceRegressionTester:
    """Main performance regression testing framework."""
    
    def __init__(self):
        self.benchmarks = self._load_benchmarks()
        self.baseline_data = self._load_baseline_data()
        self.test_results = []
        self.performance_monitor = PerformanceMonitor()
        self.memory_profiler = MemoryProfiler()
        
    def _load_benchmarks(self) -> Dict[str, PerformanceBenchmark]:
        """Load performance benchmarks."""
        return {
            # Audio processing benchmarks
            'audio_transcription_latency': PerformanceBenchmark(
                name='audio_transcription_latency',
                target_value=2.0,  # 2 seconds
                tolerance=0.3,  # 30% tolerance
                unit='seconds',
                comparison='less_than',
                critical=True
            ),
            'audio_processing_cpu': PerformanceBenchmark(
                name='audio_processing_cpu',
                target_value=50.0,  # 50% CPU
                tolerance=0.2,  # 20% tolerance
                unit='percent',
                comparison='less_than'
            ),
            
            # AI enhancement benchmarks
            'ai_enhancement_latency': PerformanceBenchmark(
                name='ai_enhancement_latency',
                target_value=3.0,  # 3 seconds
                tolerance=0.4,  # 40% tolerance
                unit='seconds',
                comparison='less_than',
                critical=True
            ),
            'ai_enhancement_memory': PerformanceBenchmark(
                name='ai_enhancement_memory',
                target_value=200.0,  # 200 MB
                tolerance=0.3,  # 30% tolerance
                unit='mb',
                comparison='less_than'
            ),
            
            # System integration benchmarks
            'text_injection_latency': PerformanceBenchmark(
                name='text_injection_latency',
                target_value=0.5,  # 0.5 seconds
                tolerance=0.5,  # 50% tolerance
                unit='seconds',
                comparison='less_than'
            ),
            'database_write_latency': PerformanceBenchmark(
                name='database_write_latency',
                target_value=0.1,  # 0.1 seconds
                tolerance=1.0,  # 100% tolerance
                unit='seconds',
                comparison='less_than'
            ),
            
            # Memory usage benchmarks
            'memory_baseline': PerformanceBenchmark(
                name='memory_baseline',
                target_value=100.0,  # 100 MB baseline
                tolerance=0.5,  # 50% tolerance
                unit='mb',
                comparison='less_than'
            ),
            'memory_growth_per_hour': PerformanceBenchmark(
                name='memory_growth_per_hour',
                target_value=10.0,  # 10 MB per hour
                tolerance=1.0,  # 100% tolerance
                unit='mb/hour',
                comparison='less_than'
            ),
            
            # Throughput benchmarks
            'transcriptions_per_minute': PerformanceBenchmark(
                name='transcriptions_per_minute',
                target_value=20.0,  # 20 transcriptions per minute
                tolerance=0.2,  # 20% tolerance
                unit='count/minute',
                comparison='greater_than'
            )
        }
    
    def _load_baseline_data(self) -> Dict[str, Any]:
        """Load baseline performance data."""
        baseline_file = Path("performance_baseline.json")
        if baseline_file.exists():
            try:
                with open(baseline_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load baseline data: {e}")
        
        return {}
    
    def _save_baseline_data(self, data: Dict[str, Any]):
        """Save baseline performance data."""
        baseline_file = Path("performance_baseline.json")
        try:
            with open(baseline_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save baseline data: {e}")
    
    @pytest.mark.performance
    async def test_audio_transcription_performance(self):
        """Test audio transcription performance."""
        test_start = time.time()
        
        # Setup test environment
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            with patch('pathlib.Path.home', return_value=temp_path):
                config = VoiceFlowConfig({
                    'audio': {'model': 'base', 'device': 'cpu'}
                })
                
                engine = create_engine(config)
                
                # Mock audio recorder with various text lengths
                test_cases = [
                    "Short test.",
                    "This is a medium length test sentence with several words.",
                    "This is a much longer test sentence that contains many more words and should test the system's ability to handle larger transcriptions with complex content and multiple clauses.",
                    "Very long transcription test that simulates a detailed dictation session with technical terms, proper nouns, and complex sentence structures that would be typical in professional or academic contexts."
                ]
                
                self.performance_monitor.start_monitoring()
                self.memory_profiler.take_snapshot("transcription_start")
                
                latencies = []
                cpu_usage = []
                memory_usage = []
                
                for i, test_text in enumerate(test_cases):
                    # Test multiple iterations for statistical significance
                    for iteration in range(3):
                        mock_recorder = Mock()
                        mock_recorder.text.return_value = test_text
                        
                        with patch.object(engine, 'recorder', mock_recorder):
                            # Measure transcription latency
                            start_time = time.time()
                            transcription = engine.transcribe_audio()
                            latency = time.time() - start_time
                            
                            latencies.append(latency)
                            
                            # Measure resource usage
                            process = psutil.Process()
                            cpu_usage.append(process.cpu_percent())
                            memory_usage.append(process.memory_info().rss / 1024 / 1024)
                            
                            # Small delay between iterations
                            await asyncio.sleep(0.1)
                
                self.memory_profiler.take_snapshot("transcription_end")
                monitoring_data = self.performance_monitor.stop_monitoring()
                
                # Calculate performance metrics
                avg_latency = statistics.mean(latencies)
                max_latency = max(latencies)
                avg_cpu = statistics.mean(cpu_usage) if cpu_usage else 0
                max_memory = max(memory_usage) if memory_usage else 0
                
                # Evaluate against benchmarks
                results = {}
                
                latency_benchmark = self.benchmarks['audio_transcription_latency']
                latency_passed, latency_msg = latency_benchmark.evaluate(avg_latency)
                results['transcription_latency'] = {
                    'value': avg_latency,
                    'benchmark': latency_benchmark.target_value,
                    'passed': latency_passed,
                    'message': latency_msg
                }
                
                cpu_benchmark = self.benchmarks['audio_processing_cpu']
                cpu_passed, cpu_msg = cpu_benchmark.evaluate(avg_cpu)
                results['processing_cpu'] = {
                    'value': avg_cpu,
                    'benchmark': cpu_benchmark.target_value,
                    'passed': cpu_passed,
                    'message': cpu_msg
                }
                
                test_result = {
                    'test_name': 'audio_transcription_performance',
                    'duration': time.time() - test_start,
                    'metrics': {
                        'avg_latency': avg_latency,
                        'max_latency': max_latency,
                        'avg_cpu': avg_cpu,
                        'max_memory_mb': max_memory,
                        'test_cases': len(test_cases),
                        'iterations_per_case': 3
                    },
                    'benchmark_results': results,
                    'monitoring_data': monitoring_data,
                    'passed': all(r['passed'] for r in results.values())
                }
                
                self.test_results.append(test_result)
                
                # Assert performance requirements
                assert latency_passed, f"Transcription latency failed: {latency_msg}"
                assert cpu_passed, f"CPU usage failed: {cpu_msg}"
    
    @pytest.mark.performance
    async def test_ai_enhancement_performance(self):
        """Test AI enhancement performance."""
        test_start = time.time()
        
        # Setup test environment
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            with patch('pathlib.Path.home', return_value=temp_path):
                config = VoiceFlowConfig({
                    'ai': {'enabled': True, 'model': 'test-model', 'temperature': 0.3}
                })
                
                # Mock AI service
                with patch('requests.Session') as mock_session_class:
                    mock_session = Mock()
                    mock_session.post.return_value.status_code = 200
                    mock_session.post.return_value.json.return_value = {
                        'response': 'Enhanced text with proper formatting and punctuation.'
                    }
                    mock_session_class.return_value = mock_session
                    
                    enhancer = create_enhancer(config)
                    
                    # Test with various text lengths
                    test_texts = [
                        "hello world",
                        "this is a test sentence that needs enhancement",
                        "this is a much longer text that contains multiple sentences and should test the ai enhancement system with more complex content that requires significant processing",
                        "very long text for performance testing that simulates real world usage patterns with technical terms academic language and complex sentence structures that would be typical in professional environments"
                    ]
                    
                    self.performance_monitor.start_monitoring()
                    self.memory_profiler.take_snapshot("ai_enhancement_start")
                    
                    latencies = []
                    memory_usage_before = []
                    memory_usage_after = []
                    
                    for text in test_texts:
                        for iteration in range(3):
                            # Measure memory before
                            process = psutil.Process()
                            mem_before = process.memory_info().rss / 1024 / 1024
                            memory_usage_before.append(mem_before)
                            
                            # Measure AI enhancement latency
                            start_time = time.time()
                            enhanced_text = await enhancer.enhance_text(text)
                            latency = time.time() - start_time
                            latencies.append(latency)
                            
                            # Measure memory after
                            mem_after = process.memory_info().rss / 1024 / 1024
                            memory_usage_after.append(mem_after)
                            
                            await asyncio.sleep(0.1)
                    
                    self.memory_profiler.take_snapshot("ai_enhancement_end")
                    monitoring_data = self.performance_monitor.stop_monitoring()
                    
                    # Calculate performance metrics
                    avg_latency = statistics.mean(latencies)
                    max_latency = max(latencies)
                    avg_memory = statistics.mean(memory_usage_after)
                    memory_growth = statistics.mean([after - before for before, after in zip(memory_usage_before, memory_usage_after)])
                    
                    # Evaluate against benchmarks
                    results = {}
                    
                    latency_benchmark = self.benchmarks['ai_enhancement_latency']
                    latency_passed, latency_msg = latency_benchmark.evaluate(avg_latency)
                    results['enhancement_latency'] = {
                        'value': avg_latency,
                        'benchmark': latency_benchmark.target_value,
                        'passed': latency_passed,
                        'message': latency_msg
                    }
                    
                    memory_benchmark = self.benchmarks['ai_enhancement_memory']
                    memory_passed, memory_msg = memory_benchmark.evaluate(avg_memory)
                    results['enhancement_memory'] = {
                        'value': avg_memory,
                        'benchmark': memory_benchmark.target_value,
                        'passed': memory_passed,
                        'message': memory_msg
                    }
                    
                    test_result = {
                        'test_name': 'ai_enhancement_performance',
                        'duration': time.time() - test_start,
                        'metrics': {
                            'avg_latency': avg_latency,
                            'max_latency': max_latency,
                            'avg_memory_mb': avg_memory,
                            'memory_growth_mb': memory_growth,
                            'test_cases': len(test_texts),
                            'iterations_per_case': 3
                        },
                        'benchmark_results': results,
                        'monitoring_data': monitoring_data,
                        'passed': all(r['passed'] for r in results.values())
                    }
                    
                    self.test_results.append(test_result)
                    
                    # Assert performance requirements
                    assert latency_passed, f"AI enhancement latency failed: {latency_msg}"
                    assert memory_passed, f"Memory usage failed: {memory_msg}"
    
    @pytest.mark.performance
    async def test_memory_leak_detection(self):
        """Test for memory leaks during extended operation."""
        test_start = time.time()
        
        # Setup test environment
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            with patch('pathlib.Path.home', return_value=temp_path):
                config = VoiceFlowConfig({
                    'audio': {'model': 'base', 'device': 'cpu'},
                    'ai': {'enabled': True, 'model': 'test-model'}
                })
                
                engine = create_engine(config)
                
                # Mock components
                mock_recorder = Mock()
                mock_recorder.text.return_value = "Memory leak test transcription"
                
                with patch('requests.Session') as mock_session_class:
                    mock_session = Mock()
                    mock_session.post.return_value.status_code = 200
                    mock_session.post.return_value.json.return_value = {
                        'response': 'Enhanced memory test text.'
                    }
                    mock_session_class.return_value = mock_session
                    
                    enhancer = create_enhancer(config)
                    
                    self.memory_profiler.take_snapshot("leak_test_start")
                    
                    # Simulate extended operation
                    iterations = 50  # Reduced for testing
                    memory_samples = []
                    
                    for i in range(iterations):
                        # Take memory snapshot every 10 iterations
                        if i % 10 == 0:
                            self.memory_profiler.take_snapshot(f"iteration_{i}")
                            
                            process = psutil.Process()
                            memory_samples.append(process.memory_info().rss / 1024 / 1024)
                        
                        # Perform operations that might leak memory
                        with patch.object(engine, 'recorder', mock_recorder):
                            transcription = engine.transcribe_audio()
                            enhanced = await enhancer.enhance_text(transcription)
                            engine.save_transcription(transcription, enhanced)
                        
                        # Force garbage collection periodically
                        if i % 20 == 0:
                            gc.collect()
                        
                        await asyncio.sleep(0.01)  # Small delay
                    
                    self.memory_profiler.take_snapshot("leak_test_end")
                    
                    # Analyze memory growth
                    leak_analysis = self.memory_profiler.detect_memory_leaks(threshold_mb=20.0)
                    
                    # Calculate memory growth trend
                    if len(memory_samples) > 1:
                        memory_trend = (memory_samples[-1] - memory_samples[0]) / len(memory_samples)
                    else:
                        memory_trend = 0.0
                    
                    test_result = {
                        'test_name': 'memory_leak_detection',
                        'duration': time.time() - test_start,
                        'metrics': {
                            'iterations': iterations,
                            'memory_samples': memory_samples,
                            'memory_trend_mb_per_iteration': memory_trend,
                            'final_memory_mb': memory_samples[-1] if memory_samples else 0,
                            'initial_memory_mb': memory_samples[0] if memory_samples else 0,
                            'total_growth_mb': leak_analysis.get('total_growth_mb', 0)
                        },
                        'leak_analysis': leak_analysis,
                        'passed': not leak_analysis.get('leak_detected', True)
                    }
                    
                    self.test_results.append(test_result)
                    
                    # Assert no significant memory leaks
                    assert not leak_analysis.get('leak_detected', True), f"Memory leak detected: {leak_analysis}"
    
    @pytest.mark.performance
    async def test_concurrent_performance(self):
        """Test performance under concurrent load."""
        test_start = time.time()
        
        async def simulate_concurrent_user():
            """Simulate a concurrent user session."""
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                with patch('pathlib.Path.home', return_value=temp_path):
                    config = VoiceFlowConfig({
                        'audio': {'model': 'base', 'device': 'cpu'}
                    })
                    
                    engine = create_engine(config)
                    mock_recorder = Mock()
                    mock_recorder.text.return_value = "Concurrent user test"
                    
                    latencies = []
                    
                    for _ in range(5):  # 5 operations per user
                        with patch.object(engine, 'recorder', mock_recorder):
                            start_time = time.time()
                            transcription = engine.transcribe_audio()
                            latency = time.time() - start_time
                            latencies.append(latency)
                            
                            await asyncio.sleep(0.05)  # Small delay
                    
                    return {
                        'latencies': latencies,
                        'avg_latency': statistics.mean(latencies),
                        'max_latency': max(latencies)
                    }
        
        # Start monitoring
        self.performance_monitor.start_monitoring()
        
        # Run concurrent users
        concurrent_users = 3
        tasks = [simulate_concurrent_user() for _ in range(concurrent_users)]
        user_results = await asyncio.gather(*tasks)
        
        monitoring_data = self.performance_monitor.stop_monitoring()
        
        # Analyze concurrent performance
        all_latencies = []
        for result in user_results:
            all_latencies.extend(result['latencies'])
        
        avg_latency = statistics.mean(all_latencies)
        max_latency = max(all_latencies)
        
        # Calculate throughput
        total_operations = len(all_latencies)
        test_duration = time.time() - test_start
        throughput = total_operations / (test_duration / 60)  # operations per minute
        
        # Evaluate benchmarks
        throughput_benchmark = self.benchmarks['transcriptions_per_minute']
        throughput_passed, throughput_msg = throughput_benchmark.evaluate(throughput)
        
        test_result = {
            'test_name': 'concurrent_performance',
            'duration': test_duration,
            'metrics': {
                'concurrent_users': concurrent_users,
                'total_operations': total_operations,
                'avg_latency': avg_latency,
                'max_latency': max_latency,
                'throughput_per_minute': throughput
            },
            'benchmark_results': {
                'throughput': {
                    'value': throughput,
                    'benchmark': throughput_benchmark.target_value,
                    'passed': throughput_passed,
                    'message': throughput_msg
                }
            },
            'user_results': user_results,
            'monitoring_data': monitoring_data,
            'passed': throughput_passed
        }
        
        self.test_results.append(test_result)
        
        # Assert performance requirements
        assert throughput_passed, f"Throughput failed: {throughput_msg}"
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['passed']])
        
        # Aggregate metrics
        all_metrics = {}
        for result in self.test_results:
            for metric_name, metric_value in result['metrics'].items():
                if isinstance(metric_value, (int, float)):
                    if metric_name not in all_metrics:
                        all_metrics[metric_name] = []
                    all_metrics[metric_name].append(metric_value)
        
        # Calculate summary statistics
        metric_summaries = {}
        for metric_name, values in all_metrics.items():
            if values:
                metric_summaries[metric_name] = {
                    'min': min(values),
                    'max': max(values),
                    'mean': statistics.mean(values),
                    'median': statistics.median(values) if len(values) > 1 else values[0]
                }
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': total_tests - passed_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            'metric_summaries': metric_summaries,
            'benchmarks': {name: bench.target_value for name, bench in self.benchmarks.items()},
            'detailed_results': self.test_results,
            'regression_analysis': self._analyze_regressions()
        }
        
        return report
    
    def _analyze_regressions(self) -> Dict[str, Any]:
        """Analyze performance regressions against baseline."""
        if not self.baseline_data:
            return {"status": "no_baseline", "message": "No baseline data available"}
        
        regressions = []
        improvements = []
        
        for result in self.test_results:
            test_name = result['test_name']
            if test_name in self.baseline_data:
                baseline_metrics = self.baseline_data[test_name].get('metrics', {})
                current_metrics = result['metrics']
                
                for metric_name, current_value in current_metrics.items():
                    if metric_name in baseline_metrics and isinstance(current_value, (int, float)):
                        baseline_value = baseline_metrics[metric_name]
                        
                        # Calculate percentage change
                        if baseline_value != 0:
                            change_percent = ((current_value - baseline_value) / baseline_value) * 100
                            
                            # Determine if this is a regression or improvement
                            # For latency/memory metrics, increase is bad
                            if metric_name in ['avg_latency', 'max_latency', 'avg_memory_mb', 'max_memory_mb']:
                                if change_percent > 10:  # More than 10% increase is regression
                                    regressions.append({
                                        'test': test_name,
                                        'metric': metric_name,
                                        'baseline': baseline_value,
                                        'current': current_value,
                                        'change_percent': change_percent
                                    })
                                elif change_percent < -10:  # More than 10% decrease is improvement
                                    improvements.append({
                                        'test': test_name,
                                        'metric': metric_name,
                                        'baseline': baseline_value,
                                        'current': current_value,
                                        'change_percent': change_percent
                                    })
                            # For throughput metrics, decrease is bad
                            elif metric_name in ['throughput_per_minute']:
                                if change_percent < -10:  # More than 10% decrease is regression
                                    regressions.append({
                                        'test': test_name,
                                        'metric': metric_name,
                                        'baseline': baseline_value,
                                        'current': current_value,
                                        'change_percent': change_percent
                                    })
                                elif change_percent > 10:  # More than 10% increase is improvement
                                    improvements.append({
                                        'test': test_name,
                                        'metric': metric_name,
                                        'baseline': baseline_value,
                                        'current': current_value,
                                        'change_percent': change_percent
                                    })
        
        return {
            'regressions': regressions,
            'improvements': improvements,
            'regression_count': len(regressions),
            'improvement_count': len(improvements),
            'has_regressions': len(regressions) > 0
        }
    
    def save_as_baseline(self):
        """Save current test results as new baseline."""
        baseline_data = {}
        for result in self.test_results:
            baseline_data[result['test_name']] = {
                'timestamp': datetime.now().isoformat(),
                'metrics': result['metrics']
            }
        
        self._save_baseline_data(baseline_data)
        logger.info("Performance baseline updated")


# Test execution functions
@pytest.mark.performance
@pytest.mark.asyncio
async def test_audio_transcription_performance():
    """Test audio transcription performance."""
    tester = PerformanceRegressionTester()
    await tester.test_audio_transcription_performance()


@pytest.mark.performance
@pytest.mark.asyncio
async def test_ai_enhancement_performance():
    """Test AI enhancement performance."""
    tester = PerformanceRegressionTester()
    await tester.test_ai_enhancement_performance()


@pytest.mark.performance
@pytest.mark.asyncio
async def test_memory_leak_detection():
    """Test for memory leaks."""
    tester = PerformanceRegressionTester()
    await tester.test_memory_leak_detection()


@pytest.mark.performance
@pytest.mark.asyncio
async def test_concurrent_performance():
    """Test concurrent performance."""
    tester = PerformanceRegressionTester()
    await tester.test_concurrent_performance()


@pytest.mark.performance
@pytest.mark.asyncio
async def test_full_performance_regression_suite():
    """Run complete performance regression test suite."""
    tester = PerformanceRegressionTester()
    
    # Run all performance tests
    await tester.test_audio_transcription_performance()
    await tester.test_ai_enhancement_performance()
    await tester.test_memory_leak_detection()
    await tester.test_concurrent_performance()
    
    # Generate and save report
    report = tester.generate_performance_report()
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = Path(f"performance_regression_report_{timestamp}.json")
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Performance regression report saved to {report_file}")
    
    # Check for critical failures
    critical_failures = []
    for result in tester.test_results:
        if not result['passed']:
            critical_failures.append(result['test_name'])
    
    assert len(critical_failures) == 0, f"Critical performance failures: {critical_failures}"
    
    # Check for regressions
    regression_analysis = report['regression_analysis']
    if regression_analysis.get('has_regressions'):
        logger.warning(f"Performance regressions detected: {regression_analysis['regression_count']}")
    
    return report


if __name__ == "__main__":
    # Run performance regression tests
    async def main():
        tester = PerformanceRegressionTester()
        
        try:
            report = await test_full_performance_regression_suite()
            
            print(f"\nPerformance Regression Test Results:")
            print(f"Total Tests: {report['summary']['total_tests']}")
            print(f"Passed: {report['summary']['passed_tests']}")
            print(f"Failed: {report['summary']['failed_tests']}")
            print(f"Success Rate: {report['summary']['success_rate']:.2f}%")
            
            if report['regression_analysis'].get('has_regressions'):
                print(f"Regressions Detected: {report['regression_analysis']['regression_count']}")
                return False
            else:
                print("No performance regressions detected")
                return True
                
        except Exception as e:
            print(f"Performance testing failed: {e}")
            return False
    
    success = asyncio.run(main())
    sys.exit(0 if success else 1)