#!/usr/bin/env python3
"""
Advanced Memory Profiling and Leak Detection for VoiceFlow
==========================================================

Comprehensive memory analysis suite for detecting memory leaks, analyzing
allocation patterns, and optimizing memory usage in VoiceFlow applications.

Key Analysis Areas:
1. Memory Leak Detection in Core Components
2. Memory Usage Pattern Analysis
3. Garbage Collection Efficiency
4. Memory Fragmentation Analysis
5. Component-Specific Memory Profiling
6. Long-Running Operation Memory Stability
7. Memory Optimization Recommendations

Author: Senior Performance Testing Expert  
Version: 1.0.0
"""

import asyncio
import gc
import json
import os
import psutil
import statistics
import sys
import threading
import time
import tracemalloc
import weakref
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from unittest.mock import Mock, patch

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


class MemorySnapshot:
    """Container for memory state snapshot."""
    
    def __init__(self, label: str):
        self.label = label
        self.timestamp = time.time()
        self.process = psutil.Process()
        
        # System memory info
        self.memory_info = self.process.memory_info()
        self.memory_percent = self.process.memory_percent()
        
        # Python-specific memory tracking
        if tracemalloc.is_tracing():
            self.current_memory, self.peak_memory = tracemalloc.get_traced_memory()
            self.top_stats = tracemalloc.take_snapshot().statistics('lineno')[:10]
        else:
            self.current_memory = 0
            self.peak_memory = 0
            self.top_stats = []
        
        # Garbage collection stats
        self.gc_stats = gc.get_stats()
        self.gc_counts = gc.get_count()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert snapshot to dictionary."""
        return {
            'label': self.label,
            'timestamp': self.timestamp,
            'rss_mb': self.memory_info.rss / 1024 / 1024,
            'vms_mb': self.memory_info.vms / 1024 / 1024,
            'memory_percent': self.memory_percent,
            'current_memory_mb': self.current_memory / 1024 / 1024,
            'peak_memory_mb': self.peak_memory / 1024 / 1024,
            'gc_counts': self.gc_counts,
            'top_allocations': [
                {
                    'filename': stat.traceback.format()[-1] if stat.traceback else 'unknown',
                    'size_mb': stat.size / 1024 / 1024,
                    'count': stat.count
                }
                for stat in self.top_stats[:5]
            ]
        }


class MemoryProfiler:
    """Advanced memory profiling and leak detection."""
    
    def __init__(self):
        self.snapshots = []
        self.baseline_snapshot = None
        self.monitoring_active = False
        self.monitor_thread = None
        self.monitor_data = []
        
    def start_profiling(self):
        """Start memory profiling."""
        tracemalloc.start()
        gc.collect()  # Clean start
        self.baseline_snapshot = MemorySnapshot("baseline")
        self.snapshots.append(self.baseline_snapshot)
        print(f"[MEMORY] Started profiling - baseline: {self.baseline_snapshot.memory_info.rss / 1024 / 1024:.1f}MB")
    
    def take_snapshot(self, label: str) -> MemorySnapshot:
        """Take a memory snapshot."""
        snapshot = MemorySnapshot(label)
        self.snapshots.append(snapshot)
        
        if self.baseline_snapshot:
            growth_mb = (snapshot.memory_info.rss - self.baseline_snapshot.memory_info.rss) / 1024 / 1024
            print(f"[MEMORY] {label}: {snapshot.memory_info.rss / 1024 / 1024:.1f}MB (+{growth_mb:+.1f}MB)")
        
        return snapshot
    
    def start_continuous_monitoring(self, interval_seconds: float = 1.0):
        """Start continuous memory monitoring in background thread."""
        self.monitoring_active = True
        self.monitor_data = []
        
        def monitor_loop():
            while self.monitoring_active:
                try:
                    process = psutil.Process()
                    memory_info = process.memory_info()
                    
                    self.monitor_data.append({
                        'timestamp': time.time(),
                        'rss_mb': memory_info.rss / 1024 / 1024,
                        'vms_mb': memory_info.vms / 1024 / 1024,
                        'memory_percent': process.memory_percent()
                    })
                    
                    time.sleep(interval_seconds)
                except Exception as e:
                    print(f"[MEMORY] Monitor error: {e}")
                    break
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        print(f"[MEMORY] Started continuous monitoring (interval: {interval_seconds}s)")
    
    def stop_continuous_monitoring(self):
        """Stop continuous memory monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print(f"[MEMORY] Stopped monitoring - collected {len(self.monitor_data)} samples")
    
    def analyze_memory_growth(self) -> Dict[str, Any]:
        """Analyze memory growth patterns."""
        if len(self.snapshots) < 2:
            return {"error": "Need at least 2 snapshots for growth analysis"}
        
        growth_analysis = {
            'total_growth_mb': 0,
            'peak_memory_mb': 0,
            'growth_rate_mb_per_snapshot': 0,
            'snapshots_analyzed': len(self.snapshots),
            'growth_trend': [],
            'concerning_growth': False
        }
        
        baseline = self.snapshots[0]
        latest = self.snapshots[-1]
        
        # Calculate total growth
        total_growth = (latest.memory_info.rss - baseline.memory_info.rss) / 1024 / 1024
        growth_analysis['total_growth_mb'] = total_growth
        
        # Find peak memory usage
        peak_memory = max(snapshot.memory_info.rss for snapshot in self.snapshots) / 1024 / 1024
        growth_analysis['peak_memory_mb'] = peak_memory
        
        # Calculate growth rate
        if len(self.snapshots) > 1:
            growth_analysis['growth_rate_mb_per_snapshot'] = total_growth / (len(self.snapshots) - 1)
        
        # Analyze growth trend
        for i, snapshot in enumerate(self.snapshots):
            growth_from_baseline = (snapshot.memory_info.rss - baseline.memory_info.rss) / 1024 / 1024
            growth_analysis['growth_trend'].append({
                'snapshot_index': i,
                'label': snapshot.label,
                'growth_mb': growth_from_baseline,
                'timestamp': snapshot.timestamp
            })
        
        # Detect concerning growth patterns
        if total_growth > 100:  # More than 100MB growth
            growth_analysis['concerning_growth'] = True
            growth_analysis['concern_reason'] = "High memory growth (>100MB)"
        elif growth_analysis['growth_rate_mb_per_snapshot'] > 10:  # More than 10MB per snapshot
            growth_analysis['concerning_growth'] = True
            growth_analysis['concern_reason'] = "High growth rate (>10MB per operation)"
        
        return growth_analysis
    
    def analyze_continuous_monitoring_data(self) -> Dict[str, Any]:
        """Analyze continuous monitoring data for trends and anomalies."""
        if not self.monitor_data:
            return {"error": "No monitoring data available"}
        
        rss_values = [sample['rss_mb'] for sample in self.monitor_data]
        timestamps = [sample['timestamp'] for sample in self.monitor_data]
        
        if len(rss_values) < 3:
            return {"error": "Insufficient monitoring data"}
        
        analysis = {
            'duration_seconds': timestamps[-1] - timestamps[0],
            'samples_collected': len(rss_values),
            'memory_stats': {
                'initial_mb': rss_values[0],
                'final_mb': rss_values[-1],
                'min_mb': min(rss_values),
                'max_mb': max(rss_values),
                'mean_mb': statistics.mean(rss_values),
                'std_dev_mb': statistics.stdev(rss_values) if len(rss_values) > 1 else 0,
                'total_growth_mb': rss_values[-1] - rss_values[0]
            },
            'trend_analysis': {},
            'anomalies': []
        }
        
        # Linear trend analysis
        if len(rss_values) > 10:
            # Simple linear regression for trend
            n = len(rss_values)
            x_values = list(range(n))
            sum_x = sum(x_values)
            sum_y = sum(rss_values)
            sum_xy = sum(x * y for x, y in zip(x_values, rss_values))
            sum_x_squared = sum(x * x for x in x_values)
            
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x_squared - sum_x * sum_x)
            
            analysis['trend_analysis'] = {
                'slope_mb_per_sample': slope,
                'trend_direction': 'increasing' if slope > 0.1 else 'decreasing' if slope < -0.1 else 'stable',
                'projected_growth_per_hour': slope * 3600 if len(timestamps) > 1 else 0  # Assuming 1 sample per second
            }
        
        # Detect memory spikes and drops
        if len(rss_values) > 5:
            mean_memory = statistics.mean(rss_values)
            std_dev = statistics.stdev(rss_values)
            threshold = 2 * std_dev  # 2 standard deviations
            
            for i, value in enumerate(rss_values):
                if abs(value - mean_memory) > threshold:
                    analysis['anomalies'].append({
                        'index': i,
                        'timestamp': timestamps[i],
                        'memory_mb': value,
                        'deviation_from_mean': value - mean_memory,
                        'type': 'spike' if value > mean_memory else 'drop'
                    })
        
        return analysis
    
    def detect_memory_leaks(self, threshold_mb: float = 50) -> Dict[str, Any]:
        """Detect potential memory leaks based on growth patterns."""
        growth_analysis = self.analyze_memory_growth()
        monitoring_analysis = self.analyze_continuous_monitoring_data()
        
        leak_indicators = []
        leak_probability = 0.0
        
        # Check growth patterns
        if growth_analysis.get('total_growth_mb', 0) > threshold_mb:
            leak_indicators.append(f"Total memory growth exceeds threshold: {growth_analysis['total_growth_mb']:.1f}MB > {threshold_mb}MB")
            leak_probability += 0.3
        
        if growth_analysis.get('growth_rate_mb_per_snapshot', 0) > 5:
            leak_indicators.append(f"High growth rate per operation: {growth_analysis['growth_rate_mb_per_snapshot']:.1f}MB")
            leak_probability += 0.2
        
        # Check continuous monitoring trends
        if monitoring_analysis and 'trend_analysis' in monitoring_analysis:
            trend = monitoring_analysis['trend_analysis']
            if trend.get('slope_mb_per_sample', 0) > 0.01:  # Consistent upward trend
                leak_indicators.append(f"Consistent upward memory trend detected")
                leak_probability += 0.3
        
        # Check garbage collection efficiency
        if len(self.snapshots) > 1:
            gc_efficiency = self._analyze_gc_efficiency()
            if gc_efficiency.get('efficiency_score', 1.0) < 0.5:
                leak_indicators.append("Poor garbage collection efficiency")
                leak_probability += 0.2
        
        # Classify leak probability
        if leak_probability > 0.7:
            leak_status = "HIGH - Likely memory leak"
        elif leak_probability > 0.4:
            leak_status = "MEDIUM - Possible memory leak"
        elif leak_probability > 0.1:
            leak_status = "LOW - Monitor closely"
        else:
            leak_status = "NONE - Memory usage appears normal"
        
        return {
            'leak_probability': leak_probability,
            'leak_status': leak_status,
            'indicators': leak_indicators,
            'recommendations': self._generate_leak_fix_recommendations(leak_indicators)
        }
    
    def _analyze_gc_efficiency(self) -> Dict[str, Any]:
        """Analyze garbage collection efficiency."""
        if len(self.snapshots) < 2:
            return {"error": "Insufficient snapshots for GC analysis"}
        
        # Compare GC counts between snapshots
        initial_gc = self.snapshots[0].gc_counts
        final_gc = self.snapshots[-1].gc_counts
        
        total_collections = sum(final_gc[i] - initial_gc[i] for i in range(len(initial_gc)))
        
        # Calculate efficiency based on memory growth vs GC activity
        memory_growth = self.snapshots[-1].memory_info.rss - self.snapshots[0].memory_info.rss
        memory_growth_mb = memory_growth / 1024 / 1024
        
        if total_collections > 0:
            efficiency_score = max(0, 1 - (memory_growth_mb / (total_collections * 10)))  # Rough heuristic
        else:
            efficiency_score = 0.5  # Neutral if no collections occurred
        
        return {
            'total_collections': total_collections,
            'gc_counts_change': [final_gc[i] - initial_gc[i] for i in range(len(initial_gc))],
            'memory_growth_mb': memory_growth_mb,
            'efficiency_score': efficiency_score,
            'analysis': 'efficient' if efficiency_score > 0.7 else 'poor' if efficiency_score < 0.3 else 'moderate'
        }
    
    def _generate_leak_fix_recommendations(self, indicators: List[str]) -> List[str]:
        """Generate recommendations for fixing memory leaks."""
        recommendations = []
        
        if any("growth" in indicator.lower() for indicator in indicators):
            recommendations.extend([
                "Review object lifecycle management",
                "Ensure proper cleanup in finally blocks",
                "Check for circular references",
                "Implement weak references where appropriate"
            ])
        
        if any("trend" in indicator.lower() for indicator in indicators):
            recommendations.extend([
                "Add explicit garbage collection calls",
                "Review caching strategies",
                "Implement object pooling for frequently created objects"
            ])
        
        if any("garbage collection" in indicator.lower() for indicator in indicators):
            recommendations.extend([
                "Review large object handling",
                "Optimize data structures",
                "Consider streaming for large data processing"
            ])
        
        # General recommendations
        recommendations.extend([
            "Use memory profilers in development",
            "Implement memory monitoring in production",
            "Set memory usage alerts",
            "Regular memory usage reviews"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def generate_memory_report(self) -> Dict[str, Any]:
        """Generate comprehensive memory analysis report."""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'profiling_summary': {
                'snapshots_taken': len(self.snapshots),
                'monitoring_samples': len(self.monitor_data),
                'baseline_memory_mb': self.baseline_snapshot.memory_info.rss / 1024 / 1024 if self.baseline_snapshot else 0
            },
            'growth_analysis': self.analyze_memory_growth(),
            'continuous_monitoring': self.analyze_continuous_monitoring_data(),
            'leak_detection': self.detect_memory_leaks(),
            'gc_analysis': self._analyze_gc_efficiency(),
            'snapshots': [snapshot.to_dict() for snapshot in self.snapshots],
            'recommendations': []
        }
        
        # Generate overall recommendations
        leak_status = report['leak_detection'].get('leak_status', '')
        if 'HIGH' in leak_status:
            report['recommendations'].extend([
                "URGENT: Investigate memory leak immediately",
                "Add memory monitoring to production",
                "Consider memory usage limits"
            ])
        elif 'MEDIUM' in leak_status:
            report['recommendations'].extend([
                "Monitor memory usage closely",
                "Review recent code changes",
                "Consider optimization"
            ])
        
        total_growth = report['growth_analysis'].get('total_growth_mb', 0)
        if total_growth > 200:
            report['recommendations'].append("Consider memory optimization - high growth detected")
        
        return report


class VoiceFlowMemoryTester:
    """Memory testing suite for VoiceFlow components."""
    
    def __init__(self):
        self.profiler = MemoryProfiler()
        self.test_results = {}
    
    def test_core_engine_memory_usage(self) -> Dict[str, Any]:
        """Test memory usage of VoiceFlow core engine."""
        print("\n[MEMORY TEST] Testing core engine memory usage...")
        
        if not VOICEFLOW_AVAILABLE:
            return {"error": "VoiceFlow components not available"}
        
        self.profiler.start_profiling()
        
        try:
            # Test engine creation and basic operations
            self.profiler.take_snapshot("before_engine_creation")
            
            with patch('core.voiceflow_core.AudioToTextRecorder'):
                engine = create_engine()
                self.profiler.take_snapshot("after_engine_creation")
                
                # Simulate multiple transcription operations
                for i in range(50):
                    engine.stats["total_transcriptions"] += 1
                    engine.stats["processing_times"].append(100 + i)
                    
                    if i % 10 == 0:
                        self.profiler.take_snapshot(f"after_{i}_operations")
                
                # Test cleanup
                engine.cleanup()
                gc.collect()
                self.profiler.take_snapshot("after_cleanup")
            
            return self.profiler.generate_memory_report()
            
        except Exception as e:
            return {"error": f"Core engine memory test failed: {e}"}
    
    def test_ai_enhancer_memory_usage(self) -> Dict[str, Any]:
        """Test memory usage of AI enhancement component."""
        print("\n[MEMORY TEST] Testing AI enhancer memory usage...")
        
        if not VOICEFLOW_AVAILABLE:
            return {"error": "VoiceFlow components not available"}
        
        self.profiler.start_profiling()
        
        try:
            # Mock Ollama responses
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"response": "Enhanced text"}
            
            with patch('requests.Session.post', return_value=mock_response):
                self.profiler.take_snapshot("before_enhancer_creation")
                
                enhancer = create_enhancer()
                self.profiler.take_snapshot("after_enhancer_creation")
                
                # Test with various text sizes
                test_texts = [
                    "Short text",
                    "Medium length text " * 10,
                    "Long text " * 100,
                    "Very long text " * 500
                ]
                
                for i, text in enumerate(test_texts):
                    for j in range(10):  # Multiple enhancements per text size
                        enhanced = enhancer.enhance_text(text, "general")
                    
                    self.profiler.take_snapshot(f"after_text_size_{i}_enhancements")
                
                # Force cleanup
                del enhancer
                gc.collect()
                self.profiler.take_snapshot("after_enhancer_cleanup")
            
            return self.profiler.generate_memory_report()
            
        except Exception as e:
            return {"error": f"AI enhancer memory test failed: {e}"}
    
    def test_database_memory_usage(self) -> Dict[str, Any]:
        """Test memory usage of database operations."""
        print("\n[MEMORY TEST] Testing database memory usage...")
        
        if not VOICEFLOW_AVAILABLE:
            return {"error": "VoiceFlow components not available"}
        
        self.profiler.start_profiling()
        
        try:
            test_dir = Path("/tmp/voiceflow_memory_test")
            test_dir.mkdir(exist_ok=True)
            
            self.profiler.take_snapshot("before_db_creation")
            
            # Test encrypted database
            secure_db = create_secure_database(test_dir)
            self.profiler.take_snapshot("after_db_creation")
            
            # Insert many records
            for i in range(100):
                text = f"Test transcription {i} with some content " * 10
                secure_db.store_transcription(
                    text=text,
                    processing_time=100 + i,
                    word_count=len(text.split()),
                    model_used="test_model",
                    session_id=f"session_{i}"
                )
                
                if i % 20 == 0:
                    self.profiler.take_snapshot(f"after_{i}_inserts")
            
            # Test data retrieval
            history = secure_db.get_transcription_history(50)
            self.profiler.take_snapshot("after_data_retrieval")
            
            # Cleanup
            del secure_db
            import shutil
            shutil.rmtree(test_dir, ignore_errors=True)
            gc.collect()
            self.profiler.take_snapshot("after_db_cleanup")
            
            return self.profiler.generate_memory_report()
            
        except Exception as e:
            return {"error": f"Database memory test failed: {e}"}
    
    def test_long_running_operation_memory(self) -> Dict[str, Any]:
        """Test memory usage during long-running operations."""
        print("\n[MEMORY TEST] Testing long-running operation memory...")
        
        self.profiler.start_profiling()
        self.profiler.start_continuous_monitoring(interval_seconds=0.5)
        
        try:
            # Simulate 30 seconds of continuous operation
            start_time = time.time()
            operation_count = 0
            
            while time.time() - start_time < 30:
                # Simulate work
                data = ["test data"] * 1000  # Create some objects
                processed = [item.upper() for item in data]  # Process them
                
                # Occasionally take snapshots
                if operation_count % 100 == 0:
                    self.profiler.take_snapshot(f"operation_{operation_count}")
                
                operation_count += 1
                
                # Brief pause
                time.sleep(0.01)
            
            self.profiler.stop_continuous_monitoring()
            self.profiler.take_snapshot("final_state")
            
            report = self.profiler.generate_memory_report()
            report['operations_completed'] = operation_count
            
            return report
            
        except Exception as e:
            self.profiler.stop_continuous_monitoring()
            return {"error": f"Long-running operation test failed: {e}"}
    
    def test_concurrent_operations_memory(self) -> Dict[str, Any]:
        """Test memory usage under concurrent operations."""
        print("\n[MEMORY TEST] Testing concurrent operations memory...")
        
        self.profiler.start_profiling()
        self.profiler.start_continuous_monitoring(interval_seconds=0.2)
        
        try:
            import concurrent.futures
            
            def worker_task(worker_id: int) -> str:
                """Simulate worker task."""
                # Create some objects
                data = [f"worker_{worker_id}_data_{i}" for i in range(1000)]
                processed = [item.upper() for item in data]
                return f"Worker {worker_id} completed"
            
            self.profiler.take_snapshot("before_concurrent_operations")
            
            # Run concurrent tasks
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(worker_task, i) for i in range(32)]
                results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            self.profiler.take_snapshot("after_concurrent_operations")
            
            # Force cleanup
            gc.collect()
            self.profiler.take_snapshot("after_gc_cleanup")
            
            time.sleep(2)  # Allow monitoring to capture post-operation state
            self.profiler.stop_continuous_monitoring()
            
            report = self.profiler.generate_memory_report()
            report['concurrent_tasks_completed'] = len(results)
            
            return report
            
        except Exception as e:
            self.profiler.stop_continuous_monitoring()
            return {"error": f"Concurrent operations test failed: {e}"}
    
    def run_comprehensive_memory_tests(self) -> Dict[str, Any]:
        """Run all memory tests."""
        print("\n" + "="*80)
        print("VOICEFLOW COMPREHENSIVE MEMORY PROFILING")
        print("="*80)
        
        test_categories = [
            ("core_engine_memory", self.test_core_engine_memory_usage),
            ("ai_enhancer_memory", self.test_ai_enhancer_memory_usage),
            ("database_memory", self.test_database_memory_usage),
            ("long_running_memory", self.test_long_running_operation_memory),
            ("concurrent_memory", self.test_concurrent_operations_memory)
        ]
        
        all_results = {}
        
        for category_name, test_function in test_categories:
            try:
                print(f"\n[CATEGORY] {category_name.upper()}")
                # Reset profiler for each test
                self.profiler = MemoryProfiler()
                result = test_function()
                all_results[category_name] = result
            except Exception as e:
                print(f"[ERROR] Failed to run {category_name}: {e}")
                all_results[category_name] = {"error": str(e)}
        
        # Generate overall summary
        all_results["memory_analysis_summary"] = self._generate_overall_summary(all_results)
        all_results["system_info"] = self._get_system_info()
        all_results["analysis_timestamp"] = datetime.now().isoformat()
        
        return all_results
    
    def _generate_overall_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall memory analysis summary."""
        summary = {
            "tests_completed": 0,
            "tests_with_errors": 0,
            "memory_leak_indicators": [],
            "overall_memory_health": "UNKNOWN",
            "key_findings": [],
            "optimization_recommendations": []
        }
        
        leak_count = 0
        concerning_growth = 0
        
        for category, result in results.items():
            if not category.endswith("_memory"):
                continue
                
            summary["tests_completed"] += 1
            
            if "error" in result:
                summary["tests_with_errors"] += 1
                continue
            
            # Analyze leak indicators
            leak_detection = result.get("leak_detection", {})
            if leak_detection.get("leak_probability", 0) > 0.4:
                leak_count += 1
                summary["memory_leak_indicators"].append({
                    "category": category,
                    "probability": leak_detection.get("leak_probability", 0),
                    "status": leak_detection.get("leak_status", ""),
                    "indicators": leak_detection.get("indicators", [])
                })
            
            # Check growth patterns
            growth_analysis = result.get("growth_analysis", {})
            if growth_analysis.get("concerning_growth", False):
                concerning_growth += 1
                summary["key_findings"].append(f"{category}: {growth_analysis.get('concern_reason', 'Concerning growth detected')}")
        
        # Determine overall health
        if leak_count == 0 and concerning_growth == 0:
            summary["overall_memory_health"] = "EXCELLENT"
        elif leak_count <= 1 and concerning_growth <= 1:
            summary["overall_memory_health"] = "GOOD"
        elif leak_count <= 2 or concerning_growth <= 2:
            summary["overall_memory_health"] = "FAIR"
        else:
            summary["overall_memory_health"] = "POOR"
        
        # Generate recommendations
        if leak_count > 0:
            summary["optimization_recommendations"].extend([
                "Investigate and fix detected memory leaks",
                "Implement regular memory monitoring",
                "Add memory usage alerts"
            ])
        
        if concerning_growth > 0:
            summary["optimization_recommendations"].extend([
                "Optimize memory usage patterns",
                "Review object lifecycle management",
                "Consider memory pooling"
            ])
        
        summary["optimization_recommendations"].extend([
            "Regular memory profiling in development",
            "Production memory monitoring",
            "Memory usage documentation",
            "Team training on memory best practices"
        ])
        
        return summary
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        try:
            import platform
            
            return {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "total_memory_gb": psutil.virtual_memory().total / (1024**3),
                "available_memory_gb": psutil.virtual_memory().available / (1024**3),
                "cpu_count": psutil.cpu_count()
            }
        except Exception as e:
            return {"error": f"Could not get system info: {e}"}


# Test execution functions
def test_memory_profiling():
    """Main test function for pytest."""
    if not VOICEFLOW_AVAILABLE:
        pytest.skip("VoiceFlow components not available")
    
    tester = VoiceFlowMemoryTester()
    results = tester.run_comprehensive_memory_tests()
    
    # Basic assertions
    assert "memory_analysis_summary" in results
    summary = results["memory_analysis_summary"]
    
    # Check that tests completed
    assert summary["tests_completed"] > 0
    
    # Check overall memory health is not POOR
    assert summary["overall_memory_health"] != "POOR", f"Poor memory health detected: {summary}"
    
    # Save detailed results
    results_file = Path("voiceflow_memory_analysis_results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n[RESULTS] Memory analysis results saved to: {results_file}")
    return results


if __name__ == "__main__":
    # Run memory profiling tests directly
    print("VoiceFlow Advanced Memory Profiling Suite")
    print("=" * 60)
    
    tester = VoiceFlowMemoryTester()
    results = tester.run_comprehensive_memory_tests()
    
    # Print summary
    print("\n" + "="*80)
    print("MEMORY ANALYSIS SUMMARY")
    print("="*80)
    
    summary = results.get("memory_analysis_summary", {})
    
    print(f"Tests completed: {summary.get('tests_completed', 0)}")
    print(f"Tests with errors: {summary.get('tests_with_errors', 0)}")
    print(f"Overall memory health: {summary.get('overall_memory_health', 'UNKNOWN')}")
    
    print("\nKey Findings:")
    for finding in summary.get("key_findings", []):
        print(f"  • {finding}")
    
    print("\nMemory Leak Indicators:")
    for indicator in summary.get("memory_leak_indicators", []):
        print(f"  • {indicator['category']}: {indicator['status']} (probability: {indicator['probability']:.2f})")
    
    print("\nOptimization Recommendations:")
    for rec in summary.get("optimization_recommendations", []):
        print(f"  • {rec}")
    
    # Save results
    results_file = "voiceflow_memory_analysis_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {results_file}")
    print("Memory profiling complete!")