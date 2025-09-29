"""
VoiceFlow Transcription Performance Testing Suite
=================================================

Comprehensive performance testing for VoiceFlow transcription system after
implementing aggressive stability improvements including:
- Model reinitialization every 2 transcriptions
- CPU-only forced configuration with int8 compute
- Comprehensive error recovery patterns
- Memory cleanup and garbage collection

Test Categories:
1. Transcription Speed Benchmarks
2. Memory Usage Monitoring
3. Latency Analysis
4. CPU Usage Patterns
5. Long Session Stability
6. Performance Regression Detection
"""

import time
import threading
import logging
import gc
import psutil
import numpy as np
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import uuid
import statistics
from contextlib import contextmanager
import matplotlib.pyplot as plt
import seaborn as sns

# VoiceFlow imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from voiceflow.core.config import Config
from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
from voiceflow.core.asr_enhanced import EnhancedWhisperASR

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Container for performance measurement data"""
    test_id: str
    test_name: str
    audio_duration: float
    processing_time: float
    speed_factor: float  # audio_duration / processing_time
    memory_before_mb: float
    memory_after_mb: float
    memory_peak_mb: float
    cpu_percent: float
    transcription_count: int
    model_reload_occurred: bool
    error_occurred: bool
    latency_ms: Optional[float] = None
    transcription_text: str = ""
    metadata: Dict[str, Any] = None

@dataclass
class SessionMetrics:
    """Container for session-level performance data"""
    session_id: str
    total_transcriptions: int
    total_audio_duration: float
    total_processing_time: float
    average_speed_factor: float
    memory_growth_mb: float
    model_reloads: int
    errors: int
    individual_metrics: List[PerformanceMetrics]

class AudioTestDataGenerator:
    """Generate consistent test audio for benchmarking"""

    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate

    def generate_silence(self, duration_seconds: float) -> np.ndarray:
        """Generate silent audio"""
        samples = int(duration_seconds * self.sample_rate)
        return np.zeros(samples, dtype=np.float32)

    def generate_tone(self, duration_seconds: float, frequency: float = 440.0, amplitude: float = 0.1) -> np.ndarray:
        """Generate pure tone for testing"""
        samples = int(duration_seconds * self.sample_rate)
        t = np.linspace(0, duration_seconds, samples, False)
        tone = amplitude * np.sin(2 * np.pi * frequency * t)
        return tone.astype(np.float32)

    def generate_speech_like(self, duration_seconds: float) -> np.ndarray:
        """Generate speech-like audio with varying frequencies"""
        samples = int(duration_seconds * self.sample_rate)
        t = np.linspace(0, duration_seconds, samples, False)

        # Mix multiple frequencies to simulate speech
        speech = (
            0.05 * np.sin(2 * np.pi * 200 * t) +  # Fundamental
            0.03 * np.sin(2 * np.pi * 400 * t) +  # First harmonic
            0.02 * np.sin(2 * np.pi * 600 * t) +  # Second harmonic
            0.01 * np.random.normal(0, 0.01, samples)  # Noise
        )

        # Add envelope to make it more speech-like
        envelope = np.exp(-t * 0.5) * (1 - np.exp(-t * 5))
        speech *= envelope

        return speech.astype(np.float32)

    def generate_test_suite(self) -> Dict[str, np.ndarray]:
        """Generate complete test audio suite"""
        return {
            "silence_0.5s": self.generate_silence(0.5),
            "silence_1s": self.generate_silence(1.0),
            "silence_2s": self.generate_silence(2.0),
            "tone_0.5s": self.generate_tone(0.5),
            "tone_1s": self.generate_tone(1.0),
            "tone_2s": self.generate_tone(2.0),
            "speech_0.5s": self.generate_speech_like(0.5),
            "speech_1s": self.generate_speech_like(1.0),
            "speech_2s": self.generate_speech_like(2.0),
            "speech_5s": self.generate_speech_like(5.0),
            "speech_10s": self.generate_speech_like(10.0),
        }

class SystemResourceMonitor:
    """Monitor system resources during transcription"""

    def __init__(self):
        self.process = psutil.Process()
        self.monitoring = False
        self.measurements = []
        self._monitor_thread = None

    @contextmanager
    def monitor_resources(self, interval: float = 0.1):
        """Context manager to monitor resources during operation"""
        initial_memory = self.get_memory_usage()
        self.start_monitoring(interval)
        try:
            yield
        finally:
            self.stop_monitoring()
            final_memory = self.get_memory_usage()
            peak_memory = max([m['memory_mb'] for m in self.measurements] + [initial_memory])

            # Return summary
            self.last_session_summary = {
                'initial_memory_mb': initial_memory,
                'final_memory_mb': final_memory,
                'peak_memory_mb': peak_memory,
                'memory_growth_mb': final_memory - initial_memory,
                'avg_cpu_percent': statistics.mean([m['cpu_percent'] for m in self.measurements]) if self.measurements else 0,
                'measurements': self.measurements.copy()
            }

    def start_monitoring(self, interval: float = 0.1):
        """Start background resource monitoring"""
        self.monitoring = True
        self.measurements = []
        self._monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
        self._monitor_thread.daemon = True
        self._monitor_thread.start()

    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)

    def _monitor_loop(self, interval: float):
        """Background monitoring loop"""
        while self.monitoring:
            try:
                measurement = {
                    'timestamp': time.perf_counter(),
                    'memory_mb': self.get_memory_usage(),
                    'cpu_percent': self.get_cpu_usage()
                }
                self.measurements.append(measurement)
                time.sleep(interval)
            except Exception as e:
                logger.warning(f"Resource monitoring error: {e}")
                break

    def get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        try:
            return self.process.memory_info().rss / 1024 / 1024
        except Exception:
            return 0.0

    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            return self.process.cpu_percent()
        except Exception:
            return 0.0

class PerformanceTester:
    """Main performance testing class"""

    def __init__(self, config: Config):
        self.config = config
        self.audio_generator = AudioTestDataGenerator()
        self.resource_monitor = SystemResourceMonitor()
        self.test_results: List[PerformanceMetrics] = []
        self.session_results: List[SessionMetrics] = []

        # Test configuration
        self.test_audio_suite = self.audio_generator.generate_test_suite()

        # Performance targets (baseline expectations)
        self.performance_targets = {
            'min_speed_factor': 1.0,  # Should be at least real-time
            'max_memory_growth_mb': 100,  # Should not grow more than 100MB per session
            'max_latency_ms': 2000,  # Should respond within 2 seconds
            'max_cpu_percent': 80,  # Should not exceed 80% CPU
        }

    def create_asr_instance(self, enhanced: bool = False) -> object:
        """Create ASR instance for testing"""
        if enhanced:
            return EnhancedWhisperASR(self.config)
        else:
            return BufferSafeWhisperASR(self.config)

    def benchmark_transcription_speed(self, asr_instance: object, test_name: str = "speed_benchmark") -> List[PerformanceMetrics]:
        """Benchmark transcription speed across different audio types"""
        logger.info(f"Starting transcription speed benchmark: {test_name}")
        results = []

        for audio_name, audio_data in self.test_audio_suite.items():
            logger.info(f"Testing {audio_name} ({len(audio_data)/16000:.1f}s)")

            # Measure performance
            with self.resource_monitor.monitor_resources():
                start_time = time.perf_counter()

                try:
                    transcription = asr_instance.transcribe(audio_data)
                    processing_time = time.perf_counter() - start_time
                    error_occurred = False
                except Exception as e:
                    logger.error(f"Transcription failed for {audio_name}: {e}")
                    transcription = ""
                    processing_time = time.perf_counter() - start_time
                    error_occurred = True

            # Calculate metrics
            audio_duration = len(audio_data) / 16000.0
            speed_factor = audio_duration / processing_time if processing_time > 0 else 0

            # Get resource usage from monitor
            resource_summary = self.resource_monitor.last_session_summary

            metrics = PerformanceMetrics(
                test_id=str(uuid.uuid4()),
                test_name=f"{test_name}_{audio_name}",
                audio_duration=audio_duration,
                processing_time=processing_time,
                speed_factor=speed_factor,
                memory_before_mb=resource_summary['initial_memory_mb'],
                memory_after_mb=resource_summary['final_memory_mb'],
                memory_peak_mb=resource_summary['peak_memory_mb'],
                cpu_percent=resource_summary['avg_cpu_percent'],
                transcription_count=1,
                model_reload_occurred=False,  # Would need to detect this
                error_occurred=error_occurred,
                transcription_text=transcription,
                metadata={'audio_type': audio_name, 'test_category': 'speed_benchmark'}
            )

            results.append(metrics)
            self.test_results.append(metrics)

            logger.info(f"  Result: {speed_factor:.2f}x realtime, {processing_time:.3f}s processing")

        return results

    def test_model_reload_performance(self, asr_instance: object, num_transcriptions: int = 10) -> SessionMetrics:
        """Test performance impact of aggressive model reloading"""
        logger.info(f"Testing model reload performance over {num_transcriptions} transcriptions")

        session_id = str(uuid.uuid4())
        session_metrics = []

        # Use medium-length speech audio for realistic testing
        test_audio = self.test_audio_suite["speech_2s"]

        with self.resource_monitor.monitor_resources():
            session_start = time.perf_counter()
            total_audio_duration = 0
            total_processing_time = 0

            for i in range(num_transcriptions):
                logger.info(f"Transcription {i+1}/{num_transcriptions}")

                start_time = time.perf_counter()
                try:
                    transcription = asr_instance.transcribe(test_audio)
                    processing_time = time.perf_counter() - start_time
                    error_occurred = False
                except Exception as e:
                    logger.error(f"Transcription {i+1} failed: {e}")
                    transcription = ""
                    processing_time = time.perf_counter() - start_time
                    error_occurred = True

                audio_duration = len(test_audio) / 16000.0
                speed_factor = audio_duration / processing_time if processing_time > 0 else 0

                total_audio_duration += audio_duration
                total_processing_time += processing_time

                # Check if model reload occurred (heuristic: slow processing after fast)
                model_reload_occurred = processing_time > 2.0 and i > 0

                metrics = PerformanceMetrics(
                    test_id=str(uuid.uuid4()),
                    test_name=f"reload_test_{i+1}",
                    audio_duration=audio_duration,
                    processing_time=processing_time,
                    speed_factor=speed_factor,
                    memory_before_mb=self.resource_monitor.get_memory_usage(),
                    memory_after_mb=0,  # Will be filled after
                    memory_peak_mb=0,  # Will be filled after
                    cpu_percent=self.resource_monitor.get_cpu_usage(),
                    transcription_count=i+1,
                    model_reload_occurred=model_reload_occurred,
                    error_occurred=error_occurred,
                    transcription_text=transcription,
                    metadata={'session_id': session_id, 'transcription_index': i}
                )

                session_metrics.append(metrics)
                self.test_results.append(metrics)

                # Brief pause between transcriptions
                time.sleep(0.1)

        # Finalize session metrics
        resource_summary = self.resource_monitor.last_session_summary

        # Update memory information for all metrics
        for metric in session_metrics:
            metric.memory_after_mb = resource_summary['final_memory_mb']
            metric.memory_peak_mb = resource_summary['peak_memory_mb']

        session_result = SessionMetrics(
            session_id=session_id,
            total_transcriptions=num_transcriptions,
            total_audio_duration=total_audio_duration,
            total_processing_time=total_processing_time,
            average_speed_factor=total_audio_duration / total_processing_time if total_processing_time > 0 else 0,
            memory_growth_mb=resource_summary['memory_growth_mb'],
            model_reloads=sum(1 for m in session_metrics if m.model_reload_occurred),
            errors=sum(1 for m in session_metrics if m.error_occurred),
            individual_metrics=session_metrics
        )

        self.session_results.append(session_result)
        return session_result

    def test_latency_from_hotkey(self, asr_instance: object, num_tests: int = 5) -> List[PerformanceMetrics]:
        """Test end-to-end latency from hotkey press to transcription completion"""
        logger.info(f"Testing hotkey-to-completion latency over {num_tests} tests")
        results = []

        test_audio = self.test_audio_suite["speech_1s"]

        for i in range(num_tests):
            logger.info(f"Latency test {i+1}/{num_tests}")

            # Simulate hotkey press
            hotkey_time = time.perf_counter()

            with self.resource_monitor.monitor_resources():
                try:
                    transcription = asr_instance.transcribe(test_audio)
                    completion_time = time.perf_counter()
                    error_occurred = False
                except Exception as e:
                    logger.error(f"Latency test {i+1} failed: {e}")
                    transcription = ""
                    completion_time = time.perf_counter()
                    error_occurred = True

            total_latency = completion_time - hotkey_time
            processing_time = total_latency  # In this case, they're the same
            audio_duration = len(test_audio) / 16000.0
            speed_factor = audio_duration / processing_time if processing_time > 0 else 0

            resource_summary = self.resource_monitor.last_session_summary

            metrics = PerformanceMetrics(
                test_id=str(uuid.uuid4()),
                test_name=f"latency_test_{i+1}",
                audio_duration=audio_duration,
                processing_time=processing_time,
                speed_factor=speed_factor,
                memory_before_mb=resource_summary['initial_memory_mb'],
                memory_after_mb=resource_summary['final_memory_mb'],
                memory_peak_mb=resource_summary['peak_memory_mb'],
                cpu_percent=resource_summary['avg_cpu_percent'],
                transcription_count=1,
                model_reload_occurred=False,
                error_occurred=error_occurred,
                latency_ms=total_latency * 1000,
                transcription_text=transcription,
                metadata={'test_category': 'latency', 'test_index': i}
            )

            results.append(metrics)
            self.test_results.append(metrics)

            logger.info(f"  Latency: {total_latency*1000:.1f}ms, Speed: {speed_factor:.2f}x")

            # Brief pause between tests
            time.sleep(0.5)

        return results

    def test_long_session_stability(self, asr_instance: object, num_transcriptions: int = 30) -> SessionMetrics:
        """Test stability and performance over long sessions"""
        logger.info(f"Testing long session stability over {num_transcriptions} transcriptions")

        session_id = str(uuid.uuid4())
        session_metrics = []

        # Mix different audio types for realistic testing
        audio_types = ["speech_1s", "speech_2s", "speech_5s", "silence_1s", "tone_1s"]

        with self.resource_monitor.monitor_resources():
            total_audio_duration = 0
            total_processing_time = 0

            for i in range(num_transcriptions):
                # Rotate through different audio types
                audio_name = audio_types[i % len(audio_types)]
                test_audio = self.test_audio_suite[audio_name]

                logger.info(f"Long session transcription {i+1}/{num_transcriptions} ({audio_name})")

                start_time = time.perf_counter()
                try:
                    transcription = asr_instance.transcribe(test_audio)
                    processing_time = time.perf_counter() - start_time
                    error_occurred = False
                except Exception as e:
                    logger.error(f"Long session transcription {i+1} failed: {e}")
                    transcription = ""
                    processing_time = time.perf_counter() - start_time
                    error_occurred = True

                audio_duration = len(test_audio) / 16000.0
                speed_factor = audio_duration / processing_time if processing_time > 0 else 0

                total_audio_duration += audio_duration
                total_processing_time += processing_time

                metrics = PerformanceMetrics(
                    test_id=str(uuid.uuid4()),
                    test_name=f"long_session_{i+1}",
                    audio_duration=audio_duration,
                    processing_time=processing_time,
                    speed_factor=speed_factor,
                    memory_before_mb=self.resource_monitor.get_memory_usage(),
                    memory_after_mb=0,  # Will be filled after
                    memory_peak_mb=0,  # Will be filled after
                    cpu_percent=self.resource_monitor.get_cpu_usage(),
                    transcription_count=i+1,
                    model_reload_occurred=False,  # Would need better detection
                    error_occurred=error_occurred,
                    transcription_text=transcription,
                    metadata={
                        'session_id': session_id,
                        'transcription_index': i,
                        'audio_type': audio_name,
                        'test_category': 'long_session'
                    }
                )

                session_metrics.append(metrics)
                self.test_results.append(metrics)

                # Brief pause between transcriptions (realistic usage)
                time.sleep(0.2)

        # Finalize session metrics
        resource_summary = self.resource_monitor.last_session_summary

        # Update memory information for all metrics
        for metric in session_metrics:
            metric.memory_after_mb = resource_summary['final_memory_mb']
            metric.memory_peak_mb = resource_summary['peak_memory_mb']

        session_result = SessionMetrics(
            session_id=session_id,
            total_transcriptions=num_transcriptions,
            total_audio_duration=total_audio_duration,
            total_processing_time=total_processing_time,
            average_speed_factor=total_audio_duration / total_processing_time if total_processing_time > 0 else 0,
            memory_growth_mb=resource_summary['memory_growth_mb'],
            model_reloads=sum(1 for m in session_metrics if m.model_reload_occurred),
            errors=sum(1 for m in session_metrics if m.error_occurred),
            individual_metrics=session_metrics
        )

        self.session_results.append(session_result)
        return session_result

    def run_comprehensive_performance_suite(self) -> Dict[str, Any]:
        """Run complete performance test suite"""
        logger.info("Starting comprehensive performance test suite")

        results = {
            'test_timestamp': time.time(),
            'config': self.config.__dict__,
            'performance_targets': self.performance_targets,
            'test_results': {},
            'summary': {}
        }

        # Create ASR instance for testing
        asr_instance = self.create_asr_instance(enhanced=False)

        try:
            # Test 1: Basic transcription speed
            logger.info("=== Running transcription speed benchmarks ===")
            speed_results = self.benchmark_transcription_speed(asr_instance, "basic_speed")
            results['test_results']['speed_benchmark'] = [r.__dict__ for r in speed_results]

            # Test 2: Model reload performance
            logger.info("=== Running model reload performance test ===")
            reload_session = self.test_model_reload_performance(asr_instance, num_transcriptions=10)
            results['test_results']['model_reload'] = reload_session.__dict__

            # Test 3: Latency tests
            logger.info("=== Running latency tests ===")
            latency_results = self.test_latency_from_hotkey(asr_instance, num_tests=5)
            results['test_results']['latency'] = [r.__dict__ for r in latency_results]

            # Test 4: Long session stability
            logger.info("=== Running long session stability test ===")
            stability_session = self.test_long_session_stability(asr_instance, num_transcriptions=30)
            results['test_results']['long_session'] = stability_session.__dict__

            # Generate summary
            results['summary'] = self.generate_performance_summary()

            logger.info("Comprehensive performance test suite completed")

        except Exception as e:
            logger.error(f"Performance test suite failed: {e}")
            results['error'] = str(e)

        return results

    def generate_performance_summary(self) -> Dict[str, Any]:
        """Generate summary of all performance test results"""
        if not self.test_results:
            return {'error': 'No test results available'}

        # Calculate aggregate statistics
        speed_factors = [r.speed_factor for r in self.test_results if r.speed_factor > 0]
        processing_times = [r.processing_time for r in self.test_results]
        memory_growths = [r.memory_after_mb - r.memory_before_mb for r in self.test_results]
        cpu_usages = [r.cpu_percent for r in self.test_results if r.cpu_percent > 0]
        latencies = [r.latency_ms for r in self.test_results if r.latency_ms is not None]

        errors = sum(1 for r in self.test_results if r.error_occurred)
        total_tests = len(self.test_results)

        summary = {
            'total_tests': total_tests,
            'error_rate': errors / total_tests if total_tests > 0 else 0,
            'speed_factor': {
                'mean': statistics.mean(speed_factors) if speed_factors else 0,
                'median': statistics.median(speed_factors) if speed_factors else 0,
                'min': min(speed_factors) if speed_factors else 0,
                'max': max(speed_factors) if speed_factors else 0,
                'std': statistics.stdev(speed_factors) if len(speed_factors) > 1 else 0
            },
            'processing_time': {
                'mean': statistics.mean(processing_times) if processing_times else 0,
                'median': statistics.median(processing_times) if processing_times else 0,
                'min': min(processing_times) if processing_times else 0,
                'max': max(processing_times) if processing_times else 0
            },
            'memory_usage': {
                'mean_growth_mb': statistics.mean(memory_growths) if memory_growths else 0,
                'max_growth_mb': max(memory_growths) if memory_growths else 0,
                'total_growth_mb': sum(memory_growths) if memory_growths else 0
            },
            'cpu_usage': {
                'mean_percent': statistics.mean(cpu_usages) if cpu_usages else 0,
                'max_percent': max(cpu_usages) if cpu_usages else 0
            },
            'latency': {
                'mean_ms': statistics.mean(latencies) if latencies else 0,
                'median_ms': statistics.median(latencies) if latencies else 0,
                'max_ms': max(latencies) if latencies else 0
            } if latencies else None,
            'performance_assessment': self.assess_performance(speed_factors, memory_growths, latencies, cpu_usages)
        }

        return summary

    def assess_performance(self, speed_factors: List[float], memory_growths: List[float],
                          latencies: List[float], cpu_usages: List[float]) -> Dict[str, Any]:
        """Assess performance against targets"""
        assessment = {
            'overall_grade': 'UNKNOWN',
            'issues': [],
            'strengths': [],
            'recommendations': []
        }

        issues = []
        strengths = []

        # Check speed factor
        if speed_factors:
            avg_speed = statistics.mean(speed_factors)
            if avg_speed < self.performance_targets['min_speed_factor']:
                issues.append(f"Average speed factor {avg_speed:.2f}x below target {self.performance_targets['min_speed_factor']}x")
            else:
                strengths.append(f"Good speed factor: {avg_speed:.2f}x realtime")

        # Check memory growth
        if memory_growths:
            max_growth = max(memory_growths)
            if max_growth > self.performance_targets['max_memory_growth_mb']:
                issues.append(f"Memory growth {max_growth:.1f}MB exceeds target {self.performance_targets['max_memory_growth_mb']}MB")
            else:
                strengths.append(f"Controlled memory growth: {max_growth:.1f}MB max")

        # Check latency
        if latencies:
            max_latency = max(latencies)
            if max_latency > self.performance_targets['max_latency_ms']:
                issues.append(f"Max latency {max_latency:.0f}ms exceeds target {self.performance_targets['max_latency_ms']}ms")
            else:
                strengths.append(f"Good latency: {max_latency:.0f}ms max")

        # Check CPU usage
        if cpu_usages:
            max_cpu = max(cpu_usages)
            if max_cpu > self.performance_targets['max_cpu_percent']:
                issues.append(f"CPU usage {max_cpu:.1f}% exceeds target {self.performance_targets['max_cpu_percent']}%")
            else:
                strengths.append(f"Reasonable CPU usage: {max_cpu:.1f}% max")

        # Determine overall grade
        if len(issues) == 0:
            assessment['overall_grade'] = 'EXCELLENT'
        elif len(issues) == 1:
            assessment['overall_grade'] = 'GOOD'
        elif len(issues) == 2:
            assessment['overall_grade'] = 'FAIR'
        else:
            assessment['overall_grade'] = 'POOR'

        assessment['issues'] = issues
        assessment['strengths'] = strengths

        # Generate recommendations
        if issues:
            assessment['recommendations'] = [
                "Consider optimizing model reload frequency if speed is impacted",
                "Monitor memory usage patterns for potential leaks",
                "Profile CPU-intensive operations during transcription",
                "Test with different model sizes for speed vs. quality trade-off"
            ]
        else:
            assessment['recommendations'] = [
                "Performance looks good - consider stress testing with longer sessions",
                "Monitor performance over extended usage periods",
                "Consider enabling more optimizations if stability remains good"
            ]

        return assessment

    def save_results(self, results: Dict[str, Any], output_dir: str = "test_results"):
        """Save test results to files"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # Save JSON results
        results_file = output_path / f"performance_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"Performance test results saved to {results_file}")
        return results_file

def main():
    """Run performance tests"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create test configuration (CPU-only, aggressive stability)
    config = Config(
        model_name="tiny.en",
        device="cpu",
        compute_type="int8",
        vad_filter=False,
        beam_size=1,
        temperature=0.0,
        max_transcriptions_before_reload=2,
        enable_lockfree_model_access=False,
        enable_ultra_fast_mode_bypass=False,
        enable_memory_pooling=False,
        enable_chunked_long_audio=False
    )

    # Create tester and run comprehensive suite
    tester = PerformanceTester(config)
    results = tester.run_comprehensive_performance_suite()

    # Save results
    results_file = tester.save_results(results)

    # Print summary
    if 'summary' in results:
        summary = results['summary']
        print("\n" + "="*60)
        print("PERFORMANCE TEST RESULTS SUMMARY")
        print("="*60)
        print(f"Total tests: {summary['total_tests']}")
        print(f"Error rate: {summary['error_rate']:.1%}")
        print(f"Average speed: {summary['speed_factor']['mean']:.2f}x realtime")
        print(f"Memory growth: {summary['memory_usage']['max_growth_mb']:.1f}MB max")
        if summary['latency']:
            print(f"Max latency: {summary['latency']['max_ms']:.0f}ms")
        print(f"Max CPU usage: {summary['cpu_usage']['max_percent']:.1f}%")
        print(f"\nOverall grade: {summary['performance_assessment']['overall_grade']}")

        if summary['performance_assessment']['issues']:
            print("\nIssues found:")
            for issue in summary['performance_assessment']['issues']:
                print(f"  - {issue}")

        if summary['performance_assessment']['strengths']:
            print("\nStrengths:")
            for strength in summary['performance_assessment']['strengths']:
                print(f"  + {strength}")

        print(f"\nDetailed results saved to: {results_file}")

    return results

if __name__ == "__main__":
    main()