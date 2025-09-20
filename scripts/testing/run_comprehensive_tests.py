#!/usr/bin/env python3
"""
VoiceFlow Comprehensive Performance Testing Suite

Validates DeepSeek optimization recommendations through systematic benchmarking.
Tests 3 high-impact optimizations:
1. Smart Audio Validation (15-25% gain) - Statistical sampling vs full validation
2. Adaptive Model Access (8-15% gain) - Context-aware locking
3. Memory Optimizations (5-10% gain) - Zero-copy operations

Target: 30-40% performance improvement (9.3x -> 12-13x realtime)
"""

import os
import sys
import json
import time
import logging
import statistics
import threading
import traceback
import subprocess
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
import psutil

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from voiceflow.core.config import Config
from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
from voiceflow.core.audio_enhanced import audio_validation_guard

# Configure logging
logging.basicConfig(
    level=logging.WARNING,  # Reduce logging overhead during testing
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Single test execution result"""
    test_name: str
    audio_duration: float
    processing_time: float
    speed_factor: float
    memory_before_mb: float
    memory_after_mb: float
    memory_delta_mb: float
    transcription_text: str
    success: bool
    error_message: Optional[str] = None
    config_flags: Dict[str, bool] = None

@dataclass
class BenchmarkSuite:
    """Complete benchmark suite results"""
    baseline_results: List[TestResult]
    smart_audio_validation_results: List[TestResult]
    adaptive_model_access_results: List[TestResult]
    memory_optimization_results: List[TestResult]
    combined_optimization_results: List[TestResult]
    test_metadata: Dict[str, Any]

class PerformanceTester:
    """Comprehensive performance testing framework"""

    def __init__(self, output_dir: str = "tests/performance_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Test audio samples (different durations)
        self.test_samples = self._generate_test_audio_samples()

        # Memory monitoring
        self.process = psutil.Process()

        # Results storage
        self.results = BenchmarkSuite(
            baseline_results=[],
            smart_audio_validation_results=[],
            adaptive_model_access_results=[],
            memory_optimization_results=[],
            combined_optimization_results=[],
            test_metadata={}
        )

        print(f"[PerformanceTester] Initialized with {len(self.test_samples)} test samples")
        print(f"[PerformanceTester] Results will be saved to: {self.output_dir}")

    def _generate_test_audio_samples(self) -> Dict[str, np.ndarray]:
        """Generate test audio samples of various durations"""
        samples = {}
        sample_rate = 16000

        # Generate synthetic speech-like signals
        durations = [1.0, 3.0, 5.0, 10.0, 15.0, 30.0]  # seconds

        for duration in durations:
            length = int(duration * sample_rate)
            t = np.linspace(0, duration, length)

            # Create speech-like signal with multiple frequencies and amplitude modulation
            frequency_base = 150  # Base frequency for speech
            signal = (
                0.3 * np.sin(2 * np.pi * frequency_base * t) +
                0.2 * np.sin(2 * np.pi * frequency_base * 2 * t) +
                0.1 * np.sin(2 * np.pi * frequency_base * 3 * t) +
                0.05 * np.random.normal(0, 0.1, length)  # Background noise
            )

            # Apply amplitude modulation to simulate speech patterns
            modulation = 0.5 + 0.5 * np.sin(2 * np.pi * 2 * t)  # 2 Hz modulation
            signal *= modulation

            # Ensure float32 format
            signal = signal.astype(np.float32)

            samples[f"{duration}s"] = signal

        # Add empty audio test
        samples["empty"] = np.array([], dtype=np.float32)

        # Add silence test
        samples["silence"] = np.zeros(int(2.0 * sample_rate), dtype=np.float32)

        return samples

    def _get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB"""
        try:
            return self.process.memory_info().rss / 1024 / 1024
        except:
            return 0.0

    def _create_config(self, optimization_flags: Dict[str, bool] = None) -> Config:
        """Create configuration with specific optimization flags"""
        cfg = Config()

        # Apply optimization flags if provided
        if optimization_flags:
            for flag, value in optimization_flags.items():
                if hasattr(cfg, flag):
                    setattr(cfg, flag, value)
                else:
                    logger.warning(f"Unknown config flag: {flag}")

        return cfg

    def _run_single_test(self, test_name: str, audio_sample: np.ndarray,
                        config_flags: Dict[str, bool] = None) -> TestResult:
        """Execute a single transcription test"""
        try:
            # Get memory before test
            memory_before = self._get_memory_usage_mb()

            # Create ASR instance with specific config
            cfg = self._create_config(config_flags)
            asr = BufferSafeWhisperASR(cfg)

            # Measure transcription performance
            start_time = time.perf_counter()
            transcription = asr.transcribe(audio_sample)
            processing_time = time.perf_counter() - start_time

            # Get memory after test
            memory_after = self._get_memory_usage_mb()
            memory_delta = memory_after - memory_before

            # Calculate metrics
            audio_duration = len(audio_sample) / 16000.0 if len(audio_sample) > 0 else 0.0
            speed_factor = audio_duration / processing_time if processing_time > 0 else 0.0

            result = TestResult(
                test_name=test_name,
                audio_duration=audio_duration,
                processing_time=processing_time,
                speed_factor=speed_factor,
                memory_before_mb=memory_before,
                memory_after_mb=memory_after,
                memory_delta_mb=memory_delta,
                transcription_text=transcription,
                success=True,
                config_flags=config_flags or {}
            )

            print(f"[TEST] {test_name}: {speed_factor:.1f}x realtime, {memory_delta:.1f}MB")
            return result

        except Exception as e:
            error_msg = f"Test failed: {str(e)}"
            logger.error(f"{test_name}: {error_msg}")

            return TestResult(
                test_name=test_name,
                audio_duration=0.0,
                processing_time=0.0,
                speed_factor=0.0,
                memory_before_mb=0.0,
                memory_after_mb=0.0,
                memory_delta_mb=0.0,
                transcription_text="",
                success=False,
                error_message=error_msg,
                config_flags=config_flags or {}
            )

    def run_baseline_tests(self) -> List[TestResult]:
        """Execute baseline performance tests with conservative settings"""
        print("\n=== BASELINE PERFORMANCE TESTS ===")

        # Conservative baseline configuration
        baseline_flags = {
            'enable_fast_audio_validation': False,
            'enable_lockfree_model_access': False,
            'enable_memory_pooling': False,
            'enable_chunked_long_audio': False,
            'ultra_fast_mode': False,
            'skip_buffer_integrity_checks': False
        }

        results = []
        for sample_name, audio_sample in self.test_samples.items():
            test_name = f"baseline_{sample_name}"
            result = self._run_single_test(test_name, audio_sample, baseline_flags)
            results.append(result)

            # Brief pause between tests to prevent interference
            time.sleep(0.5)

        self.results.baseline_results = results
        print(f"Baseline tests completed: {len(results)} tests")
        return results

    def run_smart_audio_validation_tests(self) -> List[TestResult]:
        """Test Smart Audio Validation optimization (15-25% expected gain)"""
        print("\n=== SMART AUDIO VALIDATION TESTS ===")

        # Enable only smart audio validation
        optimization_flags = {
            'enable_fast_audio_validation': True,
            'audio_validation_sample_rate': 0.05,  # 5% sampling
            'fast_nan_inf_detection': True,
            'disable_amplitude_warnings': True,
            'enable_lockfree_model_access': False,
            'enable_memory_pooling': False,
            'enable_chunked_long_audio': False,
            'ultra_fast_mode': False
        }

        results = []
        for sample_name, audio_sample in self.test_samples.items():
            test_name = f"smart_validation_{sample_name}"
            result = self._run_single_test(test_name, audio_sample, optimization_flags)
            results.append(result)
            time.sleep(0.5)

        self.results.smart_audio_validation_results = results
        print(f"Smart audio validation tests completed: {len(results)} tests")
        return results

    def run_adaptive_model_access_tests(self) -> List[TestResult]:
        """Test Adaptive Model Access optimization (8-15% expected gain)"""
        print("\n=== ADAPTIVE MODEL ACCESS TESTS ===")

        # Enable only adaptive model access
        optimization_flags = {
            'enable_lockfree_model_access': True,
            'enable_fast_audio_validation': False,
            'enable_memory_pooling': False,
            'enable_chunked_long_audio': False,
            'ultra_fast_mode': False
        }

        results = []
        for sample_name, audio_sample in self.test_samples.items():
            test_name = f"adaptive_access_{sample_name}"
            result = self._run_single_test(test_name, audio_sample, optimization_flags)
            results.append(result)
            time.sleep(0.5)

        self.results.adaptive_model_access_results = results
        print(f"Adaptive model access tests completed: {len(results)} tests")
        return results

    def run_memory_optimization_tests(self) -> List[TestResult]:
        """Test Memory Optimizations (5-10% expected gain)"""
        print("\n=== MEMORY OPTIMIZATION TESTS ===")

        # Enable only memory optimizations
        optimization_flags = {
            'enable_memory_pooling': True,
            'enable_chunked_long_audio': True,
            'chunk_size_seconds': 5.0,
            'enable_fast_audio_validation': False,
            'enable_lockfree_model_access': False,
            'ultra_fast_mode': False
        }

        results = []
        for sample_name, audio_sample in self.test_samples.items():
            test_name = f"memory_opt_{sample_name}"
            result = self._run_single_test(test_name, audio_sample, optimization_flags)
            results.append(result)
            time.sleep(0.5)

        self.results.memory_optimization_results = results
        print(f"Memory optimization tests completed: {len(results)} tests")
        return results

    def run_combined_optimization_tests(self) -> List[TestResult]:
        """Test all optimizations combined (30-40% expected total gain)"""
        print("\n=== COMBINED OPTIMIZATION TESTS ===")

        # Enable all optimizations
        combined_flags = {
            'enable_fast_audio_validation': True,
            'audio_validation_sample_rate': 0.02,  # 2% sampling for max speed
            'fast_nan_inf_detection': True,
            'disable_amplitude_warnings': True,
            'enable_lockfree_model_access': True,
            'enable_memory_pooling': True,
            'enable_chunked_long_audio': True,
            'chunk_size_seconds': 5.0,
            'ultra_fast_mode': True,
            'skip_buffer_integrity_checks': True,
            'minimal_segment_processing': True,
            'disable_fallback_detection': True
        }

        results = []
        for sample_name, audio_sample in self.test_samples.items():
            test_name = f"combined_{sample_name}"
            result = self._run_single_test(test_name, audio_sample, combined_flags)
            results.append(result)
            time.sleep(0.5)

        self.results.combined_optimization_results = results
        print(f"Combined optimization tests completed: {len(results)} tests")
        return results

    def validate_transcription_quality(self) -> Dict[str, Any]:
        """Validate that optimizations don't degrade transcription quality"""
        print("\n=== TRANSCRIPTION QUALITY VALIDATION ===")

        quality_metrics = {
            'baseline_avg_length': 0,
            'optimized_avg_length': 0,
            'quality_degradation_percent': 0,
            'empty_transcriptions_baseline': 0,
            'empty_transcriptions_optimized': 0,
            'quality_validation_passed': True
        }

        # Compare baseline vs combined optimization transcriptions
        baseline_transcriptions = [r.transcription_text for r in self.results.baseline_results if r.success]
        optimized_transcriptions = [r.transcription_text for r in self.results.combined_optimization_results if r.success]

        if baseline_transcriptions and optimized_transcriptions:
            # Calculate average transcription lengths
            baseline_lengths = [len(t) for t in baseline_transcriptions if t]
            optimized_lengths = [len(t) for t in optimized_transcriptions if t]

            if baseline_lengths:
                quality_metrics['baseline_avg_length'] = statistics.mean(baseline_lengths)
            if optimized_lengths:
                quality_metrics['optimized_avg_length'] = statistics.mean(optimized_lengths)

            # Count empty transcriptions
            quality_metrics['empty_transcriptions_baseline'] = sum(1 for t in baseline_transcriptions if not t.strip())
            quality_metrics['empty_transcriptions_optimized'] = sum(1 for t in optimized_transcriptions if not t.strip())

            # Calculate quality degradation
            if quality_metrics['baseline_avg_length'] > 0:
                degradation = (quality_metrics['baseline_avg_length'] - quality_metrics['optimized_avg_length']) / quality_metrics['baseline_avg_length'] * 100
                quality_metrics['quality_degradation_percent'] = degradation

                # Quality validation passes if degradation is less than 10%
                quality_metrics['quality_validation_passed'] = degradation < 10.0

        print(f"Quality validation: {'PASSED' if quality_metrics['quality_validation_passed'] else 'FAILED'}")
        return quality_metrics

    def analyze_performance_improvements(self) -> Dict[str, Any]:
        """Analyze performance improvements from each optimization"""
        print("\n=== PERFORMANCE IMPROVEMENT ANALYSIS ===")

        def calculate_improvement(baseline_results, optimization_results, optimization_name):
            baseline_speeds = [r.speed_factor for r in baseline_results if r.success and r.speed_factor > 0]
            optimization_speeds = [r.speed_factor for r in optimization_results if r.success and r.speed_factor > 0]

            if not baseline_speeds or not optimization_speeds:
                return 0.0

            baseline_avg = statistics.mean(baseline_speeds)
            optimization_avg = statistics.mean(optimization_speeds)

            improvement = (optimization_avg - baseline_avg) / baseline_avg * 100
            print(f"{optimization_name}: {baseline_avg:.1f}x -> {optimization_avg:.1f}x ({improvement:+.1f}%)")
            return improvement

        improvements = {
            'smart_audio_validation_improvement': calculate_improvement(
                self.results.baseline_results,
                self.results.smart_audio_validation_results,
                "Smart Audio Validation"
            ),
            'adaptive_model_access_improvement': calculate_improvement(
                self.results.baseline_results,
                self.results.adaptive_model_access_results,
                "Adaptive Model Access"
            ),
            'memory_optimization_improvement': calculate_improvement(
                self.results.baseline_results,
                self.results.memory_optimization_results,
                "Memory Optimizations"
            ),
            'combined_optimization_improvement': calculate_improvement(
                self.results.baseline_results,
                self.results.combined_optimization_results,
                "Combined Optimizations"
            )
        }

        return improvements

    def generate_detailed_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance analysis report"""
        print("\n=== GENERATING DETAILED REPORT ===")

        # System information
        system_info = {
            'cpu_count': psutil.cpu_count(),
            'cpu_freq_max': psutil.cpu_freq().max if psutil.cpu_freq() else "Unknown",
            'memory_total_gb': psutil.virtual_memory().total / (1024**3),
            'platform': sys.platform,
            'python_version': sys.version
        }

        # Performance improvements
        improvements = self.analyze_performance_improvements()

        # Quality validation
        quality_metrics = self.validate_transcription_quality()

        # Memory analysis
        memory_analysis = self._analyze_memory_usage()

        # Threading performance
        threading_analysis = self._analyze_threading_performance()

        # Recommendation matrix
        recommendations = self._generate_recommendations(improvements, quality_metrics)

        # Risk assessment
        risk_assessment = self._assess_optimization_risks(improvements, quality_metrics)

        report = {
            'test_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'system_info': system_info,
            'performance_improvements': improvements,
            'quality_validation': quality_metrics,
            'memory_analysis': memory_analysis,
            'threading_analysis': threading_analysis,
            'recommendations': recommendations,
            'risk_assessment': risk_assessment,
            'raw_results': {
                'baseline': [asdict(r) for r in self.results.baseline_results],
                'smart_audio_validation': [asdict(r) for r in self.results.smart_audio_validation_results],
                'adaptive_model_access': [asdict(r) for r in self.results.adaptive_model_access_results],
                'memory_optimization': [asdict(r) for r in self.results.memory_optimization_results],
                'combined_optimization': [asdict(r) for r in self.results.combined_optimization_results]
            }
        }

        return report

    def _analyze_memory_usage(self) -> Dict[str, Any]:
        """Analyze memory usage patterns across tests"""
        all_results = (
            self.results.baseline_results +
            self.results.smart_audio_validation_results +
            self.results.adaptive_model_access_results +
            self.results.memory_optimization_results +
            self.results.combined_optimization_results
        )

        memory_deltas = [r.memory_delta_mb for r in all_results if r.success]

        if not memory_deltas:
            return {'error': 'No memory data available'}

        return {
            'avg_memory_delta_mb': statistics.mean(memory_deltas),
            'max_memory_delta_mb': max(memory_deltas),
            'min_memory_delta_mb': min(memory_deltas),
            'memory_usage_stable': max(memory_deltas) - min(memory_deltas) < 50.0  # Within 50MB variance
        }

    def _analyze_threading_performance(self) -> Dict[str, Any]:
        """Analyze threading efficiency from lockfree vs locked access"""
        baseline_times = [r.processing_time for r in self.results.baseline_results if r.success]
        lockfree_times = [r.processing_time for r in self.results.adaptive_model_access_results if r.success]

        if not baseline_times or not lockfree_times:
            return {'error': 'Insufficient threading data'}

        return {
            'baseline_avg_time': statistics.mean(baseline_times),
            'lockfree_avg_time': statistics.mean(lockfree_times),
            'threading_improvement_percent': (
                (statistics.mean(baseline_times) - statistics.mean(lockfree_times)) /
                statistics.mean(baseline_times) * 100
            )
        }

    def _generate_recommendations(self, improvements: Dict[str, float],
                                quality_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate implementation recommendations based on test results"""
        recommendations = {
            'implement_smart_audio_validation': False,
            'implement_adaptive_model_access': False,
            'implement_memory_optimizations': False,
            'implement_combined_optimizations': False,
            'recommended_config': {},
            'implementation_priority': []
        }

        # Smart Audio Validation
        if improvements['smart_audio_validation_improvement'] >= 10.0:
            recommendations['implement_smart_audio_validation'] = True
            recommendations['implementation_priority'].append('smart_audio_validation')

        # Adaptive Model Access
        if improvements['adaptive_model_access_improvement'] >= 5.0:
            recommendations['implement_adaptive_model_access'] = True
            recommendations['implementation_priority'].append('adaptive_model_access')

        # Memory Optimizations
        if improvements['memory_optimization_improvement'] >= 3.0:
            recommendations['implement_memory_optimizations'] = True
            recommendations['implementation_priority'].append('memory_optimizations')

        # Combined approach if quality is preserved
        if (improvements['combined_optimization_improvement'] >= 20.0 and
            quality_metrics['quality_validation_passed']):
            recommendations['implement_combined_optimizations'] = True
            recommendations['implementation_priority'].insert(0, 'combined_optimizations')

        # Generate recommended configuration
        if recommendations['implement_combined_optimizations']:
            recommendations['recommended_config'] = {
                'enable_fast_audio_validation': True,
                'audio_validation_sample_rate': 0.02,
                'enable_lockfree_model_access': True,
                'enable_memory_pooling': True,
                'ultra_fast_mode': True
            }
        elif recommendations['implement_smart_audio_validation']:
            recommendations['recommended_config'] = {
                'enable_fast_audio_validation': True,
                'audio_validation_sample_rate': 0.05
            }

        return recommendations

    def _assess_optimization_risks(self, improvements: Dict[str, float],
                                 quality_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risks of each optimization"""
        risks = {
            'smart_audio_validation_risk': 'LOW',
            'adaptive_model_access_risk': 'MEDIUM',
            'memory_optimization_risk': 'LOW',
            'combined_optimization_risk': 'MEDIUM',
            'overall_risk_assessment': 'LOW'
        }

        # Quality degradation risk
        if not quality_metrics['quality_validation_passed']:
            risks['combined_optimization_risk'] = 'HIGH'
            risks['overall_risk_assessment'] = 'MEDIUM'

        # Thread safety risk for lockfree access
        if improvements['adaptive_model_access_improvement'] > 0:
            risks['adaptive_model_access_risk'] = 'MEDIUM'  # Thread safety considerations

        # Memory optimization risk is generally low
        if improvements['memory_optimization_improvement'] < 0:
            risks['memory_optimization_risk'] = 'MEDIUM'  # Performance regression

        return risks

    def save_results(self, report: Dict[str, Any]):
        """Save test results to files"""
        timestamp = time.strftime('%Y%m%d_%H%M%S')

        # Save detailed JSON report
        json_file = self.output_dir / f"performance_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Save human-readable summary
        summary_file = self.output_dir / f"performance_summary_{timestamp}.txt"
        self._save_text_summary(report, summary_file)

        print(f"\nResults saved:")
        print(f"  Detailed report: {json_file}")
        print(f"  Summary report: {summary_file}")

    def _save_text_summary(self, report: Dict[str, Any], file_path: Path):
        """Save human-readable summary report"""
        with open(file_path, 'w') as f:
            f.write("VoiceFlow Performance Testing Summary\n")
            f.write("=" * 50 + "\n\n")

            f.write(f"Test Date: {report['test_timestamp']}\n")
            f.write(f"System: {report['system_info']['cpu_count']} CPU cores, ")
            f.write(f"{report['system_info']['memory_total_gb']:.1f}GB RAM\n\n")

            f.write("Performance Improvements:\n")
            f.write("-" * 30 + "\n")
            for opt, improvement in report['performance_improvements'].items():
                f.write(f"{opt}: {improvement:+.1f}%\n")
            f.write("\n")

            f.write("Quality Validation:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Quality Preserved: {'YES' if report['quality_validation']['quality_validation_passed'] else 'NO'}\n")
            f.write(f"Quality Degradation: {report['quality_validation']['quality_degradation_percent']:.1f}%\n\n")

            f.write("Recommendations:\n")
            f.write("-" * 15 + "\n")
            for priority in report['recommendations']['implementation_priority']:
                f.write(f"✓ Implement {priority}\n")
            f.write("\n")

            f.write("Risk Assessment:\n")
            f.write("-" * 15 + "\n")
            f.write(f"Overall Risk: {report['risk_assessment']['overall_risk_assessment']}\n")

def main():
    """Execute comprehensive performance testing suite"""
    print("VoiceFlow Comprehensive Performance Testing Suite")
    print("=" * 60)
    print("Testing DeepSeek optimization recommendations:")
    print("1. Smart Audio Validation (15-25% expected gain)")
    print("2. Adaptive Model Access (8-15% expected gain)")
    print("3. Memory Optimizations (5-10% expected gain)")
    print("Target: 30-40% total improvement (9.3x -> 12-13x realtime)")
    print("=" * 60)

    # Initialize tester
    tester = PerformanceTester()

    try:
        # Execute test suite
        print("\nStarting comprehensive test suite...")

        # Baseline measurements
        tester.run_baseline_tests()

        # Individual optimization tests
        tester.run_smart_audio_validation_tests()
        tester.run_adaptive_model_access_tests()
        tester.run_memory_optimization_tests()

        # Combined optimization test
        tester.run_combined_optimization_tests()

        # Generate comprehensive report
        report = tester.generate_detailed_report()

        # Save results
        tester.save_results(report)

        # Print summary
        print("\n" + "=" * 60)
        print("PERFORMANCE TESTING COMPLETE")
        print("=" * 60)

        improvements = report['performance_improvements']
        print(f"Smart Audio Validation: {improvements['smart_audio_validation_improvement']:+.1f}%")
        print(f"Adaptive Model Access: {improvements['adaptive_model_access_improvement']:+.1f}%")
        print(f"Memory Optimizations: {improvements['memory_optimization_improvement']:+.1f}%")
        print(f"Combined Optimizations: {improvements['combined_optimization_improvement']:+.1f}%")

        quality_passed = report['quality_validation']['quality_validation_passed']
        print(f"\nQuality Validation: {'PASSED' if quality_passed else 'FAILED'}")

        target_achieved = improvements['combined_optimization_improvement'] >= 25.0
        print(f"Target Achievement: {'SUCCESS' if target_achieved else 'PARTIAL'}")

        print(f"\nRecommendations: {len(report['recommendations']['implementation_priority'])} optimizations recommended")
        print(f"Overall Risk: {report['risk_assessment']['overall_risk_assessment']}")

    except Exception as e:
        print(f"\nTesting failed: {e}")
        traceback.print_exc()
        return 1

    return 0

if __name__ == "__main__":
    exit(main())