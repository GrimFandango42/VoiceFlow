#!/usr/bin/env python3
"""
VoiceFlow Optimized System Validation
Targeted validation of the current optimized configuration
"""

import os
import sys
import time
import logging
import statistics
import traceback
from typing import Dict, List, Tuple, Optional
from pathlib import Path

import numpy as np
import psutil

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from voiceflow.core.config import Config
from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

class OptimizedSystemValidator:
    """Validate the current optimized VoiceFlow system"""

    def __init__(self):
        self.process = psutil.Process()

        # Test audio samples with proper metadata handling
        self.test_samples = self._generate_test_audio()

        print("[Validator] Initialized optimized system validation")
        print(f"[Validator] Testing {len(self.test_samples)} audio samples")

    def _generate_test_audio(self) -> Dict[str, np.ndarray]:
        """Generate test audio samples for validation"""
        samples = {}
        sample_rate = 16000

        # Generate realistic speech-like signals
        durations = [2.0, 5.0, 10.0, 15.0]  # seconds

        for duration in durations:
            length = int(duration * sample_rate)
            t = np.linspace(0, duration, length)

            # Create speech-like signal
            frequency_base = 150  # Human speech frequency range
            signal = (
                0.4 * np.sin(2 * np.pi * frequency_base * t) +
                0.3 * np.sin(2 * np.pi * frequency_base * 1.5 * t) +
                0.2 * np.sin(2 * np.pi * frequency_base * 2.2 * t) +
                0.1 * np.random.normal(0, 0.05, length)  # Light background noise
            )

            # Apply amplitude modulation for speech-like patterns
            modulation = 0.6 + 0.4 * np.sin(2 * np.pi * 1.5 * t)
            signal *= modulation

            # Ensure proper float32 format
            signal = signal.astype(np.float32)

            # Normalize to prevent clipping
            max_amplitude = np.max(np.abs(signal))
            if max_amplitude > 0:
                signal = signal * 0.8 / max_amplitude

            samples[f"{duration}s"] = signal

        return samples

    def _get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB"""
        try:
            return self.process.memory_info().rss / 1024 / 1024
        except:
            return 0.0

    def validate_current_configuration(self) -> Dict[str, any]:
        """Validate the current optimized configuration"""
        print("\n=== CURRENT CONFIGURATION VALIDATION ===")

        cfg = Config()

        # Display current optimization settings
        print(f"Lock-free Model Access: {cfg.enable_lockfree_model_access}")
        print(f"Fast Audio Validation: {cfg.enable_fast_audio_validation}")
        print(f"Audio Validation Sample Rate: {cfg.audio_validation_sample_rate}")
        print(f"Ultra Fast Mode: {cfg.ultra_fast_mode}")
        print(f"Memory Pooling: {cfg.enable_memory_pooling}")
        print(f"Chunked Long Audio: {cfg.enable_chunked_long_audio}")

        return {
            'enable_lockfree_model_access': cfg.enable_lockfree_model_access,
            'enable_fast_audio_validation': cfg.enable_fast_audio_validation,
            'audio_validation_sample_rate': cfg.audio_validation_sample_rate,
            'ultra_fast_mode': cfg.ultra_fast_mode,
            'enable_memory_pooling': cfg.enable_memory_pooling,
            'enable_chunked_long_audio': cfg.enable_chunked_long_audio
        }

    def run_performance_validation(self) -> Dict[str, any]:
        """Run performance validation with current optimized settings"""
        print("\n=== PERFORMANCE VALIDATION ===")

        results = []
        cfg = Config()

        try:
            asr = BufferSafeWhisperASR(cfg)

            for sample_name, audio_sample in self.test_samples.items():
                print(f"Testing {sample_name}...")

                # Get memory before
                memory_before = self._get_memory_usage_mb()

                # Measure transcription performance
                start_time = time.perf_counter()
                try:
                    transcription = asr.transcribe(audio_sample)
                    processing_time = time.perf_counter() - start_time
                    success = True
                    error_msg = None
                except Exception as e:
                    processing_time = time.perf_counter() - start_time
                    transcription = ""
                    success = False
                    error_msg = str(e)

                # Get memory after
                memory_after = self._get_memory_usage_mb()

                # Calculate metrics
                audio_duration = len(audio_sample) / 16000.0
                speed_factor = audio_duration / processing_time if processing_time > 0 else 0.0

                result = {
                    'sample_name': sample_name,
                    'audio_duration': audio_duration,
                    'processing_time': processing_time,
                    'speed_factor': speed_factor,
                    'memory_before_mb': memory_before,
                    'memory_after_mb': memory_after,
                    'memory_delta_mb': memory_after - memory_before,
                    'transcription_length': len(transcription),
                    'success': success,
                    'error': error_msg
                }

                results.append(result)

                if success:
                    print(f"  {speed_factor:.1f}x realtime, {memory_after - memory_before:.1f}MB delta")
                else:
                    print(f"  FAILED: {error_msg}")

                time.sleep(0.5)  # Brief pause between tests

        except Exception as e:
            print(f"ASR initialization failed: {e}")
            return {'error': str(e)}

        return {
            'test_results': results,
            'successful_tests': sum(1 for r in results if r['success']),
            'total_tests': len(results)
        }

    def run_quality_validation(self, performance_results: Dict[str, any]) -> Dict[str, any]:
        """Validate transcription quality"""
        print("\n=== QUALITY VALIDATION ===")

        if 'error' in performance_results:
            return {'error': 'Cannot validate quality due to performance test failure'}

        successful_tests = [r for r in performance_results['test_results'] if r['success']]

        if not successful_tests:
            return {'error': 'No successful transcriptions to validate'}

        # Analyze transcription quality metrics
        transcription_lengths = [r['transcription_length'] for r in successful_tests]
        non_empty_transcriptions = sum(1 for length in transcription_lengths if length > 0)

        quality_metrics = {
            'total_successful_tests': len(successful_tests),
            'non_empty_transcriptions': non_empty_transcriptions,
            'empty_transcription_rate': (len(successful_tests) - non_empty_transcriptions) / len(successful_tests) * 100,
            'avg_transcription_length': statistics.mean(transcription_lengths) if transcription_lengths else 0,
            'quality_score': non_empty_transcriptions / len(successful_tests) * 100
        }

        # Quality validation passes if most tests produce non-empty transcriptions
        quality_metrics['quality_validation_passed'] = quality_metrics['quality_score'] >= 75.0

        print(f"Quality Score: {quality_metrics['quality_score']:.1f}%")
        print(f"Empty Transcription Rate: {quality_metrics['empty_transcription_rate']:.1f}%")
        print(f"Quality Validation: {'PASSED' if quality_metrics['quality_validation_passed'] else 'FAILED'}")

        return quality_metrics

    def run_stability_validation(self) -> Dict[str, any]:
        """Validate system stability under optimized settings"""
        print("\n=== STABILITY VALIDATION ===")

        stability_metrics = {
            'consecutive_successful_runs': 0,
            'stability_test_passed': False,
            'memory_stability': True,
            'threading_stability': True
        }

        cfg = Config()
        memory_readings = []

        try:
            # Run multiple consecutive transcriptions to test stability
            for i in range(5):
                print(f"Stability test {i+1}/5...")

                memory_before = self._get_memory_usage_mb()

                asr = BufferSafeWhisperASR(cfg)

                # Use a medium-length sample for stability testing
                test_audio = self.test_samples['5.0s']

                try:
                    transcription = asr.transcribe(test_audio)
                    stability_metrics['consecutive_successful_runs'] += 1

                    memory_after = self._get_memory_usage_mb()
                    memory_readings.append(memory_after - memory_before)

                    print(f"  Success: {len(transcription)} chars, {memory_after - memory_before:.1f}MB")

                except Exception as e:
                    print(f"  Failed: {e}")
                    break

                time.sleep(1.0)  # Pause between runs

            # Check memory stability (memory usage should be consistent)
            if memory_readings:
                memory_variance = statistics.variance(memory_readings) if len(memory_readings) > 1 else 0
                stability_metrics['memory_stability'] = memory_variance < 100.0  # Less than 100MB variance
                print(f"Memory variance: {memory_variance:.1f}MB²")

            # Stability test passes if we get at least 4/5 successful runs
            stability_metrics['stability_test_passed'] = stability_metrics['consecutive_successful_runs'] >= 4

        except Exception as e:
            print(f"Stability test failed: {e}")
            stability_metrics['error'] = str(e)

        print(f"Consecutive successful runs: {stability_metrics['consecutive_successful_runs']}/5")
        print(f"Stability test: {'PASSED' if stability_metrics['stability_test_passed'] else 'FAILED'}")

        return stability_metrics

    def calculate_performance_metrics(self, performance_results: Dict[str, any]) -> Dict[str, any]:
        """Calculate overall performance metrics"""
        print("\n=== PERFORMANCE METRICS CALCULATION ===")

        if 'error' in performance_results:
            return {'error': 'Cannot calculate metrics due to test failure'}

        successful_tests = [r for r in performance_results['test_results'] if r['success']]

        if not successful_tests:
            return {'error': 'No successful tests for metric calculation'}

        # Calculate performance metrics
        speed_factors = [r['speed_factor'] for r in successful_tests if r['speed_factor'] > 0]
        processing_times = [r['processing_time'] for r in successful_tests]
        memory_deltas = [r['memory_delta_mb'] for r in successful_tests]

        metrics = {
            'avg_speed_factor': statistics.mean(speed_factors) if speed_factors else 0,
            'max_speed_factor': max(speed_factors) if speed_factors else 0,
            'avg_processing_time': statistics.mean(processing_times),
            'avg_memory_delta': statistics.mean(memory_deltas),
            'max_memory_delta': max(memory_deltas),
            'performance_target_met': False
        }

        # Check if we meet the target of 12-13x realtime performance
        metrics['performance_target_met'] = metrics['avg_speed_factor'] >= 12.0

        print(f"Average Speed Factor: {metrics['avg_speed_factor']:.1f}x realtime")
        print(f"Maximum Speed Factor: {metrics['max_speed_factor']:.1f}x realtime")
        print(f"Average Processing Time: {metrics['avg_processing_time']:.3f}s")
        print(f"Average Memory Delta: {metrics['avg_memory_delta']:.1f}MB")
        print(f"Performance Target (12x+): {'MET' if metrics['performance_target_met'] else 'NOT MET'}")

        return metrics

    def generate_validation_report(self, config_info: Dict[str, any],
                                 performance_results: Dict[str, any],
                                 quality_metrics: Dict[str, any],
                                 stability_metrics: Dict[str, any],
                                 performance_metrics: Dict[str, any]) -> Dict[str, any]:
        """Generate comprehensive validation report"""
        print("\n=== GENERATING VALIDATION REPORT ===")

        # Overall validation status
        overall_success = (
            performance_results.get('successful_tests', 0) > 0 and
            quality_metrics.get('quality_validation_passed', False) and
            stability_metrics.get('stability_test_passed', False) and
            not any('error' in result for result in [performance_results, quality_metrics, stability_metrics, performance_metrics])
        )

        report = {
            'validation_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'overall_validation_passed': overall_success,
            'configuration': config_info,
            'performance_results': performance_results,
            'quality_metrics': quality_metrics,
            'stability_metrics': stability_metrics,
            'performance_metrics': performance_metrics,
            'system_info': {
                'cpu_count': psutil.cpu_count(),
                'memory_total_gb': psutil.virtual_memory().total / (1024**3),
                'platform': sys.platform
            }
        }

        print(f"Overall Validation: {'PASSED' if overall_success else 'FAILED'}")

        return report

    def save_validation_report(self, report: Dict[str, any]):
        """Save validation report to file"""
        output_dir = Path("tests/validation_results")
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime('%Y%m%d_%H%M%S')
        report_file = output_dir / f"optimized_system_validation_{timestamp}.txt"

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("VoiceFlow Optimized System Validation Report\n")
            f.write("=" * 50 + "\n\n")

            f.write(f"Validation Date: {report['validation_timestamp']}\n")
            f.write(f"Overall Status: {'PASSED' if report['overall_validation_passed'] else 'FAILED'}\n\n")

            f.write("Current Configuration:\n")
            f.write("-" * 25 + "\n")
            for key, value in report['configuration'].items():
                f.write(f"{key}: {value}\n")
            f.write("\n")

            if 'performance_metrics' in report and 'error' not in report['performance_metrics']:
                f.write("Performance Metrics:\n")
                f.write("-" * 20 + "\n")
                metrics = report['performance_metrics']
                f.write(f"Average Speed Factor: {metrics['avg_speed_factor']:.1f}x realtime\n")
                f.write(f"Maximum Speed Factor: {metrics['max_speed_factor']:.1f}x realtime\n")
                f.write(f"Target (12x+) Met: {'YES' if metrics['performance_target_met'] else 'NO'}\n")
                f.write(f"Average Memory Usage: {metrics['avg_memory_delta']:.1f}MB\n\n")

            if 'quality_metrics' in report and 'error' not in report['quality_metrics']:
                f.write("Quality Metrics:\n")
                f.write("-" * 15 + "\n")
                quality = report['quality_metrics']
                f.write(f"Quality Score: {quality['quality_score']:.1f}%\n")
                f.write(f"Quality Validation: {'PASSED' if quality['quality_validation_passed'] else 'FAILED'}\n\n")

            if 'stability_metrics' in report and 'error' not in report['stability_metrics']:
                f.write("Stability Metrics:\n")
                f.write("-" * 18 + "\n")
                stability = report['stability_metrics']
                f.write(f"Consecutive Successful Runs: {stability['consecutive_successful_runs']}/5\n")
                f.write(f"Stability Test: {'PASSED' if stability['stability_test_passed'] else 'FAILED'}\n\n")

            f.write("System Information:\n")
            f.write("-" * 19 + "\n")
            f.write(f"CPU Cores: {report['system_info']['cpu_count']}\n")
            f.write(f"Total Memory: {report['system_info']['memory_total_gb']:.1f}GB\n")
            f.write(f"Platform: {report['system_info']['platform']}\n")

        print(f"\nValidation report saved to: {report_file}")
        return report_file

def main():
    """Execute optimized system validation"""
    print("VoiceFlow Optimized System Validation")
    print("=" * 50)
    print("Validating current optimized configuration:")
    print("- Lock-free Model Access: ENABLED")
    print("- Smart Audio Validation: ENABLED (5% sampling)")
    print("- Memory Pooling: DISABLED")
    print("- Chunked Processing: DISABLED")
    print("=" * 50)

    validator = OptimizedSystemValidator()

    try:
        # Step 1: Validate current configuration
        config_info = validator.validate_current_configuration()

        # Step 2: Run performance validation
        performance_results = validator.run_performance_validation()

        # Step 3: Run quality validation
        quality_metrics = validator.run_quality_validation(performance_results)

        # Step 4: Run stability validation
        stability_metrics = validator.run_stability_validation()

        # Step 5: Calculate performance metrics
        performance_metrics = validator.calculate_performance_metrics(performance_results)

        # Step 6: Generate comprehensive report
        report = validator.generate_validation_report(
            config_info, performance_results, quality_metrics,
            stability_metrics, performance_metrics
        )

        # Step 7: Save report
        report_file = validator.save_validation_report(report)

        # Summary
        print("\n" + "=" * 50)
        print("VALIDATION COMPLETE")
        print("=" * 50)

        if report['overall_validation_passed']:
            print("✓ VALIDATION PASSED - Optimized system meets all requirements")
        else:
            print("✗ VALIDATION FAILED - Issues detected with optimized system")

        if 'performance_metrics' in report and 'error' not in report['performance_metrics']:
            avg_speed = report['performance_metrics']['avg_speed_factor']
            target_met = report['performance_metrics']['performance_target_met']
            print(f"Performance: {avg_speed:.1f}x realtime ({'TARGET MET' if target_met else 'BELOW TARGET'})")

        if 'quality_metrics' in report and 'error' not in report['quality_metrics']:
            quality_passed = report['quality_metrics']['quality_validation_passed']
            print(f"Quality: {'MAINTAINED' if quality_passed else 'DEGRADED'}")

        if 'stability_metrics' in report and 'error' not in report['stability_metrics']:
            stability_passed = report['stability_metrics']['stability_test_passed']
            print(f"Stability: {'STABLE' if stability_passed else 'UNSTABLE'}")

        return 0 if report['overall_validation_passed'] else 1

    except Exception as e:
        print(f"\nValidation failed with error: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())