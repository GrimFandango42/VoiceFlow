"""
VoiceFlow Performance Comparison Framework
==========================================

Compare performance before and after stability improvements to quantify
the impact of aggressive model reloading and CPU-only configuration.

This module provides:
1. Performance baseline measurement
2. Before/after comparison analysis
3. Regression detection
4. Performance trend analysis
"""

import time
import json
import logging
import statistics
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import numpy as np

from test_transcription_performance import PerformanceTester, PerformanceMetrics, Config

logger = logging.getLogger(__name__)

@dataclass
class ConfigurationProfile:
    """Performance testing configuration profile"""
    name: str
    description: str
    config_overrides: Dict[str, Any]
    expected_characteristics: List[str]

@dataclass
class ComparisonResult:
    """Results of performance comparison between two configurations"""
    baseline_name: str
    comparison_name: str
    speed_factor_change: float  # Positive = improvement, negative = regression
    memory_usage_change: float  # MB difference
    latency_change: float  # ms difference
    cpu_usage_change: float  # % difference
    error_rate_change: float  # % difference
    stability_score_change: float  # Composite stability metric
    regression_detected: bool
    performance_summary: str

class PerformanceComparator:
    """Compare performance between different configuration profiles"""

    def __init__(self):
        self.test_profiles = self._create_test_profiles()
        self.baseline_results: Optional[Dict[str, Any]] = None
        self.comparison_results: Dict[str, Dict[str, Any]] = {}

    def _create_test_profiles(self) -> Dict[str, ConfigurationProfile]:
        """Create standard test configuration profiles"""
        profiles = {}

        # Original high-performance configuration (before stability fixes)
        profiles['original_optimized'] = ConfigurationProfile(
            name="Original Optimized",
            description="High-performance configuration before stability fixes",
            config_overrides={
                'device': 'cpu',  # Keep CPU for fair comparison
                'compute_type': 'int8',
                'max_transcriptions_before_reload': 50,  # Much higher reload interval
                'enable_lockfree_model_access': True,  # More optimizations
                'enable_ultra_fast_mode_bypass': True,
                'enable_memory_pooling': True,
                'enable_chunked_long_audio': True,
                'preload_model_on_startup': True,
                'enable_optimized_audio_validation': True,
                'audio_validation_sample_rate': 0.01,  # More aggressive sampling
                'skip_buffer_integrity_checks': True,  # Skip some safety checks
                'minimal_segment_processing': True,
                'disable_fallback_detection': True,
                'ultra_fast_mode': True
            },
            expected_characteristics=[
                "Higher speed factor (faster processing)",
                "Lower memory usage per transcription",
                "Potentially higher error rates",
                "Risk of stuck transcriptions",
                "Less aggressive safety checks"
            ]
        )

        # Current stability-first configuration (after fixes)
        profiles['stability_focused'] = ConfigurationProfile(
            name="Stability Focused",
            description="Current stability-first configuration with aggressive model reloading",
            config_overrides={
                'device': 'cpu',
                'compute_type': 'int8',
                'max_transcriptions_before_reload': 2,  # Very aggressive reloading
                'enable_lockfree_model_access': False,  # Disable for stability
                'enable_ultra_fast_mode_bypass': False,
                'enable_memory_pooling': False,
                'enable_chunked_long_audio': False,
                'preload_model_on_startup': False,
                'enable_optimized_audio_validation': True,
                'audio_validation_sample_rate': 0.05,  # Conservative sampling
                'skip_buffer_integrity_checks': False,  # Keep safety checks
                'minimal_segment_processing': False,
                'disable_fallback_detection': False,
                'ultra_fast_mode': False,
                'vad_filter': False,  # Ensure VAD is disabled
                'beam_size': 1,
                'temperature': 0.0
            },
            expected_characteristics=[
                "Lower speed factor due to frequent reloading",
                "Higher memory usage from model reinitialization",
                "Very low error rates",
                "No stuck transcriptions",
                "Consistent performance over time"
            ]
        )

        # Balanced configuration (compromise between speed and stability)
        profiles['balanced'] = ConfigurationProfile(
            name="Balanced",
            description="Balanced configuration with moderate stability measures",
            config_overrides={
                'device': 'cpu',
                'compute_type': 'int8',
                'max_transcriptions_before_reload': 5,  # Moderate reloading
                'enable_lockfree_model_access': False,
                'enable_ultra_fast_mode_bypass': False,
                'enable_memory_pooling': True,  # Some optimizations enabled
                'enable_chunked_long_audio': True,
                'preload_model_on_startup': False,
                'enable_optimized_audio_validation': True,
                'audio_validation_sample_rate': 0.03,  # Moderate sampling
                'skip_buffer_integrity_checks': False,
                'minimal_segment_processing': True,
                'disable_fallback_detection': True,
                'ultra_fast_mode': False,
                'vad_filter': False,
                'beam_size': 1,
                'temperature': 0.0
            },
            expected_characteristics=[
                "Moderate speed factor",
                "Controlled memory usage",
                "Low error rates",
                "Good stability",
                "Balanced performance characteristics"
            ]
        )

        # GPU comparison (if available)
        profiles['gpu_optimized'] = ConfigurationProfile(
            name="GPU Optimized",
            description="GPU-accelerated configuration for performance comparison",
            config_overrides={
                'device': 'cuda',
                'compute_type': 'float16',
                'max_transcriptions_before_reload': 10,
                'enable_lockfree_model_access': True,
                'enable_ultra_fast_mode_bypass': True,
                'enable_memory_pooling': True,
                'enable_chunked_long_audio': True,
                'preload_model_on_startup': True,
                'enable_optimized_audio_validation': True,
                'audio_validation_sample_rate': 0.01,
                'skip_buffer_integrity_checks': False,  # Keep some safety
                'minimal_segment_processing': True,
                'disable_fallback_detection': True,
                'ultra_fast_mode': False,  # GPU doesn't need ultra mode
                'vad_filter': False,
                'beam_size': 5,  # GPU can handle larger beam
                'temperature': 0.0
            },
            expected_characteristics=[
                "Highest speed factor",
                "Higher memory usage (GPU memory)",
                "Good quality with larger beam size",
                "Potential GPU-specific issues",
                "Best performance if GPU available"
            ]
        )

        return profiles

    def create_config_from_profile(self, profile: ConfigurationProfile, base_config: Config) -> Config:
        """Create a Config object from a profile and base configuration"""
        # Start with base config
        config_dict = asdict(base_config)

        # Apply profile overrides
        config_dict.update(profile.config_overrides)

        # Create new Config object
        return Config(**config_dict)

    def run_profile_comparison(self, baseline_profile: str, comparison_profiles: List[str],
                             test_iterations: int = 5) -> Dict[str, ComparisonResult]:
        """Run comprehensive performance comparison between profiles"""
        logger.info(f"Starting profile comparison with baseline: {baseline_profile}")

        results = {}

        # Create base configuration
        base_config = Config()

        # Test baseline profile first
        logger.info(f"Testing baseline profile: {baseline_profile}")
        baseline_config = self.create_config_from_profile(
            self.test_profiles[baseline_profile], base_config
        )
        baseline_results = self._run_profile_test(baseline_config, baseline_profile, test_iterations)
        self.baseline_results = baseline_results

        # Test comparison profiles
        for profile_name in comparison_profiles:
            if profile_name == baseline_profile:
                continue

            logger.info(f"Testing comparison profile: {profile_name}")

            try:
                comparison_config = self.create_config_from_profile(
                    self.test_profiles[profile_name], base_config
                )
                comparison_results = self._run_profile_test(comparison_config, profile_name, test_iterations)
                self.comparison_results[profile_name] = comparison_results

                # Calculate comparison metrics
                comparison = self._calculate_comparison(baseline_results, comparison_results,
                                                     baseline_profile, profile_name)
                results[profile_name] = comparison

            except Exception as e:
                logger.error(f"Failed to test profile {profile_name}: {e}")
                # Create error result
                results[profile_name] = ComparisonResult(
                    baseline_name=baseline_profile,
                    comparison_name=profile_name,
                    speed_factor_change=0,
                    memory_usage_change=0,
                    latency_change=0,
                    cpu_usage_change=0,
                    error_rate_change=0,
                    stability_score_change=0,
                    regression_detected=True,
                    performance_summary=f"Test failed: {str(e)}"
                )

        return results

    def _run_profile_test(self, config: Config, profile_name: str, iterations: int) -> Dict[str, Any]:
        """Run performance test for a specific profile"""
        logger.info(f"Running {iterations} test iterations for profile: {profile_name}")

        # Run multiple iterations and aggregate results
        all_results = []

        for i in range(iterations):
            logger.info(f"Profile {profile_name} iteration {i+1}/{iterations}")

            try:
                # Create fresh tester for each iteration
                tester = PerformanceTester(config)

                # Run a subset of tests for comparison (focus on key metrics)
                asr_instance = tester.create_asr_instance(enhanced=False)

                # Speed benchmark
                speed_results = tester.benchmark_transcription_speed(asr_instance, f"{profile_name}_iter_{i}")

                # Model reload test (smaller scale for comparison)
                reload_session = tester.test_model_reload_performance(asr_instance, num_transcriptions=5)

                # Latency test
                latency_results = tester.test_latency_from_hotkey(asr_instance, num_tests=3)

                iteration_results = {
                    'iteration': i,
                    'speed_results': [r.__dict__ for r in speed_results],
                    'reload_session': reload_session.__dict__,
                    'latency_results': [r.__dict__ for r in latency_results],
                    'summary': tester.generate_performance_summary()
                }

                all_results.append(iteration_results)

            except Exception as e:
                logger.error(f"Iteration {i+1} failed for profile {profile_name}: {e}")
                # Record failed iteration
                all_results.append({
                    'iteration': i,
                    'error': str(e),
                    'failed': True
                })

        # Aggregate results across iterations
        aggregated = self._aggregate_iteration_results(all_results, profile_name)
        return aggregated

    def _aggregate_iteration_results(self, results: List[Dict[str, Any]], profile_name: str) -> Dict[str, Any]:
        """Aggregate results across multiple test iterations"""
        successful_results = [r for r in results if not r.get('failed', False)]

        if not successful_results:
            return {
                'profile_name': profile_name,
                'error': 'All iterations failed',
                'total_iterations': len(results),
                'successful_iterations': 0
            }

        # Aggregate key metrics
        speed_factors = []
        memory_growths = []
        latencies = []
        cpu_usages = []
        error_rates = []

        for result in successful_results:
            summary = result.get('summary', {})

            if 'speed_factor' in summary and summary['speed_factor'].get('mean', 0) > 0:
                speed_factors.append(summary['speed_factor']['mean'])

            if 'memory_usage' in summary:
                memory_growths.append(summary['memory_usage'].get('max_growth_mb', 0))

            if 'latency' in summary and summary['latency']:
                latencies.append(summary['latency'].get('mean_ms', 0))

            if 'cpu_usage' in summary:
                cpu_usages.append(summary['cpu_usage'].get('mean_percent', 0))

            error_rates.append(summary.get('error_rate', 0))

        aggregated = {
            'profile_name': profile_name,
            'total_iterations': len(results),
            'successful_iterations': len(successful_results),
            'aggregated_metrics': {
                'speed_factor': {
                    'mean': statistics.mean(speed_factors) if speed_factors else 0,
                    'std': statistics.stdev(speed_factors) if len(speed_factors) > 1 else 0,
                    'min': min(speed_factors) if speed_factors else 0,
                    'max': max(speed_factors) if speed_factors else 0
                },
                'memory_growth_mb': {
                    'mean': statistics.mean(memory_growths) if memory_growths else 0,
                    'std': statistics.stdev(memory_growths) if len(memory_growths) > 1 else 0,
                    'max': max(memory_growths) if memory_growths else 0
                },
                'latency_ms': {
                    'mean': statistics.mean(latencies) if latencies else 0,
                    'std': statistics.stdev(latencies) if len(latencies) > 1 else 0,
                    'max': max(latencies) if latencies else 0
                } if latencies else None,
                'cpu_percent': {
                    'mean': statistics.mean(cpu_usages) if cpu_usages else 0,
                    'max': max(cpu_usages) if cpu_usages else 0
                },
                'error_rate': {
                    'mean': statistics.mean(error_rates) if error_rates else 0,
                    'max': max(error_rates) if error_rates else 0
                }
            },
            'raw_results': results
        }

        return aggregated

    def _calculate_comparison(self, baseline: Dict[str, Any], comparison: Dict[str, Any],
                            baseline_name: str, comparison_name: str) -> ComparisonResult:
        """Calculate performance comparison between baseline and comparison results"""

        baseline_metrics = baseline.get('aggregated_metrics', {})
        comparison_metrics = comparison.get('aggregated_metrics', {})

        # Calculate changes (positive = improvement for speed, negative = regression)
        speed_change = (comparison_metrics.get('speed_factor', {}).get('mean', 0) -
                       baseline_metrics.get('speed_factor', {}).get('mean', 0))

        memory_change = (comparison_metrics.get('memory_growth_mb', {}).get('mean', 0) -
                        baseline_metrics.get('memory_growth_mb', {}).get('mean', 0))

        # Latency comparison (negative = improvement)
        baseline_latency = baseline_metrics.get('latency_ms', {}).get('mean', 0) if baseline_metrics.get('latency_ms') else 0
        comparison_latency = comparison_metrics.get('latency_ms', {}).get('mean', 0) if comparison_metrics.get('latency_ms') else 0
        latency_change = comparison_latency - baseline_latency

        cpu_change = (comparison_metrics.get('cpu_percent', {}).get('mean', 0) -
                     baseline_metrics.get('cpu_percent', {}).get('mean', 0))

        error_rate_change = (comparison_metrics.get('error_rate', {}).get('mean', 0) -
                           baseline_metrics.get('error_rate', {}).get('mean', 0))

        # Calculate stability score change (composite metric)
        baseline_stability = self._calculate_stability_score(baseline_metrics)
        comparison_stability = self._calculate_stability_score(comparison_metrics)
        stability_change = comparison_stability - baseline_stability

        # Detect significant regressions
        regression_detected = (
            speed_change < -0.5 or  # >0.5x speed loss
            memory_change > 50 or   # >50MB memory increase
            latency_change > 500 or # >500ms latency increase
            error_rate_change > 0.1 # >10% error rate increase
        )

        # Generate performance summary
        summary = self._generate_comparison_summary(
            speed_change, memory_change, latency_change, cpu_change,
            error_rate_change, stability_change, regression_detected
        )

        return ComparisonResult(
            baseline_name=baseline_name,
            comparison_name=comparison_name,
            speed_factor_change=speed_change,
            memory_usage_change=memory_change,
            latency_change=latency_change,
            cpu_usage_change=cpu_change,
            error_rate_change=error_rate_change,
            stability_score_change=stability_change,
            regression_detected=regression_detected,
            performance_summary=summary
        )

    def _calculate_stability_score(self, metrics: Dict[str, Any]) -> float:
        """Calculate composite stability score (higher = more stable)"""
        # Factors that contribute to stability (normalized 0-1)

        # Low error rate (good)
        error_score = max(0, 1 - metrics.get('error_rate', {}).get('mean', 0) * 10)  # Scale error rate

        # Consistent speed (low variance)
        speed_std = metrics.get('speed_factor', {}).get('std', 0)
        consistency_score = max(0, 1 - speed_std / 2)  # Normalize std dev

        # Reasonable memory usage (not growing too much)
        memory_growth = metrics.get('memory_growth_mb', {}).get('mean', 0)
        memory_score = max(0, 1 - memory_growth / 100)  # Normalize to 100MB

        # Low CPU usage
        cpu_usage = metrics.get('cpu_percent', {}).get('mean', 0)
        cpu_score = max(0, 1 - cpu_usage / 100)  # Normalize to 100%

        # Weighted average
        stability_score = (
            error_score * 0.4 +      # Error rate most important
            consistency_score * 0.3 + # Speed consistency important
            memory_score * 0.2 +      # Memory usage
            cpu_score * 0.1           # CPU usage least important
        )

        return stability_score

    def _generate_comparison_summary(self, speed_change: float, memory_change: float,
                                   latency_change: float, cpu_change: float,
                                   error_rate_change: float, stability_change: float,
                                   regression_detected: bool) -> str:
        """Generate human-readable comparison summary"""

        summary_parts = []

        # Speed analysis
        if abs(speed_change) > 0.1:
            if speed_change > 0:
                summary_parts.append(f"Speed improved by {speed_change:.2f}x")
            else:
                summary_parts.append(f"Speed degraded by {abs(speed_change):.2f}x")
        else:
            summary_parts.append("Speed relatively unchanged")

        # Memory analysis
        if abs(memory_change) > 10:
            if memory_change > 0:
                summary_parts.append(f"Memory usage increased by {memory_change:.1f}MB")
            else:
                summary_parts.append(f"Memory usage decreased by {abs(memory_change):.1f}MB")

        # Latency analysis
        if abs(latency_change) > 100:
            if latency_change > 0:
                summary_parts.append(f"Latency increased by {latency_change:.0f}ms")
            else:
                summary_parts.append(f"Latency decreased by {abs(latency_change):.0f}ms")

        # Error rate analysis
        if abs(error_rate_change) > 0.01:
            if error_rate_change > 0:
                summary_parts.append(f"Error rate increased by {error_rate_change:.1%}")
            else:
                summary_parts.append(f"Error rate decreased by {abs(error_rate_change):.1%}")

        # Stability analysis
        if abs(stability_change) > 0.1:
            if stability_change > 0:
                summary_parts.append(f"Stability improved (score +{stability_change:.2f})")
            else:
                summary_parts.append(f"Stability decreased (score {stability_change:.2f})")

        # Overall assessment
        if regression_detected:
            summary_parts.append("⚠️ SIGNIFICANT REGRESSION DETECTED")
        elif stability_change > 0.2:
            summary_parts.append("✅ Overall improvement in stability")
        elif speed_change > 0.5:
            summary_parts.append("✅ Significant performance improvement")
        else:
            summary_parts.append("📊 Mixed results - review detailed metrics")

        return "; ".join(summary_parts)

    def save_comparison_results(self, results: Dict[str, ComparisonResult],
                              output_dir: str = "comparison_results") -> Path:
        """Save comparison results to file"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        results_file = output_path / f"performance_comparison_{timestamp}.json"

        # Convert results to serializable format
        serializable_results = {}
        for profile_name, comparison in results.items():
            serializable_results[profile_name] = asdict(comparison)

        # Include baseline and comparison data
        full_results = {
            'timestamp': timestamp,
            'baseline_results': self.baseline_results,
            'comparison_results': self.comparison_results,
            'comparisons': serializable_results,
            'test_profiles': {name: asdict(profile) for name, profile in self.test_profiles.items()}
        }

        with open(results_file, 'w') as f:
            json.dump(full_results, f, indent=2, default=str)

        logger.info(f"Comparison results saved to {results_file}")
        return results_file

def main():
    """Run performance comparison analysis"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    comparator = PerformanceComparator()

    # Run comparison between different profiles
    baseline = 'stability_focused'  # Current implementation
    comparison_profiles = ['original_optimized', 'balanced']

    # Add GPU profile if CUDA available
    try:
        import torch
        if torch.cuda.is_available():
            comparison_profiles.append('gpu_optimized')
            logger.info("GPU detected - including GPU optimization profile")
    except ImportError:
        logger.info("PyTorch not available - skipping GPU profile")

    logger.info(f"Running comparison with baseline: {baseline}")
    logger.info(f"Comparison profiles: {comparison_profiles}")

    results = comparator.run_profile_comparison(
        baseline_profile=baseline,
        comparison_profiles=comparison_profiles,
        test_iterations=3  # Reduce for faster testing
    )

    # Save results
    results_file = comparator.save_comparison_results(results)

    # Print summary
    print("\n" + "="*80)
    print("PERFORMANCE COMPARISON RESULTS")
    print("="*80)

    for profile_name, comparison in results.items():
        print(f"\n{profile_name.upper()} vs {baseline.upper()}:")
        print(f"  {comparison.performance_summary}")
        print(f"  Speed change: {comparison.speed_factor_change:+.2f}x")
        print(f"  Memory change: {comparison.memory_usage_change:+.1f}MB")
        if comparison.latency_change != 0:
            print(f"  Latency change: {comparison.latency_change:+.0f}ms")
        print(f"  Stability change: {comparison.stability_score_change:+.2f}")

        if comparison.regression_detected:
            print(f"  ⚠️  REGRESSION DETECTED")
        else:
            print(f"  ✅ No significant regressions")

    print(f"\nDetailed results saved to: {results_file}")

    return results

if __name__ == "__main__":
    main()