"""
Noise Tolerance Benchmarking Framework for VoiceFlow
Comprehensive quality assessment and performance benchmarking tools.
"""

import numpy as np
import time
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime, timedelta
import threading
import logging
from collections import defaultdict


class BenchmarkCategory(Enum):
    """Benchmark test categories"""
    SNR_TOLERANCE = "snr_tolerance"
    ENVIRONMENT_ADAPTATION = "environment_adaptation"
    NOISE_REDUCTION_EFFECTIVENESS = "noise_reduction_effectiveness"
    VAD_ACCURACY = "vad_accuracy"
    PROCESSING_LATENCY = "processing_latency"
    RESOURCE_USAGE = "resource_usage"
    LONG_TERM_STABILITY = "long_term_stability"
    REAL_TIME_PERFORMANCE = "real_time_performance"


class TestResult(Enum):
    """Test result classifications"""
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    FAILED = "failed"


@dataclass
class BenchmarkMetrics:
    """Comprehensive benchmarking metrics"""
    category: BenchmarkCategory
    test_name: str
    timestamp: float
    
    # Performance metrics
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    
    # Quality metrics
    snr_improvement_db: float
    quality_score: float
    noise_reduction_factor: float
    
    # Efficiency metrics
    processing_time_ms: float
    cpu_usage_percent: float
    memory_usage_mb: float
    
    # Robustness metrics
    false_positive_rate: float
    false_negative_rate: float
    stability_score: float
    
    # Additional metrics
    confidence_score: float
    test_conditions: Dict[str, Any]
    raw_data: Optional[Dict[str, Any]] = None


@dataclass
class BenchmarkReport:
    """Comprehensive benchmark report"""
    report_id: str
    generation_time: datetime
    system_config: Dict[str, Any]
    test_duration_hours: float
    
    # Overall scores
    overall_score: float
    category_scores: Dict[BenchmarkCategory, float]
    
    # Detailed results
    test_results: List[BenchmarkMetrics]
    
    # Summary statistics
    total_tests: int
    passed_tests: int
    failed_tests: int
    
    # Performance trends
    performance_trends: Dict[str, List[float]]
    
    # Recommendations
    recommendations: List[str]
    identified_issues: List[str]


class NoiseToleranceBenchmark:
    """
    Comprehensive noise tolerance benchmarking system
    """
    
    def __init__(self, sample_rate: int = 16000, 
                 output_dir: Optional[Path] = None):
        self.sample_rate = sample_rate
        
        # Setup output directory
        if output_dir is None:
            output_dir = Path.home() / ".voiceflow" / "benchmarks"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize database for storing results
        self.db_path = self.output_dir / "benchmark_results.db"
        self.init_database()
        
        # Test results storage
        self.test_results: List[BenchmarkMetrics] = []
        
        # Benchmark configuration
        self.test_configurations = {
            BenchmarkCategory.SNR_TOLERANCE: {
                'snr_range': list(range(-10, 21, 5)),  # -10dB to 20dB
                'noise_types': ['white', 'pink', 'office', 'vehicle', 'outdoor'],
                'test_duration': 5.0  # seconds
            },
            BenchmarkCategory.ENVIRONMENT_ADAPTATION: {
                'environments': ['quiet', 'home', 'office', 'vehicle', 'outdoor', 'noisy'],
                'adaptation_time_limit': 2.0,  # seconds
                'test_samples': 10
            },
            BenchmarkCategory.NOISE_REDUCTION_EFFECTIVENESS: {
                'noise_types': ['stationary', 'non_stationary', 'impulsive'],
                'reduction_targets': [3, 6, 10, 15],  # dB improvement targets
                'quality_preservation': 0.8  # Minimum quality retention
            },
            BenchmarkCategory.VAD_ACCURACY: {
                'speech_to_noise_ratios': [0.3, 0.5, 0.7],  # Speech activity ratios
                'noise_conditions': ['quiet', 'moderate', 'noisy'],
                'temporal_patterns': ['continuous', 'burst', 'mixed']
            },
            BenchmarkCategory.PROCESSING_LATENCY: {
                'frame_sizes': [512, 1024, 2048],
                'processing_methods': ['basic', 'advanced', 'comprehensive'],
                'latency_targets': [10, 25, 50]  # milliseconds
            }
        }
        
        # Load test dependencies
        self._load_dependencies()
        
    def _load_dependencies(self):
        """Load required testing dependencies"""
        try:
            from .noise_simulation import NoiseGenerator, SpeechSimulator, SNRTestSignalGenerator
            from ..core.noise_processing import create_noise_processor
            from .audio_quality_monitor import create_quality_monitor
            from ..core.dual_vad_system import create_dual_vad_system
            
            self.noise_gen = NoiseGenerator(self.sample_rate)
            self.speech_sim = SpeechSimulator(self.sample_rate)
            self.snr_test_gen = SNRTestSignalGenerator(self.sample_rate)
            
            # Initialize processing systems
            self.noise_analyzer, self.vad_manager, self.noise_reducer, self.noise_gate = create_noise_processor()
            self.quality_monitor = create_quality_monitor()
            self.dual_vad = create_dual_vad_system(self.sample_rate)
            
            self.dependencies_loaded = True
            print("[BENCHMARK] ✅ All dependencies loaded successfully")
            
        except ImportError as e:
            self.dependencies_loaded = False
            print(f"[BENCHMARK] ❌ Failed to load dependencies: {e}")
    
    def init_database(self):
        """Initialize benchmark results database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS benchmark_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL,
                category TEXT NOT NULL,
                test_name TEXT NOT NULL,
                timestamp REAL NOT NULL,
                accuracy REAL,
                precision_val REAL,
                recall_val REAL,
                f1_score REAL,
                snr_improvement_db REAL,
                quality_score REAL,
                noise_reduction_factor REAL,
                processing_time_ms REAL,
                cpu_usage_percent REAL,
                memory_usage_mb REAL,
                false_positive_rate REAL,
                false_negative_rate REAL,
                stability_score REAL,
                confidence_score REAL,
                test_conditions TEXT,
                raw_data TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS benchmark_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE NOT NULL,
                generation_time TEXT NOT NULL,
                system_config TEXT,
                test_duration_hours REAL,
                overall_score REAL,
                total_tests INTEGER,
                passed_tests INTEGER,
                failed_tests INTEGER,
                recommendations TEXT,
                identified_issues TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def run_snr_tolerance_benchmark(self) -> List[BenchmarkMetrics]:
        """Run SNR tolerance benchmarking"""
        if not self.dependencies_loaded:
            return []
        
        print("[BENCHMARK] Running SNR tolerance tests...")
        results = []
        config = self.test_configurations[BenchmarkCategory.SNR_TOLERANCE]
        
        # Generate clean speech reference
        clean_speech = self.speech_sim.generate_synthetic_speech(config['test_duration'])
        
        for noise_type in config['noise_types']:
            for snr_db in config['snr_range']:
                start_time = time.time()
                
                # Generate noisy speech
                if noise_type == 'white':
                    noise = self.noise_gen.generate_colored_noise(config['test_duration'], 0, 1.0)
                elif noise_type == 'pink':
                    noise = self.noise_gen.generate_colored_noise(config['test_duration'], -1, 1.0)
                elif noise_type == 'office':
                    from .noise_simulation import EnvironmentType
                    noise = self.noise_gen.generate_environment_noise(EnvironmentType.OPEN_OFFICE, config['test_duration'], 1.0)
                elif noise_type == 'vehicle':
                    from .noise_simulation import EnvironmentType
                    noise = self.noise_gen.generate_environment_noise(EnvironmentType.VEHICLE_INTERIOR, config['test_duration'], 1.0)
                elif noise_type == 'outdoor':
                    from .noise_simulation import EnvironmentType
                    noise = self.noise_gen.generate_environment_noise(EnvironmentType.OUTDOOR_URBAN, config['test_duration'], 1.0)
                else:
                    noise = self.noise_gen.generate_colored_noise(config['test_duration'], 0, 1.0)
                
                noisy_speech = self.snr_test_gen.add_noise_at_snr(clean_speech, noise, snr_db)
                
                # Test noise analysis
                self.noise_analyzer.add_audio_frame(noisy_speech)
                noise_profile = self.noise_analyzer.analyze_current_noise()
                
                # Test quality monitoring
                self.quality_monitor.add_audio_data(noisy_speech)
                quality_metrics = self.quality_monitor.analyzer.analyze_quality()
                
                # Calculate metrics
                if noise_profile and quality_metrics:
                    estimated_snr = noise_profile.snr_estimate
                    snr_error = abs(estimated_snr - snr_db)
                    
                    # Accuracy based on SNR estimation error
                    accuracy = max(0, 1.0 - snr_error / 20.0)
                    
                    # Quality score from monitor
                    quality_score = quality_metrics.quality_score / 100.0
                    
                    # Calculate other metrics
                    confidence = noise_profile.confidence
                    processing_time = (time.time() - start_time) * 1000
                    
                    metric = BenchmarkMetrics(
                        category=BenchmarkCategory.SNR_TOLERANCE,
                        test_name=f"snr_{snr_db}db_{noise_type}",
                        timestamp=time.time(),
                        accuracy=accuracy,
                        precision=accuracy,  # Simplified for this test
                        recall=accuracy,
                        f1_score=accuracy,
                        snr_improvement_db=0.0,  # No improvement applied
                        quality_score=quality_score,
                        noise_reduction_factor=1.0,
                        processing_time_ms=processing_time,
                        cpu_usage_percent=0.0,  # Would need system monitoring
                        memory_usage_mb=0.0,
                        false_positive_rate=max(0, (snr_error - 2) / 10),
                        false_negative_rate=max(0, (snr_error - 2) / 10),
                        stability_score=confidence,
                        confidence_score=confidence,
                        test_conditions={
                            'target_snr_db': snr_db,
                            'estimated_snr_db': estimated_snr,
                            'noise_type': noise_type,
                            'signal_duration': config['test_duration']
                        }
                    )
                    
                    results.append(metric)
        
        print(f"[BENCHMARK] ✅ SNR tolerance tests completed: {len(results)} tests")
        return results
    
    def run_noise_reduction_benchmark(self) -> List[BenchmarkMetrics]:
        """Run noise reduction effectiveness benchmarking"""
        if not self.dependencies_loaded:
            return []
        
        print("[BENCHMARK] Running noise reduction effectiveness tests...")
        results = []
        config = self.test_configurations[BenchmarkCategory.NOISE_REDUCTION_EFFECTIVENESS]
        
        clean_speech = self.speech_sim.generate_synthetic_speech(5.0)
        
        for noise_type in config['noise_types']:
            for target_improvement in config['reduction_targets']:
                start_time = time.time()
                
                # Generate appropriate noise
                if noise_type == 'stationary':
                    noise = self.noise_gen.generate_colored_noise(5.0, -1, 0.2)
                elif noise_type == 'non_stationary':
                    from .noise_simulation import EnvironmentType
                    noise = self.noise_gen.generate_environment_noise(EnvironmentType.VEHICLE_INTERIOR, 5.0, 0.2)
                else:  # impulsive
                    from .noise_simulation import ImpulseNoiseGenerator
                    impulse_gen = ImpulseNoiseGenerator(self.sample_rate)
                    noise = impulse_gen.generate_footsteps(5.0, 3.0)
                
                # Create noisy speech at 5dB SNR
                noisy_speech = self.snr_test_gen.add_noise_at_snr(clean_speech, noise, 5.0)
                
                # Apply noise reduction
                self.noise_analyzer.add_audio_frame(noisy_speech)
                noise_profile = self.noise_analyzer.analyze_current_noise()
                
                if noise_profile:
                    # Test spectral subtraction
                    reduced_speech = self.noise_reducer.spectral_subtraction(noisy_speech, noise_profile)
                    
                    # Measure improvement
                    noise_before = np.mean((noisy_speech - clean_speech) ** 2)
                    noise_after = np.mean((reduced_speech - clean_speech) ** 2)
                    
                    if noise_before > 0:
                        improvement_db = 10 * np.log10(noise_before / (noise_after + 1e-12))
                    else:
                        improvement_db = 0
                    
                    # Quality preservation check
                    speech_distortion = np.mean((reduced_speech - clean_speech) ** 2) / np.mean(clean_speech ** 2)
                    quality_preservation = max(0, 1.0 - speech_distortion)
                    
                    # Calculate effectiveness score
                    target_met = improvement_db >= target_improvement
                    quality_preserved = quality_preservation >= config['quality_preservation']
                    
                    effectiveness = (improvement_db / target_improvement) * quality_preservation
                    effectiveness = min(1.0, max(0.0, effectiveness))
                    
                    processing_time = (time.time() - start_time) * 1000
                    
                    metric = BenchmarkMetrics(
                        category=BenchmarkCategory.NOISE_REDUCTION_EFFECTIVENESS,
                        test_name=f"reduction_{noise_type}_{target_improvement}db",
                        timestamp=time.time(),
                        accuracy=effectiveness,
                        precision=effectiveness,
                        recall=effectiveness,
                        f1_score=effectiveness,
                        snr_improvement_db=improvement_db,
                        quality_score=quality_preservation,
                        noise_reduction_factor=noise_before / (noise_after + 1e-12),
                        processing_time_ms=processing_time,
                        cpu_usage_percent=0.0,
                        memory_usage_mb=0.0,
                        false_positive_rate=0.0,
                        false_negative_rate=1.0 - effectiveness if not target_met else 0.0,
                        stability_score=quality_preservation,
                        confidence_score=effectiveness,
                        test_conditions={
                            'noise_type': noise_type,
                            'target_improvement_db': target_improvement,
                            'actual_improvement_db': improvement_db,
                            'quality_preservation': quality_preservation,
                            'target_met': target_met,
                            'quality_preserved': quality_preserved
                        }
                    )
                    
                    results.append(metric)
        
        print(f"[BENCHMARK] ✅ Noise reduction tests completed: {len(results)} tests")
        return results
    
    def run_vad_accuracy_benchmark(self) -> List[BenchmarkMetrics]:
        """Run VAD accuracy benchmarking"""
        if not self.dependencies_loaded:
            return []
        
        print("[BENCHMARK] Running VAD accuracy tests...")
        results = []
        config = self.test_configurations[BenchmarkCategory.VAD_ACCURACY]
        
        for speech_ratio in config['speech_to_noise_ratios']:
            for noise_condition in config['noise_conditions']:
                for pattern in config['temporal_patterns']:
                    start_time = time.time()
                    
                    # Generate test signal with known speech/noise segments
                    total_duration = 10.0
                    speech_duration = total_duration * speech_ratio
                    noise_duration = total_duration - speech_duration
                    
                    # Create ground truth labels
                    ground_truth = []
                    test_signal = np.array([])
                    
                    if pattern == 'continuous':
                        # Continuous speech followed by noise
                        speech_seg = self.speech_sim.generate_synthetic_speech(speech_duration)
                        noise_seg = self.noise_gen.generate_colored_noise(noise_duration, -1, 0.05)
                        test_signal = np.concatenate([speech_seg, noise_seg])
                        
                        # Labels: 1 for speech, 0 for noise
                        ground_truth = [1] * len(speech_seg) + [0] * len(noise_seg)
                        
                    elif pattern == 'burst':
                        # Alternating short bursts
                        burst_duration = 0.5
                        for i in range(int(total_duration / burst_duration)):
                            if i % 2 == 0 and len(test_signal) < speech_duration * self.sample_rate:
                                # Speech burst
                                burst = self.speech_sim.generate_synthetic_speech(burst_duration)
                                ground_truth.extend([1] * len(burst))
                            else:
                                # Noise burst
                                burst = self.noise_gen.generate_colored_noise(burst_duration, -1, 0.05)
                                ground_truth.extend([0] * len(burst))
                            test_signal = np.concatenate([test_signal, burst])
                    
                    else:  # mixed
                        # Random speech and noise segments
                        remaining_time = total_duration
                        speech_budget = speech_duration
                        
                        while remaining_time > 0.1:
                            segment_duration = min(np.random.uniform(0.2, 1.0), remaining_time)
                            
                            if speech_budget > 0 and np.random.random() < 0.5:
                                # Add speech segment
                                seg_duration = min(segment_duration, speech_budget)
                                segment = self.speech_sim.generate_synthetic_speech(seg_duration)
                                ground_truth.extend([1] * len(segment))
                                speech_budget -= seg_duration
                            else:
                                # Add noise segment
                                segment = self.noise_gen.generate_colored_noise(segment_duration, -1, 0.05)
                                ground_truth.extend([0] * len(segment))
                            
                            test_signal = np.concatenate([test_signal, segment])
                            remaining_time -= segment_duration
                    
                    # Apply noise based on condition
                    if noise_condition == 'moderate':
                        noise_bg = self.noise_gen.generate_colored_noise(len(test_signal) / self.sample_rate, 0, 0.1)
                        test_signal += noise_bg
                    elif noise_condition == 'noisy':
                        noise_bg = self.noise_gen.generate_colored_noise(len(test_signal) / self.sample_rate, 0, 0.2)
                        test_signal += noise_bg
                    
                    # Run dual-VAD system
                    frame_size = int(0.025 * self.sample_rate)  # 25ms frames
                    vad_decisions = []
                    
                    for i in range(0, len(test_signal) - frame_size, frame_size):
                        frame = test_signal[i:i + frame_size]
                        result = self.dual_vad.process_frame(frame)
                        
                        # Convert decision to binary
                        if result.final_decision.value == 'speech':
                            vad_decisions.extend([1] * frame_size)
                        else:
                            vad_decisions.extend([0] * frame_size)
                    
                    # Align lengths
                    min_len = min(len(ground_truth), len(vad_decisions))
                    ground_truth = ground_truth[:min_len]
                    vad_decisions = vad_decisions[:min_len]
                    
                    # Calculate metrics
                    if len(ground_truth) > 0:
                        true_positives = sum(1 for i in range(len(ground_truth)) 
                                           if ground_truth[i] == 1 and vad_decisions[i] == 1)
                        false_positives = sum(1 for i in range(len(ground_truth)) 
                                            if ground_truth[i] == 0 and vad_decisions[i] == 1)
                        true_negatives = sum(1 for i in range(len(ground_truth)) 
                                           if ground_truth[i] == 0 and vad_decisions[i] == 0)
                        false_negatives = sum(1 for i in range(len(ground_truth)) 
                                            if ground_truth[i] == 1 and vad_decisions[i] == 0)
                        
                        accuracy = (true_positives + true_negatives) / len(ground_truth)
                        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
                        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
                        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                        
                        fpr = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0
                        fnr = false_negatives / (false_negatives + true_positives) if (false_negatives + true_positives) > 0 else 0
                        
                        processing_time = (time.time() - start_time) * 1000
                        
                        metric = BenchmarkMetrics(
                            category=BenchmarkCategory.VAD_ACCURACY,
                            test_name=f"vad_{speech_ratio}_{noise_condition}_{pattern}",
                            timestamp=time.time(),
                            accuracy=accuracy,
                            precision=precision,
                            recall=recall,
                            f1_score=f1_score,
                            snr_improvement_db=0.0,
                            quality_score=accuracy,
                            noise_reduction_factor=1.0,
                            processing_time_ms=processing_time,
                            cpu_usage_percent=0.0,
                            memory_usage_mb=0.0,
                            false_positive_rate=fpr,
                            false_negative_rate=fnr,
                            stability_score=f1_score,
                            confidence_score=accuracy,
                            test_conditions={
                                'speech_ratio': speech_ratio,
                                'noise_condition': noise_condition,
                                'temporal_pattern': pattern,
                                'total_samples': len(ground_truth),
                                'true_positives': true_positives,
                                'false_positives': false_positives,
                                'true_negatives': true_negatives,
                                'false_negatives': false_negatives
                            }
                        )
                        
                        results.append(metric)
        
        print(f"[BENCHMARK] ✅ VAD accuracy tests completed: {len(results)} tests")
        return results
    
    def run_comprehensive_benchmark(self) -> BenchmarkReport:
        """Run complete benchmarking suite"""
        print("[BENCHMARK] 🚀 Starting comprehensive noise tolerance benchmark...")
        start_time = time.time()
        
        report_id = f"benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        all_results = []
        
        # Run individual benchmark categories
        benchmark_functions = [
            self.run_snr_tolerance_benchmark,
            self.run_noise_reduction_benchmark,
            self.run_vad_accuracy_benchmark
        ]
        
        for benchmark_func in benchmark_functions:
            try:
                results = benchmark_func()
                all_results.extend(results)
                self.test_results.extend(results)
            except Exception as e:
                print(f"[BENCHMARK] ⚠️  Error in {benchmark_func.__name__}: {e}")
        
        # Calculate overall scores
        category_scores = {}
        for category in BenchmarkCategory:
            category_results = [r for r in all_results if r.category == category]
            if category_results:
                category_scores[category] = np.mean([r.accuracy for r in category_results])
        
        overall_score = np.mean(list(category_scores.values())) if category_scores else 0.0
        
        # Generate recommendations
        recommendations = self._generate_recommendations(all_results)
        identified_issues = self._identify_issues(all_results)
        
        # Create report
        report = BenchmarkReport(
            report_id=report_id,
            generation_time=datetime.now(),
            system_config={
                'sample_rate': self.sample_rate,
                'dependencies_loaded': self.dependencies_loaded,
                'total_categories': len(benchmark_functions)
            },
            test_duration_hours=(time.time() - start_time) / 3600,
            overall_score=overall_score,
            category_scores=category_scores,
            test_results=all_results,
            total_tests=len(all_results),
            passed_tests=len([r for r in all_results if r.accuracy > 0.7]),
            failed_tests=len([r for r in all_results if r.accuracy <= 0.3]),
            performance_trends={},  # Would be populated with historical data
            recommendations=recommendations,
            identified_issues=identified_issues
        )
        
        # Save to database
        self._save_report(report)
        
        # Generate summary
        self._print_benchmark_summary(report)
        
        print(f"[BENCHMARK] ✅ Comprehensive benchmark completed in {report.test_duration_hours:.2f} hours")
        return report
    
    def _generate_recommendations(self, results: List[BenchmarkMetrics]) -> List[str]:
        """Generate recommendations based on benchmark results"""
        recommendations = []
        
        # Analyze SNR tolerance
        snr_results = [r for r in results if r.category == BenchmarkCategory.SNR_TOLERANCE]
        if snr_results:
            avg_snr_accuracy = np.mean([r.accuracy for r in snr_results])
            if avg_snr_accuracy < 0.7:
                recommendations.append("Consider improving SNR estimation algorithms")
            
            # Check performance at low SNR
            low_snr_results = [r for r in snr_results if 'target_snr_db' in r.test_conditions and r.test_conditions['target_snr_db'] < 5]
            if low_snr_results and np.mean([r.accuracy for r in low_snr_results]) < 0.5:
                recommendations.append("Enhance noise processing for low SNR conditions")
        
        # Analyze noise reduction
        reduction_results = [r for r in results if r.category == BenchmarkCategory.NOISE_REDUCTION_EFFECTIVENESS]
        if reduction_results:
            avg_improvement = np.mean([r.snr_improvement_db for r in reduction_results])
            if avg_improvement < 3.0:
                recommendations.append("Noise reduction algorithms need improvement")
            
            quality_scores = [r.quality_score for r in reduction_results]
            if np.mean(quality_scores) < 0.8:
                recommendations.append("Balance noise reduction with speech quality preservation")
        
        # Analyze VAD performance
        vad_results = [r for r in results if r.category == BenchmarkCategory.VAD_ACCURACY]
        if vad_results:
            avg_f1 = np.mean([r.f1_score for r in vad_results])
            if avg_f1 < 0.8:
                recommendations.append("Consider tuning VAD parameters for better accuracy")
            
            high_fpr_results = [r for r in vad_results if r.false_positive_rate > 0.2]
            if high_fpr_results:
                recommendations.append("Reduce false positive rate in VAD system")
        
        # General recommendations
        processing_times = [r.processing_time_ms for r in results]
        if np.mean(processing_times) > 50:
            recommendations.append("Optimize processing algorithms for better real-time performance")
        
        if not recommendations:
            recommendations.append("System performance is within acceptable ranges")
        
        return recommendations
    
    def _identify_issues(self, results: List[BenchmarkMetrics]) -> List[str]:
        """Identify critical issues from benchmark results"""
        issues = []
        
        # Critical accuracy issues
        critical_failures = [r for r in results if r.accuracy < 0.3]
        if critical_failures:
            issues.append(f"Critical failures detected in {len(critical_failures)} tests")
        
        # Processing time issues
        slow_results = [r for r in results if r.processing_time_ms > 100]
        if slow_results:
            issues.append(f"Slow processing detected in {len(slow_results)} tests (>100ms)")
        
        # Quality degradation issues
        quality_issues = [r for r in results if r.quality_score < 0.5]
        if quality_issues:
            issues.append(f"Quality degradation detected in {len(quality_issues)} tests")
        
        # Stability issues
        unstable_results = [r for r in results if r.stability_score < 0.6]
        if unstable_results:
            issues.append(f"Stability issues detected in {len(unstable_results)} tests")
        
        return issues
    
    def _save_report(self, report: BenchmarkReport):
        """Save benchmark report to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Save main report
        cursor.execute('''
            INSERT INTO benchmark_reports (
                report_id, generation_time, system_config, test_duration_hours,
                overall_score, total_tests, passed_tests, failed_tests,
                recommendations, identified_issues
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report.report_id,
            report.generation_time.isoformat(),
            json.dumps(report.system_config),
            report.test_duration_hours,
            report.overall_score,
            report.total_tests,
            report.passed_tests,
            report.failed_tests,
            json.dumps(report.recommendations),
            json.dumps(report.identified_issues)
        ))
        
        # Save individual test results
        for result in report.test_results:
            cursor.execute('''
                INSERT INTO benchmark_results (
                    report_id, category, test_name, timestamp, accuracy,
                    precision_val, recall_val, f1_score, snr_improvement_db,
                    quality_score, noise_reduction_factor, processing_time_ms,
                    cpu_usage_percent, memory_usage_mb, false_positive_rate,
                    false_negative_rate, stability_score, confidence_score,
                    test_conditions, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report.report_id,
                result.category.value,
                result.test_name,
                result.timestamp,
                result.accuracy,
                result.precision,
                result.recall,
                result.f1_score,
                result.snr_improvement_db,
                result.quality_score,
                result.noise_reduction_factor,
                result.processing_time_ms,
                result.cpu_usage_percent,
                result.memory_usage_mb,
                result.false_positive_rate,
                result.false_negative_rate,
                result.stability_score,
                result.confidence_score,
                json.dumps(result.test_conditions),
                json.dumps(result.raw_data) if result.raw_data else None
            ))
        
        conn.commit()
        conn.close()
        
        # Also save JSON report
        json_path = self.output_dir / f"{report.report_id}.json"
        with open(json_path, 'w') as f:
            # Convert datetime and enum objects for JSON serialization
            report_dict = asdict(report)
            report_dict['generation_time'] = report.generation_time.isoformat()
            report_dict['category_scores'] = {k.value: v for k, v in report.category_scores.items()}
            
            # Convert test results
            results_list = []
            for result in report.test_results:
                result_dict = asdict(result)
                result_dict['category'] = result.category.value
                results_list.append(result_dict)
            report_dict['test_results'] = results_list
            
            json.dump(report_dict, f, indent=2)
        
        print(f"[BENCHMARK] 💾 Report saved: {json_path}")
    
    def _print_benchmark_summary(self, report: BenchmarkReport):
        """Print comprehensive benchmark summary"""
        print("\n" + "="*80)
        print(f"🎯 VOICEFLOW NOISE ROBUSTNESS BENCHMARK REPORT")
        print(f"📅 Generated: {report.generation_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🆔 Report ID: {report.report_id}")
        print("="*80)
        
        print(f"\n📊 OVERALL RESULTS:")
        print(f"   Overall Score: {report.overall_score:.1%}")
        print(f"   Total Tests: {report.total_tests}")
        print(f"   Passed Tests: {report.passed_tests} ({report.passed_tests/report.total_tests:.1%})")
        print(f"   Failed Tests: {report.failed_tests} ({report.failed_tests/report.total_tests:.1%})")
        print(f"   Test Duration: {report.test_duration_hours:.2f} hours")
        
        print(f"\n🎯 CATEGORY SCORES:")
        for category, score in report.category_scores.items():
            status = "✅" if score > 0.8 else "⚠️" if score > 0.6 else "❌"
            print(f"   {status} {category.value:.<35} {score:.1%}")
        
        if report.recommendations:
            print(f"\n💡 RECOMMENDATIONS:")
            for i, rec in enumerate(report.recommendations, 1):
                print(f"   {i}. {rec}")
        
        if report.identified_issues:
            print(f"\n⚠️  IDENTIFIED ISSUES:")
            for i, issue in enumerate(report.identified_issues, 1):
                print(f"   {i}. {issue}")
        
        print("\n" + "="*80)


def run_noise_benchmark_suite(output_dir: Optional[Path] = None) -> BenchmarkReport:
    """
    Run complete noise robustness benchmark suite
    
    Args:
        output_dir: Directory to save results
    
    Returns:
        Comprehensive benchmark report
    """
    print("🔊 VoiceFlow Noise Robustness Benchmark Suite")
    print("="*60)
    
    benchmark = NoiseToleranceBenchmark(output_dir=output_dir)
    
    if not benchmark.dependencies_loaded:
        print("❌ Cannot run benchmarks - dependencies not available")
        return None
    
    report = benchmark.run_comprehensive_benchmark()
    
    print(f"\n🎉 Benchmark suite completed!")
    print(f"📄 Full report available at: {benchmark.output_dir}")
    
    return report


if __name__ == "__main__":
    # Run benchmark suite
    output_path = Path(__file__).parent.parent / "test_results" / "noise_benchmarks"
    run_noise_benchmark_suite(output_path)