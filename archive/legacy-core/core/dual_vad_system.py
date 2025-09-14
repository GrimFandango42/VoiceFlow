"""
Dual-VAD Cross-Validation System for VoiceFlow
Implements redundant voice activity detection for improved robustness in noisy environments.
"""

import numpy as np
import scipy.signal
from typing import Dict, List, Tuple, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum
import threading
import time
from collections import deque
import logging


class VADMethod(Enum):
    """Voice Activity Detection methods"""
    ENERGY_BASED = "energy_based"
    SPECTRAL_CENTROID = "spectral_centroid"
    ZERO_CROSSING = "zero_crossing"
    SPECTRAL_ENTROPY = "spectral_entropy"
    HARMONIC_RATIO = "harmonic_ratio"
    SPECTRAL_FLUX = "spectral_flux"
    MFCC_BASED = "mfcc_based"
    MACHINE_LEARNING = "machine_learning"


class VADDecision(Enum):
    """VAD decision states"""
    SPEECH = "speech"
    NOISE = "noise"
    UNCERTAIN = "uncertain"


@dataclass
class VADResult:
    """Result from a single VAD method"""
    method: VADMethod
    decision: VADDecision
    confidence: float  # 0.0 to 1.0
    timestamp: float
    features: Dict[str, float]  # Method-specific features
    processing_time_ms: float


@dataclass
class CrossValidationResult:
    """Result from dual-VAD cross-validation"""
    final_decision: VADDecision
    overall_confidence: float
    individual_results: List[VADResult]
    consensus_score: float  # Agreement between methods
    timestamp: float
    reliability_score: float  # Overall system reliability


class EnergyBasedVAD:
    """Traditional energy-based voice activity detection"""
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
        self.frame_size = int(sample_rate * 0.025)  # 25ms
        self.threshold = -30.0  # dB
        self.noise_floor = -60.0  # dB
        self.adaptation_rate = 0.01
        
    def process(self, audio_frame: np.ndarray) -> VADResult:
        """Process audio frame and return VAD decision"""
        start_time = time.time()
        
        # Calculate frame energy
        energy = np.sum(audio_frame ** 2)
        if energy > 0:
            energy_db = 10 * np.log10(energy)
        else:
            energy_db = -80.0
        
        # Adaptive threshold adjustment
        if energy_db < self.threshold - 10:
            # Update noise floor estimate
            self.noise_floor = (1 - self.adaptation_rate) * self.noise_floor + \
                              self.adaptation_rate * energy_db
            self.threshold = self.noise_floor + 15.0  # 15dB above noise floor
        
        # Make decision
        if energy_db > self.threshold:
            decision = VADDecision.SPEECH
            confidence = min(1.0, (energy_db - self.threshold) / 20.0)
        elif energy_db > self.threshold - 5:
            decision = VADDecision.UNCERTAIN
            confidence = 0.5
        else:
            decision = VADDecision.NOISE
            confidence = min(1.0, (self.threshold - energy_db) / 20.0)
        
        processing_time = (time.time() - start_time) * 1000
        
        return VADResult(
            method=VADMethod.ENERGY_BASED,
            decision=decision,
            confidence=confidence,
            timestamp=time.time(),
            features={
                'energy_db': energy_db,
                'threshold': self.threshold,
                'noise_floor': self.noise_floor
            },
            processing_time_ms=processing_time
        )


class SpectralCentroidVAD:
    """Spectral centroid-based voice activity detection"""
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
        self.frame_size = int(sample_rate * 0.025)
        self.speech_centroid_range = (800, 3000)  # Hz
        self.noise_centroid_range = (0, 800)     # Hz
        
    def process(self, audio_frame: np.ndarray) -> VADResult:
        """Process audio frame using spectral centroid analysis"""
        start_time = time.time()
        
        # Apply window to reduce spectral leakage
        windowed = audio_frame * np.hanning(len(audio_frame))
        
        # Compute FFT
        fft_data = np.fft.fft(windowed, n=max(1024, len(windowed)))
        magnitude = np.abs(fft_data[:len(fft_data)//2])
        freqs = np.fft.fftfreq(len(fft_data), 1/self.sample_rate)[:len(magnitude)]
        
        # Calculate spectral centroid
        if np.sum(magnitude) > 0:
            spectral_centroid = np.sum(freqs * magnitude) / np.sum(magnitude)
        else:
            spectral_centroid = 0
        
        # Calculate spectral energy in speech frequency range
        speech_mask = (freqs >= self.speech_centroid_range[0]) & \
                     (freqs <= self.speech_centroid_range[1])
        speech_energy = np.sum(magnitude[speech_mask] ** 2)
        total_energy = np.sum(magnitude ** 2)
        
        if total_energy > 0:
            speech_ratio = speech_energy / total_energy
        else:
            speech_ratio = 0
        
        # Make decision based on centroid and speech ratio
        if (self.speech_centroid_range[0] <= spectral_centroid <= self.speech_centroid_range[1] and 
            speech_ratio > 0.3):
            decision = VADDecision.SPEECH
            confidence = min(1.0, speech_ratio * 2)
        elif speech_ratio > 0.15:
            decision = VADDecision.UNCERTAIN
            confidence = 0.5
        else:
            decision = VADDecision.NOISE
            confidence = min(1.0, (1 - speech_ratio) * 2)
        
        processing_time = (time.time() - start_time) * 1000
        
        return VADResult(
            method=VADMethod.SPECTRAL_CENTROID,
            decision=decision,
            confidence=confidence,
            timestamp=time.time(),
            features={
                'spectral_centroid': spectral_centroid,
                'speech_ratio': speech_ratio,
                'total_energy': float(total_energy)
            },
            processing_time_ms=processing_time
        )


class ZeroCrossingVAD:
    """Zero crossing rate-based voice activity detection"""
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
        self.speech_zcr_range = (0.02, 0.15)  # Typical speech ZCR range
        
    def process(self, audio_frame: np.ndarray) -> VADResult:
        """Process audio frame using zero crossing rate"""
        start_time = time.time()
        
        # Calculate zero crossing rate
        zero_crossings = np.sum(np.abs(np.diff(np.sign(audio_frame))))
        zcr = zero_crossings / (2 * len(audio_frame))
        
        # Calculate frame energy for weighting
        energy = np.mean(audio_frame ** 2)
        energy_db = 10 * np.log10(energy) if energy > 0 else -80
        
        # Make decision
        if (self.speech_zcr_range[0] <= zcr <= self.speech_zcr_range[1] and 
            energy_db > -40):
            decision = VADDecision.SPEECH
            # Confidence based on how close ZCR is to optimal range
            zcr_center = (self.speech_zcr_range[0] + self.speech_zcr_range[1]) / 2
            zcr_distance = abs(zcr - zcr_center) / (self.speech_zcr_range[1] - self.speech_zcr_range[0])
            confidence = max(0.1, 1.0 - zcr_distance * 2)
        elif energy_db > -45:
            decision = VADDecision.UNCERTAIN
            confidence = 0.4
        else:
            decision = VADDecision.NOISE
            confidence = 0.8
        
        processing_time = (time.time() - start_time) * 1000
        
        return VADResult(
            method=VADMethod.ZERO_CROSSING,
            decision=decision,
            confidence=confidence,
            timestamp=time.time(),
            features={
                'zero_crossing_rate': zcr,
                'energy_db': energy_db
            },
            processing_time_ms=processing_time
        )


class SpectralEntropyVAD:
    """Spectral entropy-based voice activity detection"""
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
        self.speech_entropy_range = (6.0, 12.0)  # Typical speech entropy range
        
    def process(self, audio_frame: np.ndarray) -> VADResult:
        """Process audio frame using spectral entropy"""
        start_time = time.time()
        
        # Apply window and compute FFT
        windowed = audio_frame * np.hanning(len(audio_frame))
        fft_data = np.fft.fft(windowed, n=max(512, len(windowed)))
        magnitude = np.abs(fft_data[:len(fft_data)//2])
        
        # Calculate power spectrum
        power = magnitude ** 2
        power_sum = np.sum(power)
        
        if power_sum > 0:
            # Normalize to probability distribution
            prob = power / power_sum
            # Calculate spectral entropy
            entropy = -np.sum(prob * np.log2(prob + 1e-12))
        else:
            entropy = 0
        
        # Calculate frame energy
        energy = np.mean(audio_frame ** 2)
        energy_db = 10 * np.log10(energy) if energy > 0 else -80
        
        # Make decision
        if (self.speech_entropy_range[0] <= entropy <= self.speech_entropy_range[1] and 
            energy_db > -35):
            decision = VADDecision.SPEECH
            # Higher entropy usually indicates more complex spectral content (speech)
            confidence = min(1.0, entropy / self.speech_entropy_range[1])
        elif energy_db > -40:
            decision = VADDecision.UNCERTAIN
            confidence = 0.5
        else:
            decision = VADDecision.NOISE
            confidence = 0.7
        
        processing_time = (time.time() - start_time) * 1000
        
        return VADResult(
            method=VADMethod.SPECTRAL_ENTROPY,
            decision=decision,
            confidence=confidence,
            timestamp=time.time(),
            features={
                'spectral_entropy': entropy,
                'energy_db': energy_db
            },
            processing_time_ms=processing_time
        )


class HarmonicRatioVAD:
    """Harmonic ratio-based voice activity detection"""
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
        self.frame_size = int(sample_rate * 0.025)
        
    def process(self, audio_frame: np.ndarray) -> VADResult:
        """Process audio frame using harmonic to noise ratio"""
        start_time = time.time()
        
        # Apply window and compute FFT
        windowed = audio_frame * np.hanning(len(audio_frame))
        fft_data = np.fft.fft(windowed, n=1024)
        magnitude = np.abs(fft_data[:512])
        freqs = np.fft.fftfreq(1024, 1/self.sample_rate)[:512]
        
        # Find fundamental frequency (peak in voice range)
        voice_range = (freqs >= 80) & (freqs <= 400)
        if np.any(voice_range):
            voice_spectrum = magnitude[voice_range]
            voice_freqs = freqs[voice_range]
            
            if len(voice_spectrum) > 0 and np.max(voice_spectrum) > 0:
                f0_idx = np.argmax(voice_spectrum)
                f0 = voice_freqs[f0_idx]
                
                # Look for harmonics
                harmonic_energy = 0
                total_energy = np.sum(magnitude ** 2)
                
                for h in range(1, 6):  # First 5 harmonics
                    harmonic_freq = f0 * h
                    if harmonic_freq < self.sample_rate / 2:
                        # Find closest frequency bin
                        harmonic_idx = np.argmin(np.abs(freqs - harmonic_freq))
                        # Sum energy in small window around harmonic
                        window_size = 2
                        start_idx = max(0, harmonic_idx - window_size)
                        end_idx = min(len(magnitude), harmonic_idx + window_size + 1)
                        harmonic_energy += np.sum(magnitude[start_idx:end_idx] ** 2)
                
                harmonic_ratio = harmonic_energy / (total_energy + 1e-12)
            else:
                harmonic_ratio = 0
        else:
            harmonic_ratio = 0
        
        # Calculate frame energy
        energy = np.mean(audio_frame ** 2)
        energy_db = 10 * np.log10(energy) if energy > 0 else -80
        
        # Make decision
        if harmonic_ratio > 0.3 and energy_db > -35:
            decision = VADDecision.SPEECH
            confidence = min(1.0, harmonic_ratio * 2)
        elif harmonic_ratio > 0.1 and energy_db > -40:
            decision = VADDecision.UNCERTAIN
            confidence = 0.5
        else:
            decision = VADDecision.NOISE
            confidence = 0.6
        
        processing_time = (time.time() - start_time) * 1000
        
        return VADResult(
            method=VADMethod.HARMONIC_RATIO,
            decision=decision,
            confidence=confidence,
            timestamp=time.time(),
            features={
                'harmonic_ratio': harmonic_ratio,
                'energy_db': energy_db
            },
            processing_time_ms=processing_time
        )


class DualVADSystem:
    """
    Dual-VAD cross-validation system that combines multiple VAD methods
    for improved robustness in noisy environments
    """
    
    def __init__(self, sample_rate: int = 16000, 
                 primary_methods: List[VADMethod] = None,
                 secondary_methods: List[VADMethod] = None):
        self.sample_rate = sample_rate
        
        # Default method selection
        if primary_methods is None:
            primary_methods = [VADMethod.ENERGY_BASED, VADMethod.SPECTRAL_CENTROID]
        if secondary_methods is None:
            secondary_methods = [VADMethod.ZERO_CROSSING, VADMethod.SPECTRAL_ENTROPY]
        
        self.primary_methods = primary_methods
        self.secondary_methods = secondary_methods
        
        # Initialize VAD processors
        self.vad_processors = {
            VADMethod.ENERGY_BASED: EnergyBasedVAD(sample_rate),
            VADMethod.SPECTRAL_CENTROID: SpectralCentroidVAD(sample_rate),
            VADMethod.ZERO_CROSSING: ZeroCrossingVAD(sample_rate),
            VADMethod.SPECTRAL_ENTROPY: SpectralEntropyVAD(sample_rate),
            VADMethod.HARMONIC_RATIO: HarmonicRatioVAD(sample_rate)
        }
        
        # Performance tracking
        self.method_performance = {method: {'correct': 0, 'total': 0} 
                                 for method in self.vad_processors.keys()}
        
        # Decision history for temporal smoothing
        self.decision_history = deque(maxlen=5)
        
        # Consensus thresholds
        self.consensus_threshold = 0.6  # Minimum agreement for confident decision
        self.uncertainty_threshold = 0.3  # Below this, decision is uncertain
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
    def process_frame(self, audio_frame: np.ndarray) -> CrossValidationResult:
        """
        Process audio frame through dual-VAD system
        
        Args:
            audio_frame: Audio frame to process
            
        Returns:
            Cross-validation result with consensus decision
        """
        with self.lock:
            # Get results from all active methods
            primary_results = []
            secondary_results = []
            
            for method in self.primary_methods:
                if method in self.vad_processors:
                    result = self.vad_processors[method].process(audio_frame)
                    primary_results.append(result)
            
            for method in self.secondary_methods:
                if method in self.vad_processors:
                    result = self.vad_processors[method].process(audio_frame)
                    secondary_results.append(result)
            
            all_results = primary_results + secondary_results
            
            # Perform cross-validation
            consensus_result = self._cross_validate(primary_results, secondary_results)
            
            # Add to decision history for temporal smoothing
            self.decision_history.append(consensus_result)
            
            # Apply temporal smoothing
            final_result = self._apply_temporal_smoothing(consensus_result)
            
            return final_result
    
    def _cross_validate(self, primary_results: List[VADResult], 
                       secondary_results: List[VADResult]) -> CrossValidationResult:
        """
        Cross-validate results from primary and secondary VAD methods
        """
        all_results = primary_results + secondary_results
        
        if not all_results:
            return CrossValidationResult(
                final_decision=VADDecision.UNCERTAIN,
                overall_confidence=0.0,
                individual_results=[],
                consensus_score=0.0,
                timestamp=time.time(),
                reliability_score=0.0
            )
        
        # Count decisions
        decision_counts = {
            VADDecision.SPEECH: 0,
            VADDecision.NOISE: 0,
            VADDecision.UNCERTAIN: 0
        }
        
        # Weight decisions by confidence and method reliability
        weighted_scores = {
            VADDecision.SPEECH: 0.0,
            VADDecision.NOISE: 0.0,
            VADDecision.UNCERTAIN: 0.0
        }
        
        total_weight = 0.0
        
        for result in all_results:
            decision_counts[result.decision] += 1
            
            # Weight by confidence and historical performance
            method_reliability = self._get_method_reliability(result.method)
            weight = result.confidence * method_reliability
            
            weighted_scores[result.decision] += weight
            total_weight += weight
        
        # Normalize weighted scores
        if total_weight > 0:
            for decision in weighted_scores:
                weighted_scores[decision] /= total_weight
        
        # Determine consensus
        max_decision = max(weighted_scores, key=weighted_scores.get)
        max_score = weighted_scores[max_decision]
        
        # Calculate consensus score (agreement level)
        consensus_score = max_score
        
        # Determine final decision and confidence
        if consensus_score >= self.consensus_threshold:
            final_decision = max_decision
            overall_confidence = consensus_score
        elif consensus_score >= self.uncertainty_threshold:
            # Moderate confidence - use primary methods for tie-breaking
            primary_votes = [r.decision for r in primary_results]
            if primary_votes:
                from collections import Counter
                primary_consensus = Counter(primary_votes).most_common(1)[0][0]
                final_decision = primary_consensus
                overall_confidence = consensus_score * 0.8
            else:
                final_decision = VADDecision.UNCERTAIN
                overall_confidence = 0.5
        else:
            final_decision = VADDecision.UNCERTAIN
            overall_confidence = consensus_score
        
        # Calculate system reliability
        reliability_score = self._calculate_reliability_score(all_results, consensus_score)
        
        return CrossValidationResult(
            final_decision=final_decision,
            overall_confidence=overall_confidence,
            individual_results=all_results,
            consensus_score=consensus_score,
            timestamp=time.time(),
            reliability_score=reliability_score
        )
    
    def _get_method_reliability(self, method: VADMethod) -> float:
        """Get historical reliability score for a VAD method"""
        if method not in self.method_performance:
            return 0.8  # Default reliability
        
        perf = self.method_performance[method]
        if perf['total'] < 10:
            return 0.8  # Not enough data
        
        accuracy = perf['correct'] / perf['total']
        return max(0.3, min(1.0, accuracy))  # Clamp to reasonable range
    
    def _calculate_reliability_score(self, results: List[VADResult], 
                                   consensus_score: float) -> float:
        """Calculate overall system reliability"""
        if not results:
            return 0.0
        
        # Factors affecting reliability:
        # 1. Number of methods agreeing
        # 2. Confidence levels of individual methods
        # 3. Historical performance of methods
        # 4. Processing time consistency
        
        # Average confidence of all methods
        avg_confidence = np.mean([r.confidence for r in results])
        
        # Processing time consistency (lower variance = more reliable)
        processing_times = [r.processing_time_ms for r in results]
        time_consistency = 1.0 / (1.0 + np.std(processing_times) / np.mean(processing_times))
        
        # Method diversity (using different types of analysis)
        unique_methods = len(set(r.method for r in results))
        diversity_factor = min(1.0, unique_methods / 3.0)  # Max benefit from 3+ methods
        
        # Combine factors
        reliability = (avg_confidence * 0.4 + 
                      consensus_score * 0.3 + 
                      time_consistency * 0.2 + 
                      diversity_factor * 0.1)
        
        return max(0.0, min(1.0, reliability))
    
    def _apply_temporal_smoothing(self, current_result: CrossValidationResult) -> CrossValidationResult:
        """Apply temporal smoothing to reduce decision jitter"""
        if len(self.decision_history) < 3:
            return current_result
        
        # Get recent decisions
        recent_decisions = [r.final_decision for r in list(self.decision_history)[-3:]]
        recent_confidences = [r.overall_confidence for r in list(self.decision_history)[-3:]]
        
        # Count decision consistency
        from collections import Counter
        decision_counts = Counter(recent_decisions)
        most_common = decision_counts.most_common(1)[0]
        
        # If there's strong consistency, boost confidence
        if most_common[1] >= 2:  # At least 2 out of 3 agree
            consistency_boost = 0.1 * (most_common[1] - 1)
            new_confidence = min(1.0, current_result.overall_confidence + consistency_boost)
            
            return CrossValidationResult(
                final_decision=current_result.final_decision,
                overall_confidence=new_confidence,
                individual_results=current_result.individual_results,
                consensus_score=current_result.consensus_score,
                timestamp=current_result.timestamp,
                reliability_score=current_result.reliability_score
            )
        
        return current_result
    
    def update_method_performance(self, method: VADMethod, correct: bool):
        """Update performance tracking for a method"""
        with self.lock:
            if method in self.method_performance:
                self.method_performance[method]['total'] += 1
                if correct:
                    self.method_performance[method]['correct'] += 1
    
    def get_performance_statistics(self) -> Dict[str, Any]:
        """Get performance statistics for all methods"""
        with self.lock:
            stats = {}
            for method, perf in self.method_performance.items():
                if perf['total'] > 0:
                    accuracy = perf['correct'] / perf['total']
                    stats[method.value] = {
                        'accuracy': accuracy,
                        'total_samples': perf['total'],
                        'reliability': self._get_method_reliability(method)
                    }
                else:
                    stats[method.value] = {
                        'accuracy': 0.0,
                        'total_samples': 0,
                        'reliability': 0.8
                    }
            
            return stats
    
    def configure_for_environment(self, noise_level: str):
        """
        Configure VAD system for specific noise environment
        
        Args:
            noise_level: 'quiet', 'moderate', 'noisy', 'extreme'
        """
        if noise_level == 'quiet':
            # Use fewer methods for speed
            self.primary_methods = [VADMethod.ENERGY_BASED]
            self.secondary_methods = [VADMethod.SPECTRAL_CENTROID]
            self.consensus_threshold = 0.5
        elif noise_level == 'moderate':
            # Balanced approach
            self.primary_methods = [VADMethod.ENERGY_BASED, VADMethod.SPECTRAL_CENTROID]
            self.secondary_methods = [VADMethod.ZERO_CROSSING]
            self.consensus_threshold = 0.6
        elif noise_level == 'noisy':
            # Use more robust methods
            self.primary_methods = [VADMethod.SPECTRAL_CENTROID, VADMethod.HARMONIC_RATIO]
            self.secondary_methods = [VADMethod.SPECTRAL_ENTROPY, VADMethod.ZERO_CROSSING]
            self.consensus_threshold = 0.7
        elif noise_level == 'extreme':
            # Use all available methods
            self.primary_methods = [VADMethod.SPECTRAL_CENTROID, VADMethod.HARMONIC_RATIO]
            self.secondary_methods = [VADMethod.SPECTRAL_ENTROPY, VADMethod.ZERO_CROSSING, VADMethod.ENERGY_BASED]
            self.consensus_threshold = 0.8
        
        print(f"[DUAL-VAD] Configured for {noise_level} environment")
        print(f"[DUAL-VAD] Primary methods: {[m.value for m in self.primary_methods]}")
        print(f"[DUAL-VAD] Secondary methods: {[m.value for m in self.secondary_methods]}")


def create_dual_vad_system(sample_rate: int = 16000, 
                          environment: str = 'moderate') -> DualVADSystem:
    """
    Factory function to create a configured dual-VAD system
    
    Args:
        sample_rate: Audio sample rate
        environment: Environment type ('quiet', 'moderate', 'noisy', 'extreme')
    
    Returns:
        Configured DualVADSystem instance
    """
    system = DualVADSystem(sample_rate=sample_rate)
    system.configure_for_environment(environment)
    return system