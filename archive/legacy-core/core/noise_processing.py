"""
Noise Processing Module for VoiceFlow
Advanced noise detection, filtering, and adaptive VAD configuration.
"""

import numpy as np
import scipy.signal
import scipy.fft
from typing import Dict, Tuple, Optional, List, Any
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum


class NoiseEnvironment(Enum):
    """Predefined noise environment types"""
    QUIET = "quiet"
    HOME = "home"
    OFFICE = "office"
    OUTDOOR = "outdoor"
    VEHICLE = "vehicle"
    NOISY = "noisy"


class NoiseType(Enum):
    """Types of noise interference"""
    STATIONARY = "stationary"
    NON_STATIONARY = "non_stationary"
    IMPULSIVE = "impulsive"
    PERIODIC = "periodic"
    MIXED = "mixed"


@dataclass
class NoiseProfile:
    """Noise characteristics profile"""
    environment: NoiseEnvironment
    snr_estimate: float
    noise_floor: float
    dominant_frequencies: List[float]
    noise_type: NoiseType
    spectral_entropy: float
    temporal_variance: float
    confidence: float
    timestamp: float


@dataclass
class VADConfig:
    """Voice Activity Detection configuration"""
    silero_sensitivity: float
    webrtc_sensitivity: int
    post_speech_silence_duration: float
    min_length_of_recording: float
    min_gap_between_recordings: float
    energy_threshold: float
    zero_crossing_threshold: float
    spectral_centroid_threshold: float


class AdaptiveVADManager:
    """
    Adaptive Voice Activity Detection manager that adjusts VAD parameters
    based on real-time noise analysis.
    """
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
        self.frame_size = int(sample_rate * 0.025)  # 25ms frames
        self.hop_size = int(sample_rate * 0.010)    # 10ms hop
        
        # Noise environment configurations
        self.vad_configs = {
            NoiseEnvironment.QUIET: VADConfig(
                silero_sensitivity=0.3,
                webrtc_sensitivity=2,
                post_speech_silence_duration=0.5,
                min_length_of_recording=0.1,
                min_gap_between_recordings=0.2,
                energy_threshold=-40,
                zero_crossing_threshold=0.3,
                spectral_centroid_threshold=2000
            ),
            NoiseEnvironment.HOME: VADConfig(
                silero_sensitivity=0.4,
                webrtc_sensitivity=3,
                post_speech_silence_duration=0.8,
                min_length_of_recording=0.2,
                min_gap_between_recordings=0.3,
                energy_threshold=-35,
                zero_crossing_threshold=0.35,
                spectral_centroid_threshold=2200
            ),
            NoiseEnvironment.OFFICE: VADConfig(
                silero_sensitivity=0.5,
                webrtc_sensitivity=3,
                post_speech_silence_duration=1.0,
                min_length_of_recording=0.3,
                min_gap_between_recordings=0.4,
                energy_threshold=-30,
                zero_crossing_threshold=0.4,
                spectral_centroid_threshold=2500
            ),
            NoiseEnvironment.OUTDOOR: VADConfig(
                silero_sensitivity=0.6,
                webrtc_sensitivity=4,
                post_speech_silence_duration=1.2,
                min_length_of_recording=0.4,
                min_gap_between_recordings=0.5,
                energy_threshold=-25,
                zero_crossing_threshold=0.45,
                spectral_centroid_threshold=2800
            ),
            NoiseEnvironment.VEHICLE: VADConfig(
                silero_sensitivity=0.7,
                webrtc_sensitivity=4,
                post_speech_silence_duration=1.5,
                min_length_of_recording=0.5,
                min_gap_between_recordings=0.6,
                energy_threshold=-20,
                zero_crossing_threshold=0.5,
                spectral_centroid_threshold=3000
            ),
            NoiseEnvironment.NOISY: VADConfig(
                silero_sensitivity=0.8,
                webrtc_sensitivity=5,
                post_speech_silence_duration=2.0,
                min_length_of_recording=0.6,
                min_gap_between_recordings=0.8,
                energy_threshold=-15,
                zero_crossing_threshold=0.6,
                spectral_centroid_threshold=3500
            )
        }
        
        self.current_config = self.vad_configs[NoiseEnvironment.HOME]
        self.current_environment = NoiseEnvironment.HOME
        
    def get_config_for_environment(self, environment: NoiseEnvironment) -> VADConfig:
        """Get VAD configuration for specific environment"""
        return self.vad_configs.get(environment, self.current_config)
    
    def adapt_config(self, noise_profile: NoiseProfile) -> VADConfig:
        """
        Adapt VAD configuration based on current noise profile
        """
        base_config = self.vad_configs[noise_profile.environment]
        
        # Create adaptive adjustments based on SNR and noise characteristics
        snr_factor = min(max(noise_profile.snr_estimate / 20.0, 0.1), 2.0)
        noise_factor = 1.0 + (1.0 - snr_factor)
        
        # Adjust sensitivity based on noise level
        adapted_config = VADConfig(
            silero_sensitivity=min(base_config.silero_sensitivity * noise_factor, 0.9),
            webrtc_sensitivity=min(int(base_config.webrtc_sensitivity * noise_factor), 5),
            post_speech_silence_duration=base_config.post_speech_silence_duration * noise_factor,
            min_length_of_recording=base_config.min_length_of_recording * noise_factor,
            min_gap_between_recordings=base_config.min_gap_between_recordings * noise_factor,
            energy_threshold=base_config.energy_threshold - (10 * (1.0 - snr_factor)),
            zero_crossing_threshold=base_config.zero_crossing_threshold * noise_factor,
            spectral_centroid_threshold=base_config.spectral_centroid_threshold * noise_factor
        )
        
        self.current_config = adapted_config
        self.current_environment = noise_profile.environment
        
        return adapted_config


class NoiseAnalyzer:
    """
    Real-time noise analysis and classification engine
    """
    
    def __init__(self, sample_rate: int = 16000, analysis_window: float = 2.0):
        self.sample_rate = sample_rate
        self.analysis_window = analysis_window
        self.window_samples = int(sample_rate * analysis_window)
        
        # Circular buffer for audio analysis
        self.audio_buffer = deque(maxlen=self.window_samples)
        self.noise_floor_estimates = deque(maxlen=10)
        self.snr_estimates = deque(maxlen=10)
        
        # Analysis parameters
        self.fft_size = 2048
        self.freq_bins = np.fft.fftfreq(self.fft_size, 1/sample_rate)[:self.fft_size//2]
        
        # Initialize noise floor estimation
        self.noise_floor = -40.0  # dB
        self.speech_threshold = -30.0  # dB
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
    def add_audio_frame(self, audio_frame: np.ndarray):
        """Add audio frame to analysis buffer"""
        with self.lock:
            self.audio_buffer.extend(audio_frame)
    
    def estimate_snr(self, audio_signal: np.ndarray) -> float:
        """
        Estimate Signal-to-Noise Ratio using voice activity detection
        """
        # Frame-based energy analysis
        frame_length = int(self.sample_rate * 0.025)  # 25ms
        hop_length = int(self.sample_rate * 0.010)    # 10ms
        
        frames = []
        for i in range(0, len(audio_signal) - frame_length, hop_length):
            frame = audio_signal[i:i + frame_length]
            frames.append(frame)
        
        if not frames:
            return 0.0
        
        # Calculate frame energies
        frame_energies = []
        for frame in frames:
            energy = np.sum(frame ** 2)
            if energy > 0:
                energy_db = 10 * np.log10(energy)
                frame_energies.append(energy_db)
        
        if len(frame_energies) < 2:
            return 0.0
        
        # Separate speech and noise frames using energy threshold
        frame_energies = np.array(frame_energies)
        median_energy = np.median(frame_energies)
        
        # Adaptive threshold based on energy distribution
        noise_threshold = median_energy - 5.0
        speech_threshold = median_energy + 3.0
        
        noise_frames = frame_energies[frame_energies < noise_threshold]
        speech_frames = frame_energies[frame_energies > speech_threshold]
        
        if len(noise_frames) == 0 or len(speech_frames) == 0:
            return 10.0  # Default moderate SNR
        
        noise_power = np.mean(noise_frames)
        speech_power = np.mean(speech_frames)
        
        snr = speech_power - noise_power
        return max(snr, -10.0)  # Minimum SNR of -10dB
    
    def analyze_spectral_characteristics(self, audio_signal: np.ndarray) -> Dict[str, float]:
        """
        Analyze spectral characteristics of the audio signal
        """
        # Apply window to reduce spectral leakage
        windowed_signal = audio_signal * scipy.signal.windows.hann(len(audio_signal))
        
        # Compute FFT
        fft_data = np.fft.fft(windowed_signal, self.fft_size)
        magnitude_spectrum = np.abs(fft_data[:self.fft_size//2])
        power_spectrum = magnitude_spectrum ** 2
        
        # Avoid log of zero
        power_spectrum = np.maximum(power_spectrum, 1e-12)
        power_spectrum_db = 10 * np.log10(power_spectrum)
        
        # Spectral centroid
        spectral_centroid = np.sum(self.freq_bins * power_spectrum) / np.sum(power_spectrum)
        
        # Spectral rolloff (95% of energy)
        cumsum_power = np.cumsum(power_spectrum)
        rolloff_idx = np.where(cumsum_power >= 0.95 * cumsum_power[-1])[0]
        spectral_rolloff = self.freq_bins[rolloff_idx[0]] if len(rolloff_idx) > 0 else self.sample_rate / 4
        
        # Spectral entropy
        normalized_spectrum = power_spectrum / np.sum(power_spectrum)
        spectral_entropy = -np.sum(normalized_spectrum * np.log2(normalized_spectrum + 1e-12))
        
        # Zero crossing rate
        zero_crossings = np.sum(np.abs(np.diff(np.sign(audio_signal)))) / (2 * len(audio_signal))
        
        # Find dominant frequencies (peaks)
        peaks, _ = scipy.signal.find_peaks(power_spectrum_db, height=np.max(power_spectrum_db) - 20)
        dominant_frequencies = self.freq_bins[peaks].tolist() if len(peaks) > 0 else []
        
        return {
            'spectral_centroid': spectral_centroid,
            'spectral_rolloff': spectral_rolloff,
            'spectral_entropy': spectral_entropy,
            'zero_crossing_rate': zero_crossings,
            'dominant_frequencies': dominant_frequencies[:5],  # Top 5 peaks
            'spectral_flatness': np.exp(np.mean(np.log(power_spectrum))) / np.mean(power_spectrum)
        }
    
    def classify_noise_environment(self, spectral_features: Dict[str, float], snr: float) -> NoiseEnvironment:
        """
        Classify noise environment based on spectral features and SNR
        """
        # Rule-based classification using spectral characteristics
        centroid = spectral_features['spectral_centroid']
        entropy = spectral_features['spectral_entropy']
        flatness = spectral_features['spectral_flatness']
        zcr = spectral_features['zero_crossing_rate']
        
        # Classification logic
        if snr > 15:
            return NoiseEnvironment.QUIET
        elif snr > 10:
            if centroid < 2000 and entropy < 8:
                return NoiseEnvironment.HOME
            else:
                return NoiseEnvironment.OFFICE
        elif snr > 5:
            if flatness > 0.5:  # Broadband noise typical of vehicles
                return NoiseEnvironment.VEHICLE
            else:
                return NoiseEnvironment.OUTDOOR
        else:
            return NoiseEnvironment.NOISY
    
    def classify_noise_type(self, audio_signal: np.ndarray, spectral_features: Dict[str, float]) -> NoiseType:
        """
        Classify type of noise interference
        """
        # Temporal analysis for stationarity
        frame_length = int(self.sample_rate * 0.1)  # 100ms frames
        frames = [audio_signal[i:i+frame_length] for i in range(0, len(audio_signal) - frame_length, frame_length)]
        
        if len(frames) < 3:
            return NoiseType.MIXED
        
        # Calculate energy variance across frames
        frame_energies = [np.mean(frame**2) for frame in frames]
        energy_variance = np.var(frame_energies) / (np.mean(frame_energies) + 1e-12)
        
        # Check for impulsive characteristics
        peak_ratio = np.max(np.abs(audio_signal)) / (np.mean(np.abs(audio_signal)) + 1e-12)
        
        # Classification
        if peak_ratio > 5:
            return NoiseType.IMPULSIVE
        elif energy_variance < 0.1:
            return NoiseType.STATIONARY
        elif len(spectral_features['dominant_frequencies']) > 3:
            return NoiseType.PERIODIC
        elif energy_variance > 0.5:
            return NoiseType.NON_STATIONARY
        else:
            return NoiseType.MIXED
    
    def analyze_current_noise(self) -> Optional[NoiseProfile]:
        """
        Analyze current noise conditions and return noise profile
        """
        with self.lock:
            if len(self.audio_buffer) < self.window_samples // 2:
                return None
            
            # Convert to numpy array
            audio_data = np.array(list(self.audio_buffer))
        
        # Estimate SNR
        snr = self.estimate_snr(audio_data)
        
        # Analyze spectral characteristics
        spectral_features = self.analyze_spectral_characteristics(audio_data)
        
        # Classify environment and noise type
        environment = self.classify_noise_environment(spectral_features, snr)
        noise_type = self.classify_noise_type(audio_data, spectral_features)
        
        # Update noise floor estimate
        noise_frames = audio_data[np.abs(audio_data) < np.percentile(np.abs(audio_data), 25)]
        if len(noise_frames) > 0:
            current_noise_floor = 20 * np.log10(np.mean(np.abs(noise_frames)) + 1e-12)
            self.noise_floor_estimates.append(current_noise_floor)
            self.noise_floor = np.median(list(self.noise_floor_estimates))
        
        # Calculate confidence based on analysis consistency
        confidence = min(1.0, snr / 20.0 + 0.3)
        
        return NoiseProfile(
            environment=environment,
            snr_estimate=snr,
            noise_floor=self.noise_floor,
            dominant_frequencies=spectral_features['dominant_frequencies'],
            noise_type=noise_type,
            spectral_entropy=spectral_features['spectral_entropy'],
            temporal_variance=np.var(audio_data),
            confidence=confidence,
            timestamp=time.time()
        )


class NoiseReducer:
    """
    Adaptive noise reduction using spectral subtraction and Wiener filtering
    """
    
    def __init__(self, sample_rate: int = 16000, frame_size: int = 512):
        self.sample_rate = sample_rate
        self.frame_size = frame_size
        self.hop_size = frame_size // 2
        
        # Noise estimation parameters
        self.alpha = 0.95  # Noise floor tracking factor
        self.beta = 0.01   # Over-subtraction factor
        self.noise_spectrum = None
        self.frames_for_noise_estimation = 10
        self.noise_frames_count = 0
        
        # Spectral subtraction parameters
        self.oversubtraction_factor = 2.0
        self.spectral_floor = 0.05
        
    def estimate_noise_spectrum(self, audio_frame: np.ndarray) -> np.ndarray:
        """
        Estimate noise spectrum from audio frame
        """
        # Apply window
        windowed_frame = audio_frame * scipy.signal.windows.hann(len(audio_frame))
        
        # Compute magnitude spectrum
        fft_frame = np.fft.fft(windowed_frame, self.frame_size)
        magnitude_spectrum = np.abs(fft_frame)
        
        if self.noise_spectrum is None:
            self.noise_spectrum = magnitude_spectrum.copy()
        else:
            # Update noise spectrum using first-order smoothing
            self.noise_spectrum = (self.alpha * self.noise_spectrum + 
                                 (1 - self.alpha) * magnitude_spectrum)
        
        return self.noise_spectrum
    
    def spectral_subtraction(self, audio_signal: np.ndarray, noise_profile: NoiseProfile) -> np.ndarray:
        """
        Apply spectral subtraction noise reduction
        """
        # Adjust parameters based on noise profile
        if noise_profile.snr_estimate < 5:
            self.oversubtraction_factor = 3.0
            self.spectral_floor = 0.1
        elif noise_profile.snr_estimate < 10:
            self.oversubtraction_factor = 2.5
            self.spectral_floor = 0.075
        else:
            self.oversubtraction_factor = 2.0
            self.spectral_floor = 0.05
        
        # Process in overlapping frames
        output_signal = np.zeros_like(audio_signal)
        window = scipy.signal.windows.hann(self.frame_size)
        
        for i in range(0, len(audio_signal) - self.frame_size, self.hop_size):
            frame = audio_signal[i:i + self.frame_size]
            
            # Apply window
            windowed_frame = frame * window
            
            # FFT
            fft_frame = np.fft.fft(windowed_frame, self.frame_size)
            magnitude = np.abs(fft_frame)
            phase = np.angle(fft_frame)
            
            # Update noise spectrum during initial frames or quiet periods
            if (self.noise_frames_count < self.frames_for_noise_estimation or 
                noise_profile.snr_estimate < 0):
                self.estimate_noise_spectrum(frame)
                self.noise_frames_count += 1
            
            # Spectral subtraction
            if self.noise_spectrum is not None:
                # Calculate spectral subtraction gain
                snr_frame = magnitude / (self.noise_spectrum + 1e-12)
                gain = 1 - (self.oversubtraction_factor / snr_frame)
                
                # Apply spectral floor
                gain = np.maximum(gain, self.spectral_floor)
                
                # Apply gain to magnitude
                clean_magnitude = magnitude * gain
            else:
                clean_magnitude = magnitude
            
            # Reconstruct signal
            clean_fft = clean_magnitude * np.exp(1j * phase)
            clean_frame = np.real(np.fft.ifft(clean_fft))[:self.frame_size]
            
            # Overlap-add
            output_signal[i:i + self.frame_size] += clean_frame * window
        
        return output_signal
    
    def adaptive_wiener_filter(self, audio_signal: np.ndarray, noise_profile: NoiseProfile) -> np.ndarray:
        """
        Apply adaptive Wiener filtering
        """
        # Estimate signal and noise power spectral densities
        frame_length = self.frame_size
        hop_length = self.hop_size
        
        output_signal = np.zeros_like(audio_signal)
        window = scipy.signal.windows.hann(frame_length)
        
        for i in range(0, len(audio_signal) - frame_length, hop_length):
            frame = audio_signal[i:i + frame_length]
            windowed_frame = frame * window
            
            # FFT
            fft_frame = np.fft.fft(windowed_frame, frame_length)
            magnitude = np.abs(fft_frame)
            phase = np.angle(fft_frame)
            power = magnitude ** 2
            
            # Estimate noise power (use noise spectrum if available)
            if self.noise_spectrum is not None:
                noise_power = self.noise_spectrum ** 2
            else:
                noise_power = power * 0.1  # Assume 10% noise
            
            # Wiener filter gain
            signal_power = np.maximum(power - noise_power, 0.1 * power)
            wiener_gain = signal_power / (signal_power + noise_power)
            
            # Apply gain
            filtered_magnitude = magnitude * wiener_gain
            
            # Reconstruct
            filtered_fft = filtered_magnitude * np.exp(1j * phase)
            filtered_frame = np.real(np.fft.ifft(filtered_fft))[:frame_length]
            
            # Overlap-add
            output_signal[i:i + frame_length] += filtered_frame * window
        
        return output_signal


class NoiseGate:
    """
    Adaptive noise gate with automatic threshold adjustment
    """
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
        self.frame_size = int(sample_rate * 0.025)  # 25ms
        self.attack_time = 0.003   # 3ms
        self.release_time = 0.100  # 100ms
        
        # Convert to samples
        self.attack_samples = int(self.attack_time * sample_rate)
        self.release_samples = int(self.release_time * sample_rate)
        
        # Gate state
        self.gate_state = 0.0
        self.threshold = -40.0  # dB
        
    def set_adaptive_threshold(self, noise_profile: NoiseProfile):
        """
        Set gate threshold based on noise profile
        """
        # Adaptive threshold based on noise floor and SNR
        base_threshold = noise_profile.noise_floor + 6.0  # 6dB above noise floor
        
        # Adjust based on environment
        if noise_profile.environment == NoiseEnvironment.QUIET:
            self.threshold = base_threshold
        elif noise_profile.environment == NoiseEnvironment.HOME:
            self.threshold = base_threshold + 3.0
        elif noise_profile.environment == NoiseEnvironment.OFFICE:
            self.threshold = base_threshold + 5.0
        elif noise_profile.environment in [NoiseEnvironment.OUTDOOR, NoiseEnvironment.VEHICLE]:
            self.threshold = base_threshold + 8.0
        elif noise_profile.environment == NoiseEnvironment.NOISY:
            self.threshold = base_threshold + 10.0
    
    def process(self, audio_signal: np.ndarray) -> np.ndarray:
        """
        Apply noise gate to audio signal
        """
        output = np.zeros_like(audio_signal)
        
        for i in range(0, len(audio_signal), self.frame_size):
            frame = audio_signal[i:i + self.frame_size]
            if len(frame) == 0:
                break
            
            # Calculate frame energy in dB
            energy = np.mean(frame ** 2)
            if energy > 0:
                energy_db = 10 * np.log10(energy)
            else:
                energy_db = -80.0
            
            # Determine target gate state
            target_state = 1.0 if energy_db > self.threshold else 0.0
            
            # Apply attack/release smoothing
            if target_state > self.gate_state:
                # Attack
                self.gate_state = min(1.0, self.gate_state + (1.0 / self.attack_samples))
            elif target_state < self.gate_state:
                # Release
                self.gate_state = max(0.0, self.gate_state - (1.0 / self.release_samples))
            
            # Apply gate
            output[i:i + len(frame)] = frame * self.gate_state
        
        return output


def create_noise_processor(sample_rate: int = 16000) -> Tuple[NoiseAnalyzer, AdaptiveVADManager, NoiseReducer, NoiseGate]:
    """
    Factory function to create integrated noise processing components
    """
    analyzer = NoiseAnalyzer(sample_rate=sample_rate)
    vad_manager = AdaptiveVADManager(sample_rate=sample_rate)
    reducer = NoiseReducer(sample_rate=sample_rate)
    gate = NoiseGate(sample_rate=sample_rate)
    
    return analyzer, vad_manager, reducer, gate