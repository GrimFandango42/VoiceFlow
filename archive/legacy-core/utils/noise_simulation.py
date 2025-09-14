"""
Noise Simulation Library for VoiceFlow
Generates standard test signals for various acoustic environments and noise conditions.
"""

import numpy as np
import scipy.signal
import scipy.fft
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path


class EnvironmentType(Enum):
    """Standard acoustic environment types for testing"""
    ANECHOIC = "anechoic"          # No reverberation
    QUIET_ROOM = "quiet_room"      # Typical quiet indoor space
    HOME_OFFICE = "home_office"    # Residential work environment
    OPEN_OFFICE = "open_office"    # Commercial office space
    CONFERENCE_ROOM = "conference_room"  # Meeting room
    VEHICLE_INTERIOR = "vehicle_interior"  # Car, bus, train
    OUTDOOR_QUIET = "outdoor_quiet"      # Park, residential area
    OUTDOOR_URBAN = "outdoor_urban"      # Street, urban environment
    INDUSTRIAL = "industrial"      # Factory, construction
    RESTAURANT = "restaurant"      # Dining establishment
    AIRPORT = "airport"           # Transportation hub
    CUSTOM = "custom"             # User-defined environment


@dataclass
class EnvironmentParameters:
    """Parameters defining an acoustic environment"""
    name: str
    reverberation_time_ms: float  # RT60 in milliseconds
    noise_floor_db: float         # Background noise level
    frequency_response: Dict[float, float]  # Frequency -> gain mapping
    dominant_frequencies: List[float]  # Prominent frequency components
    modulation_frequency: Optional[float]  # For time-varying noise
    spectral_tilt: float          # Overall spectral slope (dB/octave)
    description: str


class StandardEnvironments:
    """
    Standard acoustic environment definitions based on real-world measurements
    """
    
    ENVIRONMENTS = {
        EnvironmentType.ANECHOIC: EnvironmentParameters(
            name="Anechoic Chamber",
            reverberation_time_ms=0.0,
            noise_floor_db=-60.0,
            frequency_response={},
            dominant_frequencies=[],
            modulation_frequency=None,
            spectral_tilt=0.0,
            description="Ideal noise-free environment with no reflections"
        ),
        
        EnvironmentType.QUIET_ROOM: EnvironmentParameters(
            name="Quiet Room",
            reverberation_time_ms=300.0,
            noise_floor_db=-45.0,
            frequency_response={60: -3, 120: -1, 1000: 0, 4000: -1, 8000: -2},
            dominant_frequencies=[60, 120],  # AC hum
            modulation_frequency=None,
            spectral_tilt=-1.0,
            description="Typical quiet indoor room with minimal ambient noise"
        ),
        
        EnvironmentType.HOME_OFFICE: EnvironmentParameters(
            name="Home Office",
            reverberation_time_ms=400.0,
            noise_floor_db=-40.0,
            frequency_response={60: -2, 250: 0, 1000: 0, 2000: 1, 4000: 0, 8000: -3},
            dominant_frequencies=[60, 120, 1200, 2400],  # AC, computer, fans
            modulation_frequency=0.5,  # Gentle variations
            spectral_tilt=-1.5,
            description="Residential workspace with computer and HVAC noise"
        ),
        
        EnvironmentType.OPEN_OFFICE: EnvironmentParameters(
            name="Open Office",
            reverberation_time_ms=600.0,
            noise_floor_db=-35.0,
            frequency_response={125: -1, 250: 0, 500: 1, 1000: 2, 2000: 1, 4000: -1, 8000: -4},
            dominant_frequencies=[60, 120, 300, 800, 1600],  # HVAC, equipment, voices
            modulation_frequency=0.2,  # Slow variations from activity
            spectral_tilt=-2.0,
            description="Commercial office with background chatter and equipment"
        ),
        
        EnvironmentType.CONFERENCE_ROOM: EnvironmentParameters(
            name="Conference Room",
            reverberation_time_ms=800.0,
            noise_floor_db=-38.0,
            frequency_response={125: 1, 250: 2, 500: 2, 1000: 1, 2000: 0, 4000: -2, 8000: -5},
            dominant_frequencies=[60, 120, 240, 1000],  # HVAC, projector
            modulation_frequency=None,
            spectral_tilt=-1.8,
            description="Meeting room with moderate reverberation and equipment noise"
        ),
        
        EnvironmentType.VEHICLE_INTERIOR: EnvironmentParameters(
            name="Vehicle Interior",
            reverberation_time_ms=150.0,
            noise_floor_db=-20.0,
            frequency_response={31: 3, 63: 5, 125: 3, 250: 1, 500: 0, 1000: -1, 2000: -2, 4000: -4, 8000: -8},
            dominant_frequencies=[80, 160, 320, 1000, 2000],  # Engine, road, wind
            modulation_frequency=1.5,  # Engine RPM variations
            spectral_tilt=-6.0,  # Strong low-frequency emphasis
            description="Automobile interior with engine, road, and wind noise"
        ),
        
        EnvironmentType.OUTDOOR_QUIET: EnvironmentParameters(
            name="Outdoor Quiet",
            reverberation_time_ms=50.0,
            noise_floor_db=-42.0,
            frequency_response={125: -2, 250: -1, 500: 0, 1000: 0, 2000: -1, 4000: -3, 8000: -6},
            dominant_frequencies=[],  # Natural ambient
            modulation_frequency=0.1,  # Wind variations
            spectral_tilt=-3.0,
            description="Quiet outdoor environment with minimal traffic"
        ),
        
        EnvironmentType.OUTDOOR_URBAN: EnvironmentParameters(
            name="Outdoor Urban",
            reverberation_time_ms=200.0,
            noise_floor_db=-25.0,
            frequency_response={63: 2, 125: 3, 250: 2, 500: 1, 1000: 0, 2000: -1, 4000: -3, 8000: -6},
            dominant_frequencies=[80, 160, 250, 500, 1000],  # Traffic, construction
            modulation_frequency=0.3,  # Traffic flow variations
            spectral_tilt=-4.0,
            description="Urban outdoor environment with traffic and activity"
        ),
        
        EnvironmentType.INDUSTRIAL: EnvironmentParameters(
            name="Industrial",
            reverberation_time_ms=1500.0,
            noise_floor_db=-15.0,
            frequency_response={125: 4, 250: 3, 500: 2, 1000: 1, 2000: 0, 4000: -2, 8000: -6},
            dominant_frequencies=[50, 100, 200, 315, 630, 1250],  # Machinery
            modulation_frequency=5.0,  # Machinery cycles
            spectral_tilt=-3.0,
            description="Factory or construction environment with heavy machinery"
        ),
        
        EnvironmentType.RESTAURANT: EnvironmentParameters(
            name="Restaurant",
            reverberation_time_ms=1000.0,
            noise_floor_db=-28.0,
            frequency_response={125: 0, 250: 1, 500: 2, 1000: 3, 2000: 2, 4000: 0, 8000: -4},
            dominant_frequencies=[200, 400, 800, 1600],  # Conversation, dishes
            modulation_frequency=0.8,  # Conversation dynamics
            spectral_tilt=-2.5,
            description="Restaurant with conversation, kitchen, and ambient sounds"
        ),
        
        EnvironmentType.AIRPORT: EnvironmentParameters(
            name="Airport",
            reverberation_time_ms=2000.0,
            noise_floor_db=-18.0,
            frequency_response={63: 3, 125: 4, 250: 3, 500: 2, 1000: 1, 2000: 0, 4000: -2, 8000: -5},
            dominant_frequencies=[63, 125, 250, 500, 800],  # HVAC, announcements, crowd
            modulation_frequency=0.05,  # Very slow variations
            spectral_tilt=-4.5,
            description="Airport terminal with HVAC, announcements, and crowd noise"
        )
    }


class NoiseGenerator:
    """
    Advanced noise generator for creating realistic acoustic environments
    """
    
    def __init__(self, sample_rate: int = 16000, random_seed: Optional[int] = None):
        self.sample_rate = sample_rate
        self.nyquist = sample_rate / 2
        
        if random_seed is not None:
            np.random.seed(random_seed)
    
    def generate_colored_noise(self, duration: float, color_exponent: float = 0.0, 
                              amplitude: float = 1.0) -> np.ndarray:
        """
        Generate colored noise with specified spectral slope
        
        Args:
            duration: Duration in seconds
            color_exponent: Spectral slope (0=white, -1=pink, -2=brown)
            amplitude: RMS amplitude
        """
        samples = int(duration * self.sample_rate)
        
        # Generate white noise
        white_noise = np.random.normal(0, 1, samples)
        
        if color_exponent == 0:
            # White noise - no filtering needed
            colored_noise = white_noise
        else:
            # Apply spectral shaping via FFT
            fft_white = np.fft.fft(white_noise)
            freqs = np.fft.fftfreq(samples, 1/self.sample_rate)
            
            # Create frequency-dependent scaling
            freq_scaling = np.ones_like(freqs, dtype=complex)
            positive_freqs = freqs > 0
            freq_scaling[positive_freqs] = (freqs[positive_freqs] / self.nyquist) ** (color_exponent / 2)
            
            # Maintain symmetry for real output
            freq_scaling[freqs < 0] = np.conj(freq_scaling[freqs > 0][::-1])
            freq_scaling[0] = 1.0  # DC component
            
            # Apply filtering
            fft_colored = fft_white * freq_scaling
            colored_noise = np.real(np.fft.ifft(fft_colored))
        
        # Normalize to desired amplitude
        if np.std(colored_noise) > 0:
            colored_noise = colored_noise / np.std(colored_noise) * amplitude
        
        return colored_noise
    
    def apply_frequency_response(self, signal: np.ndarray, 
                                frequency_response: Dict[float, float]) -> np.ndarray:
        """
        Apply frequency response curve to signal
        
        Args:
            signal: Input signal
            frequency_response: Dict mapping frequency (Hz) to gain (dB)
        """
        if not frequency_response:
            return signal
        
        # Get FFT of signal
        fft_signal = np.fft.fft(signal)
        freqs = np.fft.fftfreq(len(signal), 1/self.sample_rate)
        freqs_positive = freqs[:len(freqs)//2]
        
        # Interpolate frequency response
        response_freqs = list(frequency_response.keys())
        response_gains = list(frequency_response.values())
        
        # Add endpoints for extrapolation
        if 0 not in response_freqs:
            response_freqs.insert(0, 0)
            response_gains.insert(0, response_gains[0])
        if self.nyquist not in response_freqs:
            response_freqs.append(self.nyquist)
            response_gains.append(response_gains[-1])
        
        # Interpolate gains for all frequencies
        gains_db = np.interp(np.abs(freqs_positive), response_freqs, response_gains)
        gains_linear = 10 ** (gains_db / 20)
        
        # Apply gains (maintain symmetry)
        fft_filtered = fft_signal.copy()
        fft_filtered[:len(gains_linear)] *= gains_linear
        fft_filtered[-len(gains_linear)+1:] *= gains_linear[-2::-1]  # Mirror for negative frequencies
        
        return np.real(np.fft.ifft(fft_filtered))
    
    def add_tonal_components(self, signal: np.ndarray, 
                           frequencies: List[float], 
                           amplitudes: Optional[List[float]] = None,
                           modulation_freq: Optional[float] = None) -> np.ndarray:
        """
        Add tonal components to signal
        
        Args:
            signal: Base signal
            frequencies: List of frequencies to add
            amplitudes: Amplitude for each frequency (relative to signal RMS)
            modulation_freq: Optional amplitude modulation frequency
        """
        if not frequencies:
            return signal
        
        if amplitudes is None:
            amplitudes = [0.1] * len(frequencies)  # Default 10% of signal RMS
        
        duration = len(signal) / self.sample_rate
        t = np.linspace(0, duration, len(signal))
        signal_rms = np.sqrt(np.mean(signal**2))
        
        tonal_signal = signal.copy()
        
        for freq, amp in zip(frequencies, amplitudes):
            if freq < self.nyquist:
                tone = amp * signal_rms * np.sin(2 * np.pi * freq * t)
                
                # Apply modulation if specified
                if modulation_freq is not None:
                    modulation = 1 + 0.3 * np.sin(2 * np.pi * modulation_freq * t)
                    tone *= modulation
                
                tonal_signal += tone
        
        return tonal_signal
    
    def apply_reverberation(self, signal: np.ndarray, rt60_ms: float) -> np.ndarray:
        """
        Apply artificial reverberation to signal
        
        Args:
            signal: Input signal
            rt60_ms: Reverberation time (RT60) in milliseconds
        """
        if rt60_ms <= 0:
            return signal
        
        # Create impulse response for reverberation
        rt60_samples = int(rt60_ms * self.sample_rate / 1000)
        
        if rt60_samples < 10:
            return signal
        
        # Exponential decay
        decay_time = rt60_samples / 6.91  # Time constant for 60dB decay
        t = np.arange(rt60_samples)
        impulse_response = np.exp(-t / decay_time) * np.random.normal(0, 1, rt60_samples)
        
        # Apply some frequency-dependent decay
        impulse_response = scipy.signal.lfilter([1], [1, -0.7], impulse_response)
        
        # Normalize
        impulse_response = impulse_response / np.max(np.abs(impulse_response)) * 0.3
        
        # Convolve with signal
        reverb_signal = scipy.signal.convolve(signal, impulse_response, mode='same')
        
        return reverb_signal
    
    def generate_environment_noise(self, environment: EnvironmentType, 
                                  duration: float,
                                  base_amplitude: float = 0.1) -> np.ndarray:
        """
        Generate noise for a specific environment type
        
        Args:
            environment: Environment type
            duration: Duration in seconds
            base_amplitude: Base noise amplitude (RMS)
        """
        if environment not in StandardEnvironments.ENVIRONMENTS:
            raise ValueError(f"Unknown environment: {environment}")
        
        params = StandardEnvironments.ENVIRONMENTS[environment]
        
        # Start with colored noise based on spectral tilt
        color_exponent = params.spectral_tilt / 6.0  # Convert dB/octave to exponent
        base_noise = self.generate_colored_noise(duration, color_exponent, base_amplitude)
        
        # Apply frequency response
        shaped_noise = self.apply_frequency_response(base_noise, params.frequency_response)
        
        # Add tonal components
        if params.dominant_frequencies:
            # Amplitudes decrease with frequency index
            amplitudes = [0.15 / (i + 1) for i in range(len(params.dominant_frequencies))]
            tonal_noise = self.add_tonal_components(
                shaped_noise, 
                params.dominant_frequencies, 
                amplitudes,
                params.modulation_frequency
            )
        else:
            tonal_noise = shaped_noise
        
        # Apply reverberation
        if params.reverberation_time_ms > 0:
            reverb_noise = self.apply_reverberation(tonal_noise, params.reverberation_time_ms)
        else:
            reverb_noise = tonal_noise
        
        # Scale to noise floor level
        noise_floor_linear = 10 ** (params.noise_floor_db / 20)
        final_noise = reverb_noise / np.sqrt(np.mean(reverb_noise**2)) * noise_floor_linear
        
        return final_noise


class ImpulseNoiseGenerator:
    """
    Generator for impulsive noise events (door slams, phone rings, etc.)
    """
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
    
    def generate_door_slam(self, amplitude: float = 0.5) -> np.ndarray:
        """Generate door slam impulse"""
        duration = 0.3  # 300ms
        samples = int(duration * self.sample_rate)
        t = np.linspace(0, duration, samples)
        
        # Sharp attack, exponential decay
        envelope = np.exp(-t * 15)
        
        # Broadband noise with low-frequency emphasis
        noise = np.random.normal(0, 1, samples)
        
        # Low-pass filter for realistic frequency content
        b, a = scipy.signal.butter(4, 1000 / (self.sample_rate/2), 'low')
        filtered_noise = scipy.signal.filtfilt(b, a, noise)
        
        return amplitude * envelope * filtered_noise
    
    def generate_phone_ring(self, frequency: float = 1000, 
                           ring_duration: float = 1.0) -> np.ndarray:
        """Generate phone ring tone"""
        samples = int(ring_duration * self.sample_rate)
        t = np.linspace(0, ring_duration, samples)
        
        # Dual-tone with amplitude modulation
        tone1 = np.sin(2 * np.pi * frequency * t)
        tone2 = np.sin(2 * np.pi * (frequency * 1.2) * t)
        
        # Ring pattern (on-off modulation)
        ring_pattern = np.where((t % 0.5) < 0.25, 1, 0)
        
        return 0.3 * (tone1 + tone2) * ring_pattern
    
    def generate_keyboard_typing(self, duration: float, 
                                typing_rate: float = 5.0) -> np.ndarray:
        """Generate keyboard typing sounds"""
        samples = int(duration * self.sample_rate)
        output = np.zeros(samples)
        
        # Random key presses
        key_interval = self.sample_rate / typing_rate
        
        for i in range(0, samples, int(key_interval)):
            if np.random.random() < 0.8:  # 80% chance of key press
                # Short click sound
                click_duration = int(0.02 * self.sample_rate)  # 20ms
                if i + click_duration < samples:
                    t_click = np.linspace(0, 0.02, click_duration)
                    click = 0.1 * np.exp(-t_click * 50) * np.random.normal(0, 1, click_duration)
                    output[i:i + click_duration] += click
        
        return output
    
    def generate_footsteps(self, duration: float, 
                          step_rate: float = 2.0) -> np.ndarray:
        """Generate footstep sounds"""
        samples = int(duration * self.sample_rate)
        output = np.zeros(samples)
        
        step_interval = self.sample_rate / step_rate
        
        for i in range(0, samples, int(step_interval)):
            if np.random.random() < 0.9:  # 90% regularity
                # Footstep impact
                step_duration = int(0.1 * self.sample_rate)  # 100ms
                if i + step_duration < samples:
                    t_step = np.linspace(0, 0.1, step_duration)
                    
                    # Low-frequency thump with some higher frequency content
                    low_freq = 0.2 * np.sin(2 * np.pi * 60 * t_step) * np.exp(-t_step * 20)
                    high_freq = 0.1 * np.random.normal(0, 1, step_duration) * np.exp(-t_step * 30)
                    
                    step = low_freq + high_freq
                    output[i:i + step_duration] += step
        
        return output


class SNRTestSignalGenerator:
    """
    Generates test signals at specific SNR levels for evaluation
    """
    
    def __init__(self, sample_rate: int = 16000):
        self.sample_rate = sample_rate
        self.noise_gen = NoiseGenerator(sample_rate)
        self.impulse_gen = ImpulseNoiseGenerator(sample_rate)
    
    def create_snr_test_suite(self, clean_signal: np.ndarray, 
                             test_snrs: List[float],
                             noise_types: List[str] = None) -> Dict[str, Dict[float, np.ndarray]]:
        """
        Create comprehensive SNR test suite
        
        Args:
            clean_signal: Clean reference signal
            test_snrs: List of SNR values to test (in dB)
            noise_types: List of noise types to test
        
        Returns:
            Dictionary organized as {noise_type: {snr: noisy_signal}}
        """
        if noise_types is None:
            noise_types = ['white', 'pink', 'office', 'vehicle', 'outdoor']
        
        duration = len(clean_signal) / self.sample_rate
        test_suite = {}
        
        for noise_type in noise_types:
            test_suite[noise_type] = {}
            
            # Generate appropriate noise
            if noise_type == 'white':
                noise = self.noise_gen.generate_colored_noise(duration, 0, 1.0)
            elif noise_type == 'pink':
                noise = self.noise_gen.generate_colored_noise(duration, -1, 1.0)
            elif noise_type == 'office':
                noise = self.noise_gen.generate_environment_noise(EnvironmentType.OPEN_OFFICE, duration, 1.0)
            elif noise_type == 'vehicle':
                noise = self.noise_gen.generate_environment_noise(EnvironmentType.VEHICLE_INTERIOR, duration, 1.0)
            elif noise_type == 'outdoor':
                noise = self.noise_gen.generate_environment_noise(EnvironmentType.OUTDOOR_URBAN, duration, 1.0)
            else:
                # Default to white noise
                noise = self.noise_gen.generate_colored_noise(duration, 0, 1.0)
            
            # Create signals at different SNRs
            for snr in test_snrs:
                noisy_signal = self.add_noise_at_snr(clean_signal, noise, snr)
                test_suite[noise_type][snr] = noisy_signal
        
        return test_suite
    
    def add_noise_at_snr(self, signal: np.ndarray, noise: np.ndarray, 
                        target_snr_db: float) -> np.ndarray:
        """Add noise to signal at specific SNR"""
        # Ensure noise is same length as signal
        if len(noise) != len(signal):
            if len(noise) > len(signal):
                noise = noise[:len(signal)]
            else:
                # Repeat noise to match signal length
                repeats = int(np.ceil(len(signal) / len(noise)))
                noise = np.tile(noise, repeats)[:len(signal)]
        
        # Calculate signal and noise power
        signal_power = np.mean(signal ** 2)
        noise_power = np.mean(noise ** 2)
        
        # Calculate required noise scaling
        target_noise_power = signal_power / (10 ** (target_snr_db / 10))
        
        if noise_power > 0:
            noise_scale = np.sqrt(target_noise_power / noise_power)
        else:
            noise_scale = 0
        
        return signal + noise * noise_scale


def create_standard_test_signals(sample_rate: int = 16000, 
                                duration: float = 5.0) -> Dict[str, np.ndarray]:
    """
    Create standard test signals for noise robustness evaluation
    
    Returns:
        Dictionary of test signal name -> signal array
    """
    noise_gen = NoiseGenerator(sample_rate)
    impulse_gen = ImpulseNoiseGenerator(sample_rate)
    
    test_signals = {}
    
    # Environmental noise signals
    for env_type in [EnvironmentType.QUIET_ROOM, EnvironmentType.HOME_OFFICE, 
                     EnvironmentType.OPEN_OFFICE, EnvironmentType.VEHICLE_INTERIOR,
                     EnvironmentType.OUTDOOR_URBAN, EnvironmentType.RESTAURANT]:
        signal = noise_gen.generate_environment_noise(env_type, duration, 0.1)
        test_signals[f"env_{env_type.value}"] = signal
    
    # Colored noise signals
    for color, exponent in [("white", 0), ("pink", -1), ("brown", -2)]:
        signal = noise_gen.generate_colored_noise(duration, exponent, 0.1)
        test_signals[f"noise_{color}"] = signal
    
    # Impulsive noise signals
    impulse_signals = [
        ("door_slams", impulse_gen.generate_door_slam),
        ("phone_ring", lambda: impulse_gen.generate_phone_ring(ring_duration=duration)),
        ("typing", lambda: impulse_gen.generate_keyboard_typing(duration)),
        ("footsteps", lambda: impulse_gen.generate_footsteps(duration))
    ]
    
    for name, generator in impulse_signals:
        test_signals[f"impulse_{name}"] = generator()
    
    return test_signals


def save_test_signals(output_dir: Path, sample_rate: int = 16000):
    """
    Generate and save standard test signals to disk
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate test signals
    test_signals = create_standard_test_signals(sample_rate, duration=10.0)
    
    # Save metadata
    metadata = {
        "sample_rate": sample_rate,
        "duration": 10.0,
        "description": "Standard noise test signals for VoiceFlow robustness testing",
        "signals": list(test_signals.keys()),
        "environments": [env.value for env in StandardEnvironments.ENVIRONMENTS.keys()]
    }
    
    with open(output_dir / "test_signals_metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    
    # Save signals as numpy arrays
    for name, signal in test_signals.items():
        np.save(output_dir / f"{name}.npy", signal)
    
    print(f"✅ Saved {len(test_signals)} test signals to {output_dir}")
    print(f"📊 Total file size: {sum((output_dir / f'{name}.npy').stat().st_size for name in test_signals) / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    # Demo: Generate and save test signals
    output_path = Path(__file__).parent.parent / "test_results" / "noise_test_signals"
    save_test_signals(output_path)