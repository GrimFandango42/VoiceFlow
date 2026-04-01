"""Audio preprocessing pipeline for VoiceFlow.

Applies signal conditioning to raw captured audio before it reaches Whisper:
- High-pass filter (FFT-based, zero-phase): removes HVAC rumble and low-frequency noise
- RMS normalization: scales audio to a consistent loudness level
- Noise gate (optional): zeroes frames below an energy threshold

All stages are configurable via Config and can be toggled independently.
Only numpy is used — no scipy dependency.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from voiceflow.core.config import Config

logger = logging.getLogger(__name__)

# Minimum RMS below which normalization is skipped (silence / near-silence)
_SILENCE_RMS_FLOOR = 1e-9


class AudioPreprocessor:
    """Applies configurable signal conditioning to mono float32 audio."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def process(self, audio: np.ndarray) -> np.ndarray:
        """Run the enabled preprocessing stages and return conditioned audio.

        The pipeline order is intentional:
        1. High-pass filter first — removes DC and rumble before measuring levels
        2. Noise gate — blanks silent frames on the rumble-free signal
        3. RMS normalization last — scales the gated signal to a consistent level
        """
        if not getattr(self.cfg, "audio_preprocessing_enabled", True):
            return audio

        if len(audio) == 0:
            return audio

        if getattr(self.cfg, "audio_highpass_enabled", True):
            audio = self._apply_highpass(audio)

        if getattr(self.cfg, "audio_noise_gate_enabled", False):
            audio = self._apply_noise_gate(audio)

        if getattr(self.cfg, "audio_normalize_enabled", True):
            audio = self._apply_rms_normalize(audio)

        return audio

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _apply_highpass(self, audio: np.ndarray) -> np.ndarray:
        """Zero-phase high-pass filter implemented via FFT.

        Removes frequency content below ``audio_highpass_cutoff_hz`` (default
        80 Hz).  FFT-domain masking gives linear-phase behaviour with no
        group-delay artefacts, which matters for short PTT clips.

        Short clips below 32 samples are returned unchanged.
        """
        n = len(audio)
        if n < 32:
            return audio

        cutoff_hz: float = getattr(self.cfg, "audio_highpass_cutoff_hz", 80.0)
        sample_rate: int = getattr(self.cfg, "sample_rate", 16000)

        spectrum = np.fft.rfft(audio)
        freqs = np.fft.rfftfreq(n, d=1.0 / sample_rate)
        spectrum[freqs < cutoff_hz] = 0.0
        filtered = np.fft.irfft(spectrum, n=n)
        return filtered.astype(np.float32)

    def _apply_rms_normalize(self, audio: np.ndarray) -> np.ndarray:
        """Scale audio so its RMS matches ``audio_normalize_target_rms``.

        Gain is capped at ``audio_normalize_max_gain`` (linear) to avoid
        amplifying near-silent recordings into noise.  The result is hard-
        clipped to [-1, 1] to prevent downstream overflow.
        """
        rms = float(np.sqrt(np.mean(audio.astype(np.float64) ** 2)))
        if rms < _SILENCE_RMS_FLOOR:
            # True silence — don't amplify
            return audio

        target_rms: float = getattr(self.cfg, "audio_normalize_target_rms", 0.1)
        max_gain: float = getattr(self.cfg, "audio_normalize_max_gain", 10.0)

        gain = min(target_rms / rms, max_gain)
        normalized = np.clip(audio * gain, -1.0, 1.0)
        return normalized.astype(np.float32)

    def _apply_noise_gate(self, audio: np.ndarray) -> np.ndarray:
        """Frame-based noise gate with smooth crossfade at gate boundaries.

        Frames whose RMS falls below ``audio_noise_gate_threshold`` are
        attenuated to zero.  A half-cosine crossfade of ``_FADE_SAMPLES``
        samples is applied at each open→close and close→open transition to
        avoid audible clicks.
        """
        sample_rate: int = getattr(self.cfg, "sample_rate", 16000)
        frame_ms: float = getattr(self.cfg, "audio_noise_gate_frame_ms", 20.0)
        threshold: float = getattr(self.cfg, "audio_noise_gate_threshold", 0.005)

        frame_size = max(1, int(frame_ms * sample_rate / 1000.0))
        n = len(audio)
        out = audio.copy()

        # Compute per-frame gain (1.0 = pass, 0.0 = gate closed)
        n_frames = (n + frame_size - 1) // frame_size
        frame_gains = np.ones(n_frames, dtype=np.float32)
        for fi in range(n_frames):
            start = fi * frame_size
            end = min(start + frame_size, n)
            rms = float(np.sqrt(np.mean(audio[start:end].astype(np.float64) ** 2)))
            if rms < threshold:
                frame_gains[fi] = 0.0

        # Expand frame gains to sample-level and apply crossfade
        _FADE_SAMPLES = min(frame_size // 2, 64)
        for fi in range(n_frames):
            start = fi * frame_size
            end = min(start + frame_size, n)
            g = frame_gains[fi]

            if g == 0.0:
                # Apply crossfade at the leading edge if previous frame was open
                fade_in_end = start + _FADE_SAMPLES
                if fi > 0 and frame_gains[fi - 1] > 0.0 and fade_in_end <= n:
                    fade = np.linspace(1.0, 0.0, _FADE_SAMPLES, dtype=np.float32)
                    out[start:fade_in_end] *= fade
                    out[fade_in_end:end] = 0.0
                else:
                    out[start:end] = 0.0
            else:
                # Apply crossfade at the leading edge if previous frame was closed
                fade_in_end = start + _FADE_SAMPLES
                if fi > 0 and frame_gains[fi - 1] == 0.0 and fade_in_end <= n:
                    fade = np.linspace(0.0, 1.0, _FADE_SAMPLES, dtype=np.float32)
                    out[start:fade_in_end] *= fade
                    # rest of frame is already audio * 1.0

        return out
