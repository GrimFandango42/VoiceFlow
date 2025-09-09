from __future__ import annotations

import threading
from typing import Optional, List
from collections import deque
import time

import numpy as np
import sounddevice as sd

from .config import Config


class BoundedRingBuffer:
    """Memory-safe ring buffer for audio data with size limits"""
    
    def __init__(self, max_duration_seconds: float, sample_rate: int):
        self.max_samples = int(max_duration_seconds * sample_rate)
        self.sample_rate = sample_rate
        self.buffer = np.zeros(self.max_samples, dtype=np.float32)
        self.write_pos = 0
        self.samples_written = 0
        self.lock = threading.Lock()
        print(f"[AudioBuffer] Initialized with {max_duration_seconds}s capacity ({self.max_samples} samples)")
    
    def append(self, data: np.ndarray):
        """Add data to ring buffer, overwriting old data if full"""
        with self.lock:
            data_len = len(data)
            
            if data_len >= self.max_samples:
                # Data larger than buffer - take only the most recent part
                data = data[-self.max_samples:]
                data_len = len(data)
                self.buffer[:data_len] = data
                self.write_pos = data_len % self.max_samples
                self.samples_written = data_len
                return
            
            # Normal case: append to buffer
            end_pos = self.write_pos + data_len
            
            if end_pos <= self.max_samples:
                # No wraparound needed
                self.buffer[self.write_pos:end_pos] = data
            else:
                # Wraparound needed
                first_part_len = self.max_samples - self.write_pos
                self.buffer[self.write_pos:] = data[:first_part_len]
                remaining = data[first_part_len:]
                self.buffer[:len(remaining)] = remaining
            
            self.write_pos = end_pos % self.max_samples
            self.samples_written += data_len
    
    def get_data(self) -> np.ndarray:
        """Get all data from buffer in correct order"""
        with self.lock:
            if self.samples_written == 0:
                return np.array([], dtype=np.float32)
            
            if self.samples_written < self.max_samples:
                # Buffer not full yet - return from start to write_pos
                return self.buffer[:self.write_pos].copy()
            else:
                # Buffer is full - return from write_pos to end, then from start to write_pos
                return np.concatenate([
                    self.buffer[self.write_pos:],
                    self.buffer[:self.write_pos]
                ])
    
    def clear(self):
        """Clear the buffer"""
        with self.lock:
            self.write_pos = 0
            self.samples_written = 0
    
    def get_duration_seconds(self) -> float:
        """Get current data duration in seconds"""
        with self.lock:
            return min(self.samples_written, self.max_samples) / self.sample_rate


class EnhancedAudioRecorder:
    """Enhanced audio recorder with memory-safe bounded buffers"""
    
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._stream: Optional[sd.InputStream] = None
        
        # CRITICAL FIX: Bounded buffer instead of unlimited list
        max_duration = 300.0  # 5 minutes maximum
        self._ring_buffer = BoundedRingBuffer(max_duration, cfg.sample_rate)
        
        self._lock = threading.Lock()
        self._recording = False
        self._start_time = 0.0
        
        # Performance monitoring
        self._callback_count = 0
        self._total_frames = 0
        
        print(f"[AudioRecorder] Enhanced recorder initialized:")
        print(f"  - Sample rate: {cfg.sample_rate}Hz")
        print(f"  - Channels: {cfg.channels}")
        print(f"  - Block size: {cfg.blocksize} frames")
        print(f"  - Max duration: {max_duration}s")

    def _callback(self, indata, frames, time, status):
        """Enhanced audio callback with bounded buffer"""
        if status:
            # Log non-fatal warnings from PortAudio
            print(f"[AudioRecorder] PortAudio warning: {status}")
        
        if not self._recording:
            return
        
        self._callback_count += 1
        self._total_frames += frames
        
        # Convert to mono if needed
        data = indata.copy()
        if data.ndim == 2 and data.shape[1] > 1:
            data = np.mean(data, axis=1, keepdims=True)
        
        # Add to bounded buffer (thread-safe)
        audio_data = data.reshape(-1).astype(np.float32)
        self._ring_buffer.append(audio_data)
        
        # Performance logging every 100 callbacks (~6.4 seconds at 64ms blocks)
        if self._callback_count % 100 == 0:
            duration = self._ring_buffer.get_duration_seconds()
            print(f"[AudioRecorder] Recording: {duration:.1f}s ({self._callback_count} callbacks)")

    def start(self):
        """Start recording with enhanced monitoring"""
        if self._recording:
            return
        
        print("[AudioRecorder] Starting enhanced recording...")
        self._ring_buffer.clear()
        self._callback_count = 0
        self._total_frames = 0
        self._start_time = time.time()
        
        self._stream = sd.InputStream(
            channels=self.cfg.channels,
            samplerate=self.cfg.sample_rate,
            dtype="float32",
            blocksize=self.cfg.blocksize,
            callback=self._callback,
        )
        self._stream.start()
        self._recording = True
        print(f"[AudioRecorder] Recording started successfully")

    def is_recording(self) -> bool:
        """Check if currently recording"""
        return self._recording

    def stop(self) -> np.ndarray:
        """Stop recording and return audio data"""
        if not self._recording:
            return np.array([], dtype=np.float32)

        try:
            self._recording = False
            if self._stream is not None:
                self._stream.stop()
                self._stream.close()
                self._stream = None
            
            # Get the recorded audio data
            audio_data = self._ring_buffer.get_data()
            duration = len(audio_data) / self.cfg.sample_rate
            
            # Performance summary
            actual_duration = time.time() - self._start_time
            print(f"[AudioRecorder] Recording stopped:")
            print(f"  - Audio duration: {duration:.2f}s")
            print(f"  - Actual duration: {actual_duration:.2f}s")
            print(f"  - Callbacks: {self._callback_count}")
            print(f"  - Samples: {len(audio_data)}")
            print(f"  - Memory usage: {len(audio_data) * 4 / 1024 / 1024:.2f}MB")
            
            return audio_data
            
        except Exception as e:
            print(f"[AudioRecorder] Error stopping recording: {e}")
            return np.array([], dtype=np.float32)
    
    def get_current_duration(self) -> float:
        """Get current recording duration in seconds"""
        return self._ring_buffer.get_duration_seconds()
    
    def get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB"""
        return self._ring_buffer.max_samples * 4 / 1024 / 1024  # 4 bytes per float32


# Compatibility alias for drop-in replacement
AudioRecorder = EnhancedAudioRecorder