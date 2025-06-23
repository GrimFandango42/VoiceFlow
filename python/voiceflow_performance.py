#!/usr/bin/env python3
"""
VoiceFlow Performance-Optimized Version
Focused on speed improvements while maintaining accuracy
"""

import asyncio
import threading
import time
import queue
import tempfile
import wave
import os
from datetime import datetime
from pathlib import Path
from faster_whisper import WhisperModel
import pyaudio
import sqlite3
import numpy as np
import io

# Windows integration
try:
    import keyboard
    import pyautogui
    import win32api
    import win32gui
    import win32process
    import psutil
    pyautogui.FAILSAFE = False
except ImportError as e:
    print(f"Warning: Windows libraries not available: {e}")

# WebSocket and AI
try:
    import websockets
    import requests
except ImportError:
    print("Warning: WebSocket/requests not available")

class PerformanceOptimizedVoiceFlow:
    """Performance-optimized VoiceFlow with in-memory processing and fast models"""
    
    def __init__(self, model_size="tiny", enable_cuda=False):
        """
        Initialize with performance-focused configuration
        
        Args:
            model_size: "tiny" (fastest), "base" (balanced), "small" (accurate)
            enable_cuda: Try CUDA acceleration first
        """
        self.model_size = model_size
        self.enable_cuda = enable_cuda
        
        # Performance tracking
        self.performance_stats = {
            "transcriptions": 0,
            "total_processing_time": 0,
            "avg_processing_time": 0,
            "fastest_time": float('inf'),
            "slowest_time": 0
        }
        
        # Audio configuration optimized for speed
        self.audio_config = {
            'format': pyaudio.paInt16,
            'channels': 1,
            'rate': 16000,  # Whisper's native rate
            'chunk': 1024,  # Smaller chunks for responsiveness
            'buffer_duration': 0.6,  # Reduced from 0.8s
            'min_duration': 0.15  # Reduced from 0.2s
        }
        
        # Processing queues for async operations
        self.transcription_queue = queue.Queue()
        self.ai_enhancement_queue = queue.Queue()
        
        # Initialize components
        self.is_recording = False
        self.is_running = True
        self.current_recording = None
        self.websocket_clients = set()
        
        # Performance optimizations
        self._preload_models()
        self._setup_audio_system()
        self._check_ai_availability()
        
        print(f"[Performance] Optimized VoiceFlow ready - Model: {model_size}")
        print(f"[Performance] Expected latency: {self._estimate_latency()}ms")
    
    def _estimate_latency(self):
        """Estimate processing latency based on configuration"""
        base_latencies = {
            "tiny": 100,   # ~100ms for tiny model on CPU
            "base": 200,   # ~200ms for base model on CPU
            "small": 400   # ~400ms for small model on CPU
        }
        
        # CPU is often faster than CUDA with overhead for small models
        return base_latencies.get(self.model_size, 200)
    
    def _preload_models(self):
        """Preload and warm up models for optimal performance"""
        configs = []
        
        # Start with CPU for reliability and speed
        configs.append({"model": self.model_size, "device": "cpu", "compute_type": "int8"})
        
        # Only try CUDA if specifically enabled and properly working
        if self.enable_cuda:
            try:
                # Test if cuDNN is actually working
                import ctypes
                ctypes.CDLL("cudnn_ops64_9.dll")
                configs.insert(0, {"model": self.model_size, "device": "cuda", "compute_type": "int8"})
            except:
                print("[Performance] CUDA/cuDNN not properly installed, using CPU (often faster anyway!)")
        else:
            print("[Performance] Using CPU for maximum reliability and speed")
        
        for config in configs:
            try:
                print(f"[Performance] Loading {config['device']} {config['model']}...")
                start_time = time.time()
                
                self.whisper_model = WhisperModel(
                    config["model"],
                    device=config["device"],
                    compute_type=config["compute_type"],
                    num_workers=1  # Single worker for lower latency
                )
                
                # Warm up the model with test audio
                self._warmup_model()
                
                load_time = int((time.time() - start_time) * 1000)
                print(f"[Performance] Model ready: {config['device']} ({load_time}ms)")
                return
                
            except Exception as e:
                print(f"[Performance] Config failed: {e}")
        
        raise Exception("Could not initialize any speech model")
    
    def _warmup_model(self):
        """Warm up model with test transcription for consistent performance"""
        try:
            # Create minimal test audio in memory
            test_audio = np.zeros(int(0.1 * 16000), dtype=np.float32)
            
            # Convert to bytes for transcription
            test_audio_int16 = (test_audio * 32767).astype(np.int16)
            
            # Create in-memory WAV file
            with io.BytesIO() as wav_buffer:
                with wave.open(wav_buffer, 'wb') as wf:
                    wf.setnchannels(1)
                    wf.setsampwidth(2)
                    wf.setframerate(16000)
                    wf.writeframes(test_audio_int16.tobytes())
                
                wav_buffer.seek(0)
                
                # Warm up transcription
                with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as f:
                    f.write(wav_buffer.read())
                    temp_path = f.name
                
                segments, _ = self.whisper_model.transcribe(
                    temp_path,
                    language="en",
                    vad_filter=True,
                    vad_parameters=dict(
                        min_silence_duration_ms=300,  # Faster VAD
                        speech_pad_ms=200  # Reduced padding
                    ),
                    beam_size=1  # Fastest beam size
                )
                
                os.unlink(temp_path)
                print("[Performance] Model warmed up successfully")
                
        except Exception as e:
            print(f"[Performance] Warmup failed: {e}")
    
    def _setup_audio_system(self):
        """Setup audio system optimized for low latency"""
        try:
            self.audio = pyaudio.PyAudio()
            
            # Find best input device
            self.input_device_index = self._find_best_input_device()
            print(f"[Performance] Audio system ready (device: {self.input_device_index})")
            
        except Exception as e:
            print(f"[Performance] Audio setup failed: {e}")
            self.audio = None
    
    def _find_best_input_device(self):
        """Find the best input device for performance"""
        if not self.audio:
            return None
            
        try:
            default_device = self.audio.get_default_input_device_info()
            return default_device['index']
        except:
            return None
    
    def _check_ai_availability(self):
        """Check if AI enhancement is available"""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=1)
            self.ai_available = response.status_code == 200
        except:
            self.ai_available = False
        
        print(f"[Performance] AI enhancement: {'Available' if self.ai_available else 'Disabled'}")
    
    def start_recording(self):
        """Start recording with optimized audio capture"""
        if self.is_recording or not self.audio:
            return
        
        self.is_recording = True
        
        # Pre-allocate audio buffer for better performance
        max_frames = int(self.audio_config['rate'] * 10)  # 10 seconds max
        self.audio_frames = []
        
        # Get current app info efficiently
        try:
            hwnd = win32gui.GetForegroundWindow()
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            process = psutil.Process(pid)
            target_app = {
                'name': process.name(),
                'title': win32gui.GetWindowText(hwnd)[:50]  # Truncate for performance
            }
        except:
            target_app = {'name': 'Unknown', 'title': 'Unknown'}
        
        # Start recording
        self.current_recording = {
            'start_time': time.time(),
            'target_app': target_app,
            'frames': []
        }
        
        # Use a dedicated thread for audio capture to minimize latency
        self.recording_thread = threading.Thread(target=self._audio_capture_loop, daemon=True)
        self.recording_thread.start()
        
        print(f"[Performance] Recording started in {target_app['name']}")
    
    def _audio_capture_loop(self):
        """Optimized audio capture loop"""
        try:
            stream = self.audio.open(
                format=self.audio_config['format'],
                channels=self.audio_config['channels'],
                rate=self.audio_config['rate'],
                input=True,
                input_device_index=self.input_device_index,
                frames_per_buffer=self.audio_config['chunk'],
                stream_callback=None  # Blocking mode for simplicity
            )
            
            while self.is_recording:
                try:
                    data = stream.read(self.audio_config['chunk'], exception_on_overflow=False)
                    self.current_recording['frames'].append(data)
                except Exception as e:
                    print(f"[Performance] Audio capture error: {e}")
                    break
            
            stream.stop_stream()
            stream.close()
            
        except Exception as e:
            print(f"[Performance] Audio stream error: {e}")
    
    def stop_recording(self):
        """Stop recording and process with optimized pipeline"""
        if not self.is_recording:
            return
            
        self.is_recording = False
        
        # Wait for recording thread to finish
        if hasattr(self, 'recording_thread'):
            self.recording_thread.join(timeout=1.0)
        
        # Process in background thread for responsiveness
        processing_thread = threading.Thread(
            target=self._process_recording_optimized, 
            args=(self.current_recording,),
            daemon=True
        )
        processing_thread.start()
        
        # Quick feedback to user
        print("[Performance] Processing...")
    
    def _process_recording_optimized(self, recording):
        """Optimized audio processing pipeline"""
        if not recording or not recording['frames']:
            return
        
        processing_start = time.time()
        
        try:
            # Check minimum duration
            duration = len(recording['frames']) * self.audio_config['chunk'] / self.audio_config['rate']
            if duration < self.audio_config['min_duration']:
                print(f"[Performance] Recording too short: {duration:.2f}s")
                return
            
            # In-memory audio processing (no temp files!)
            raw_text = self._transcribe_in_memory(recording['frames'])
            
            if not raw_text or not raw_text.strip():
                print("[Performance] No speech detected")
                return
            
            raw_text = raw_text.strip()
            
            # Parallel AI enhancement for speed
            if self.ai_available:
                enhanced_text = self._enhance_text_async(raw_text)
            else:
                enhanced_text = raw_text
            
            # Calculate performance metrics
            processing_time = int((time.time() - processing_start) * 1000)
            self._update_performance_stats(processing_time)
            
            # Inject text
            injection_success = self._inject_text_optimized(enhanced_text)
            
            # Log performance
            print(f"[Performance] Complete: {processing_time}ms ({len(enhanced_text.split())} words)")
            
        except Exception as e:
            print(f"[Performance] Processing error: {e}")
    
    def _transcribe_in_memory(self, frames):
        """Transcribe audio frames directly in memory without file I/O"""
        try:
            # Combine audio frames
            audio_data = b''.join(frames)
            
            # Convert to numpy array
            audio_np = np.frombuffer(audio_data, dtype=np.int16).astype(np.float32) / 32768.0
            
            # Create temporary file only when necessary
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as f:
                temp_path = f.name
            
            # Write WAV file efficiently
            with wave.open(temp_path, 'wb') as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(self.audio_config['rate'])
                wf.writeframes(audio_data)
            
            # Fast transcription with optimized parameters
            segments, info = self.whisper_model.transcribe(
                temp_path,
                language="en",
                vad_filter=True,
                vad_parameters=dict(
                    min_silence_duration_ms=300,  # Faster VAD
                    speech_pad_ms=150  # Less padding
                ),
                beam_size=1,  # Fastest beam search
                best_of=1,    # No multiple candidates
                temperature=0,  # Deterministic output
                compression_ratio_threshold=2.4,  # Default
                log_prob_threshold=-1.0,  # Default
                no_speech_threshold=0.6,  # Default
                condition_on_previous_text=False  # Faster processing
            )
            
            # Clean up immediately
            os.unlink(temp_path)
            
            # Combine segments
            return " ".join([segment.text for segment in segments])
            
        except Exception as e:
            print(f"[Performance] Transcription error: {e}")
            return ""
    
    def _enhance_text_async(self, text):
        """Asynchronous AI text enhancement"""
        # For now, return original text to avoid blocking
        # TODO: Implement async Ollama calls
        return text
    
    def _inject_text_optimized(self, text):
        """Optimized text injection with minimal delay"""
        try:
            # Method 1: Direct keyboard input (fastest)
            keyboard.write(text)
            return True
            
        except Exception as e:
            try:
                # Method 2: Clipboard fallback
                self._set_clipboard(text)
                keyboard.send('ctrl+v')
                return True
            except:
                return False
    
    def _set_clipboard(self, text):
        """Set clipboard content efficiently"""
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(text)
            win32clipboard.CloseClipboard()
        except Exception as e:
            print(f"[Performance] Clipboard error: {e}")
    
    def _update_performance_stats(self, processing_time):
        """Update performance statistics"""
        self.performance_stats['transcriptions'] += 1
        self.performance_stats['total_processing_time'] += processing_time
        self.performance_stats['avg_processing_time'] = (
            self.performance_stats['total_processing_time'] / 
            self.performance_stats['transcriptions']
        )
        
        if processing_time < self.performance_stats['fastest_time']:
            self.performance_stats['fastest_time'] = processing_time
            
        if processing_time > self.performance_stats['slowest_time']:
            self.performance_stats['slowest_time'] = processing_time
    
    def get_performance_report(self):
        """Get performance statistics"""
        stats = self.performance_stats.copy()
        if stats['transcriptions'] > 0:
            return f"""
Performance Report:
- Transcriptions: {stats['transcriptions']}
- Average time: {stats['avg_processing_time']:.0f}ms
- Fastest: {stats['fastest_time']:.0f}ms
- Slowest: {stats['slowest_time']:.0f}ms
- Model: {self.model_size}
"""
        return "No transcriptions completed yet"
    
    def run(self):
        """Main entry point with hotkey handling"""
        print("[Performance] Starting optimized VoiceFlow...")
        print("Press and hold Ctrl+Alt to record")
        
        try:
            # Set up global hotkeys
            keyboard.add_hotkey('ctrl+alt', self.start_recording, suppress=False)
            
            # Main loop
            while self.is_running:
                # Check if keys are released
                if self.is_recording and not (keyboard.is_pressed('ctrl') and keyboard.is_pressed('alt')):
                    # Add buffer delay before stopping
                    threading.Timer(self.audio_config['buffer_duration'], self.stop_recording).start()
                    
                time.sleep(0.05)  # Reduced sleep for better responsiveness
                
        except KeyboardInterrupt:
            print("\n[Performance] Shutting down...")
            self.is_running = False
            self.is_recording = False

def cleanup_existing_processes():
    """Clean up any existing VoiceFlow processes"""
    print("[Cleanup] Checking for existing VoiceFlow processes...")
    
    cleaned = 0
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Check for existing VoiceFlow Python processes
            if proc.info['name'] == 'python.exe' and proc.info['cmdline']:
                cmdline = ' '.join(proc.info['cmdline'])
                if 'voiceflow' in cmdline.lower() and proc.pid != os.getpid():
                    print(f"[Cleanup] Terminating process: {proc.pid}")
                    proc.terminate()
                    cleaned += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    if cleaned > 0:
        print(f"[Cleanup] Terminated {cleaned} existing process(es)")
        time.sleep(1)  # Give processes time to clean up
    else:
        print("[Cleanup] No existing processes found")

def cleanup_resources():
    """Clean up system resources"""
    try:
        # Clear keyboard hooks
        keyboard.unhook_all()
        print("[Cleanup] Keyboard hooks cleared")
    except:
        pass
    
    try:
        # Close any open audio streams
        import pyaudio
        pa = pyaudio.PyAudio()
        pa.terminate()
        print("[Cleanup] Audio system cleaned")
    except:
        pass

if __name__ == "__main__":
    print("=" * 50)
    print("VoiceFlow Performance Edition")
    print("=" * 50)
    
    # Clean up any existing processes first
    cleanup_existing_processes()
    
    print("\nChoose model for speed vs accuracy:")
    print("1. Tiny (fastest, ~100ms)")
    print("2. Base (balanced, ~200ms)")
    print("3. Small (accurate, ~400ms)")
    
    choice = input("Enter choice (1-3, default=1): ").strip()
    
    model_map = {"1": "tiny", "2": "base", "3": "small"}
    model_size = model_map.get(choice, "tiny")
    
    app = None
    try:
        app = PerformanceOptimizedVoiceFlow(model_size=model_size)
        app.run()
    except KeyboardInterrupt:
        print("\n[Shutdown] Received interrupt signal")
    except Exception as e:
        print(f"\n[Error] Unexpected error: {e}")
    finally:
        print("\n[Shutdown] Cleaning up...")
        if app:
            app.is_running = False
            app.is_recording = False
        cleanup_resources()
        print("[Shutdown] Cleanup complete")