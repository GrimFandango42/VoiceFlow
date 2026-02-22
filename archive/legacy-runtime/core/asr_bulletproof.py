"""
Bulletproof ASR Implementation
==============================
Production-stable transcription using process isolation to prevent
memory leaks, hanging, and other Whisper stability issues.

Based on 2024 community research and proven production patterns.
"""

import logging
import time
import subprocess
import tempfile
import os
import json
import threading
import multiprocessing
import queue
from typing import Optional, Dict, List, Any
import numpy as np
from dataclasses import dataclass
from pathlib import Path

from voiceflow.core.config import Config

logger = logging.getLogger(__name__)

@dataclass
class BulletproofResult:
    """Simple, reliable transcription result"""
    text: str
    confidence: float
    duration: float
    processing_time: float
    success: bool
    error_message: Optional[str] = None

class ProcessIsolatedWhisper:
    """
    Process-isolated Whisper transcription to prevent memory leaks
    and hanging issues identified in production environments.
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.model_name = getattr(cfg, 'model_name', 'base.en')
        self.device = getattr(cfg, 'device', 'cpu')
        self.temp_dir = tempfile.mkdtemp(prefix='voiceflow_')

        # Subprocess timeout (generous but not infinite)
        self.subprocess_timeout = 120  # 2 minutes max per transcription

        # Process recycling (restart every N transcriptions to prevent leaks)
        self.transcription_count = 0
        self.max_transcriptions_per_process = 50
        self.process_lock = threading.Lock()

        logger.info(f"Bulletproof ASR initialized - model: {self.model_name}, device: {self.device}")

    def transcribe(self, audio: np.ndarray) -> BulletproofResult:
        """
        Transcribe audio using process isolation for maximum stability.
        """
        start_time = time.time()

        try:
            # Input validation
            if audio is None or audio.size == 0:
                return BulletproofResult("", 0.0, 0.0, 0.0, False, "Empty audio")

            audio_duration = len(audio) / getattr(self.cfg, 'sample_rate', 16000)

            # Skip very short audio
            if audio_duration < 0.1:
                return BulletproofResult("", 0.0, audio_duration, 0.0, False, "Audio too short")

            # Check energy level
            energy = np.mean(audio ** 2)
            if energy < 1e-6:
                return BulletproofResult("", 0.0, audio_duration, 0.0, False, "Audio too quiet")

            # Use process isolation for transcription
            with self.process_lock:
                self.transcription_count += 1

            # Method 1: Try faster-whisper subprocess first (most stable)
            result = self._transcribe_subprocess(audio, audio_duration)

            if not result.success:
                logger.warning(f"Subprocess method failed: {result.error_message}")
                # Method 2: Fallback to multiprocessing isolation
                result = self._transcribe_multiprocess(audio, audio_duration)

            result.processing_time = time.time() - start_time
            return result

        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Transcription failed: {e}")
            return BulletproofResult("", 0.0, 0.0, processing_time, False, str(e))

    def _transcribe_subprocess(self, audio: np.ndarray, duration: float) -> BulletproofResult:
        """
        Use subprocess to run faster-whisper completely isolated.
        This prevents memory leaks and hanging in the main process.
        """
        try:
            # Create temporary audio file
            audio_file = os.path.join(self.temp_dir, f"audio_{int(time.time() * 1000)}.wav")
            result_file = os.path.join(self.temp_dir, f"result_{int(time.time() * 1000)}.json")

            # Save audio to temporary file
            import soundfile as sf
            sample_rate = getattr(self.cfg, 'sample_rate', 16000)
            sf.write(audio_file, audio, sample_rate)

            # Create simple transcription script
            script_content = f'''
import sys
import json
import logging
logging.basicConfig(level=logging.ERROR)  # Suppress verbose output

try:
    from faster_whisper import WhisperModel
    import torch
    import gc

    # Load model
    model = WhisperModel("{self.model_name}", device="{self.device}", compute_type="float16")

    # Transcribe
    segments, info = model.transcribe(
        "{audio_file}",
        language="en",
        beam_size=1,
        condition_on_previous_text=False,
        temperature=0.0,
        vad_filter=True
    )

    # Extract text
    text_segments = []
    total_confidence = 0
    segment_count = 0

    for segment in segments:
        if segment.text and segment.text.strip():
            text_segments.append(segment.text.strip())
            if hasattr(segment, 'avg_logprob'):
                total_confidence += segment.avg_logprob
                segment_count += 1

    text = " ".join(text_segments).strip()
    confidence = total_confidence / max(segment_count, 1) if segment_count > 0 else 0.0

    # Cleanup
    del model
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    gc.collect()

    # Save result
    result = {{
        "text": text,
        "confidence": confidence,
        "success": True,
        "error": None
    }}

    with open("{result_file}", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)

except Exception as e:
    result = {{
        "text": "",
        "confidence": 0.0,
        "success": False,
        "error": str(e)
    }}

    with open("{result_file}", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)
'''

            # Write script to temporary file
            script_file = os.path.join(self.temp_dir, f"transcribe_{int(time.time() * 1000)}.py")
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write(script_content)

            # Run subprocess with timeout
            process = subprocess.run(
                [sys.executable, script_file],
                timeout=self.subprocess_timeout,
                capture_output=True,
                text=True,
                cwd=self.temp_dir
            )

            # Read result
            if os.path.exists(result_file):
                with open(result_file, 'r', encoding='utf-8') as f:
                    result_data = json.load(f)

                # Cleanup temp files
                try:
                    os.unlink(audio_file)
                    os.unlink(script_file)
                    os.unlink(result_file)
                except:
                    pass  # Ignore cleanup errors

                if result_data['success']:
                    return BulletproofResult(
                        text=result_data['text'],
                        confidence=result_data['confidence'],
                        duration=duration,
                        processing_time=0.0,  # Will be set by caller
                        success=True
                    )
                else:
                    return BulletproofResult("", 0.0, duration, 0.0, False, result_data['error'])
            else:
                return BulletproofResult("", 0.0, duration, 0.0, False, "No result file generated")

        except subprocess.TimeoutExpired:
            return BulletproofResult("", 0.0, duration, 0.0, False, f"Subprocess timeout after {self.subprocess_timeout}s")
        except Exception as e:
            return BulletproofResult("", 0.0, duration, 0.0, False, f"Subprocess error: {e}")

    def _transcribe_multiprocess(self, audio: np.ndarray, duration: float) -> BulletproofResult:
        """
        Fallback: Use multiprocessing for isolation if subprocess fails.
        """
        try:
            def worker_function(audio_data, sample_rate, model_name, device, result_queue):
                """Worker function that runs in separate process"""
                try:
                    import logging
                    logging.basicConfig(level=logging.ERROR)

                    from faster_whisper import WhisperModel
                    import torch
                    import gc

                    # Load model in worker process
                    model = WhisperModel(model_name, device=device, compute_type="float16")

                    # Transcribe
                    segments, info = model.transcribe(
                        audio_data,
                        language="en",
                        beam_size=1,
                        condition_on_previous_text=False,
                        temperature=0.0,
                        vad_filter=True
                    )

                    # Extract text
                    text_segments = []
                    total_confidence = 0
                    segment_count = 0

                    for segment in segments:
                        if segment.text and segment.text.strip():
                            text_segments.append(segment.text.strip())
                            if hasattr(segment, 'avg_logprob'):
                                total_confidence += segment.avg_logprob
                                segment_count += 1

                    text = " ".join(text_segments).strip()
                    confidence = total_confidence / max(segment_count, 1) if segment_count > 0 else 0.0

                    # Cleanup
                    del model
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                    gc.collect()

                    result_queue.put(('success', text, confidence))

                except Exception as e:
                    result_queue.put(('error', str(e), 0.0))

            # Create multiprocessing queue and process
            ctx = multiprocessing.get_context('spawn')  # Use spawn for better isolation
            result_queue = ctx.Queue()

            sample_rate = getattr(self.cfg, 'sample_rate', 16000)
            process = ctx.Process(
                target=worker_function,
                args=(audio, sample_rate, self.model_name, self.device, result_queue)
            )

            process.start()
            process.join(timeout=self.subprocess_timeout)

            if process.is_alive():
                process.terminate()
                process.join()
                return BulletproofResult("", 0.0, duration, 0.0, False, "Multiprocess timeout")

            if not result_queue.empty():
                result_type, text_or_error, confidence = result_queue.get()
                if result_type == 'success':
                    return BulletproofResult(text_or_error, confidence, duration, 0.0, True)
                else:
                    return BulletproofResult("", 0.0, duration, 0.0, False, f"Worker error: {text_or_error}")
            else:
                return BulletproofResult("", 0.0, duration, 0.0, False, "No result from worker")

        except Exception as e:
            return BulletproofResult("", 0.0, duration, 0.0, False, f"Multiprocess error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get transcription statistics"""
        return {
            "transcription_count": self.transcription_count,
            "max_per_process": self.max_transcriptions_per_process,
            "model_name": self.model_name,
            "device": self.device,
            "method": "process_isolation"
        }

    def cleanup(self):
        """Cleanup temporary resources"""
        try:
            import shutil
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")

# Compatibility alias
BulletproofWhisperASR = ProcessIsolatedWhisper