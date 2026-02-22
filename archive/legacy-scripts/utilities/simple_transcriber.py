"""
Simple, Working Transcriber

Back to basics - just a hotkey, record audio, transcribe with faster-whisper.
No complex buffers, no session management, no over-engineering.
"""

import sys
import os
import time
import threading
import logging
import numpy as np
import sounddevice as sd
import keyboard

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from voiceflow.core.config import Config

# Simple logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

class SimpleTranscriber:
    """Ultra-simple transcriber - no complexity, just working transcription"""

    def __init__(self):
        # Load config
        self.cfg = Config()

        # Audio settings
        self.sample_rate = 16000
        self.recording = False
        self.audio_data = []

        # Whisper model - load once, keep forever
        self.model = None
        self.model_lock = threading.Lock()

        # Stats
        self.transcription_count = 0

        print("Simple Transcriber initialized")
        print(f"Model: {self.cfg.model_name}")
        print(f"Device: {self.cfg.device}")
        print("Hotkey: Ctrl+Shift (hold to record)")

    def load_model(self):
        """Load Whisper model once"""
        if self.model is not None:
            return

        print("Loading Whisper model...")
        start_time = time.time()

        try:
            from faster_whisper import WhisperModel

            self.model = WhisperModel(
                self.cfg.model_name,
                device=self.cfg.device,
                compute_type="float16",  # Fast inference
                cpu_threads=4
            )

            # Quick warmup
            silence = np.zeros(1600, dtype=np.float32)  # 0.1 second
            list(self.model.transcribe(silence))

            load_time = time.time() - start_time
            print(f"Model loaded in {load_time:.2f}s")

        except Exception as e:
            print(f"Failed to load model: {e}")
            self.model = None
            raise

    def audio_callback(self, indata, frames, time, status):
        """Audio callback - just collect data"""
        if self.recording:
            self.audio_data.extend(indata[:, 0])  # Mono audio

    def start_recording(self):
        """Start recording audio"""
        if self.recording:
            return

        self.recording = True
        self.audio_data = []
        print("[RECORDING] Started...")

    def stop_recording(self):
        """Stop recording and transcribe"""
        if not self.recording:
            return

        self.recording = False

        if not self.audio_data:
            print("[RECORDING] No audio captured")
            return

        # Convert to numpy array
        audio = np.array(self.audio_data, dtype=np.float32)
        duration = len(audio) / self.sample_rate

        print(f"[RECORDING] Stopped - {duration:.2f}s captured")

        # Skip very short recordings
        if duration < 0.5:
            print("[RECORDING] Too short, skipping")
            return

        # Skip very quiet recordings
        energy = np.mean(audio ** 2)
        if energy < 1e-6:
            print("[RECORDING] Too quiet, skipping")
            return

        # Transcribe
        self.transcribe_audio(audio)

    def transcribe_audio(self, audio):
        """Simple transcription"""
        try:
            # Load model if needed
            if self.model is None:
                self.load_model()

            if self.model is None:
                print("[ERROR] Model not loaded")
                return

            print("[TRANSCRIBING] Processing...")
            start_time = time.time()

            with self.model_lock:
                # Transcribe with simple settings
                segments, info = self.model.transcribe(
                    audio,
                    language="en",
                    beam_size=1,
                    condition_on_previous_text=False,  # No context pollution
                    vad_filter=False,  # We'll handle VAD ourselves
                    temperature=0.0
                )

                # Extract text
                text_parts = []
                for segment in segments:
                    if segment.text and segment.text.strip():
                        text_parts.append(segment.text.strip())

                text = " ".join(text_parts).strip()

            processing_time = time.time() - start_time
            self.transcription_count += 1

            if text:
                print(f"[RESULT] {text}")
                print(f"[STATS] {processing_time:.2f}s processing, {self.transcription_count} total")

                # Copy to clipboard (optional)
                try:
                    import pyperclip
                    pyperclip.copy(text)
                    print("[CLIPBOARD] Text copied")
                except:
                    pass
            else:
                print("[RESULT] (no speech detected)")

        except Exception as e:
            print(f"[ERROR] Transcription failed: {e}")

    def run(self):
        """Main loop"""
        try:
            # Setup audio stream
            stream = sd.InputStream(
                samplerate=self.sample_rate,
                channels=1,
                callback=self.audio_callback,
                blocksize=512
            )

            print("\nReady! Hold Ctrl+Shift to record, release to transcribe.")
            print("Press Ctrl+C to exit.\n")

            with stream:
                while True:
                    # Check hotkey state
                    if keyboard.is_pressed('ctrl+shift'):
                        if not self.recording:
                            self.start_recording()
                    else:
                        if self.recording:
                            self.stop_recording()

                    time.sleep(0.1)  # 100ms polling

        except KeyboardInterrupt:
            print("\nExiting...")
        except Exception as e:
            print(f"Error: {e}")

def main():
    print("Simple VoiceFlow Transcriber")
    print("=" * 40)

    transcriber = SimpleTranscriber()
    transcriber.run()

if __name__ == "__main__":
    main()