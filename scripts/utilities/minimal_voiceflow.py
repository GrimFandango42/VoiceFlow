"""
Minimal Working VoiceFlow

Just the absolute basics:
1. Hold Ctrl+Shift to record
2. Release to transcribe with faster-whisper
3. Copy result to clipboard

No session management, no complex buffers, just working transcription.
"""

import sys
import os
import time
import threading
import numpy as np
import sounddevice as sd
import keyboard

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

class MinimalVoiceFlow:
    """Minimal working transcription system"""

    def __init__(self):
        # Audio settings
        self.sample_rate = 16000
        self.recording = False
        self.audio_data = []

        # Whisper model
        self.model = None

        # Stats
        self.count = 0

        print("Minimal VoiceFlow starting...")

    def load_model(self):
        """Load Whisper model once"""
        if self.model is not None:
            return

        print("Loading Whisper model...")
        try:
            from faster_whisper import WhisperModel

            # Use simple settings
            self.model = WhisperModel(
                "base.en",  # Good balance of speed/accuracy
                device="auto",  # Let it choose
                compute_type="float16"
            )

            # Quick warmup
            silence = np.zeros(1600, dtype=np.float32)
            list(self.model.transcribe(silence))

            print("Model loaded!")

        except Exception as e:
            print(f"Failed to load model: {e}")
            raise

    def audio_callback(self, indata, frames, time, status):
        """Collect audio data"""
        if self.recording:
            self.audio_data.extend(indata[:, 0])

    def transcribe(self, audio):
        """Simple transcription"""
        try:
            if self.model is None:
                self.load_model()

            # Transcribe with basic settings
            segments, info = self.model.transcribe(
                audio,
                language="en",
                beam_size=1,
                condition_on_previous_text=False,
                temperature=0.0
            )

            # Get text
            text = " ".join(segment.text.strip() for segment in segments if segment.text.strip())
            return text.strip()

        except Exception as e:
            print(f"Transcription error: {e}")
            return ""

    def run(self):
        """Main loop"""
        try:
            # Setup audio stream
            stream = sd.InputStream(
                samplerate=self.sample_rate,
                channels=1,
                callback=self.audio_callback
            )

            print("\nReady! Hold Ctrl+Shift to record.")
            print("Release to transcribe. Press Ctrl+C to exit.\n")

            with stream:
                while True:
                    # Check hotkey
                    if keyboard.is_pressed('ctrl+shift'):
                        if not self.recording:
                            # Start recording
                            self.recording = True
                            self.audio_data = []
                            print("[REC] Recording...")
                    else:
                        if self.recording:
                            # Stop recording and transcribe
                            self.recording = False

                            if not self.audio_data:
                                print("[REC] No audio")
                                continue

                            # Convert to numpy
                            audio = np.array(self.audio_data, dtype=np.float32)
                            duration = len(audio) / self.sample_rate

                            print(f"[REC] Stopped ({duration:.1f}s)")

                            # Skip very short/quiet audio
                            if duration < 0.5:
                                print("[REC] Too short, skipping")
                                continue

                            energy = np.mean(audio ** 2)
                            if energy < 1e-6:
                                print("[REC] Too quiet, skipping")
                                continue

                            # Transcribe
                            print("[PROCESSING]...")
                            start_time = time.time()
                            text = self.transcribe(audio)
                            process_time = time.time() - start_time

                            self.count += 1

                            if text:
                                print(f"[RESULT] {text}")
                                print(f"[STATS] {process_time:.2f}s, #{self.count}")

                                # Copy to clipboard
                                try:
                                    import pyperclip
                                    pyperclip.copy(text)
                                    print("[CLIPBOARD] Copied!")
                                except:
                                    print("[CLIPBOARD] Failed to copy")
                            else:
                                print("[RESULT] (no speech)")

                    time.sleep(0.05)  # 50ms polling

        except KeyboardInterrupt:
            print("\nExiting...")
        except Exception as e:
            print(f"Error: {e}")

def main():
    app = MinimalVoiceFlow()
    app.run()

if __name__ == "__main__":
    main()