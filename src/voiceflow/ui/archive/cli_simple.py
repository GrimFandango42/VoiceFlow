"""
Simple CLI Interface

Just the basics: hotkey → record → transcribe → output
No complex session management, no buffers, no over-engineering
"""

import time
import threading
import logging
import sys
import signal
import numpy as np

from voiceflow.core.config import Config
from voiceflow.core.asr_modern import ModernWhisperASR
from voiceflow.integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener
from voiceflow.core.audio_enhanced import EnhancedAudioRecorder
from voiceflow.integrations.inject import ClipboardInjector

logger = logging.getLogger(__name__)

class SimpleVoiceFlowApp:
    """Simple VoiceFlow app - just the essentials"""

    def __init__(self):
        # Load config
        self.cfg = Config()

        # Core components
        self.asr = ModernWhisperASR(self.cfg)
        self.injector = ClipboardInjector(self.cfg)

        # Audio recording
        self.audio_recorder = EnhancedAudioRecorder(
            sample_rate=self.cfg.sample_rate,
            channels=1,
            max_duration=self.cfg.max_recording_time
        )

        # Hotkey listener
        self.hotkey_listener = EnhancedPTTHotkeyListener(
            self.cfg.ptt_key,
            tail_buffer_duration=1.0
        )

        # Simple state
        self.is_recording = False
        self.running = True

        # Stats
        self.transcription_count = 0

        print("Simple VoiceFlow initialized")
        print(f"Hotkey: {self.cfg.ptt_key}")
        print("Hold hotkey to record, release to transcribe")

    def start(self):
        """Start the application"""
        try:
            # Load ASR model
            print("Loading ASR model...")
            self.asr.load()
            print("Model loaded successfully")

            # Setup hotkey callbacks
            self.hotkey_listener.set_start_callback(self.start_recording)
            self.hotkey_listener.set_stop_callback(self.stop_recording)

            # Start hotkey listener
            self.hotkey_listener.start()

            print("\nReady! Hold hotkey to record...")
            print("Press Ctrl+C to exit\n")

            # Main loop
            try:
                while self.running:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                print("\nShutting down...")
                self.stop()

        except Exception as e:
            logger.error(f"Application error: {e}")
            print(f"Error: {e}")

    def stop(self):
        """Stop the application"""
        self.running = False
        if hasattr(self, 'hotkey_listener'):
            self.hotkey_listener.stop()

    def start_recording(self):
        """Start recording audio"""
        if self.is_recording:
            return

        self.is_recording = True
        print("[RECORDING] Started...")

        try:
            self.audio_recorder.start_recording()
        except Exception as e:
            logger.error(f"Failed to start recording: {e}")
            self.is_recording = False

    def stop_recording(self):
        """Stop recording and transcribe"""
        if not self.is_recording:
            return

        self.is_recording = False
        print("[RECORDING] Stopped")

        try:
            # Get audio data
            audio_data = self.audio_recorder.stop_recording()

            if audio_data is None or len(audio_data) == 0:
                print("[RECORDING] No audio captured")
                return

            # Basic validation
            duration = len(audio_data) / self.cfg.sample_rate
            if duration < 0.3:  # Less than 0.3 seconds
                print(f"[RECORDING] Too short ({duration:.1f}s), skipping")
                return

            # Check for silence
            energy = np.mean(audio_data ** 2)
            if energy < 1e-5:  # Very quiet
                print(f"[RECORDING] Too quiet (energy: {energy:.6f}), skipping")
                return

            print(f"[RECORDING] {duration:.1f}s captured, transcribing...")

            # Transcribe
            self.transcribe_audio(audio_data)

        except Exception as e:
            logger.error(f"Failed to stop recording: {e}")
            print(f"[ERROR] Recording failed: {e}")

    def transcribe_audio(self, audio_data):
        """Transcribe audio data"""
        try:
            start_time = time.time()

            # Transcribe with ASR
            text = self.asr.transcribe(audio_data)

            processing_time = time.time() - start_time
            self.transcription_count += 1

            if text and text.strip():
                # Clean up text
                text = text.strip()

                print(f"[RESULT] {text}")
                print(f"[STATS] {processing_time:.2f}s processing, #{self.transcription_count}")

                # Copy to clipboard and inject
                try:
                    self.injector.inject_text(text)
                    print("[CLIPBOARD] Text copied and injected")
                except Exception as e:
                    logger.warning(f"Failed to inject text: {e}")
                    print("[CLIPBOARD] Text copied (injection failed)")

            else:
                print("[RESULT] (no speech detected)")

        except Exception as e:
            logger.error(f"Transcription failed: {e}")
            print(f"[ERROR] Transcription failed: {e}")

def main():
    """Main entry point"""
    # Setup logging
    logging.basicConfig(
        level=logging.WARNING,  # Reduce log noise
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("VoiceFlow Simple CLI")
    print("=" * 30)

    # Create and start app
    app = SimpleVoiceFlowApp()

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\nReceived interrupt signal")
        app.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Start the application
    app.start()

if __name__ == "__main__":
    main()