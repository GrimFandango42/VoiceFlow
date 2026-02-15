"""
Automated Transcription Test for VoiceFlow

This script:
1. Generates speech using text-to-speech
2. Plays audio through speakers while recording via microphone
3. Transcribes the recorded audio using VoiceFlow's ASR engine
4. Compares the result to the original text

Requirements: sounddevice, pyttsx3, numpy
"""

import sys
import os
import time
import tempfile
import wave
import threading
from typing import Optional, Tuple

# Add src to path
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(os.path.dirname(script_dir), 'src')
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

import numpy as np
import sounddevice as sd
import pyttsx3

from voiceflow.core.asr_engine import ASREngine, ModelTier


class TranscriptionTester:
    """Automated transcription testing with TTS and microphone recording"""

    def __init__(self, model_tier: ModelTier = ModelTier.QUICK):
        self.sample_rate = 16000
        self.channels = 1
        self.engine: Optional[ASREngine] = None
        self.tts = pyttsx3.init()
        self.model_tier = model_tier

        # Configure TTS for clarity
        self.tts.setProperty('rate', 150)  # Slower for clarity
        self.tts.setProperty('volume', 0.9)

    def initialize_asr(self):
        """Initialize the ASR engine"""
        print(f"Initializing ASR engine ({self.model_tier.value} tier)...")
        self.engine = ASREngine(tier=self.model_tier, device='cpu', compute_type='int8')

        print("Loading model...")
        start = time.time()
        self.engine.load()
        print(f"Model loaded in {time.time() - start:.2f}s")

    def generate_tts_audio(self, text: str) -> str:
        """Generate TTS audio and save to temp file"""
        temp_file = tempfile.mktemp(suffix='.wav')
        self.tts.save_to_file(text, temp_file)
        self.tts.runAndWait()
        return temp_file

    def play_and_record(self, audio_file: str, extra_seconds: float = 1.0) -> np.ndarray:
        """Play audio file while simultaneously recording from microphone"""
        # Read the audio file
        with wave.open(audio_file, 'rb') as wf:
            play_rate = wf.getframerate()
            n_frames = wf.getnframes()
            n_channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()

            raw_data = wf.readframes(n_frames)

            # Handle different sample widths
            if sampwidth == 2:
                audio_data = np.frombuffer(raw_data, dtype=np.int16)
                audio_data = audio_data.astype(np.float32) / 32768.0
            elif sampwidth == 4:
                audio_data = np.frombuffer(raw_data, dtype=np.int32)
                audio_data = audio_data.astype(np.float32) / 2147483648.0
            else:
                audio_data = np.frombuffer(raw_data, dtype=np.uint8)
                audio_data = (audio_data.astype(np.float32) - 128) / 128.0

            # Convert to mono if stereo
            if n_channels == 2:
                audio_data = audio_data.reshape(-1, 2).mean(axis=1)

        duration = len(audio_data) / play_rate + extra_seconds

        print(f"Playing audio ({len(audio_data)/play_rate:.2f}s) and recording for {duration:.2f}s...")

        # Record audio - ensure float32 output and proper format
        recording = sd.rec(
            int(duration * self.sample_rate),
            samplerate=self.sample_rate,
            channels=self.channels,
            dtype='float32',
            blocking=False
        )

        # Play audio (slight delay to ensure recording started)
        time.sleep(0.2)
        sd.play(audio_data, samplerate=play_rate, blocking=True)

        # Wait for recording to complete
        sd.wait()

        # Normalize recording to proper range [-1, 1]
        result = recording.flatten().astype(np.float32)

        # Ensure values are in valid range
        max_val = np.max(np.abs(result))
        if max_val > 1.0:
            result = result / max_val

        return result

    def record_microphone(self, duration: float) -> np.ndarray:
        """Record directly from microphone"""
        print(f"Recording from microphone for {duration:.2f}s...")
        recording = sd.rec(
            int(duration * self.sample_rate),
            samplerate=self.sample_rate,
            channels=self.channels,
            dtype=np.float32
        )
        sd.wait()
        return recording.flatten()

    def transcribe(self, audio: np.ndarray) -> str:
        """Transcribe audio using the ASR engine"""
        if self.engine is None:
            raise RuntimeError("ASR engine not initialized")

        result = self.engine.transcribe(audio)
        return result.text if hasattr(result, 'text') else str(result)

    def calculate_similarity(self, original: str, transcribed: str) -> float:
        """Calculate word-level similarity between original and transcribed text"""
        orig_words = set(original.lower().split())
        trans_words = set(transcribed.lower().split())

        if not orig_words:
            return 1.0 if not trans_words else 0.0

        intersection = orig_words & trans_words
        union = orig_words | trans_words

        return len(intersection) / len(union) if union else 0.0

    def run_test(self, text: str, use_tts: bool = True) -> Tuple[str, float]:
        """Run a single transcription test"""
        if self.engine is None:
            self.initialize_asr()

        print(f"\n{'='*60}")
        print(f"Test: \"{text}\"")
        print('='*60)

        if use_tts:
            # Generate and play TTS
            print("Generating TTS audio...")
            audio_file = self.generate_tts_audio(text)

            try:
                # Play and record
                audio = self.play_and_record(audio_file)
            finally:
                # Cleanup temp file
                try:
                    os.unlink(audio_file)
                except:
                    pass
        else:
            # Just record from microphone
            print("Please speak the following text:")
            print(f"  \"{text}\"")
            input("Press Enter when ready to record...")
            audio = self.record_microphone(5.0)

        # Analyze audio
        energy = np.sqrt(np.mean(audio ** 2))
        max_amp = np.max(np.abs(audio))
        print(f"Audio stats: energy={energy:.6f}, max_amplitude={max_amp:.6f}")

        # Transcribe
        print("Transcribing...")
        start = time.time()
        transcribed = self.transcribe(audio)
        elapsed = time.time() - start

        duration = len(audio) / self.sample_rate
        print(f"Transcription time: {elapsed:.3f}s ({duration/elapsed:.1f}x realtime)")
        print(f"Result: \"{transcribed}\"")

        # Calculate similarity
        similarity = self.calculate_similarity(text, transcribed)
        print(f"Similarity: {similarity*100:.1f}%")

        return transcribed, similarity

    def run_test_suite(self, use_tts: bool = True):
        """Run a suite of transcription tests"""
        test_phrases = [
            # Short phrases
            "Hello world",
            "Testing one two three",
            "The quick brown fox",

            # Medium phrases
            "Please transcribe this sentence accurately",
            "Voice recognition is working correctly",

            # Longer phrases
            "The quick brown fox jumps over the lazy dog near the riverbank",
            "I am testing the voice transcription system to make sure it works properly",
        ]

        print("\n" + "="*60)
        print("VoiceFlow Automated Transcription Test Suite")
        print("="*60)

        if use_tts:
            print("\nMode: TTS playback through speakers -> Microphone recording")
            print("Make sure your speakers and microphone are working.")
        else:
            print("\nMode: Manual speech -> Microphone recording")

        input("\nPress Enter to start tests...")

        results = []
        for phrase in test_phrases:
            transcribed, similarity = self.run_test(phrase, use_tts)
            results.append({
                'original': phrase,
                'transcribed': transcribed,
                'similarity': similarity
            })

        # Summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)

        total_similarity = 0
        for i, r in enumerate(results, 1):
            status = "PASS" if r['similarity'] > 0.5 else "FAIL"
            print(f"{i}. [{status}] {r['similarity']*100:.0f}%")
            print(f"   Original:    \"{r['original']}\"")
            print(f"   Transcribed: \"{r['transcribed']}\"")
            total_similarity += r['similarity']

        avg_similarity = total_similarity / len(results) if results else 0
        print(f"\nAverage similarity: {avg_similarity*100:.1f}%")

        if avg_similarity > 0.7:
            print("\n✓ Overall: PASS - Transcription is working well!")
        elif avg_similarity > 0.4:
            print("\n~ Overall: PARTIAL - Transcription needs improvement")
        else:
            print("\n✗ Overall: FAIL - Transcription has issues")

    def cleanup(self):
        """Cleanup resources"""
        if self.engine:
            self.engine.cleanup()


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Automated VoiceFlow transcription testing')
    parser.add_argument('--manual', action='store_true', help='Use manual speech instead of TTS')
    parser.add_argument('--tier', choices=['tiny', 'quick', 'quality'], default='quick',
                       help='Model tier to use')
    parser.add_argument('--single', type=str, help='Test a single phrase')

    args = parser.parse_args()

    tier_map = {
        'tiny': ModelTier.TINY,
        'quick': ModelTier.QUICK,
        'quality': ModelTier.QUALITY
    }

    tester = TranscriptionTester(model_tier=tier_map[args.tier])

    try:
        if args.single:
            tester.initialize_asr()
            tester.run_test(args.single, use_tts=not args.manual)
        else:
            tester.run_test_suite(use_tts=not args.manual)
    finally:
        tester.cleanup()


if __name__ == "__main__":
    main()
