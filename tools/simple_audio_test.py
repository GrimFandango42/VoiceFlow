"""
Simple audio test - Play TTS and record, then transcribe
"""

import sys
import os
import time
import tempfile
import wave

# Add src to path
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(os.path.dirname(script_dir), 'src')
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

import numpy as np
import sounddevice as sd
import pyttsx3

def main():
    print("="*60)
    print("Simple Audio Transcription Test")
    print("="*60)

    # Initialize TTS
    print("\n1. Initializing TTS...")
    tts = pyttsx3.init()
    tts.setProperty('rate', 150)

    # Generate TTS audio
    text = "Hello world, this is a test"
    print(f"\n2. Generating TTS for: \"{text}\"")
    temp_file = tempfile.mktemp(suffix='.wav')
    tts.save_to_file(text, temp_file)
    tts.runAndWait()

    # Read TTS audio
    print("\n3. Reading TTS audio file...")
    with wave.open(temp_file, 'rb') as wf:
        play_rate = wf.getframerate()
        n_frames = wf.getnframes()
        sampwidth = wf.getsampwidth()
        print(f"   Rate: {play_rate}, Frames: {n_frames}, Width: {sampwidth}")

        raw_data = wf.readframes(n_frames)
        play_audio = np.frombuffer(raw_data, dtype=np.int16).astype(np.float32) / 32768.0

    duration = len(play_audio) / play_rate
    record_duration = duration + 1.5
    print(f"   TTS duration: {duration:.2f}s")
    print(f"   Will record for: {record_duration:.2f}s")

    # Start recording
    print("\n4. Starting recording...")
    sample_rate = 16000
    recording = sd.rec(
        int(record_duration * sample_rate),
        samplerate=sample_rate,
        channels=1,
        dtype='float32',
        blocking=False
    )

    # Wait a moment then play
    time.sleep(0.3)
    print("5. Playing TTS audio...")
    sd.play(play_audio, samplerate=play_rate, blocking=True)
    print("   Playback complete")

    # Wait for recording
    print("6. Waiting for recording to complete...")
    sd.wait()

    # Cleanup temp file
    os.unlink(temp_file)

    # Process recording
    audio = recording.flatten()
    print(f"\n7. Recording analysis:")
    print(f"   Shape: {audio.shape}")
    print(f"   Dtype: {audio.dtype}")
    print(f"   Min: {np.min(audio):.6f}")
    print(f"   Max: {np.max(audio):.6f}")
    print(f"   Has NaN: {np.any(np.isnan(audio))}")
    print(f"   Has Inf: {np.any(np.isinf(audio))}")

    # Calculate energy safely
    valid_audio = audio[~np.isnan(audio) & ~np.isinf(audio)]
    if len(valid_audio) > 0:
        energy = np.sqrt(np.mean(valid_audio ** 2))
        max_amp = np.max(np.abs(valid_audio))
        print(f"   Energy: {energy:.6f}")
        print(f"   Max amplitude: {max_amp:.6f}")
    else:
        print("   ERROR: No valid audio samples!")
        return

    # Initialize ASR
    print("\n8. Initializing ASR engine...")
    from voiceflow.core.asr_engine import ASREngine, ModelTier

    engine = ASREngine(tier=ModelTier.TINY, device='cpu', compute_type='int8')
    engine.load()
    print("   Model loaded")

    # Transcribe
    print("\n9. Transcribing...")
    start = time.time()
    result = engine.transcribe(audio)
    elapsed = time.time() - start

    result_text = result.text if hasattr(result, 'text') else str(result)

    print(f"\n{'='*60}")
    print("RESULTS")
    print('='*60)
    print(f"Original text:    \"{text}\"")
    print(f"Transcribed text: \"{result_text}\"")
    print(f"Transcription time: {elapsed:.3f}s")

    # Simple word match
    orig_words = set(text.lower().split())
    trans_words = set(result_text.lower().split())
    common = orig_words & trans_words
    print(f"Words matched: {len(common)}/{len(orig_words)}")

    engine.cleanup()
    print("\nTest complete!")

if __name__ == "__main__":
    main()
