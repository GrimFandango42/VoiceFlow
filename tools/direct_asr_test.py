"""
Direct ASR Test - Test transcription with TTS audio directly (no speaker/mic loop)
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
from scipy import signal


def _normalize_words(text: str) -> set[str]:
    cleaned = (
        text.lower()
        .replace(".", " ")
        .replace(",", " ")
        .replace("!", " ")
        .replace("?", " ")
    )
    number_map = {"1": "one", "2": "two", "3": "three"}
    words = []
    for token in cleaned.split():
        words.append(number_map.get(token, token))
    return set(words)


def main():
    print("="*60)
    print("Direct ASR Test (TTS -> ASR, no speaker/mic)")
    print("="*60)

    # Import after path setup
    import pyttsx3
    from voiceflow.core.asr_engine import ASREngine, ModelTier
    from voiceflow.core.config import Config
    from voiceflow.utils.settings import load_config

    # Test phrases
    test_phrases = [
        "Hello world",
        "Testing one two three",
        "The quick brown fox jumps over the lazy dog",
        "Please transcribe this sentence accurately",
    ]

    # Initialize TTS
    print("\n1. Initializing TTS...")
    tts = pyttsx3.init()
    tts.setProperty('rate', 150)  # Slower for clarity

    # Initialize ASR
    print("\n2. Initializing ASR engine (Distil Large v3)...")
    cfg = load_config(Config())
    engine = ASREngine(
        tier=ModelTier.QUICK,
        device=getattr(cfg, "device", "cpu"),
        compute_type=getattr(cfg, "compute_type", "int8"),
    )
    engine.load()
    print(f"   Model loaded on device={getattr(cfg, 'device', 'cpu')} compute_type={getattr(cfg, 'compute_type', 'int8')}")

    results = []
    target_rate = 16000  # Whisper expects 16kHz

    for phrase in test_phrases:
        print(f"\n{'='*60}")
        print(f"Testing: \"{phrase}\"")
        print("-"*60)

        # Generate TTS audio
        temp_file = tempfile.mktemp(suffix='.wav')
        tts.save_to_file(phrase, temp_file)
        tts.runAndWait()

        # Read TTS audio
        with wave.open(temp_file, 'rb') as wf:
            source_rate = wf.getframerate()
            n_frames = wf.getnframes()
            raw_data = wf.readframes(n_frames)
            audio = np.frombuffer(raw_data, dtype=np.int16).astype(np.float32) / 32768.0

        os.unlink(temp_file)

        print(f"   TTS rate: {source_rate}Hz, samples: {len(audio)}")

        # Resample to 16kHz if needed
        if source_rate != target_rate:
            num_samples = int(len(audio) * target_rate / source_rate)
            audio = signal.resample(audio, num_samples).astype(np.float32)
            print(f"   Resampled to {target_rate}Hz: {len(audio)} samples")

        duration = len(audio) / target_rate
        print(f"   Duration: {duration:.2f}s")

        # Audio stats
        energy = np.sqrt(np.mean(audio ** 2))
        max_amp = np.max(np.abs(audio))
        print(f"   Energy: {energy:.6f}, Max amplitude: {max_amp:.6f}")

        # Transcribe
        start = time.time()
        result = engine.transcribe(audio)
        elapsed = time.time() - start

        result_text = result.text if hasattr(result, 'text') else str(result)

        print(f"   Transcription time: {elapsed:.3f}s ({duration/elapsed:.1f}x realtime)")
        print(f"   Result: \"{result_text}\"")

        # Calculate word match
        orig_words = _normalize_words(phrase)
        trans_words = _normalize_words(result_text)
        common = orig_words & trans_words
        match_rate = len(common) / len(orig_words) if orig_words else 0

        print(f"   Word match: {len(common)}/{len(orig_words)} ({match_rate*100:.0f}%)")

        results.append({
            'original': phrase,
            'transcribed': result_text,
            'match_rate': match_rate,
            'time': elapsed
        })

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print("="*60)

    total_match = 0
    for i, r in enumerate(results, 1):
        status = "PASS" if r['match_rate'] > 0.5 else "FAIL"
        print(f"{i}. [{status}] {r['match_rate']*100:.0f}% - \"{r['original']}\" -> \"{r['transcribed']}\"")
        total_match += r['match_rate']

    avg_match = total_match / len(results) if results else 0
    print(f"\nAverage word match: {avg_match*100:.1f}%")

    if avg_match > 0.7:
        print("\n✓ ASR engine is working correctly!")
    elif avg_match > 0.3:
        print("\n~ ASR has partial accuracy - may need tuning")
    else:
        print("\n✗ ASR has issues - needs investigation")

    engine.cleanup()

if __name__ == "__main__":
    main()
