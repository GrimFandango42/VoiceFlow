import pytest
pytestmark = pytest.mark.integration

"""VoiceFlow transcription accuracy tests using pre-generated audio samples.

This harness scans `tests/audio_samples` for WAV files produced by
`audio_test_generator.py --auto` during CI. For each sample it looks up a
matching `<sample>_expected.txt` file containing the ground-truth transcript
(or empty string for silence / tone tests). The test passes if VoiceFlow
successfully runs and the expected text is a substring of the transcript.

To execute locally:
    python -m pytest -v tests/test_voiceflow_samples.py
"""
from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path
from typing import List, Tuple

import pytest

# Resolve paths relative to repository root (two levels up from this file)
REPO_ROOT = Path(__file__).resolve().parents[1]
VOICEFLOW_SCRIPT = REPO_ROOT / "voiceflow_main.py"
SAMPLES_DIR = Path(__file__).parent / "audio_samples"


def _collect_samples() -> List[Tuple[Path, str]]:
    """Return list of (wav_path, expected_text) tuples for parametrisation."""
    if not SAMPLES_DIR.exists():
        pytest.skip(f"Sample directory {SAMPLES_DIR} not found; run audio_test_generator.py first")

    sample_cases: List[Tuple[Path, str]] = []
    for wav_path in sorted(SAMPLES_DIR.glob("*.wav")):
        base_name = wav_path.stem  # without extension
        expected_path = SAMPLES_DIR / f"{base_name}_expected.txt"
        if expected_path.exists():
            expected_text = expected_path.read_text(encoding="utf-8").strip()
        else:
            # If no expected transcript file, assume we just want VoiceFlow to run
            expected_text = ""
        sample_cases.append((wav_path, expected_text))
    if not sample_cases:
        pytest.skip("No audio samples discovered in tests/audio_samples")
    return sample_cases


@pytest.mark.parametrize("wav_path,expected_text", _collect_samples())
def test_sample_transcription(wav_path: Path, expected_text: str):
    """Verify VoiceFlow transcription matches expected text for each sample."""
    assert VOICEFLOW_SCRIPT.exists(), "voiceflow_main.py not found at repository root"

    cmd = [sys.executable, str(VOICEFLOW_SCRIPT), "--audio_input", str(wav_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    # Confirm process completed successfully
    assert result.returncode == 0, f"VoiceFlow exited with code {result.returncode}: {result.stderr}"

    transcript = result.stdout.strip().lower()
    # Basic containment check – allows minor punctuation/case differences
    assert expected_text.lower() in transcript, (
        f"Expected text not found.\nExpected: '{expected_text}'\nGot: '{transcript}'"
    )

