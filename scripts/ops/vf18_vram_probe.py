"""VF-18: how much VRAM does each candidate model take, loaded and after a long decode?

Read-only with respect to other processes: it loads ONE model at a time in this
process, samples ``nvidia-smi`` before/after, and exits. Refuses to start when
free VRAM is below --min-free-mb so it cannot starve a running app.
"""

from __future__ import annotations

import argparse
import gc
import os
import subprocess
import sys
import time
import wave
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")

import numpy as np

REPOS = {
    "distil-large-v3": "Systran/faster-distil-whisper-large-v3",
    "distil-large-v3.5": "distil-whisper/distil-large-v3.5-ct2",
    "large-v3-turbo": "mobiuslabsgmbh/faster-whisper-large-v3-turbo",
}


def used_mb() -> int:
    out = subprocess.run(
        ["nvidia-smi", "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits"],
        capture_output=True, text=True, timeout=10, check=True,
    ).stdout.strip().splitlines()[0]
    return int(out.split(",")[0])


def total_mb() -> int:
    out = subprocess.run(
        ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
        capture_output=True, text=True, timeout=10, check=True,
    ).stdout.strip().splitlines()[0]
    return int(out)


def load_wav(path: Path) -> np.ndarray:
    with wave.open(str(path), "rb") as wf:
        raw = wf.readframes(wf.getnframes())
    return np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clip", required=True, type=Path, help="a long clip (35 s works)")
    ap.add_argument("--min-free-mb", type=int, default=2600)
    args = ap.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    from voiceflow.core.asr_engine import _cuda_runtime_ready

    if not _cuda_runtime_ready():
        print("CUDA runtime not found")
        return 2
    from faster_whisper import WhisperModel
    from faster_whisper.utils import download_model

    audio = load_wav(args.clip)
    for key, repo in REPOS.items():
        free = total_mb() - used_mb()
        if free < args.min_free_mb:
            print(f"{key}: skipped, only {free} MB free")
            continue
        base = used_mb()
        model = WhisperModel(download_model(repo, local_files_only=True), device="cuda", compute_type="float16")
        loaded = used_mb()
        segs, _ = model.transcribe(audio, language="en", beam_size=2, vad_filter=True, without_timestamps=True)
        list(segs)
        time.sleep(0.5)
        after = used_mb()
        print(f"{key}: loaded +{loaded - base} MB, after 35s decode (beam 2) +{after - base} MB (free before: {free} MB)")
        del model
        gc.collect()
        time.sleep(1.0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
