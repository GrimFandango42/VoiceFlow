from __future__ import annotations

"""
Pre-download and warm up Whisper models via faster-whisper so first use is instant.

Usage:
  py -3 scripts\preload_models.py small.en medium.en distil-large-v3
"""

import sys
from typing import List

import numpy as np


def preload(model_name: str):
    from faster_whisper import WhisperModel

    print(f"Loading {model_name}…")
    model = WhisperModel(model_name, device="cuda", compute_type="float16")
    # 1s of silence warmup (forces model and tokenizer load)
    silence = np.zeros(16000, dtype=np.float32)
    _ = list(model.transcribe(silence, language="en"))
    print(f"Warmed {model_name}")


def main(argv: List[str]):
    targets = argv[1:] or ["small.en", "medium.en"]
    for name in targets:
        try:
            preload(name)
        except Exception as e:
            print(f"Failed to preload {name}: {e}")


if __name__ == "__main__":
    main(sys.argv)

