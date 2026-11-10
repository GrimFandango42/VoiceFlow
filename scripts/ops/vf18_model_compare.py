"""VF-18: offline speed/accuracy comparison of the candidate dictation models.

Loads one model at a time from the local Hugging Face cache (no network), decodes
each clip with the app's own decode settings, and reports per-clip time, word
error rate against the known reference text, and the word-level differences from
the current default. Run with the test venv's interpreter::

    python -I scripts/ops/vf18_model_compare.py --clips <dir> --out <report.json>

Safety: the GPU is shared with other workloads, so before each model is loaded
the script checks free VRAM and skips (or falls to CPU with --cpu-fallback)
rather than risk starving a process that is already running. Models are released
and garbage collected between runs.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import re
import statistics
import subprocess
import sys
import time
import wave
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")

import numpy as np

# key -> HF repo id. All three are CTranslate2 exports.
CANDIDATES = {
    "distil-large-v3": "Systran/faster-distil-whisper-large-v3",
    "distil-large-v3.5": "distil-whisper/distil-large-v3.5-ct2",
    "large-v3-turbo": "mobiuslabsgmbh/faster-whisper-large-v3-turbo",
}
BASELINE = "distil-large-v3"


def free_vram_mb() -> int | None:
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total,memory.used", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip().splitlines()[0]
        total, used = (int(x.strip()) for x in out.split(","))
        return total - used
    except Exception:
        return None


def load_wav(path: Path) -> np.ndarray:
    with wave.open(str(path), "rb") as wf:
        assert wf.getframerate() == 16000 and wf.getsampwidth() == 2 and wf.getnchannels() == 1, path
        raw = wf.readframes(wf.getnframes())
    return np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0


_NUM = {"1": "one", "2": "two", "3": "three", "4": "four", "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine"}


def norm_words(text: str) -> list[str]:
    text = text.lower().replace("-", " ")
    text = re.sub(r"[^a-z0-9 ']+", " ", text)
    return text.split()


def edit_ops(ref: list[str], hyp: list[str]) -> tuple[int, list[str]]:
    """Levenshtein distance plus a compact list of the differences."""
    n, m = len(ref), len(hyp)
    d = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        d[i][0] = i
    for j in range(m + 1):
        d[0][j] = j
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = 0 if ref[i - 1] == hyp[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
    ops: list[str] = []
    i, j = n, m
    while i > 0 or j > 0:
        if i > 0 and j > 0 and d[i][j] == d[i - 1][j - 1] + (0 if ref[i - 1] == hyp[j - 1] else 1):
            if ref[i - 1] != hyp[j - 1]:
                ops.append(f"{ref[i-1]}->{hyp[j-1]}")
            i, j = i - 1, j - 1
        elif i > 0 and d[i][j] == d[i - 1][j] + 1:
            ops.append(f"-{ref[i-1]}")
            i -= 1
        else:
            ops.append(f"+{hyp[j-1]}")
            j -= 1
    return d[n][m], ops[::-1]


def decode(model, audio: np.ndarray) -> tuple[str, float]:
    dur = len(audio) / 16000.0
    beam = 2 if dur >= 12.0 else 1  # mirrors FasterWhisperBackend long-form handling
    t0 = time.perf_counter()
    segs, _info = model.transcribe(
        audio, language="en", beam_size=beam, best_of=beam, temperature=0.0,
        condition_on_previous_text=(dur >= 12.0 and dur <= 30.0),
        without_timestamps=True, vad_filter=True,
        vad_parameters={"threshold": 0.35, "min_speech_duration_ms": 150, "max_speech_duration_s": 300},
    )
    text = " ".join(s.text.strip() for s in segs if s.text and s.text.strip()).strip()
    return text, time.perf_counter() - t0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clips", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--models", default=",".join(CANDIDATES))
    ap.add_argument("--device", default="cuda", choices=["cuda", "cpu"])
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--min-free-mb", type=int, default=2600)
    args = ap.parse_args()

    # Use the app's own CUDA DLL discovery so this measures what the app would get.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    if args.device == "cuda":
        from voiceflow.core.asr_engine import _cuda_runtime_ready

        if not _cuda_runtime_ready():
            print("CUDA runtime not found by the app's probe; rerun with --device cpu", flush=True)
            return 2

    from faster_whisper import WhisperModel
    from faster_whisper.utils import download_model

    ref = json.loads((args.clips / "reference.json").read_text(encoding="utf-8-sig"))
    clips = {name: load_wav(args.clips / name) for name in ref}
    report: dict = {"device": args.device, "clips": {n: round(len(a) / 16000, 2) for n, a in clips.items()}, "models": {}}

    for key in [m.strip() for m in args.models.split(",") if m.strip()]:
        repo = CANDIDATES[key]
        compute = "float16" if args.device == "cuda" else "int8"
        if args.device == "cuda":
            free = free_vram_mb()
            if free is not None and free < args.min_free_mb:
                report["models"][key] = {"skipped": f"free VRAM {free} MB < {args.min_free_mb} MB"}
                print(f"[skip] {key}: free VRAM {free} MB", flush=True)
                continue
        path = download_model(repo, local_files_only=True)
        t0 = time.perf_counter()
        model = WhisperModel(path, device=args.device, compute_type=compute, cpu_threads=8)
        load_s = time.perf_counter() - t0
        decode(model, clips[next(iter(clips))])  # warmup
        entry: dict = {"repo": repo, "compute": compute, "load_s": round(load_s, 2), "clips": {}}
        for name, audio in clips.items():
            times, text = [], ""
            for _ in range(args.repeats):
                text, secs = decode(model, audio)
                times.append(secs)
            entry["clips"][name] = {"text": text, "median_s": round(statistics.median(times), 3), "audio_s": round(len(audio) / 16000, 2)}
        report["models"][key] = entry
        del model
        gc.collect()
        print(f"[done] {key} load={load_s:.1f}s", flush=True)

    # Score
    base = report["models"].get(BASELINE, {}).get("clips", {})
    for key, entry in report["models"].items():
        if "clips" not in entry:
            continue
        errs = words = 0
        total_s = total_audio = 0.0
        for name, c in entry["clips"].items():
            r = norm_words(ref[name]["text"])
            e, ops = edit_ops(r, norm_words(c["text"]))
            errs += e
            words += len(r)
            c["wer"] = round(e / max(1, len(r)), 3)
            c["errors_vs_reference"] = ops
            if key != BASELINE and name in base:
                _d, diff = edit_ops(norm_words(base[name]["text"]), norm_words(c["text"]))
                c["diff_vs_baseline"] = diff
            total_s += c["median_s"]
            total_audio += c["audio_s"]
        entry["wer"] = round(errs / max(1, words), 4)
        entry["total_decode_s"] = round(total_s, 3)
        entry["realtime_factor"] = round(total_s / max(0.001, total_audio), 4)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for key, entry in report["models"].items():
        if "clips" in entry:
            print(f"{key:20s} wer={entry['wer']:.3f} decode={entry['total_decode_s']:.2f}s rtf={entry['realtime_factor']:.3f} load={entry['load_s']}s")
        else:
            print(f"{key:20s} {entry}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
