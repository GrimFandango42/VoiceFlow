#!/usr/bin/env python3
"""
Disk-aware local ASR model prefetch helper for VoiceFlow.

Defaults to dry-run so you can inspect recommendations before downloading.
"""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass(frozen=True)
class ModelCandidate:
    repo_id: str
    est_size_gb: float
    priority: int
    note: str


MODEL_CANDIDATES: List[ModelCandidate] = [
    ModelCandidate(
        repo_id="distil-whisper/distil-large-v3.5",
        est_size_gb=1.6,
        priority=1,
        note="Balanced speed/accuracy baseline for fast local dictation",
    ),
    ModelCandidate(
        repo_id="Systran/faster-distil-whisper-large-v3",
        est_size_gb=1.5,
        priority=2,
        note="Quick fallback with strong realtime performance",
    ),
    ModelCandidate(
        repo_id="openai/whisper-large-v3-turbo",
        est_size_gb=3.2,
        priority=3,
        note="High-quality Whisper tier when accuracy bar is strict",
    ),
    ModelCandidate(
        repo_id="nvidia/parakeet-tdt-0.6b-v2",
        est_size_gb=2.0,
        priority=4,
        note="Fast non-Whisper option for comparative quality testing",
    ),
]


def select_candidates(free_gb: float, reserve_gb: float) -> List[ModelCandidate]:
    budget_gb = max(0.0, free_gb - reserve_gb)
    selected: List[ModelCandidate] = []
    used = 0.0

    for candidate in sorted(MODEL_CANDIDATES, key=lambda m: m.priority):
        if used + candidate.est_size_gb <= budget_gb:
            selected.append(candidate)
            used += candidate.est_size_gb
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Prefetch recommended local ASR models.")
    parser.add_argument("--root", default="C:/", help="Drive or path used for disk budget calculation.")
    parser.add_argument(
        "--cache-dir",
        default=str(Path.home() / ".voiceflow" / "models"),
        help="Target directory for prefetched models.",
    )
    parser.add_argument(
        "--reserve-gb",
        type=float,
        default=20.0,
        help="Free space to keep unallocated after downloads.",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Actually download selected models (dry-run by default).",
    )
    parser.add_argument(
        "--output-json",
        default="",
        help="Optional path to save plan and results as JSON.",
    )
    args = parser.parse_args()

    total, used, free = shutil.disk_usage(args.root)
    free_gb = free / (1024 ** 3)
    selected = select_candidates(free_gb=free_gb, reserve_gb=args.reserve_gb)

    plan = {
        "disk": {
            "root": args.root,
            "total_gb": round(total / (1024 ** 3), 2),
            "used_gb": round(used / (1024 ** 3), 2),
            "free_gb": round(free_gb, 2),
            "reserve_gb": args.reserve_gb,
        },
        "selected_models": [
            {
                "repo_id": m.repo_id,
                "est_size_gb": m.est_size_gb,
                "priority": m.priority,
                "note": m.note,
            }
            for m in selected
        ],
        "downloaded": [],
        "dry_run": not args.download,
    }

    print(json.dumps(plan["disk"], indent=2))
    if not selected:
        print("No models selected within disk budget.")
        return 0

    print("\nSelected models:")
    for model in selected:
        print(f"- {model.repo_id} (~{model.est_size_gb} GB): {model.note}")

    if args.download:
        try:
            from huggingface_hub import snapshot_download
        except Exception as exc:
            print(f"\nUnable to import huggingface_hub: {exc}")
            print("Install with: pip install huggingface_hub")
            return 1

        cache_dir = Path(args.cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)

        print(f"\nDownloading to: {cache_dir}")
        for model in selected:
            target = cache_dir / model.repo_id.replace("/", "__")
            print(f"\n[download] {model.repo_id} -> {target}")
            path = snapshot_download(
                repo_id=model.repo_id,
                local_dir=str(target),
                local_dir_use_symlinks=False,
                resume_download=True,
            )
            plan["downloaded"].append({"repo_id": model.repo_id, "path": path})

    if args.output_json:
        output_path = Path(args.output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        print(f"\nWrote plan: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

