#!/usr/bin/env python3
"""Latency summary from a VoiceFlow log, without reading any dictated text.

Only `transcription_timing` lines are parsed, and from them only numeric
`key=value` fields, so transcript text in other lines is never read into the
report. (VF-10 review: an earlier evidence report quoted processing time alone
as if it were the user-visible delay.)

What the fields mean (src/voiceflow/ui/cli_enhanced.py):
  total_ms   processing only: audio handed to the transcription job -> final
             text ready (ASR decode, retries, cleanup passes). Starts after
             recorder.stop(), so the stop drain (<= stop_drain_seconds, exits
             early once callbacks go quiet) is NOT included.
  inject_ms  typing/pasting the final text into the focused app. Logged
             separately and NOT part of total_ms.
  warmup_ms  idle-resume warm-up, already inside total_ms.

So `total_ms + inject_ms` is the release-through-injection latency the log can
see; the real figure is that plus the stop drain.

Usage:
    python scripts/dev/log_latency.py path\\to\\voiceflow.log [--json]
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Iterable

MARKER = "transcription_timing "
_NUM = re.compile(r"\b([a-z][a-z0-9_]*)=(-?[0-9]+(?:\.[0-9]+)?)(?=\s|$)")
FIELDS = ("total_ms", "inject_ms", "asr_ms", "post_ms", "warmup_ms", "raw_dur")


def parse(lines: Iterable[str]) -> list[dict[str, float]]:
    records: list[dict[str, float]] = []
    for line in lines:
        idx = line.find(MARKER)
        if idx < 0:
            continue
        values = {k: float(v) for k, v in _NUM.findall(line[idx + len(MARKER):]) if k in FIELDS}
        if "total_ms" in values and "inject_ms" in values:
            records.append(values)
    return records


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile, q in (0, 100]: always an observed sample.

    For an even count the median is the lower middle value, which differs
    slightly from an interpolated median; for latency reporting an observed
    value is the honest choice.
    """
    if not values:
        return float("nan")
    data = sorted(values)
    rank = max(1, math.ceil(len(data) * q / 100.0))
    return data[min(rank, len(data)) - 1]


def _stats(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "median": round(percentile(values, 50), 1),
        "p90": round(percentile(values, 90), 1),
        "max": round(max(values), 1) if values else float("nan"),
    }


def summarize(records: list[dict[str, float]]) -> dict[str, dict[str, float]]:
    processing = [r["total_ms"] for r in records]
    inject = [r["inject_ms"] for r in records]
    end_to_end = [r["total_ms"] + r["inject_ms"] for r in records]
    return {
        "processing_only_ms": _stats(processing),
        "inject_ms": _stats(inject),
        "release_through_injection_ms": _stats(end_to_end),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    with args.log.open(encoding="utf-8", errors="replace") as fh:
        summary = summarize(parse(fh))
    if args.json:
        print(json.dumps(summary, indent=2))
        return 0
    print(f"{'metric':32} {'n':>4} {'median':>9} {'p90':>9} {'max':>9}")
    for name, s in summary.items():
        print(f"{name:32} {s['n']:>4} {s['median']:>9.1f} {s['p90']:>9.1f} {s['max']:>9.1f}")
    print("release_through_injection = total_ms + inject_ms; excludes the stop drain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
