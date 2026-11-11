#!/usr/bin/env python3
"""Latency summary from a VoiceFlow log, without reading any dictated text.

Only structured marker lines are parsed (`transcription_timing`,
`transcription_finished`, and with --causes a few lifecycle markers), and from
them only numeric `key=value` fields plus a handful of enum fields (`device`,
`idle_resume`). Transcript text in other lines is never read into the report.
(VF-10 review: an earlier evidence report quoted processing time alone as if it
were the user-visible delay.)

What the fields mean (src/voiceflow/ui/cli_enhanced.py):
  total_ms   processing only: audio handed to the transcription job -> final
             text ready (ASR decode, retries, cleanup passes). Starts after
             recorder.stop(), so the stop drain is NOT included.
  inject_ms  typing/pasting the final text into the focused app. Logged
             separately and NOT part of total_ms.
  warmup_ms  idle-resume warm-up, already inside total_ms.
  stop_ms, queue_ms, stop_wait_ms  (VF-19, newer logs only) the stop path, the
             wait behind a previous dictation still decoding, and the stop
             callback's own queue wait. Older logs have none of them; with
             --causes the queue wait is recovered from the second-resolution
             recording_stopped -> transcription_started timestamps instead.

So `total_ms + inject_ms (+ stop_ms + queue_ms + stop_wait_ms)` is the
release-through-injection latency the log can see.

VF-19 adds latency per minute of audio: seconds of latency divided by minutes
of audio, with clips shorter than AUDIO_FLOOR_S counted as AUDIO_FLOOR_S so the
fixed cost of a two-second clip does not dominate. A long dictation is
expected to take longer in wall time; per minute of audio it should not.

Usage:
    python scripts/dev/log_latency.py path\\to\\voiceflow.log [--json]
    python scripts/dev/log_latency.py path\\to\\voiceflow.log --causes --date 2026-11-10 [--json]
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Optional

MARKER = "transcription_timing "
_NUM = re.compile(r"\b([a-z][a-z0-9_]*)=(-?[0-9]+(?:\.[0-9]+)?)(?=\s|$)")
_WORD = re.compile(r"\b(device|idle_resume)=([A-Za-z0-9_]+)(?=\s|$)")
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})")
FIELDS = (
    "total_ms", "inject_ms", "asr_ms", "post_ms", "warmup_ms", "raw_dur", "compacted_dur",
    "stop_ms", "queue_ms", "stop_wait_ms", "stop_to_text_ms",
)

#: Clips shorter than this count as this long in the per-minute figure.
AUDIO_FLOOR_S = 10.0
#: Wall-time limit the health run uses (voiceflow-health.ps1 $P90_LIMIT_S).
WALL_LIMIT_S = 1.2
#: Proposed per-minute limit: 6 s of latency per minute of audio (10% of real time).
#: Normal GPU dictation on 2026-11-10/11 ran 0.7-4.6 s per minute.
PER_MINUTE_LIMIT_S = 6.0


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


def latency_per_audio_minute(latency_s: float, audio_s: float, floor_s: float = AUDIO_FLOOR_S) -> float:
    """Seconds of latency per minute of audio; clips under ``floor_s`` count as ``floor_s``."""
    minutes = max(float(audio_s), float(floor_s), 1e-6) / 60.0
    return float(latency_s) / minutes


def _stats(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "median": round(percentile(values, 50), 1),
        "p90": round(percentile(values, 90), 1),
        "max": round(max(values), 1) if values else float("nan"),
    }


def _end_to_end_ms(r: dict[str, float]) -> float:
    return (
        r["total_ms"] + r["inject_ms"]
        + r.get("stop_ms", 0.0) + r.get("queue_ms", 0.0) + r.get("stop_wait_ms", 0.0)
    )


def summarize(records: list[dict[str, float]]) -> dict[str, dict[str, float]]:
    processing = [r["total_ms"] for r in records]
    inject = [r["inject_ms"] for r in records]
    end_to_end = [_end_to_end_ms(r) for r in records]
    per_minute = [
        latency_per_audio_minute(_end_to_end_ms(r) / 1000.0, r.get("compacted_dur", r.get("raw_dur", 0.0)))
        for r in records
        if "compacted_dur" in r or "raw_dur" in r
    ]
    summary = {
        "processing_only_ms": _stats(processing),
        "inject_ms": _stats(inject),
        "release_through_injection_ms": _stats(end_to_end),
    }
    if per_minute:
        summary["latency_per_audio_minute_s"] = _stats(per_minute)
    return summary


# --------------------------------------------------------------------------- causes (VF-19)


def _ts(line: str) -> Optional[datetime]:
    m = _TS.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _nums(line: str, marker: str) -> dict[str, float]:
    idx = line.find(marker)
    return {k: float(v) for k, v in _NUM.findall(line[idx + len(marker):])}


def parse_events(lines: Iterable[str]) -> dict[str, Any]:
    """Recordings (one per transcription_finished) plus the context needed to explain them."""
    recordings: list[dict[str, Any]] = []
    starts: list[datetime] = []
    model_ready: list[datetime] = []
    reconstructions: list[tuple[datetime, datetime]] = []
    last_stop: Optional[datetime] = None
    pending_start: Optional[datetime] = None
    for line in lines:
        ts = _ts(line)
        if ts is None:
            continue
        if " single_instance_ok " in line:
            starts.append(ts)
        elif "Model preloading complete" in line:
            model_ready.append(ts)
        elif " reconstruction_async " in line:
            latency_ms = _nums(line, "reconstruction_async ").get("latency_ms", 0.0)
            if latency_ms > 0:
                reconstructions.append((ts - timedelta(milliseconds=latency_ms), ts))
        elif " recording_stopped " in line:
            last_stop = ts
        elif " transcription_started " in line:
            pending_start = ts
        elif " transcription_finished " in line:
            v = _nums(line, "transcription_finished ")
            if "seconds" not in v:
                continue
            queue_s = 0.0
            if last_stop is not None and pending_start is not None and pending_start >= last_stop:
                queue_s = (pending_start - last_stop).total_seconds()
            recordings.append({
                "ts": ts,
                "audio_s": v.get("duration", 0.0),
                "latency_s": v["seconds"],
                "words": int(v.get("words", 0)),
                "queue_s_from_timestamps": queue_s,
            })
            pending_start = None
        elif MARKER in line and recordings and "timing" not in recordings[-1]:
            timing = _nums(line, MARKER)
            words = dict(_WORD.findall(line[line.find(MARKER) + len(MARKER):]))
            recordings[-1]["timing"] = {k: v for k, v in timing.items() if k in FIELDS}
            recordings[-1]["device"] = words.get("device", "")
            recordings[-1]["idle_resume"] = words.get("idle_resume", "") == "True"
    return {"recordings": recordings, "starts": starts, "model_ready": model_ready, "reconstructions": reconstructions}


def queue_seconds(rec: dict[str, Any]) -> float:
    """Wait behind a previous dictation: logged queue_ms when present, else from timestamps.

    The timestamp gap (recording_stopped -> transcription_started) also contains the
    idle-resume warm-up and has 1 s resolution, so both are taken off.
    """
    timing = rec.get("timing", {})
    if "queue_ms" in timing:
        return timing["queue_ms"] / 1000.0
    gap = rec.get("queue_s_from_timestamps", 0.0) - timing.get("warmup_ms", 0.0) / 1000.0 - 1.0
    return max(0.0, gap)


def classify(rec: dict[str, Any], ctx: dict[str, Any], slow_s: float = WALL_LIMIT_S,
             per_minute_limit_s: float = PER_MINUTE_LIMIT_S) -> list[str]:
    """Why a recording was slow. [] when it was not slow."""
    if rec["latency_s"] <= slow_s:
        return []
    timing = rec.get("timing", {})
    per_minute = latency_per_audio_minute(rec["latency_s"], rec["audio_s"])
    if per_minute <= per_minute_limit_s:
        return ["long_dictation"]  # slow in wall time only because there was a lot of audio
    causes: list[str] = []
    finished = rec["ts"]
    began = finished - timedelta(seconds=rec["latency_s"])
    if rec.get("device") == "cpu":
        causes.append("cpu_fallback")
    if rec.get("idle_resume") and timing.get("warmup_ms", 0.0) >= 1000.0:
        causes.append("first_after_idle")
    started = [s for s in ctx["starts"] if s <= began]
    if started:
        ready = [r for r in ctx["model_ready"] if r >= started[-1]]
        if not ready or ready[0] > began:
            causes.append("model_loading_after_restart")
    if queue_seconds(rec) >= 1.0:
        causes.append("queued_behind_previous")
    if timing.get("inject_ms", 0.0) >= 500.0:
        causes.append("paste_wait")
    # Log stamps have 1 s resolution: a background job that merely starts or ends in the
    # same second as this dictation does not count as overlapping it.
    margin = timedelta(seconds=1)
    if any(a < finished - margin and began + margin < b for a, b in ctx["reconstructions"]):
        causes.append("reconstruction_running")
    if not causes:
        # On the GPU with nothing in VoiceFlow explaining it: the CPU or GPU was busy
        # with something else (another build, tests, a local LLM) or the process was starved.
        causes.append("contention_unexplained")
    return causes


def day_report(lines: Iterable[str], date: str, slow_s: float = WALL_LIMIT_S) -> dict[str, Any]:
    ctx = parse_events(lines)
    day = [r for r in ctx["recordings"] if r["ts"].strftime("%Y-%m-%d") == date]
    wall = [r["latency_s"] for r in day]
    per_min = [latency_per_audio_minute(r["latency_s"], r["audio_s"]) for r in day]
    slow = []
    for r in day:
        causes = classify(r, ctx, slow_s=slow_s)
        if causes:
            slow.append({
                "time": r["ts"].strftime("%H:%M:%S"),
                "audio_s": round(r["audio_s"], 2),
                "latency_s": round(r["latency_s"], 3),
                "per_audio_min_s": round(latency_per_audio_minute(r["latency_s"], r["audio_s"]), 1),
                "device": r.get("device", ""),
                "queue_s": round(queue_seconds(r), 1),
                "causes": causes,
            })
    starts = [s for s in ctx["starts"] if s.strftime("%Y-%m-%d") == date]
    wall_p90 = percentile(wall, 90) if wall else None
    per_min_p90 = percentile(per_min, 90) if per_min else None
    return {
        "date": date,
        "recordings": len(day),
        "release_to_text_median_s": round(percentile(wall, 50), 3) if wall else None,
        "release_to_text_p90_s": round(wall_p90, 3) if wall_p90 is not None else None,
        "latency_per_audio_minute_p90_s": round(per_min_p90, 2) if per_min_p90 is not None else None,
        "long_recordings": sum(1 for r in day if r["audio_s"] >= 30.0),
        "app_starts": len(starts),
        "regression_wall_only": bool(wall_p90 is not None and wall_p90 > WALL_LIMIT_S),
        "regression_wall_and_per_minute": bool(
            wall_p90 is not None and wall_p90 > WALL_LIMIT_S
            and per_min_p90 is not None and per_min_p90 > PER_MINUTE_LIMIT_S
        ),
        "slow": slow,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--causes", action="store_true", help="per-day slow-recording cause table")
    parser.add_argument("--date", help="YYYY-MM-DD for --causes (default: last day in the log)")
    args = parser.parse_args(argv)
    with args.log.open(encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    if args.causes:
        date = args.date
        if not date:
            stamps = [_ts(line) for line in lines]
            date = max((s for s in stamps if s is not None), default=datetime.now()).strftime("%Y-%m-%d")
        report = day_report(lines, date)
        if args.json:
            print(json.dumps(report, indent=2))
            return 0
        print(
            f"{report['date']}: {report['recordings']} recordings, median {report['release_to_text_median_s']} s, "
            f"p90 {report['release_to_text_p90_s']} s, p90 per audio minute {report['latency_per_audio_minute_p90_s']} s, "
            f"app starts {report['app_starts']}"
        )
        print(f"{'time':8} {'audio_s':>8} {'latency_s':>9} {'s/min':>7} {'device':>6} {'queue_s':>7}  causes")
        for s in report["slow"]:
            print(
                f"{s['time']:8} {s['audio_s']:>8.2f} {s['latency_s']:>9.3f} {s['per_audio_min_s']:>7.1f} "
                f"{s['device']:>6} {s['queue_s']:>7.1f}  {', '.join(s['causes'])}"
            )
        return 0
    summary = summarize(parse(lines))
    if args.json:
        print(json.dumps(summary, indent=2))
        return 0
    print(f"{'metric':32} {'n':>4} {'median':>9} {'p90':>9} {'max':>9}")
    for name, s in summary.items():
        print(f"{name:32} {s['n']:>4} {s['median']:>9.1f} {s['p90']:>9.1f} {s['max']:>9.1f}")
    print("release_through_injection = total_ms + inject_ms (+ stop/queue on newer logs).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
