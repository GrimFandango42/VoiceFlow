#!/usr/bin/env python3
"""
PyInstaller entrypoint for VoiceFlow on Windows.

This module runs the packaged Windows runtime entrypoint:
`voiceflow.ui.cli_enhanced:main`.
"""

from __future__ import annotations

import os
import sys
import time
import wave
from pathlib import Path

import numpy as np


def _ensure_std_streams() -> None:
    """
    Give the app real stdout/stderr before anything prints.

    A windowed PyInstaller build has no console, so sys.stdout and sys.stderr
    are None. The app prints diagnostics throughout startup, and print() to a
    None stream raises AttributeError -- so how VoiceFlow was launched decided
    how far it got through startup. Launched from a shell with redirected
    output it logged normally; launched by Task Scheduler, the watchdog or the
    Startup shortcut -- which is to say, nearly always -- a print somewhere
    ahead of AsyncLogger threw, logging was never initialised, and the app ran
    for days with no telemetry at all. That is why a bug reported from daily
    use left nothing in the log to diagnose.

    Redirect to os.devnull rather than inventing a log file: the real log is
    AsyncLogger's, and the point here is only that printing must never be able
    to interrupt startup.
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        usable = False
        if stream is not None:
            try:
                stream.write("")
                stream.flush()
                usable = True
            except Exception:
                usable = False
        if not usable:
            try:
                setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
            except Exception:
                # Last resort: a sink that satisfies print() and never raises.
                class _NullStream:
                    def write(self, _data):
                        return 0

                    def flush(self):
                        return None

                setattr(sys, name, _NullStream())


def _ensure_src_on_path() -> None:
    """Allow direct invocation from source tree during local packaging."""
    if getattr(sys, "frozen", False):
        return
    repo_root = Path(__file__).resolve().parents[2]
    src_root = repo_root / "src"
    src_text = str(src_root)
    if src_text not in sys.path:
        sys.path.insert(0, src_text)


def _configure_frozen_tk_runtime() -> None:
    """Expose bundled Tcl/Tk assets for packaged setup wizard launches."""
    if not getattr(sys, "frozen", False):
        return

    roots = []
    try:
        roots.append(Path(sys.executable).resolve().parent)
    except Exception:
        pass

    try:
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            roots.append(Path(str(meipass)))
    except Exception:
        pass

    seen: set[str] = set()
    for root in roots:
        key = str(root).lower()
        if key in seen:
            continue
        seen.add(key)
        tcl_root = root / "tcl"
        tcl_lib = tcl_root / "tcl8.6"
        tk_lib = tcl_root / "tk8.6"
        if tcl_lib.exists() and tk_lib.exists():
            os.environ.setdefault("TCL_LIBRARY", str(tcl_lib))
            os.environ.setdefault("TK_LIBRARY", str(tk_lib))
            break


def _load_wav_mono_16k(path: Path) -> np.ndarray:
    with wave.open(str(path), "rb") as wf:
        sample_rate = int(wf.getframerate())
        frames = int(wf.getnframes())
        channels = int(wf.getnchannels())
        sample_width = int(wf.getsampwidth())
        raw = wf.readframes(frames)

    if sample_width == 2:
        audio = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
    elif sample_width == 1:
        audio = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0) / 128.0
    else:
        raise ValueError(f"Unsupported WAV sample width: {sample_width}")

    if channels > 1:
        audio = audio.reshape(-1, channels).mean(axis=1)

    if sample_rate != 16000:
        old_t = np.linspace(0.0, len(audio) / sample_rate, num=len(audio), endpoint=False)
        new_len = int((len(audio) * 16000) / sample_rate)
        new_t = np.linspace(0.0, len(audio) / sample_rate, num=new_len, endpoint=False)
        audio = np.interp(new_t, old_t, audio).astype(np.float32)

    return np.clip(audio.astype(np.float32), -1.0, 1.0)


def _run_diagnostic_benchmark(wav_path: Path) -> int:
    from voiceflow.core.asr_engine import ModernWhisperASR
    from voiceflow.core.config import Config
    from voiceflow.utils.settings import load_config

    if not wav_path.exists():
        print(f"[DIAG] WAV not found: {wav_path}")
        return 2

    cfg = load_config(Config())
    asr = ModernWhisperASR(cfg)

    audio = _load_wav_mono_16k(wav_path)
    total_duration = len(audio) / 16000.0
    short_audio = audio[: max(1600, min(len(audio), int(4.0 * 16000)))]

    model = getattr(asr, "model_config", None)
    if model is not None:
        print(
            "[DIAG] model={} model_id={} device={} compute={}".format(
                getattr(model, "name", ""),
                getattr(model, "model_id", ""),
                getattr(model, "device", ""),
                getattr(model, "compute_type", ""),
            )
        )

    t0 = time.perf_counter()
    short_text = asr.transcribe(short_audio)
    short_elapsed = time.perf_counter() - t0
    short_duration = len(short_audio) / 16000.0
    short_speed = short_duration / max(short_elapsed, 1e-6)
    print(
        "[DIAG] first_short dur_s={:.2f} wall_s={:.3f} speed_x={:.2f} chars={}".format(
            short_duration,
            short_elapsed,
            short_speed,
            len((short_text or "").strip()),
        )
    )

    t1 = time.perf_counter()
    long_text = asr.transcribe(audio)
    long_elapsed = time.perf_counter() - t1
    long_speed = total_duration / max(long_elapsed, 1e-6)
    print(
        "[DIAG] second_long dur_s={:.2f} wall_s={:.3f} speed_x={:.2f} chars={}".format(
            total_duration,
            long_elapsed,
            long_speed,
            len((long_text or "").strip()),
        )
    )
    return 0


def main() -> int:
    _ensure_std_streams()
    _ensure_src_on_path()
    _configure_frozen_tk_runtime()
    diag_wav = os.environ.get("VOICEFLOW_DIAG_BENCH_WAV", "").strip()
    if diag_wav:
        return _run_diagnostic_benchmark(Path(diag_wav).expanduser())

    from voiceflow.ui.cli_enhanced import main as cli_main

    result = cli_main()
    return int(result) if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
