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


# Modules the running app needs. A missing one here is a broken bundle.
SELF_CHECK_MODULES = (
    "voiceflow.core.asr_engine",
    "voiceflow.core.audio_enhanced",
    "voiceflow.core.streaming",
    "voiceflow.integrations.inject",
    "voiceflow.integrations.hotkeys_enhanced",
    "voiceflow.ui.cli_enhanced",
    "faster_whisper",
    "faster_whisper.vad",
    "ctranslate2",
    "onnxruntime",
    "sounddevice",
    "keyboard",
    "pystray",
    "win32gui",
    "tkinter",
)


def _run_self_check(out_path: str) -> int:
    """Verify the frozen bundle without starting the app (no tray, hotkeys, mic).

    Imports the app's modules, loads the Silero VAD asset through onnxruntime and
    probes the CUDA runtime, then writes a JSON report. The windowed EXE has no
    console, so the report goes to a file:
        VoiceFlow.exe --self-check=C:\\path\\report.json
    Exit code 0 = everything the daily-driver path needs is present.
    """
    import importlib
    import json
    import traceback

    report: dict = {"frozen": bool(getattr(sys, "frozen", False)), "checks": {}}
    ok = True

    def _record(name: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        report["checks"][name] = {"ok": bool(passed), "detail": detail}
        ok = ok and bool(passed)

    for mod in SELF_CHECK_MODULES:
        try:
            importlib.import_module(mod)
            _record(f"import:{mod}", True)
        except Exception as exc:  # noqa: BLE001 - report every failure
            _record(f"import:{mod}", False, f"{type(exc).__name__}: {exc}")

    try:
        from faster_whisper.utils import get_assets_path

        vad_path = Path(get_assets_path()) / "silero_vad_v6.onnx"
        if not vad_path.is_file():
            _record("vad_asset", False, f"missing: {vad_path}")
        else:
            import onnxruntime

            onnxruntime.InferenceSession(str(vad_path), providers=["CPUExecutionProvider"])
            _record("vad_asset", True, str(vad_path))
    except Exception as exc:  # noqa: BLE001
        _record("vad_asset", False, f"{type(exc).__name__}: {exc}")

    try:
        from voiceflow.core import asr_engine

        cuda_ready = bool(asr_engine._cuda_runtime_ready())
        missing = asr_engine._missing_cuda_dlls(list(asr_engine.CUDA_REQUIRED_DLLS))
        report["cuda_ready"] = cuda_ready
        report["cuda_missing_dlls"] = missing
        # Missing DLLs is a broken GPU bundle. "No GPU on this machine" is not.
        _record("cuda_runtime_dlls", not missing, ",".join(missing) or "all present")
    except Exception as exc:  # noqa: BLE001
        _record("cuda_runtime_dlls", False, f"{type(exc).__name__}: {exc}")

    report["ok"] = ok
    text = json.dumps(report, indent=2)
    try:
        Path(out_path).write_text(text, encoding="utf-8")
    except Exception:
        traceback.print_exc()
        ok = False
    if sys.stdout is not None:
        try:
            print(text)
        except Exception:
            pass
    return 0 if ok else 1


def _self_check_target(argv: list[str]) -> str | None:
    for arg in argv[1:]:
        if arg == "--self-check":
            return str(Path(os.environ.get("TEMP", ".")) / "voiceflow_self_check.json")
        if arg.startswith("--self-check="):
            return arg.split("=", 1)[1]
    return None


def main() -> int:
    _ensure_src_on_path()
    _configure_frozen_tk_runtime()
    self_check_out = _self_check_target(sys.argv)
    if self_check_out:
        return _run_self_check(self_check_out)
    diag_wav = os.environ.get("VOICEFLOW_DIAG_BENCH_WAV", "").strip()
    if diag_wav:
        return _run_diagnostic_benchmark(Path(diag_wav).expanduser())

    from voiceflow.ui.cli_enhanced import main as cli_main

    result = cli_main()
    return int(result) if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
