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


# Modules the running app needs. A missing one here is a broken bundle.
SELF_CHECK_MODULES = (
    "voiceflow.core.asr_engine",
    "voiceflow.core.audio_enhanced",
    "voiceflow.core.live_caption",
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


# Loaded together with asr_engine.CUDA_REQUIRED_DLLS: they are what the required
# pair links against. scripts/setup/verify_bundle.py reads this tuple too.
CUDA_COMPANION_DLLS = ("cublasLt64_12.dll", "cudnn64_9.dll")


def _bundle_root() -> Path | None:
    """Where PyInstaller unpacked the bundle (one-dir: _internal; one-file: temp)."""
    meipass = getattr(sys, "_MEIPASS", "")
    return Path(str(meipass)) if meipass else None


def _check_bundled_cuda(required: tuple[str, ...]) -> tuple[bool, str]:
    """Load the CUDA DLLs from inside the bundle, ignoring PATH and venvs.

    The runtime probe (`asr_engine._cuda_runtime_ready`) also searches PATH and
    nearby venvs, so on a dev machine it can pass for a bundle that ships no
    CUDA at all. This check only looks in the bundle.
    """
    import ctypes

    root = _bundle_root()
    if root is None:
        return False, "not a frozen bundle"
    lib = root / "torch" / "lib"
    names = list(required) + list(CUDA_COMPANION_DLLS)
    missing = [n for n in names if not (lib / n).is_file()]
    if missing:
        return False, f"missing in bundle {lib}: {', '.join(missing)}"
    try:
        os.add_dll_directory(str(lib))
    except Exception:
        pass
    for name in names:
        try:
            ctypes.WinDLL(str(lib / name))
        except OSError as exc:
            return False, f"{name} present but does not load: {exc}"
    return True, f"{len(names)} DLLs load from {lib}"


def _self_check_flags(argv: list[str]) -> set[str]:
    return {a for a in argv[1:] if a == "--self-check-allow-cpu-only"}


def _run_self_check(out_path: str, *, allow_cpu_only: bool = False) -> int:
    """Verify the frozen bundle without starting the app (no tray, hotkeys, mic).

    Runs inside the frozen interpreter, so every import and the VAD load use the
    bundle's own modules and native libraries. It imports the app's modules
    (import only: nothing here creates a tray icon, registers a hotkey or opens
    an audio stream), runs the Silero VAD through the bundled onnxruntime the
    way streaming preview does, and loads the bundled CUDA DLLs. The windowed
    EXE has no console, so the report goes to a file:
        VoiceFlow.exe --self-check=C:\\path\\report.json [--self-check-allow-cpu-only]
    Exit code 0 = everything the daily-driver path needs is present.
    `scripts/setup/verify_bundle.py` runs this from the build and fails the
    build on a non-zero exit.
    """
    import importlib
    import json
    import traceback

    frozen = bool(getattr(sys, "frozen", False))
    root = _bundle_root()
    report: dict = {
        "frozen": frozen,
        "bundle_root": str(root) if root else None,
        "allow_cpu_only": bool(allow_cpu_only),
        "checks": {},
    }
    ok = True

    def _record(name: str, passed: bool, detail: str = "", *, warn_only: bool = False) -> None:
        nonlocal ok
        report["checks"][name] = {"ok": bool(passed), "detail": detail, "warn_only": warn_only}
        if not passed and not warn_only:
            ok = False

    for mod in SELF_CHECK_MODULES:
        try:
            importlib.import_module(mod)
            _record(f"import:{mod}", True)
        except Exception as exc:  # noqa: BLE001 - report every failure
            _record(f"import:{mod}", False, f"{type(exc).__name__}: {exc}")

    if frozen and root is not None:
        # Prove the natives came from the bundle, not from a Python install the
        # build machine happens to have.
        try:
            import onnxruntime

            ort_file = Path(onnxruntime.__file__).resolve()
            inside = str(ort_file).lower().startswith(str(root.resolve()).lower())
            _record("onnxruntime_from_bundle", inside, str(ort_file))
        except Exception as exc:  # noqa: BLE001
            _record("onnxruntime_from_bundle", False, f"{type(exc).__name__}: {exc}")

    try:
        from faster_whisper.utils import get_assets_path

        vad_path = Path(get_assets_path()) / "silero_vad_v6.onnx"
        if not vad_path.is_file():
            _record("vad_asset", False, f"missing: {vad_path}")
        else:
            # The exact call that logged "Applying the VAD filter requires the
            # onnxruntime package" / NO_SUCHFILE in the field.
            from faster_whisper.vad import VadOptions, get_speech_timestamps

            get_speech_timestamps(np.zeros(16000, dtype=np.float32), VadOptions())
            _record("vad_asset", True, f"{vad_path} (VAD ran on 1 s of silence)")
    except Exception as exc:  # noqa: BLE001
        _record("vad_asset", False, f"{type(exc).__name__}: {exc}")

    try:
        from voiceflow.core import asr_engine

        required = tuple(asr_engine.CUDA_REQUIRED_DLLS)
        if frozen:
            passed, detail = _check_bundled_cuda(required)
        else:
            asr_engine._cuda_runtime_ready()
            missing = asr_engine._missing_cuda_dlls(list(required))
            passed, detail = (not missing), (",".join(missing) or "all present")
        # Missing DLLs is a broken GPU bundle. "No GPU on this machine" is not,
        # so this loads the DLLs but never asks for a CUDA device.
        _record(
            "cuda_runtime_dlls",
            passed,
            detail + (" (accepted: CPU-only build)" if (not passed and allow_cpu_only) else ""),
            warn_only=allow_cpu_only,
        )
    except Exception as exc:  # noqa: BLE001
        _record("cuda_runtime_dlls", False, f"{type(exc).__name__}: {exc}", warn_only=allow_cpu_only)

    # Which commit this bundle was built from, as the frozen code itself sees
    # it. Informational (not a check): verify_bundle.py compares it to HEAD so a
    # stale bundle cannot pass as a build of the current tip.
    try:
        from voiceflow import _build_stamp as stamp

        report["build"] = {
            "version": getattr(stamp, "VERSION", None),
            "commit": getattr(stamp, "COMMIT", None),
            "built_at": getattr(stamp, "BUILT_AT", None),
            "dirty": getattr(stamp, "DIRTY", None),
        }
    except Exception as exc:  # noqa: BLE001 - absent in source checkouts that were never built
        report["build"] = {"error": f"{type(exc).__name__}: {exc}"}

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


def _boot_breadcrumb(event: str, **fields) -> None:
    """Append to logs/boot_breadcrumb.log with plain file I/O (VF-18).

    Deliberately independent of the app's logging: it must work when the app
    dies, stalls or mis-initialises before AsyncLogger exists. Never raises.
    """
    # Standard library only. Importing the voiceflow package here would pull in
    # the tray and PIL before stdout/stderr are repaired.
    try:
        lad = os.environ.get("LOCALAPPDATA")
        directory = Path(lad) / "VoiceFlow" / "logs" if lad else Path.home() / ".voiceflow" / "logs"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "boot_breadcrumb.log"
        try:
            if path.exists() and path.stat().st_size > 512 * 1024:
                os.replace(path, path.with_name("boot_breadcrumb.log.1"))
        except Exception:
            pass
        parts = [time.strftime("%Y-%m-%d %H:%M:%S"), f"pid={os.getpid()}", event]
        for key, value in fields.items():
            parts.append("{}={}".format(key, str(value).replace("\r", " ").replace("\n", " ")[:400]))
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(" ".join(parts) + "\n")
    except Exception:
        pass


def _stream_states() -> dict:
    states = {}
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            states[name] = "none"
            continue
        try:
            stream.write("")
            stream.flush()
            states[name] = "ok"
        except Exception as exc:
            states[name] = f"unusable:{type(exc).__name__}"
    return states


def main() -> int:
    # Record how the process was launched before _ensure_std_streams repairs a
    # missing stdout/stderr, so the breadcrumb shows the launcher's real state.
    original_streams = _stream_states()
    _ensure_std_streams()
    _ensure_src_on_path()
    # Handed to cli_enhanced so the startup self-check reports the original state.
    os.environ["VOICEFLOW_LAUNCH_STREAMS"] = "stdout={};stderr={}".format(
        original_streams.get("stdout", "unknown"),
        original_streams.get("stderr", "unknown"),
    )
    try:
        cwd_text = os.getcwd()
    except Exception:
        cwd_text = "unavailable"
    _boot_breadcrumb(
        "boot",
        frozen=bool(getattr(sys, "frozen", False)),
        stdout=original_streams.get("stdout", "unknown"),
        stderr=original_streams.get("stderr", "unknown"),
        cwd=cwd_text,
        localappdata_set="LOCALAPPDATA" in os.environ,
    )
    _configure_frozen_tk_runtime()
    self_check_out = _self_check_target(sys.argv)
    if self_check_out:
        # Returns before anything below runs: no tray, hotkeys or microphone.
        return _run_self_check(
            self_check_out,
            allow_cpu_only="--self-check-allow-cpu-only" in _self_check_flags(sys.argv),
        )
    diag_wav = os.environ.get("VOICEFLOW_DIAG_BENCH_WAV", "").strip()
    if diag_wav:
        return _run_diagnostic_benchmark(Path(diag_wav).expanduser())

    from voiceflow.ui.cli_enhanced import main as cli_main

    _boot_breadcrumb("entering_cli_main")
    try:
        result = cli_main()
    except SystemExit as exc:
        _boot_breadcrumb("cli_main_exit", code=exc.code)
        raise
    except BaseException as exc:
        import traceback

        _boot_breadcrumb("cli_main_crash", error=f"{type(exc).__name__}: {exc}", tb=traceback.format_exc()[-1500:])
        raise
    _boot_breadcrumb("cli_main_returned", result=result)
    return int(result) if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
