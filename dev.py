#!/usr/bin/env python3
"""VoiceFlow hot-reload dev launcher — two-process edition.

Splits VoiceFlow into two processes so Whisper never has to reload on code
changes:

  Model Server  — loads Whisper once, exposes transcription on localhost HTTP.
                  Only restarted when ASR/model-server source files change.

  App Process   — UI, audio, hotkeys, all the interaction logic.
                  Restarted on every source change.  ~instant reload.

Usage:
    python dev.py [--no-model-server] [--debounce 1.0] [-- voiceflow-args...]

Flags:
    --no-model-server   Fall back to the original single-process behaviour
                        (Whisper reloads on every restart, like the old dev.py).
    --debounce SECS     Wait this long after last change before restarting (1.2s).
    --watch DIR         Extra directories to watch (can repeat).
    --port PORT         Model-server port (default: 8765).
    --poll-interval     How often to poll for file changes (0.8s).
    --no-restart        Run app once without watching (profiling / one-shot use).

Environment:
    VOICEFLOW_DEV=1 is set automatically.
    VOICEFLOW_MODEL_SERVER_ENABLED=1 is set when the model server is active.
    VOICEFLOW_MODEL_SERVER_PORT is propagated to both processes.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
ENTRY_POINT = REPO_ROOT / "voiceflow.py"
MODEL_SERVER_MODULE = "voiceflow.core.model_server"

# Extensions that trigger a restart when changed.
WATCHED_EXTENSIONS = {".py"}

# Paths to ignore (relative to REPO_ROOT).
IGNORED_DIRS = {
    "__pycache__", ".git", "venv", "whisper_env", "build", "dist",
    "node_modules", ".mypy_cache", ".pytest_cache", "htmlcov",
}

# Source files that, when changed, require the model server to restart too.
# Everything else only restarts the app.
MODEL_SERVER_SOURCE_FILES = {
    SRC_DIR / "voiceflow" / "core" / "asr_engine.py",
    SRC_DIR / "voiceflow" / "core" / "model_server.py",
    SRC_DIR / "voiceflow" / "core" / "preloader.py",
}


# ---------------------------------------------------------------------------
# File watching helpers (same as original dev.py)
# ---------------------------------------------------------------------------

def _collect_mtimes(watch_dirs: list[Path]) -> dict[Path, float]:
    mtimes: dict[Path, float] = {}
    for root_dir in watch_dirs:
        if not root_dir.exists():
            continue
        for path in root_dir.rglob("*"):
            if path.suffix not in WATCHED_EXTENSIONS:
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            try:
                mtimes[path] = path.stat().st_mtime
            except OSError:
                pass
    return mtimes


def _changed_files(old: dict[Path, float], new: dict[Path, float]) -> list[Path]:
    changed = []
    for path, mtime in new.items():
        if old.get(path) != mtime:
            changed.append(path)
    for path in old:
        if path not in new:
            changed.append(path)
    return changed


def _needs_model_server_restart(changed: list[Path]) -> bool:
    return any(p in MODEL_SERVER_SOURCE_FILES for p in changed)


# ---------------------------------------------------------------------------
# Process management
# ---------------------------------------------------------------------------

def _build_base_env() -> dict[str, str]:
    env = os.environ.copy()
    env["VOICEFLOW_DEV"] = "1"
    src_str = str(SRC_DIR)
    existing = env.get("PYTHONPATH", "")
    if src_str not in existing.split(os.pathsep):
        env["PYTHONPATH"] = src_str + (os.pathsep + existing if existing else "")
    return env


def _stop_proc(proc: Optional[subprocess.Popen], label: str, timeout: float = 5.0) -> None:
    if proc is None or proc.poll() is not None:
        return
    print(f"[dev] Stopping {label}...", flush=True)
    try:
        if sys.platform == "win32":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[dev] {label} did not exit cleanly — killing.", flush=True)
        proc.kill()
        proc.wait()


def _start_model_server(port: int, env: dict[str, str]) -> subprocess.Popen:
    cmd = [
        sys.executable, "-m", MODEL_SERVER_MODULE,
        "--port", str(port),
    ]
    print(f"\n[dev] Starting model server: {' '.join(cmd)}", flush=True)
    return subprocess.Popen(cmd, env=env, cwd=str(SRC_DIR))


def _start_app(extra_args: list[str], env: dict[str, str]) -> subprocess.Popen:
    # Use _app_entry.py wrapper instead of -m voiceflow.ui.cli_enhanced.
    # The singleton logic in cli_enhanced.py kills processes whose cmdline
    # contains "-m voiceflow.ui.cli_enhanced" (psutil.terminate -> exit 15).
    # The frozen exe was immune; this wrapper achieves the same effect.
    entry = REPO_ROOT / "_app_entry.py"
    cmd = [sys.executable, str(entry)] + extra_args
    print(f"\n[dev] Starting app: {' '.join(cmd)}  (cwd={SRC_DIR})", flush=True)
    return subprocess.Popen(cmd, env=env, cwd=str(SRC_DIR))


# ---------------------------------------------------------------------------
# Model server readiness check
# ---------------------------------------------------------------------------

def _model_server_health(port: int) -> Optional[dict]:
    try:
        resp = urllib.request.urlopen(
            f"http://127.0.0.1:{port}/health", timeout=1.0
        )
        return json.loads(resp.read())
    except Exception:
        return None


def _wait_for_model_server(port: int, timeout: float = 10.0, label: str = "model server") -> bool:
    """Wait until the model server HTTP port is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        health = _model_server_health(port)
        if health is not None:
            return True
        time.sleep(0.2)
    print(f"[dev] WARNING: {label} did not come up within {timeout:.0f}s", flush=True)
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="VoiceFlow hot-reload dev launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--no-model-server",
        action="store_true",
        help="Single-process mode: Whisper reloads on every restart (original behaviour)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("VOICEFLOW_MODEL_SERVER_PORT", "8765")),
        metavar="PORT",
        help="Model server port (default: 8765)",
    )
    parser.add_argument(
        "--debounce",
        type=float,
        default=1.2,
        metavar="SECONDS",
        help="Wait this long after a change before restarting (default: 1.2s)",
    )
    parser.add_argument(
        "--watch",
        action="append",
        default=None,
        metavar="DIR",
        help="Additional directories to watch (default: src/)",
    )
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="Run once without watching (useful for profiling)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.8,
        metavar="SECONDS",
        help="How often to poll for file changes (default: 0.8s)",
    )
    args, voiceflow_args = parser.parse_known_args()
    if voiceflow_args and voiceflow_args[0] == "--":
        voiceflow_args = voiceflow_args[1:]

    use_model_server = not args.no_model_server

    watch_dirs: list[Path] = [SRC_DIR]
    if args.watch:
        for d in args.watch:
            p = Path(d).resolve()
            if not p.exists():
                print(f"[dev] WARNING: watch dir does not exist: {p}", flush=True)
            watch_dirs.append(p)

    print("=" * 60, flush=True)
    print("  VoiceFlow Dev Launcher", flush=True)
    if use_model_server:
        print(f"  Mode: two-process  (model server on port {args.port})", flush=True)
        print("  Whisper loads ONCE and persists across app restarts.", flush=True)
    else:
        print("  Mode: single-process  (--no-model-server)", flush=True)
    print(f"  Watching: {', '.join(str(d) for d in watch_dirs)}", flush=True)
    print(f"  Debounce: {args.debounce}s  |  Poll: {args.poll_interval}s", flush=True)
    print("  Press Ctrl+C to stop.", flush=True)
    print("=" * 60, flush=True)

    base_env = _build_base_env()

    model_server_proc: Optional[subprocess.Popen] = None
    app_proc: Optional[subprocess.Popen] = None

    if use_model_server:
        # Propagate the port to both processes.
        base_env["VOICEFLOW_MODEL_SERVER_PORT"] = str(args.port)
        base_env["VOICEFLOW_MODEL_SERVER_ENABLED"] = "1"

        # Check if a model server is already running on this port.
        existing = _model_server_health(args.port)
        if existing is not None:
            print(
                f"[dev] Model server already running on port {args.port} "
                f"(status={existing.get('status', '?')}). Reusing it.",
                flush=True,
            )
        else:
            model_server_proc = _start_model_server(args.port, base_env)
            _wait_for_model_server(args.port, timeout=10.0)

    app_proc = _start_app(voiceflow_args, base_env)

    if args.no_restart:
        print("[dev] --no-restart mode: waiting for app to exit.", flush=True)
        rc = app_proc.wait()
        _stop_proc(model_server_proc, "model server")
        return rc

    mtimes = _collect_mtimes(watch_dirs)
    last_change_time: float = 0.0
    pending_restart = False
    restart_model_server = False

    try:
        while True:
            time.sleep(args.poll_interval)

            # Check if app exited on its own.
            if app_proc is not None and app_proc.poll() is not None:
                code = app_proc.returncode
                print(f"\n[dev] App exited (code {code}). Watching for changes...", flush=True)
                app_proc = None

            # Check if model server died unexpectedly.
            if (
                use_model_server
                and model_server_proc is not None
                and model_server_proc.poll() is not None
            ):
                code = model_server_proc.returncode
                print(
                    f"\n[dev] Model server exited unexpectedly (code {code}). "
                    "Restarting it...",
                    flush=True,
                )
                model_server_proc = _start_model_server(args.port, base_env)
                _wait_for_model_server(args.port, timeout=10.0)
                # Restart the app too so it reconnects cleanly.
                _stop_proc(app_proc, "app")
                app_proc = _start_app(voiceflow_args, base_env)

            new_mtimes = _collect_mtimes(watch_dirs)
            changed = _changed_files(mtimes, new_mtimes)
            mtimes = new_mtimes

            if changed:
                last_change_time = time.monotonic()
                pending_restart = True
                if use_model_server and _needs_model_server_restart(changed):
                    restart_model_server = True
                rel = [str(f.relative_to(REPO_ROOT)) for f in changed[:5]]
                more = f" (+{len(changed) - 5} more)" if len(changed) > 5 else ""
                server_note = " [model server will restart too]" if restart_model_server else ""
                print(
                    f"\n[dev] Changed: {', '.join(rel)}{more}{server_note}",
                    flush=True,
                )

            if pending_restart:
                elapsed = time.monotonic() - last_change_time
                if elapsed >= args.debounce:
                    pending_restart = False

                    _stop_proc(app_proc, "app")
                    app_proc = None

                    if restart_model_server and use_model_server:
                        restart_model_server = False
                        _stop_proc(model_server_proc, "model server")
                        model_server_proc = None
                        mtimes = _collect_mtimes(watch_dirs)
                        model_server_proc = _start_model_server(args.port, base_env)
                        _wait_for_model_server(args.port, timeout=10.0)
                    else:
                        mtimes = _collect_mtimes(watch_dirs)

                    app_proc = _start_app(voiceflow_args, base_env)

    except KeyboardInterrupt:
        print("\n[dev] Shutting down...", flush=True)
        _stop_proc(app_proc, "app")
        _stop_proc(model_server_proc, "model server")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
