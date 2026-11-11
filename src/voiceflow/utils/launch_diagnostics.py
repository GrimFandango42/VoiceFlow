"""Launch diagnostics (VF-18): prove at startup that VoiceFlow can record, and say how it was launched.

Why this exists. Started by Task Scheduler, the watchdog or Explorer, the same
binary has been seen to write no ``voiceflow.log``, leave ``active_log_path.txt``
alone and record no history, while the same binary started from a shell does all
three. The cause is an environment difference that has not been pinned down, and
it cannot be pinned down by reading code: it needs a record of what each launch
looked like. This module produces that record, and it makes the failure loud
instead of silent.

Three pieces, in the order a launch meets them:

``write_boot_breadcrumb``
    Plain ``open(..., "a")`` appends to ``logs/boot_breadcrumb.log``. No logging
    framework, no queue, no imports from the app, never raises. If the app dies
    or stalls before ``AsyncLogger`` exists, this is the only trace.

``launch_context``
    Facts that differ between launchers: parent process, session, whether a
    console and stdout/stderr exist, working directory, and the *names* of the
    environment variables (never values, apart from a short allow-list of paths
    that are not secrets).

``run_startup_selfcheck``
    Writes a first record through each path the app relies on, reads it back, and
    reports. Used by the app to raise a tray warning when recording is broken.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Environment variables whose *values* are safe and useful to record. Everything
# else is recorded by name only.
_SAFE_ENV_VALUES = (
    "LOCALAPPDATA",
    "TEMP",
    "SESSIONNAME",
    "HF_HUB_OFFLINE",
    "VOICEFLOW_SKIP_SETUP_UI",
    "VOICEFLOW_FORCE_CPU",
)

_BREADCRUMB_MAX_BYTES = 512 * 1024


def _default_dir() -> Path:
    lad = os.environ.get("LOCALAPPDATA")
    if lad:
        return Path(lad) / "VoiceFlow" / "logs"
    return Path.home() / ".voiceflow" / "logs"


def write_boot_breadcrumb(event: str, directory: Optional[Path] = None, **fields: Any) -> None:
    """Append one line to ``boot_breadcrumb.log``. Never raises, never blocks on app code."""
    try:
        target_dir = Path(directory) if directory is not None else _default_dir()
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / "boot_breadcrumb.log"
        try:
            if path.exists() and path.stat().st_size > _BREADCRUMB_MAX_BYTES:
                os.replace(path, path.with_name("boot_breadcrumb.log.1"))
        except Exception:
            pass
        parts = [time.strftime("%Y-%m-%d %H:%M:%S"), f"pid={os.getpid()}", event]
        for key, value in fields.items():
            text = str(value).replace("\r", " ").replace("\n", " ")
            parts.append(f"{key}={text[:400]}")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(" ".join(parts) + "\n")
    except Exception:
        pass


def _parent_process_name() -> str:
    """Name of the parent process; best effort, no hard dependency."""
    try:
        import psutil  # type: ignore

        parent = psutil.Process(os.getpid()).parent()
        return parent.name() if parent else "none"
    except Exception:
        pass
    if os.name != "nt":
        return "unknown"
    try:  # ToolHelp snapshot, stdlib only.
        import ctypes
        from ctypes import wintypes

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        snapshot = kernel32.CreateToolhelp32Snapshot(0x2, 0)
        if snapshot in (0, -1):
            return "unknown"
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            names: Dict[int, str] = {}
            parent_of: Dict[int, int] = {}
            ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                names[entry.th32ProcessID] = entry.szExeFile
                parent_of[entry.th32ProcessID] = entry.th32ParentProcessID
                ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)
        ppid = parent_of.get(os.getpid(), 0)
        return names.get(ppid, f"pid{ppid}(exited)")
    except Exception:
        return "unknown"


def _stream_state(stream: Any) -> str:
    if stream is None:
        return "none"
    try:
        stream.write("")
        stream.flush()
        return "ok"
    except Exception as exc:
        return f"unusable:{type(exc).__name__}"


def launch_context(*, original_streams: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """What this launch looked like. Env var names only, plus a short value allow-list."""
    ctx: Dict[str, Any] = {
        "pid": os.getpid(),
        "parent": _parent_process_name(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "executable": sys.executable,
        "cwd": os.getcwd() if _cwd_ok() else "unavailable",
        "argv_count": len(sys.argv),
        "stdout": original_streams.get("stdout") if original_streams else _stream_state(sys.stdout),
        "stderr": original_streams.get("stderr") if original_streams else _stream_state(sys.stderr),
        "stdin": _stream_state(sys.stdin),
        "env_var_count": len(os.environ),
        "env_names": sorted(os.environ.keys()),
        "env_values": {k: os.environ.get(k) for k in _SAFE_ENV_VALUES if k in os.environ},
        "localappdata_set": "LOCALAPPDATA" in os.environ,
    }
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            session = ctypes.c_ulong(0)
            kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session))
            ctx["windows_session_id"] = int(session.value)
            ctx["console_window"] = bool(kernel32.GetConsoleWindow())
        except Exception:
            pass
    return ctx


def _cwd_ok() -> bool:
    try:
        os.getcwd()
        return True
    except Exception:
        return False


def snapshot_streams() -> Dict[str, str]:
    """Record stdout/stderr state; call before anything replaces missing streams."""
    return {"stdout": _stream_state(sys.stdout), "stderr": _stream_state(sys.stderr)}


def _read_back(path: Path, needle: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_s)
    while True:
        try:
            if path.exists() and needle in path.read_text(encoding="utf-8", errors="ignore")[-65536:]:
                return True
        except Exception:
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def run_startup_selfcheck(
    *,
    log_write: Callable[[str], None],
    active_log_path: Path,
    data_dir: Path,
    marker_path: Optional[Path] = None,
    original_streams: Optional[Dict[str, str]] = None,
    log_wait_s: float = 3.0,
) -> Dict[str, Any]:
    """Write a first record through the log and the history store's helpers, then read each back.

    ``log_write`` emits one line through the app's real logger. The history
    probe goes through the same ``append_jsonl_bounded`` / ``read_text_tail_lines``
    helpers the history store uses, against a sibling file: the history file
    itself feeds the history panel and the learning pipeline, so a synthetic row
    there would be mistaken for a dictation.

    Always writes ``startup_selfcheck.json`` and appends the launch context to
    ``launch_contexts.jsonl`` so launches can be compared side by side. Returns
    the report; ``report["ok"]`` is False when the log or the store could not be
    read back.
    """
    from voiceflow.utils.settings import append_jsonl_bounded, read_text_tail_lines

    token = uuid.uuid4().hex[:12]
    problems: List[str] = []
    report: Dict[str, Any] = {
        "token": token,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "log_path": str(active_log_path),
        "data_dir": str(data_dir),
        "context": launch_context(original_streams=original_streams),
    }

    # 1. Log: emit through the real logger, then look for it on disk.
    try:
        log_write(f"startup_selfcheck token={token} parent={report['context'].get('parent')}")
        log_ok = _read_back(active_log_path, token, log_wait_s)
    except Exception as exc:
        log_ok = False
        report["log_error"] = f"{type(exc).__name__}: {exc}"
    report["log_readback_ok"] = log_ok
    if not log_ok:
        problems.append(f"log not readable at {active_log_path}")

    # 1b. The pointer file other tools use to find the live log.
    if marker_path is not None:
        try:
            marker_ok = Path(marker_path).read_text(encoding="utf-8").strip() == str(active_log_path)
        except Exception:
            marker_ok = False
        report["marker_ok"] = marker_ok
        if not marker_ok:
            problems.append(f"active_log_path.txt at {marker_path} does not point at {active_log_path}")

    # 2. History store helpers.
    probe = data_dir / "startup_selfcheck.jsonl"
    try:
        wrote = append_jsonl_bounded(
            probe,
            {"token": token, "kind": "startup_selfcheck", "event_epoch": time.time()},
            max_file_bytes=65536,
            keep_lines=20,
        )
        tail = read_text_tail_lines(probe, max_lines=1, max_bytes=65536, max_line_chars=8192)
        store_ok = bool(wrote) and bool(tail) and token in tail[-1]
    except Exception as exc:
        store_ok = False
        report["store_error"] = f"{type(exc).__name__}: {exc}"
    report["history_store_readback_ok"] = store_ok
    if not store_ok:
        problems.append(f"history store not writable/readable in {data_dir}")

    report["ok"] = not problems
    report["problems"] = problems

    # 3. Leave the evidence behind (never let it break startup).
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "startup_selfcheck.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    except Exception:
        pass
    try:
        append_jsonl_bounded(
            data_dir / "launch_contexts.jsonl",
            {
                "time": report["time"],
                "ok": report["ok"],
                "token": token,
                "context": report["context"],
                "env_names_hash": _hash_names(report["context"].get("env_names", [])),
            },
            max_file_bytes=512 * 1024,
            keep_lines=200,
            max_line_chars=16384,
        )
    except Exception:
        pass
    write_boot_breadcrumb(
        "startup_selfcheck",
        ok=report["ok"],
        log_readback=log_ok,
        store_readback=store_ok,
        parent=report["context"].get("parent"),
    )
    return report


def _hash_names(names: List[str]) -> str:
    import hashlib

    return hashlib.sha1("\n".join(sorted(names)).encode("utf-8")).hexdigest()[:12]
