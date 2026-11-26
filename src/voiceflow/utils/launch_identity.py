"""What started this VoiceFlow, and the instance record the watchdog reads (VF-22).

Two things live here:

* ``launch_path_line``: the one greppable line per start, written after the
  engine is ready::

      launch_path kind=source parent=pyw.exe python=3.13.1 device=cuda compute=float16

* the instance record, ``%LOCALAPPDATA%\\VoiceFlow\\instance.json``: pid,
  process name, start time and launch kind of the running instance. The
  watchdog (``scripts/ops/voiceflow-watchdog.ps1``) decides "VoiceFlow is
  running" from this record and the single-instance mutex, not from a process
  name, so a source-launched ``pythonw.exe`` counts as running.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

INSTANCE_FILE_NAME = "instance.json"
#: The named mutex ``cli_enhanced._acquire_single_instance_mutex`` holds.
SINGLE_INSTANCE_MUTEX_NAME = "Local\\VoiceFlow_CLI_Enhanced"


def launch_kind() -> str:
    """``bundle`` for the PyInstaller EXE, ``source`` for any Python interpreter."""
    return "bundle" if getattr(sys, "frozen", False) else "source"


def launch_path_line(
    *,
    device: Any,
    compute: Any,
    parent: Optional[str],
    kind: Optional[str] = None,
    python_version: Optional[str] = None,
) -> str:
    def _token(value: Any) -> str:
        text = str(value if value not in (None, "") else "unknown").strip()
        return "_".join(text.split()) or "unknown"

    return "launch_path kind=%s parent=%s python=%s device=%s compute=%s" % (
        _token(kind or launch_kind()),
        _token(parent),
        _token(python_version or platform.python_version()),
        _token(device),
        _token(compute),
    )


def instance_record_path(data_dir: Path) -> Path:
    return Path(data_dir) / INSTANCE_FILE_NAME


def _process_identity(pid: int) -> tuple[str, float]:
    """(process name, creation time as unix seconds) for ``pid``; best effort."""
    try:
        import psutil  # type: ignore

        proc = psutil.Process(pid)
        return str(proc.name()), float(proc.create_time())
    except Exception:
        return Path(sys.executable).name, time.time()


def build_instance_record(
    *,
    pid: int,
    process_name: str,
    started_unix: float,
    kind: str,
    executable: str,
) -> Dict[str, Any]:
    return {
        "pid": int(pid),
        "process_name": str(process_name),
        "started_unix": round(float(started_unix), 3),
        "kind": str(kind),
        "executable": str(executable),
        "mutex": SINGLE_INSTANCE_MUTEX_NAME,
    }


def write_instance_record(data_dir: Path, *, pid: Optional[int] = None) -> Optional[Path]:
    """Publish this process as the running VoiceFlow. Never raises."""
    try:
        pid = int(pid if pid is not None else os.getpid())
        name, started = _process_identity(pid)
        record = build_instance_record(
            pid=pid,
            process_name=name,
            started_unix=started,
            kind=launch_kind(),
            executable=sys.executable,
        )
        target = instance_record_path(data_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
        os.replace(tmp, target)
        return target
    except Exception:
        return None


def read_instance_record(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and "pid" in data else None
    except Exception:
        return None


def remove_instance_record(data_dir: Path, *, pid: Optional[int] = None) -> bool:
    """Delete the record if it still names ``pid`` (this process by default)."""
    pid = int(pid if pid is not None else os.getpid())
    path = instance_record_path(data_dir)
    record = read_instance_record(path)
    if not record or int(record.get("pid", -1)) != pid:
        return False
    try:
        path.unlink()
        return True
    except Exception:
        return False
