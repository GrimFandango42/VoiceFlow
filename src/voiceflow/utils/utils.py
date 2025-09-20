from __future__ import annotations

import ctypes
import shutil
import subprocess
from typing import Optional


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore
    except (OSError, AttributeError):
        return False


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def nvidia_smi_info() -> Optional[str]:
    exe = which("nvidia-smi")
    if not exe:
        return None
    try:
        out = subprocess.check_output(
            [exe, "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"],
            universal_newlines=True,
            timeout=5,
        )
        return out.strip()
    except Exception:
        return None

