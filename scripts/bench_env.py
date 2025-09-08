from __future__ import annotations

import importlib
import platform
import subprocess
import sys

from localflow.utils import nvidia_smi_info


def pkg_version(name: str) -> str:
    try:
        m = importlib.import_module(name)
        v = getattr(m, "__version__", "?")
        return f"{name}={v}"
    except Exception:
        return f"{name}=not_installed"


def main():
    print(f"Python: {sys.version.split()[0]} ({platform.platform()})")
    print(f"GPU: {nvidia_smi_info() or 'n/a'}")
    for p in ["numpy", "sounddevice", "keyboard", "pyperclip", "faster_whisper"]:
        print(pkg_version(p))
    try:
        out = subprocess.check_output([sys.executable, "-c", "import torch;print(torch.cuda.is_available())"], universal_newlines=True)
        print(f"torch_cuda_available={out.strip()}")
    except Exception:
        print("torch=not_installed")


if __name__ == "__main__":
    main()

