"""VF-23: build preflight and Python resolver, tested without a build or a GPU.

The real functions are lifted out of ``build_windows_exe.ps1`` and run in pwsh against
temporary fake site-packages layouts and temporary git repositories. Nothing outside
``tmp_path`` is touched and PyInstaller is never started.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "setup" / "build_windows_exe.ps1"
VERIFY = ROOT / "scripts" / "setup" / "verify_bundle.py"
PWSH = shutil.which("pwsh")
GIT = shutil.which("git")

pytestmark = pytest.mark.skipif(PWSH is None, reason="pwsh not installed")

FUNCTIONS = (
    "Get-MainCheckoutRoot",
    "Resolve-PythonExe",
    "Get-RequiredCudaDlls",
    "Get-VadAssetName",
    "Test-BuildPreflight",
    "Get-CudaRuntimeDlls",
)


def _source(name: str) -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index(f"function {name} ")
    end = text.find("\nfunction ", start + 10)
    return text[start:end if end != -1 else len(text)]


def _pwsh(body: str, env_drop=("VOICEFLOW_TORCH_LIB_DIR", "VOICEFLOW_USE_GPU_VENV")):
    script = "\n".join(_source(n) for n in FUNCTIONS) + "\n" + body
    env = {k: v for k, v in os.environ.items() if k not in env_drop}
    return subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=120, env=env,
    )


def _vad_name() -> str:
    m = re.search(r'VAD_RELATIVE = Path\("faster_whisper"\) / "assets" / "([^"]+)"', VERIFY.read_text(encoding="utf-8"))
    assert m
    return m.group(1)


def _required_dlls() -> list[str]:
    proc = _pwsh("Get-RequiredCudaDlls")
    assert proc.returncode == 0, proc.stderr
    names = proc.stdout.split()
    assert len(names) >= 10
    return names


def _make_layout(tmp_path: Path, *, vad: str | None, cuda: bool = True, pyinstaller: bool = True) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    (repo / "scripts" / "setup").mkdir(parents=True)
    shutil.copy(VERIFY, repo / "scripts" / "setup" / "verify_bundle.py")
    sp = tmp_path / "site-packages"
    (sp / "ctranslate2").mkdir(parents=True)
    if pyinstaller:
        (sp / "PyInstaller").mkdir()
    assets = sp / "faster_whisper" / "assets"
    assets.mkdir(parents=True)
    if vad:
        (assets / vad).write_bytes(b"onnx")
    if cuda:
        for pkg, dlls in (("cudnn", [d for d in _required_dlls() if d.startswith("cudnn")]),
                          ("cublas", [d for d in _required_dlls() if d.startswith("cublas")])):
            b = sp / "nvidia" / pkg / "bin"
            b.mkdir(parents=True)
            for d in dlls:
                (b / d).write_bytes(b"dll")
    return repo, sp


def _preflight(repo: Path, sp: Path, extra: str = ""):
    body = (
        f"$p = @(Test-BuildPreflight -RepoRoot '{repo}' -PythonExe 'python' -SitePackages '{sp}' {extra})\n"
        "$p | ForEach-Object { Write-Output ('PROBLEM: ' + $_) }\n"
        "exit $p.Count\n"
    )
    proc = _pwsh(body)
    return proc.returncode, proc.stdout


def test_vad_name_comes_from_verify_bundle_not_a_second_copy():
    assert _vad_name() == "silero_vad_v6.onnx"
    proc = _pwsh(f"Get-VadAssetName -VerifyBundlePath '{VERIFY}'")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == _vad_name()
    code = [ln for ln in SCRIPT.read_text(encoding="utf-8").splitlines() if "silero_vad" in ln and not ln.lstrip().startswith("#")]
    assert code == [], "the build script must read the name from verify_bundle.py, not repeat it"


def test_complete_layout_passes(tmp_path):
    repo, sp = _make_layout(tmp_path, vad=_vad_name())
    code, out = _preflight(repo, sp)
    assert code == 0, out


def test_v5_only_faster_whisper_fails_and_names_it(tmp_path):
    repo, sp = _make_layout(tmp_path, vad=None)
    for n in ("silero_encoder_v5.onnx", "silero_decoder_v5.onnx"):
        (sp / "faster_whisper" / "assets" / n).write_bytes(b"x")
    code, out = _preflight(repo, sp)
    assert code == 1
    assert "faster-whisper" in out and _vad_name() in out and "bootstrap_windows.ps1 -BuildVenv" in out


def test_missing_nvidia_wheels_fail_unless_allow_cpu_only(tmp_path):
    repo, sp = _make_layout(tmp_path, vad=_vad_name(), cuda=False)
    code, out = _preflight(repo, sp)
    assert code == 1
    assert "cudnn64_9.dll" in out and "-AllowCpuOnly" in out
    code, out = _preflight(repo, sp, "-AllowCpuOnly")
    assert code == 0, out


def test_partial_cuda_set_names_only_what_is_missing(tmp_path):
    repo, sp = _make_layout(tmp_path, vad=_vad_name())
    (sp / "nvidia" / "cublas" / "bin" / "cublasLt64_12.dll").unlink()
    code, out = _preflight(repo, sp)
    assert code == 1
    assert "cublasLt64_12.dll" in out and "cudnn64_9.dll" not in out


def test_missing_pyinstaller_fails(tmp_path):
    repo, sp = _make_layout(tmp_path, vad=_vad_name(), pyinstaller=False)
    code, out = _preflight(repo, sp)
    assert code == 1 and "pyinstaller" in out


# ---- resolver -------------------------------------------------------------

def _touch_python(root: Path, venv: str) -> Path:
    exe = root / venv / "Scripts" / "python.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"")
    return exe


def _resolve(repo: Path, explicit: str = "") -> str:
    proc = _pwsh(f"Resolve-PythonExe -RepoRoot '{repo}' -ExplicitPython '{explicit}'")
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _same(a: str, b) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(str(b)))


def test_resolver_order_in_a_plain_folder(tmp_path):
    assert _resolve(tmp_path) == "python"
    venv = _touch_python(tmp_path, "venv")
    assert _same(_resolve(tmp_path), venv)
    gpu = _touch_python(tmp_path, ".venv-gpu")
    assert _same(_resolve(tmp_path), gpu)
    build = _touch_python(tmp_path, ".venv-build")
    assert _same(_resolve(tmp_path), build)
    assert _resolve(tmp_path, "C:\\x\\python.exe") == "C:\\x\\python.exe"


@pytest.mark.skipif(GIT is None, reason="git not installed")
def test_worktree_without_environments_uses_the_main_checkouts_build_venv(tmp_path):
    main = tmp_path / "main"
    main.mkdir()
    g = [GIT, "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(g + ["init", "-q", str(main)], check=True)
    subprocess.run(g + ["-C", str(main), "commit", "-q", "--allow-empty", "-m", "init"], check=True)
    wt = tmp_path / "wt"
    subprocess.run(g + ["-C", str(main), "worktree", "add", "-q", str(wt), "-b", "side"], check=True)

    assert _resolve(wt) == "python", "no .venv-build anywhere"
    assert _resolve(main) == "python"
    main_build = _touch_python(main, ".venv-build")
    assert _same(_resolve(wt), main_build)
    own = _touch_python(wt, "venv")
    assert _same(_resolve(wt), own), "the worktree's own environment beats the main checkout's"
    wt_build = _touch_python(wt, ".venv-build")
    assert _same(_resolve(wt), wt_build)
