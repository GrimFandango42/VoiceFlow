"""VF-26: the two documented commands work as written.

1. ``scripts/dev/correct.py`` logs a mis-hearing from the repository root (where
   ``python -m voiceflow.ai.corrections`` hits the ``voiceflow.py`` shadow).
2. The build script's interpreter lookup order and CUDA DLL fallback, run in pwsh
   against temporary folders. No build, no GPU, nothing outside ``tmp_path``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "setup" / "build_windows_exe.ps1"
CORRECT = ROOT / "scripts" / "dev" / "correct.py"
PWSH = shutil.which("pwsh")
GIT = shutil.which("git")


def test_correct_script_works_from_the_repository_root(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    add = subprocess.run(
        [sys.executable, str(CORRECT.relative_to(ROOT)), "add", "--heard", "Jamelan", "--meant", "Gemini",
         "--data-dir", str(data)],
        cwd=ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert add.returncode == 0, add.stderr
    rows = [json.loads(ln) for ln in (data / "transcription_corrections.jsonl").read_text("utf-8").splitlines()]
    assert [(r["original_text"], r["corrected_text"]) for r in rows] == [("Jamelan", "Gemini")]
    listing = subprocess.run(
        [sys.executable, str(CORRECT.relative_to(ROOT)), "list", "--data-dir", str(data)],
        cwd=ROOT, capture_output=True, text=True, timeout=60, env=env,
    )
    assert listing.returncode == 0, listing.stderr
    assert "Jamelan -> Gemini" in listing.stdout


def test_correct_script_works_from_src(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(CORRECT), "list", "--data-dir", str(tmp_path)],
        cwd=ROOT / "src", capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr


# ---- build script lookup --------------------------------------------------

needs_pwsh = pytest.mark.skipif(PWSH is None, reason="pwsh not installed")
FUNCTIONS = (
    "Get-MainCheckoutRoot",
    "Resolve-PythonExe",
    "Get-RequiredCudaDlls",
    "Resolve-CudaFallbackDir",
    "Get-CudaRuntimeDlls",
)


def _source(name: str) -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index(f"function {name} ")
    end = text.find("\nfunction ", start + 10)
    return text[start:end if end != -1 else len(text)]


def _pwsh(body: str, env_extra: dict | None = None):
    script = "\n".join(_source(n) for n in FUNCTIONS) + "\n" + body
    env = {k: v for k, v in os.environ.items() if k not in ("VOICEFLOW_TORCH_LIB_DIR", "VOICEFLOW_USE_GPU_VENV")}
    env.update(env_extra or {})
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=120, env=env)


def _touch_python(root: Path, venv: str) -> Path:
    exe = root / venv / "Scripts" / "python.exe"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"")
    return exe


def _resolve(repo: Path) -> str:
    proc = _pwsh(f"Resolve-PythonExe -RepoRoot '{repo}' -ExplicitPython ''")
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _same(a: str, b) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(str(b)))


def _worktree(tmp_path: Path) -> tuple[Path, Path]:
    main = tmp_path / "main"
    main.mkdir()
    g = [GIT, "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(g + ["init", "-q", str(main)], check=True)
    subprocess.run(g + ["-C", str(main), "commit", "-q", "--allow-empty", "-m", "init"], check=True)
    wt = tmp_path / "wt"
    subprocess.run(g + ["-C", str(main), "worktree", "add", "-q", str(wt), "-b", "side"], check=True)
    return main, wt


@needs_pwsh
@pytest.mark.skipif(GIT is None, reason="git not installed")
def test_worktree_lookup_order_build_then_test_own_then_main(tmp_path):
    main, wt = _worktree(tmp_path)
    assert _resolve(wt) == "python"
    main_test = _touch_python(main, ".venv-test")
    assert _same(_resolve(wt), main_test), "main's .venv-test beats system Python"
    main_build = _touch_python(main, ".venv-build")
    assert _same(_resolve(wt), main_build), "main's .venv-build beats main's .venv-test"
    wt_test = _touch_python(wt, ".venv-test")
    assert _same(_resolve(wt), wt_test), "the worktree's own environment beats the main checkout's"
    wt_build = _touch_python(wt, ".venv-build")
    assert _same(_resolve(wt), wt_build)


@needs_pwsh
def test_venv_test_is_found_in_a_plain_checkout(tmp_path):
    assert _resolve(tmp_path) == "python"
    test_py = _touch_python(tmp_path, ".venv-test")
    assert _same(_resolve(tmp_path), test_py)


def _dlls() -> list[str]:
    proc = _pwsh("Get-RequiredCudaDlls")
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.split()


def _fallback(repo: Path, sp: Path, env_extra: dict | None = None) -> str:
    proc = _pwsh(f"Resolve-CudaFallbackDir -RepoRoot '{repo}' -PythonExe 'python' -SitePackages '{sp}'", env_extra)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


@needs_pwsh
@pytest.mark.skipif(GIT is None, reason="git not installed")
def test_cuda_fallback_uses_main_bundle_only_when_complete(tmp_path):
    main, wt = _worktree(tmp_path)
    sp = tmp_path / "site-packages"
    sp.mkdir()
    internal = main / "dist" / "VoiceFlow" / "_internal"
    internal.mkdir(parents=True)
    names = _dlls()
    for n in names[:-1]:
        (internal / n).write_bytes(b"dll")
    assert _fallback(wt, sp) == "", "an incomplete bundle is not used"
    (internal / names[-1]).write_bytes(b"dll")
    assert _same(_fallback(wt, sp), internal)
    explicit = tmp_path / "elsewhere"
    explicit.mkdir()
    assert _fallback(wt, sp, {"VOICEFLOW_TORCH_LIB_DIR": str(explicit)}) == "", "an explicit folder wins"


@needs_pwsh
@pytest.mark.skipif(GIT is None, reason="git not installed")
def test_cuda_fallback_skipped_when_environment_already_has_the_dlls(tmp_path):
    main, wt = _worktree(tmp_path)
    internal = main / "dist" / "VoiceFlow" / "_internal"
    internal.mkdir(parents=True)
    sp = tmp_path / "site-packages"
    for n in _dlls():
        (internal / n).write_bytes(b"dll")
        pkg = "cudnn" if n.startswith("cudnn") else "cublas"
        (sp / "nvidia" / pkg / "bin").mkdir(parents=True, exist_ok=True)
        (sp / "nvidia" / pkg / "bin" / n).write_bytes(b"dll")
    assert _fallback(wt, sp) == ""
