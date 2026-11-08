"""VF-12 review finding 4: build snapshot pruning is opt-in and only touches generated names.

Runs the real ``Remove-StaleBuildArtifacts`` function from the build script in pwsh against a
temporary folder of empty fixture files. Nothing outside ``tmp_path`` is read or deleted.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "setup" / "build_windows_exe.ps1"
PWSH = shutil.which("pwsh")


def _function_source() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("function Remove-StaleBuildArtifacts")
    end = text.index("\nfunction ", start + 10)
    return text[start:end]


def _make_fixture(folder: Path) -> dict:
    import os
    import time

    names = {
        "snap1": "VoiceFlow-20260101-010101-portable.zip",
        "snap2": "VoiceFlow-20260201-010101-portable.zip",
        "snap3": "VoiceFlow-20260301-010101-onefile.zip",
        "snap4": "VoiceFlow-20260401-010101-portable.zip",
        "asset_exe": "VoiceFlow-win64.exe",
        "asset_zip": "VoiceFlow-portable-win64.zip",
        "asset_sums": "SHA256SUMS.txt",
    }
    base = time.time() - 10_000
    for i, name in enumerate(names.values()):
        f = folder / name
        f.write_bytes(b"x")
        os.utime(f, (base + i * 100, base + i * 100))
    return names


def _run_prune(folder: Path, keep: int | None) -> set[str]:
    call = f"Remove-StaleBuildArtifacts -PackagePath '{folder}'"
    if keep is not None:
        call += f" -Keep {keep}"
    script = f"{_function_source()}\n{call}\n"
    proc = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return {p.name for p in folder.iterdir()}


def test_default_keep_packages_is_zero_so_a_build_deletes_nothing():
    text = SCRIPT.read_text(encoding="utf-8")
    assert re.search(r"\[int\]\$KeepPackages\s*=\s*0\b", text), "pruning must be opt-in"
    assert re.search(r"\[int\]\$Keep\s*=\s*0\b", _function_source())
    assert "Remove-StaleBuildArtifacts -PackagePath $packagePath -Keep $KeepPackages" in text


@pytest.mark.skipif(PWSH is None, reason="pwsh not installed")
def test_zero_and_default_keep_everything(tmp_path):
    names = _make_fixture(tmp_path)
    assert _run_prune(tmp_path, 0) == set(names.values())
    assert _run_prune(tmp_path, None) == set(names.values()), "no -Keep given must not delete"


@pytest.mark.skipif(PWSH is None, reason="pwsh not installed")
def test_opt_in_keeps_n_newest_snapshots_and_never_release_assets(tmp_path):
    names = _make_fixture(tmp_path)
    left = _run_prune(tmp_path, 2)
    assert left == {names["snap3"], names["snap4"], names["asset_exe"], names["asset_zip"], names["asset_sums"]}


@pytest.mark.skipif(PWSH is None, reason="pwsh not installed")
def test_opt_in_is_a_noop_when_there_are_fewer_snapshots_than_the_limit(tmp_path):
    names = _make_fixture(tmp_path)
    assert _run_prune(tmp_path, 10) == set(names.values())
