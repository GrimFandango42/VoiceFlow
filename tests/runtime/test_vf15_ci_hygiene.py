"""VF-15 review regressions: CI config must stay safe and whitespace-clean."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _bytes(rel: str) -> bytes:
    return (ROOT / rel).read_bytes()


def test_config_files_have_consistent_line_endings():
    # Mixed CRLF/LF made `git diff --check` fail (VF-15 review finding 2).
    for rel in ("pyproject.toml", "scripts/setup/requirements_windows.txt"):
        data = _bytes(rel)
        crlf = data.count(b"\r\n")
        lf = data.count(b"\n")
        assert crlf in (0, lf), f"{rel} mixes CRLF and LF line endings"


def test_build_workflow_publish_jobs_cannot_run_from_a_branch_dispatch():
    # Review finding 1: a manual verification dispatch must never publish.
    wf = yaml.safe_load(_bytes(".github/workflows/build-release.yml"))
    on = wf.get("on") or wf.get(True)
    inputs = on["workflow_dispatch"]["inputs"]
    assert "publish_rolling_release" in inputs and "publish_tag_release" in inputs
    jobs = wf["jobs"]
    assert "refs/heads/main" in jobs["release-latest-main"]["if"]
    assert "publish_tag_release == 'true'" in jobs["release-tag"]["if"]
    assert "release_version != ''" in jobs["release-tag"]["if"]


def test_build_workflow_builds_are_cpu_only_on_runners():
    text = _bytes(".github/workflows/build-release.yml").decode("utf-8")
    # Both the portable and one-file builds must opt in to CPU-only (no CUDA on runners).
    assert text.count("build_windows_exe.ps1") == text.count("-AllowCpuOnly") == 2
