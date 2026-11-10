#!/usr/bin/env python3
"""Post-build self-check for the packaged VoiceFlow bundle (VF-09 / VF-10).

Run by build_windows_exe.ps1 after PyInstaller, for one-dir and one-file builds
alike; a non-zero exit fails the build. Two layers:

1. Frozen self-check (authoritative). Runs `VoiceFlow.exe --self-check=<json>`
   and waits for it. That code path lives in voiceflow_exe_entry.main() and
   returns before the tray, hotkeys or microphone are touched. Inside the frozen
   interpreter it imports the app's modules from the bundle, runs the Silero VAD
   through the *bundled* onnxruntime, and loads the *bundled* CUDA DLLs. The EXE
   runs with LOCALAPPDATA/APPDATA/TEMP/USERPROFILE pointed into a scratch folder
   next to the report and a minimal PATH, so it cannot touch live app data or
   borrow DLLs from the build machine.

2. Static pre-filter (one-dir only, quick, clearer messages). Checks the files
   on disk: the VAD asset loads as ONNX, onnxruntime/ctranslate2 natives exist,
   the CUDA DLLs exist and load in an isolated interpreter (unless
   --allow-cpu-only), and the app's modules are in the PYZ.

Usage:
    python scripts/setup/verify_bundle.py dist/VoiceFlow            # one-dir
    python scripts/setup/verify_bundle.py dist/VoiceFlow.exe        # one-file
        [--allow-cpu-only] [--json-out report.json] [--static-only]
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ASR_ENGINE = REPO_ROOT / "src" / "voiceflow" / "core" / "asr_engine.py"
EXE_ENTRY = REPO_ROOT / "scripts" / "setup" / "voiceflow_exe_entry.py"

VAD_RELATIVE = Path("faster_whisper") / "assets" / "silero_vad_v6.onnx"
CUDA_RELATIVE = Path("torch") / "lib"
FROZEN_SELF_CHECK_TIMEOUT_S = 300.0


def _literal_tuple(path: Path, name: str) -> tuple[str, ...]:
    """Read a module-level tuple constant without importing the module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
            value = node.value
        if name in targets:
            return tuple(ast.literal_eval(value))
    raise RuntimeError(f"{name} not found in {path}")


class Report:
    def __init__(self) -> None:
        self.checks: dict[str, dict] = {}
        self.frozen_report: dict | None = None

    def add(self, name: str, ok: bool, detail: str = "", *, warn_only: bool = False) -> None:
        self.checks[name] = {"ok": bool(ok), "detail": detail, "warn_only": warn_only}
        tag = "PASS" if ok else ("WARN" if warn_only else "FAIL")
        print(f"[verify_bundle] {tag:4} {name}: {detail}")

    @property
    def ok(self) -> bool:
        return all(c["ok"] or c["warn_only"] for c in self.checks.values())


def _pyz_module_names(exe: Path) -> set[str]:
    from PyInstaller.archive.readers import PKG_ITEM_PYZ, CArchiveReader

    pkg = CArchiveReader(str(exe))
    names: set[str] = set()
    for entry_name, entry in pkg.toc.items():
        typecode = entry[-1] if isinstance(entry, tuple) else None
        if typecode == PKG_ITEM_PYZ or entry_name.lower().endswith(".pyz"):
            pyz = pkg.open_embedded_archive(entry_name)
            names.update(pyz.toc.keys())
    return names


def _top_level_stamp(exe: Path) -> tuple[list[str], dict[str, str]]:
    """Names in the executable's own archive that contain ``_build_stamp``, and the constants of the first one.

    The order's rebuild gate reads exactly this table (``CArchiveReader(exe).toc``). The stamp module inside the PYZ
    is invisible to it, so the build also ships the stamp as a runtime hook, which PyInstaller lists by file name.
    """
    import marshal

    from PyInstaller.archive.readers import CArchiveReader

    pkg = CArchiveReader(str(exe))
    names = [n for n in pkg.toc if "_build_stamp" in n]
    constants: dict[str, str] = {}
    if names:
        # Constants only: no builtins, so nothing but `NAME = literal` assignments can run.
        namespace: dict[str, object] = {"__builtins__": {}}
        exec(marshal.loads(pkg.extract(names[0])), namespace)  # noqa: S102
        constants = {k: str(v) for k, v in namespace.items() if k.isupper()}
    return names, constants


def _check_stamp_entry(exe: Path, expected_commit: str | None, report: Report) -> None:
    try:
        names, constants = _top_level_stamp(exe)
    except Exception as exc:  # noqa: BLE001
        report.add("build_stamp_entry", False, f"cannot read the executable's archive: {type(exc).__name__}: {exc}")
        return
    if not names:
        report.add("build_stamp_entry", False, "no _build_stamp entry in the executable's top-level archive")
        return
    commit = constants.get("COMMIT", "")
    if not commit or commit == "unknown":
        report.add("build_stamp_entry", False, f"{names[0]} carries no commit ({constants})")
        return
    if expected_commit and not (expected_commit.startswith(commit) or commit.startswith(expected_commit)):
        report.add("build_stamp_entry", False, f"stamp commit {commit} != expected {expected_commit}")
        return
    report.add("build_stamp_entry", True, f"{names[0]} commit={commit} built={constants.get('BUILT_AT', '?')}")


def _check_vad(internal: Path, report: Report) -> None:
    vad = internal / VAD_RELATIVE
    if not vad.is_file() or vad.stat().st_size == 0:
        report.add("vad_asset", False, f"missing {vad}")
        return
    try:
        import onnxruntime

        onnxruntime.InferenceSession(str(vad), providers=["CPUExecutionProvider"])
    except Exception as exc:  # noqa: BLE001
        report.add("vad_asset", False, f"{vad} does not load: {type(exc).__name__}: {exc}")
        return
    report.add("vad_asset", True, f"{vad.relative_to(internal)} ({vad.stat().st_size} bytes, loads)")


def _check_native(internal: Path, report: Report) -> None:
    ort_pyd = list((internal / "onnxruntime" / "capi").glob("onnxruntime_pybind11_state*.pyd"))
    ort_dll = list((internal / "onnxruntime" / "capi").glob("onnxruntime*.dll"))
    report.add(
        "onnxruntime_native",
        bool(ort_pyd and ort_dll),
        ", ".join(p.name for p in ort_pyd + ort_dll) or "onnxruntime capi binaries missing",
    )
    ct2 = list((internal / "ctranslate2").glob("ctranslate2*.dll"))
    report.add("ctranslate2_native", bool(ct2), ", ".join(p.name for p in ct2) or "ctranslate2.dll missing")


def _check_cuda(internal: Path, required: tuple[str, ...], allow_cpu_only: bool, report: Report) -> None:
    lib = internal / CUDA_RELATIVE
    wanted = list(required) + list(_literal_tuple(EXE_ENTRY, "CUDA_COMPANION_DLLS"))
    missing = [d for d in wanted if not (lib / d).is_file()]
    if missing:
        report.add(
            "cuda_runtime_dlls",
            False,
            f"missing under {CUDA_RELATIVE}: {', '.join(missing)}"
            + (" (accepted: --allow-cpu-only; this build runs CPU int8 only)" if allow_cpu_only else ""),
            warn_only=allow_cpu_only,
        )
        return
    # Load each DLL in a throwaway isolated interpreter so a bad DLL cannot take
    # the verifier down, and so dependency resolution is tested, not just presence.
    code = (
        "import ctypes, os, sys\n"
        "lib = sys.argv[1]\n"
        "os.add_dll_directory(lib)\n"
        "for name in sys.argv[2:]:\n"
        "    ctypes.WinDLL(os.path.join(lib, name))\n"
        "print('loaded', len(sys.argv) - 2)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", code, str(lib), *wanted],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or ["no output"]
        report.add("cuda_runtime_dlls", False, f"present but failed to load: {tail[0]}", warn_only=allow_cpu_only)
        return
    report.add("cuda_runtime_dlls", True, f"{', '.join(wanted)} present and load from {CUDA_RELATIVE}")


def _has_extension_module(internal: Path, module: str) -> bool:
    """C extensions (e.g. pywin32's win32gui) ship as .pyd files, not in the PYZ."""
    leaf = module.rsplit(".", 1)[-1]
    for pattern in (f"{leaf}.pyd", f"{leaf}.*.pyd"):
        if any(internal.rglob(pattern)):
            return True
    return False


def _check_modules(exe: Path, internal: Path, modules: tuple[str, ...], report: Report) -> None:
    try:
        names = _pyz_module_names(exe)
    except Exception as exc:  # noqa: BLE001
        report.add("bundled_modules", False, f"cannot read PYZ from {exe.name}: {type(exc).__name__}: {exc}")
        return
    if not names:
        report.add("bundled_modules", False, "no PYZ archive found in the executable")
        return
    expected = list(modules) + ["voiceflow._build_stamp"]
    missing = [m for m in expected if m not in names and not _has_extension_module(internal, m)]
    report.add(
        "bundled_modules",
        not missing,
        f"missing: {', '.join(missing)}" if missing else f"{len(expected)} required modules present ({len(names)} total)",
    )


# Variables that could let the frozen EXE find DLLs or code outside the bundle.
_STRIPPED_ENV = ("VOICEFLOW_TORCH_LIB_DIR", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "VOICEFLOW_DIAG_BENCH_WAV")
_SANDBOXED_DIRS = ("LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "USERPROFILE", "HOME")


def _sandbox_env(sandbox: Path) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k.upper() not in _STRIPPED_ENV and not k.upper().startswith("CUDA_PATH")
    }
    for name in _SANDBOXED_DIRS:
        d = sandbox / name.lower()
        d.mkdir(parents=True, exist_ok=True)
        env[name] = str(d)
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    env["PATH"] = os.pathsep.join(
        [os.path.join(system_root, "System32"), system_root, os.path.join(system_root, "System32", "Wbem")]
    )
    return env


def _frozen_command(exe: Path) -> list[str]:
    """Command that launches the frozen EXE. A seam so tests can substitute a stub."""
    return [str(exe)]


def run_frozen_self_check(
    exe: Path,
    work_dir: Path,
    allow_cpu_only: bool,
    report: Report,
    timeout: float = FROZEN_SELF_CHECK_TIMEOUT_S,
) -> dict | None:
    """Run `<exe> --self-check=<json>` in a sandbox and wait for it.

    subprocess.run waits for GUI-subsystem processes too (PowerShell's `&` does
    not), so the exit code is the EXE's own. Passes only if the EXE exits 0 and
    wrote a report that says it ran frozen and ok.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    sandbox = work_dir / "self_check_sandbox"
    shutil.rmtree(sandbox, ignore_errors=True)
    out = work_dir / "frozen_self_check.json"
    if out.exists():
        out.unlink()
    cmd = _frozen_command(exe) + [f"--self-check={out}"]
    if allow_cpu_only:
        cmd.append("--self-check-allow-cpu-only")
    env = _sandbox_env(sandbox)
    try:
        proc = subprocess.run(
            cmd,
            env=env,
            cwd=str(sandbox),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        report.add("frozen_self_check", False, f"{exe.name} --self-check did not exit within {timeout:.0f}s")
        return None
    except OSError as exc:
        report.add("frozen_self_check", False, f"could not run {exe}: {exc}")
        return None

    data: dict | None = None
    try:
        data = json.loads(out.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        report.add(
            "frozen_self_check",
            False,
            f"exit {proc.returncode}; no readable report at {out} ({type(exc).__name__})",
        )
        return None

    checks = data.get("checks") or {}
    failing = [
        f"{name}: {c.get('detail', '')}".strip()
        for name, c in checks.items()
        if not c.get("ok") and not c.get("warn_only")
    ]
    warned = [name for name, c in checks.items() if not c.get("ok") and c.get("warn_only")]
    passed = proc.returncode == 0 and bool(data.get("ok")) and bool(data.get("frozen")) and not failing
    if not passed:
        why = []
        if proc.returncode != 0:
            why.append(f"exit {proc.returncode}")
        if not data.get("frozen"):
            why.append("report not produced by a frozen EXE")
        why.extend(failing[:8])
        report.add("frozen_self_check", False, "; ".join(why) or "report says not ok")
        return data
    detail = f"exit 0, {len(checks)} in-bundle checks passed ({out})"
    if warned:
        detail += f"; accepted warnings: {', '.join(warned)}"
    report.add("frozen_self_check", True, detail)
    return data


def verify(
    target: Path,
    allow_cpu_only: bool,
    *,
    run_frozen: bool = True,
    work_dir: Path | None = None,
) -> Report:
    """Verify a one-dir bundle directory or a one-file EXE."""
    report = Report()
    work_dir = work_dir or (REPO_ROOT / "build" / "verify_bundle")

    if target.suffix.lower() == ".exe":
        # One-file: nothing to inspect on disk; the frozen check is the gate.
        report.add("executable", target.is_file(), str(target))
        if not target.is_file():
            return report
        if not run_frozen:
            report.add("frozen_self_check", False, "one-file builds can only be verified by the frozen self-check")
            return report
        report.frozen_report = run_frozen_self_check(target, work_dir, allow_cpu_only, report)
        return report

    exe = target / "VoiceFlow.exe"
    internal = target / "_internal"
    report.add("executable", exe.is_file(), str(exe))
    report.add("internal_dir", internal.is_dir(), str(internal))
    if not (exe.is_file() and internal.is_dir()):
        return report

    required = _literal_tuple(ASR_ENGINE, "CUDA_REQUIRED_DLLS")
    modules = _literal_tuple(EXE_ENTRY, "SELF_CHECK_MODULES")

    _check_vad(internal, report)
    _check_native(internal, report)
    _check_cuda(internal, required, allow_cpu_only, report)
    _check_modules(exe, internal, modules, report)
    _check_stamp_entry(exe, os.environ.get("VOICEFLOW_EXPECT_COMMIT") or None, report)
    if run_frozen:
        report.frozen_report = run_frozen_self_check(exe, work_dir, allow_cpu_only, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path, help="one-dir bundle (dist/VoiceFlow) or one-file EXE (dist/VoiceFlow.exe)")
    parser.add_argument("--allow-cpu-only", action="store_true", help="accept a bundle without CUDA DLLs (loud warning)")
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="skip running the EXE's --self-check (debugging only; the build never passes this)",
    )
    args = parser.parse_args(argv)

    work_dir = args.json_out.resolve().parent if args.json_out else None
    report = verify(args.bundle.resolve(), args.allow_cpu_only, run_frozen=not args.static_only, work_dir=work_dir)
    if args.json_out:
        args.json_out.write_text(
            json.dumps(
                {
                    "ok": report.ok,
                    "bundle": str(args.bundle.resolve()),
                    "checks": report.checks,
                    "frozen_report": report.frozen_report,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    if report.ok:
        print("[verify_bundle] OK")
        return 0
    print("[verify_bundle] FAILED - this bundle is not fit for daily use", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
