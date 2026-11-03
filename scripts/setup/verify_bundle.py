#!/usr/bin/env python3
"""Post-build self-check for the packaged VoiceFlow bundle (VF-09 / VF-10).

Run by build_windows_exe.ps1 after PyInstaller; a non-zero exit fails the build.
It never launches VoiceFlow.exe (no tray, hotkeys or microphone). It checks:

  * the Silero VAD asset is bundled where faster-whisper looks for it and is a
    loadable ONNX model (streaming preview needs it; its absence produced the
    `NO_SUCHFILE` / "requires the onnxruntime package" warnings in the field log)
  * onnxruntime and ctranslate2 native libraries are present
  * the CUDA runtime DLLs the app requires are bundled under _internal\\torch\\lib
    and actually load (dependencies resolve), unless --allow-cpu-only
  * the app's Python modules are inside the bundle's PYZ archive

Usage:
    python scripts/setup/verify_bundle.py dist/VoiceFlow [--allow-cpu-only] [--json-out report.json]

For an in-process check from inside the frozen app (imports every module,
probes CUDA the way the app does) run, when the app is not otherwise running:
    dist\\VoiceFlow\\VoiceFlow.exe --self-check=C:\\path\\report.json
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ASR_ENGINE = REPO_ROOT / "src" / "voiceflow" / "core" / "asr_engine.py"
EXE_ENTRY = REPO_ROOT / "scripts" / "setup" / "voiceflow_exe_entry.py"

VAD_RELATIVE = Path("faster_whisper") / "assets" / "silero_vad_v6.onnx"
CUDA_RELATIVE = Path("torch") / "lib"
# Loaded alongside the required pair: they are what the required pair links to.
CUDA_COMPANION_DLLS = ("cublasLt64_12.dll", "cudnn64_9.dll")


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
    wanted = list(required) + list(CUDA_COMPANION_DLLS)
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


def verify(bundle: Path, allow_cpu_only: bool) -> Report:
    report = Report()
    exe = bundle / "VoiceFlow.exe"
    internal = bundle / "_internal"
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
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path, help="bundle directory, e.g. dist/VoiceFlow")
    parser.add_argument("--allow-cpu-only", action="store_true", help="accept a bundle without CUDA DLLs (loud warning)")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)

    report = verify(args.bundle.resolve(), args.allow_cpu_only)
    if args.json_out:
        args.json_out.write_text(
            json.dumps({"ok": report.ok, "bundle": str(args.bundle.resolve()), "checks": report.checks}, indent=2),
            encoding="utf-8",
        )
    if report.ok:
        print("[verify_bundle] OK")
        return 0
    print("[verify_bundle] FAILED - this bundle is not fit for daily use", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
