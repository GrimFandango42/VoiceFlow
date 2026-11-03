"""VF-10 / VF-09: the post-build self-check must fail a broken bundle.

Field log: 171 "Applying the VAD filter requires the onnxruntime package" and
18 "[ONNXRuntimeError] NO_SUCHFILE" (silero_vad_v6.onnx not bundled), plus two
CPU-only builds shipped by accident via -SkipCudaRuntime.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


vb = _load("vf_verify_bundle", REPO / "scripts" / "setup" / "verify_bundle.py")
entry = _load("vf_exe_entry", REPO / "scripts" / "setup" / "voiceflow_exe_entry.py")


def _real_vad_asset() -> Path | None:
    try:
        from faster_whisper.utils import get_assets_path
    except Exception:
        return None
    p = Path(get_assets_path()) / "silero_vad_v6.onnx"
    return p if p.is_file() else None


def _fake_bundle(root: Path, *, vad: bool = True, cuda: bool = False) -> Path:
    bundle = root / "VoiceFlow"
    internal = bundle / "_internal"
    (internal / "onnxruntime" / "capi").mkdir(parents=True)
    (internal / "ctranslate2").mkdir(parents=True)
    (bundle / "VoiceFlow.exe").write_bytes(b"MZ not a real exe")
    (internal / "onnxruntime" / "capi" / "onnxruntime_pybind11_state.pyd").write_bytes(b"x")
    (internal / "onnxruntime" / "capi" / "onnxruntime.dll").write_bytes(b"x")
    (internal / "ctranslate2" / "ctranslate2.dll").write_bytes(b"x")
    if vad:
        src = _real_vad_asset()
        if src is None:
            pytest.skip("faster-whisper VAD asset not installed in this venv")
        dest = internal / vb.VAD_RELATIVE
        dest.parent.mkdir(parents=True)
        shutil.copyfile(src, dest)
    if cuda:
        lib = internal / vb.CUDA_RELATIVE
        lib.mkdir(parents=True)
        for name in ("cudnn_ops64_9.dll", "cublas64_12.dll", *entry.CUDA_COMPANION_DLLS):
            (lib / name).write_bytes(b"not a dll")
    return bundle


def test_required_cuda_list_matches_the_runtime_check():
    from voiceflow.core import asr_engine

    assert vb._literal_tuple(vb.ASR_ENGINE, "CUDA_REQUIRED_DLLS") == asr_engine.CUDA_REQUIRED_DLLS


def test_module_list_is_read_from_the_exe_entry():
    assert vb._literal_tuple(vb.EXE_ENTRY, "SELF_CHECK_MODULES") == entry.SELF_CHECK_MODULES
    assert "faster_whisper.vad" in entry.SELF_CHECK_MODULES
    assert "onnxruntime" in entry.SELF_CHECK_MODULES


def _static(bundle: Path, allow_cpu_only: bool):
    return vb.verify(bundle, allow_cpu_only=allow_cpu_only, run_frozen=False)


def test_companion_dll_list_is_read_from_the_exe_entry():
    assert vb._literal_tuple(vb.EXE_ENTRY, "CUDA_COMPANION_DLLS") == entry.CUDA_COMPANION_DLLS


def test_missing_vad_asset_fails(tmp_path):
    report = _static(_fake_bundle(tmp_path, vad=False), allow_cpu_only=True)
    assert not report.ok
    assert report.checks["vad_asset"]["ok"] is False


def test_vad_asset_is_loaded_not_just_found(tmp_path):
    bundle = _fake_bundle(tmp_path)
    report = _static(bundle, allow_cpu_only=True)
    assert report.checks["vad_asset"]["ok"] is True
    (bundle / "_internal" / vb.VAD_RELATIVE).write_bytes(b"corrupt")
    report = _static(bundle, allow_cpu_only=True)
    assert report.checks["vad_asset"]["ok"] is False


def test_missing_cuda_fails_unless_cpu_only_is_explicit(tmp_path):
    bundle = _fake_bundle(tmp_path)
    strict = _static(bundle, allow_cpu_only=False)
    assert not strict.ok
    assert strict.checks["cuda_runtime_dlls"]["ok"] is False
    assert strict.checks["cuda_runtime_dlls"]["warn_only"] is False

    lenient = _static(bundle, allow_cpu_only=True)
    assert lenient.checks["cuda_runtime_dlls"]["warn_only"] is True


@pytest.mark.skipif(sys.platform != "win32", reason="DLL loading is Windows-only")
def test_cuda_dlls_that_do_not_load_fail(tmp_path):
    report = _static(_fake_bundle(tmp_path, cuda=True), allow_cpu_only=False)
    assert report.checks["cuda_runtime_dlls"]["ok"] is False
    assert "failed to load" in report.checks["cuda_runtime_dlls"]["detail"]


def test_unreadable_exe_fails_module_check(tmp_path):
    report = _static(_fake_bundle(tmp_path), allow_cpu_only=True)
    assert report.checks["bundled_modules"]["ok"] is False
    assert not report.ok


def test_extension_modules_count_as_bundled(tmp_path):
    # pywin32's win32gui ships as _internal/win32/win32gui.pyd, never in the PYZ.
    internal = _fake_bundle(tmp_path) / "_internal"
    assert not vb._has_extension_module(internal, "win32gui")
    (internal / "win32").mkdir()
    (internal / "win32" / "win32gui.pyd").write_bytes(b"x")
    assert vb._has_extension_module(internal, "win32gui")
    (internal / "_tkinter.cp313-win_amd64.pyd").write_bytes(b"x")
    assert vb._has_extension_module(internal, "_tkinter")


def test_cli_exit_code_and_json(tmp_path):
    bundle = _fake_bundle(tmp_path, vad=False)
    out = tmp_path / "r.json"
    assert vb.main([str(bundle), "--allow-cpu-only", "--static-only", "--json-out", str(out)]) == 1
    assert '"ok": false' in out.read_text(encoding="utf-8")


def test_missing_bundle_fails(tmp_path):
    assert vb.main([str(tmp_path / "nope")]) == 1


class TestExeSelfCheckFlag:
    def test_flag_parsing(self, monkeypatch, tmp_path):
        monkeypatch.setenv("TEMP", str(tmp_path))
        assert entry._self_check_target(["VoiceFlow.exe"]) is None
        assert entry._self_check_target(["VoiceFlow.exe", "--self-check=C:/r.json"]) == "C:/r.json"
        assert entry._self_check_target(["VoiceFlow.exe", "--self-check"]) == str(tmp_path / "voiceflow_self_check.json")

    def test_self_check_from_source_writes_report(self, tmp_path):
        out = tmp_path / "self_check.json"
        rc = entry._run_self_check(str(out))
        text = out.read_text(encoding="utf-8")
        assert '"vad_asset"' in text
        assert '"cuda_runtime_dlls"' in text
        # In the test venv every import and the VAD asset must pass; CUDA DLLs
        # may legitimately be absent, so only that check may fail.
        import json

        report = json.loads(text)
        failing = [k for k, v in report["checks"].items() if not v["ok"]]
        assert set(failing) <= {"cuda_runtime_dlls"}, failing
        assert rc == (0 if not failing else 1)

    def test_self_check_never_starts_tray_hotkeys_or_microphone(self, monkeypatch, tmp_path):
        """Review finding (fa5ff26): the self-check must exit before tray,
        hotkey or microphone initialization. Every entry point that would
        start one of them raises here; the self-check must still complete."""
        import keyboard
        import pystray
        import sounddevice

        from voiceflow.ui import cli_enhanced

        def _forbidden(what):
            def _raise(*_a, **_k):
                raise AssertionError(f"self-check started {what}")

            return _raise

        monkeypatch.setattr(sounddevice, "InputStream", _forbidden("a microphone stream"))
        monkeypatch.setattr(sounddevice, "rec", _forbidden("a microphone recording"))
        for name in ("add_hotkey", "hook", "on_press", "on_release", "hook_key"):
            monkeypatch.setattr(keyboard, name, _forbidden(f"keyboard.{name}"))
        monkeypatch.setattr(pystray, "Icon", _forbidden("a tray icon"))
        monkeypatch.setattr(cli_enhanced, "main", _forbidden("the app"))

        out = tmp_path / "r.json"
        monkeypatch.setattr(sys, "argv", ["VoiceFlow.exe", f"--self-check={out}"])
        rc = entry.main()
        import json

        report = json.loads(out.read_text(encoding="utf-8"))
        failing = [k for k, v in report["checks"].items() if not v["ok"]]
        assert set(failing) <= {"cuda_runtime_dlls"}, failing
        assert rc in (0, 1)

    def test_import_failure_fails_the_self_check(self, monkeypatch, tmp_path):
        monkeypatch.setattr(entry, "SELF_CHECK_MODULES", entry.SELF_CHECK_MODULES + ("voiceflow.no_such_module",))
        out = tmp_path / "r.json"
        assert entry._run_self_check(str(out), allow_cpu_only=True) == 1
        import json

        report = json.loads(out.read_text(encoding="utf-8"))
        assert report["ok"] is False
        assert report["checks"]["import:voiceflow.no_such_module"]["ok"] is False

    def test_cpu_only_flag_downgrades_only_the_cuda_check(self, monkeypatch, tmp_path):
        from voiceflow.core import asr_engine

        monkeypatch.setattr(asr_engine, "_missing_cuda_dlls", lambda dlls: list(dlls))
        out = tmp_path / "r.json"
        assert entry._run_self_check(str(out)) == 1
        assert entry._run_self_check(str(out), allow_cpu_only=True) == 0
        import json

        cuda = json.loads(out.read_text(encoding="utf-8"))["checks"]["cuda_runtime_dlls"]
        assert cuda["ok"] is False and cuda["warn_only"] is True
        assert entry._self_check_flags(["x", "--self-check=a", "--self-check-allow-cpu-only"]) == {
            "--self-check-allow-cpu-only"
        }

    def test_bundled_cuda_check_ignores_path_and_venvs(self, monkeypatch, tmp_path):
        monkeypatch.delattr(sys, "_MEIPASS", raising=False)
        assert entry._check_bundled_cuda(("cublas64_12.dll",)) == (False, "not a frozen bundle")
        monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
        ok, detail = entry._check_bundled_cuda(("cublas64_12.dll",))
        assert not ok and "missing in bundle" in detail
        if sys.platform == "win32":
            lib = tmp_path / "torch" / "lib"
            lib.mkdir(parents=True)
            for name in ("cublas64_12.dll", *entry.CUDA_COMPANION_DLLS):
                (lib / name).write_bytes(b"not a dll")
            ok, detail = entry._check_bundled_cuda(("cublas64_12.dll",))
            assert not ok and "does not load" in detail


_STUB = r'''
import json, os, sys, time
out = [a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--self-check=")][0]
mode = os.environ.get("VF_STUB_MODE", "ok")
if mode == "hang":
    time.sleep(60)
if mode == "silent":
    sys.exit(0)
report = {
    "frozen": mode != "unfrozen",
    "ok": mode in ("ok", "unfrozen", "cpu", "exit1"),
    "argv": sys.argv[1:],
    "env": {k: os.environ.get(k) for k in ("LOCALAPPDATA", "APPDATA", "TEMP", "USERPROFILE", "PATH", "VOICEFLOW_TORCH_LIB_DIR")},
    "checks": {"import:voiceflow.ui.cli_enhanced": {"ok": True, "detail": ""}},
}
if mode in ("fail", "exit0_but_failed"):
    report["checks"]["vad_asset"] = {"ok": False, "detail": "missing silero", "warn_only": False}
if mode == "cpu":
    report["checks"]["cuda_runtime_dlls"] = {"ok": False, "detail": "missing", "warn_only": True}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh)
sys.exit(0 if mode in ("ok", "unfrozen", "cpu", "exit0_but_failed") else 1)
'''


class TestFrozenSelfCheckRunner:
    """The build runs the frozen EXE's --self-check and fails on any problem.
    A Python stub stands in for VoiceFlow.exe so every outcome is exercised."""

    @pytest.fixture
    def stub(self, tmp_path, monkeypatch):
        script = tmp_path / "stub_exe.py"
        script.write_text(_STUB, encoding="utf-8")
        monkeypatch.setattr(vb, "_frozen_command", lambda exe: [sys.executable, "-I", str(script)])
        monkeypatch.setenv("VOICEFLOW_TORCH_LIB_DIR", r"C:\somewhere\torch\lib")
        return tmp_path

    def _run(self, stub, monkeypatch, mode, *, allow_cpu_only=False, timeout=60.0):
        monkeypatch.setenv("VF_STUB_MODE", mode)
        report = vb.Report()
        data = vb.run_frozen_self_check(
            stub / "VoiceFlow.exe", stub / "work", allow_cpu_only, report, timeout=timeout
        )
        return report, data

    def test_passing_exe_passes_and_runs_sandboxed(self, stub, monkeypatch):
        report, data = self._run(stub, monkeypatch, "ok")
        assert report.ok, report.checks
        sandbox = str(stub / "work" / "self_check_sandbox")
        for var in ("LOCALAPPDATA", "APPDATA", "TEMP", "USERPROFILE"):
            assert data["env"][var].startswith(sandbox), var
        assert data["env"]["VOICEFLOW_TORCH_LIB_DIR"] is None
        assert "site-packages" not in data["env"]["PATH"].lower()
        assert "--self-check-allow-cpu-only" not in data["argv"]

    @pytest.mark.parametrize("mode", ["fail", "exit1", "exit0_but_failed", "silent", "unfrozen"])
    def test_any_failure_fails(self, stub, monkeypatch, mode):
        report, _ = self._run(stub, monkeypatch, mode)
        assert not report.ok
        assert report.checks["frozen_self_check"]["ok"] is False

    def test_failure_detail_names_the_failing_check(self, stub, monkeypatch):
        report, _ = self._run(stub, monkeypatch, "fail")
        assert "vad_asset: missing silero" in report.checks["frozen_self_check"]["detail"]

    def test_hung_exe_times_out_and_fails(self, stub, monkeypatch):
        report, _ = self._run(stub, monkeypatch, "hang", timeout=2.0)
        assert not report.ok
        assert "did not exit" in report.checks["frozen_self_check"]["detail"]

    def test_cpu_only_flag_is_forwarded(self, stub, monkeypatch):
        report, data = self._run(stub, monkeypatch, "cpu", allow_cpu_only=True)
        assert report.ok
        assert "--self-check-allow-cpu-only" in data["argv"]
        assert "cuda_runtime_dlls" in report.checks["frozen_self_check"]["detail"]

    def test_missing_exe_fails(self, tmp_path):
        report = vb.Report()
        vb.run_frozen_self_check(tmp_path / "nope.exe", tmp_path / "w", False, report, timeout=10)
        assert not report.ok

    def test_one_file_target_is_verified_by_the_frozen_check(self, stub, monkeypatch):
        exe = stub / "VoiceFlow.exe"
        exe.write_bytes(b"MZ")
        out = stub / "work" / "verify.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("VF_STUB_MODE", "ok")
        assert vb.main([str(exe), "--json-out", str(out)]) == 0
        monkeypatch.setenv("VF_STUB_MODE", "fail")
        assert vb.main([str(exe), "--json-out", str(out)]) == 1
        # --static-only cannot verify a one-file EXE at all.
        assert vb.main([str(exe), "--static-only", "--json-out", str(out)]) == 1

    def test_one_dir_runs_the_frozen_check_after_static_checks(self, stub, monkeypatch):
        bundle = _fake_bundle(stub / "dist", cuda=False)
        monkeypatch.setenv("VF_STUB_MODE", "fail")
        report = vb.verify(bundle, allow_cpu_only=True, work_dir=stub / "work")
        assert report.checks["frozen_self_check"]["ok"] is False


def test_build_script_verifies_every_mode():
    """Both the one-dir and the one-file branch go through the same
    verification, and a failure throws (non-zero exit)."""
    text = (REPO / "scripts" / "setup" / "build_windows_exe.ps1").read_text(encoding="utf-8")
    assert "Invoke-BundleVerification -Target $oneFileExe" in text
    assert "Invoke-BundleVerification -Target $bundleRoot" in text
    assert "unverified" not in text
    assert 'throw "[build_windows_exe] Bundle self-check FAILED' in text
    assert "--static-only" not in text
