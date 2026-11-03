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
        for name in ("cudnn_ops64_9.dll", "cublas64_12.dll", *vb.CUDA_COMPANION_DLLS):
            (lib / name).write_bytes(b"not a dll")
    return bundle


def test_required_cuda_list_matches_the_runtime_check():
    from voiceflow.core import asr_engine

    assert vb._literal_tuple(vb.ASR_ENGINE, "CUDA_REQUIRED_DLLS") == asr_engine.CUDA_REQUIRED_DLLS


def test_module_list_is_read_from_the_exe_entry():
    assert vb._literal_tuple(vb.EXE_ENTRY, "SELF_CHECK_MODULES") == entry.SELF_CHECK_MODULES
    assert "faster_whisper.vad" in entry.SELF_CHECK_MODULES
    assert "onnxruntime" in entry.SELF_CHECK_MODULES


def test_missing_vad_asset_fails(tmp_path):
    report = vb.verify(_fake_bundle(tmp_path, vad=False), allow_cpu_only=True)
    assert not report.ok
    assert report.checks["vad_asset"]["ok"] is False


def test_vad_asset_is_loaded_not_just_found(tmp_path):
    bundle = _fake_bundle(tmp_path)
    report = vb.verify(bundle, allow_cpu_only=True)
    assert report.checks["vad_asset"]["ok"] is True
    (bundle / "_internal" / vb.VAD_RELATIVE).write_bytes(b"corrupt")
    report = vb.verify(bundle, allow_cpu_only=True)
    assert report.checks["vad_asset"]["ok"] is False


def test_missing_cuda_fails_unless_cpu_only_is_explicit(tmp_path):
    bundle = _fake_bundle(tmp_path)
    strict = vb.verify(bundle, allow_cpu_only=False)
    assert not strict.ok
    assert strict.checks["cuda_runtime_dlls"]["ok"] is False
    assert strict.checks["cuda_runtime_dlls"]["warn_only"] is False

    lenient = vb.verify(bundle, allow_cpu_only=True)
    assert lenient.checks["cuda_runtime_dlls"]["warn_only"] is True


@pytest.mark.skipif(sys.platform != "win32", reason="DLL loading is Windows-only")
def test_cuda_dlls_that_do_not_load_fail(tmp_path):
    report = vb.verify(_fake_bundle(tmp_path, cuda=True), allow_cpu_only=False)
    assert report.checks["cuda_runtime_dlls"]["ok"] is False
    assert "failed to load" in report.checks["cuda_runtime_dlls"]["detail"]


def test_unreadable_exe_fails_module_check(tmp_path):
    report = vb.verify(_fake_bundle(tmp_path), allow_cpu_only=True)
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
    assert vb.main([str(bundle), "--allow-cpu-only", "--json-out", str(out)]) == 1
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
