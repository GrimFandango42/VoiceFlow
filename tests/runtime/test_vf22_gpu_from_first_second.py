"""VF-22: on the GPU from the first second.

The 2026-11-26 start from the Desktop shortcut (wscript -> pyw.exe ->
launcher_silent.pyw on the system Python 3.13) dictated on the CPU for 2.5-3
minutes: the startup check looked for cudnn_ops64_9.dll / cublas64_12.dll on
PATH, in torch/lib and in the checkout's bundle, but never in
``site-packages/nvidia/*/bin``, where the pip CUDA wheels put them (and where
they were). These tests build that layout under a temporary directory for each
launch path and check that the *first* check finds it.

No GPU, no app, no process, no device: ctranslate2 and torch are fakes, model
classes are fakes, os.add_dll_directory is recorded instead of called, and
%LOCALAPPDATA% stays the suite's sandbox.
"""

from __future__ import annotations

import logging
import os
import site
import sys
import types
from pathlib import Path
from typing import Callable, List, Optional

import pytest

from voiceflow.core import asr_engine as ae
from voiceflow.core.asr_engine import ASREngine, FasterWhisperBackend, ModelConfig

REQUIRED = list(ae.CUDA_REQUIRED_DLLS)  # cudnn_ops64_9.dll, cublas64_12.dll


# ---------------------------------------------------------------------------
# A fake machine: interpreter layout, PATH, ctranslate2/torch, DLL registration.
# ---------------------------------------------------------------------------


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    return path


def _install_nvidia_wheels(site_packages: Path) -> List[Path]:
    """The layout `pip install nvidia-cublas-cu12 nvidia-cudnn-cu12` produces on Windows."""
    cublas = site_packages / "nvidia" / "cublas" / "bin"
    cudnn = site_packages / "nvidia" / "cudnn" / "bin"
    for name in ("cublas64_12.dll", "cublasLt64_12.dll"):
        _touch(cublas / name)
    for name in ("cudnn_ops64_9.dll", "cudnn64_9.dll"):
        _touch(cudnn / name)
    _touch(site_packages / "nvidia" / "cuda_nvrtc" / "bin" / "nvrtc64_120_0.dll")
    return [cublas, cudnn]


class FakeMachine:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        self.root = tmp_path
        self.mp = monkeypatch
        self.dll_dirs: List[str] = []
        self.ct2_device_queries = 0

        def _add_dll_directory(path: str):
            self.dll_dirs.append(str(path))
            return types.SimpleNamespace(close=lambda: None)

        monkeypatch.setattr(ae.os, "add_dll_directory", _add_dll_directory, raising=False)
        for var in ("VOICEFLOW_TORCH_LIB_DIR", "VOICEFLOW_CUDA_DLL_DIR"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("VOICEFLOW_CUDA_PROBE_BUNDLE", "0")
        monkeypatch.setenv("PATH", "")

        # torch absent (packaged builds and the minimal case); ctranslate2 is a fake
        # that reports one device without touching a driver.
        monkeypatch.setitem(sys.modules, "torch", None)

        def _count() -> int:
            self.ct2_device_queries += 1
            return 1

        fake_ct2 = types.SimpleNamespace(
            get_cuda_device_count=_count,
            get_supported_compute_types=lambda device: {"float16", "int8_float16"},
        )
        monkeypatch.setitem(sys.modules, "ctranslate2", fake_ct2)

        checkout = tmp_path / "checkout"
        cwd = tmp_path / "cwd"
        checkout.mkdir()
        cwd.mkdir()
        monkeypatch.setattr(ae, "_repo_root", lambda: checkout)
        monkeypatch.chdir(cwd)

    def interpreter(
        self,
        *,
        executable: Path,
        prefix: Path,
        base_prefix: Optional[Path] = None,
        site_dirs: Optional[List[Path]] = None,
        user_site: Optional[Path] = None,
        frozen: bool = False,
        meipass: Optional[Path] = None,
    ) -> None:
        mp = self.mp
        _touch(executable)
        mp.setattr(ae.sys, "executable", str(executable))
        mp.setattr(ae.sys, "prefix", str(prefix))
        mp.setattr(ae.sys, "exec_prefix", str(prefix))
        mp.setattr(ae.sys, "base_prefix", str(base_prefix or prefix))
        mp.setattr(ae.sys, "path", [str(executable.parent)] + [str(d) for d in (site_dirs or [])])
        if frozen:
            mp.setattr(ae.sys, "frozen", True, raising=False)
            mp.setattr(ae.sys, "_MEIPASS", str(meipass), raising=False)
        else:
            mp.delattr(ae.sys, "frozen", raising=False)
            mp.delattr(ae.sys, "_MEIPASS", raising=False)
        mp.setattr(site, "getsitepackages", lambda: [str(d) for d in (site_dirs or [])], raising=False)
        mp.setattr(site, "getusersitepackages", lambda: str(user_site) if user_site else "", raising=False)

    def path_entries(self) -> List[str]:
        return [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]


@pytest.fixture
def machine(tmp_path, monkeypatch) -> FakeMachine:
    return FakeMachine(tmp_path, monkeypatch)


def _system_python_313(m: FakeMachine) -> Path:
    """The Desktop shortcut: pyw.exe -> pythonw.exe of the per-user system Python 3.13."""
    py = m.root / "Programs" / "Python" / "Python313"
    sp = py / "Lib" / "site-packages"
    m.interpreter(executable=py / "pythonw.exe", prefix=py, site_dirs=[py, sp])
    return sp


def _project_venv(m: FakeMachine) -> Path:
    base = m.root / "Programs" / "Python" / "Python313"
    venv = m.root / "checkout" / ".venv-gpu"
    sp = venv / "Lib" / "site-packages"
    m.interpreter(executable=venv / "Scripts" / "pythonw.exe", prefix=venv, base_prefix=base, site_dirs=[venv, sp])
    return sp


def _user_site(m: FakeMachine) -> Path:
    py = m.root / "Programs" / "Python" / "Python313"
    user = m.root / "Roaming" / "Python" / "Python313" / "site-packages"
    m.interpreter(executable=py / "pythonw.exe", prefix=py, site_dirs=[py, py / "Lib" / "site-packages"], user_site=user)
    return user


def _frozen_bundle(m: FakeMachine) -> Path:
    exe_dir = m.root / "dist" / "VoiceFlow"
    internal = exe_dir / "_internal"
    internal.mkdir(parents=True)
    m.interpreter(executable=exe_dir / "VoiceFlow.exe", prefix=internal, site_dirs=[], frozen=True, meipass=internal)
    return internal


LAUNCH_PATHS: dict[str, Callable[[FakeMachine], Path]] = {
    "source-pyw-system-python": _system_python_313,
    "source-venv": _project_venv,
    "source-user-site": _user_site,
    "bundle-nvidia-layout": _frozen_bundle,
}


# ---------------------------------------------------------------------------
# 1. The runtime check registers the pip wheels' bin dirs before it looks.
# ---------------------------------------------------------------------------


class TestFirstCheckFindsTheWheels:
    @pytest.mark.parametrize("launch", sorted(LAUNCH_PATHS))
    @pytest.mark.parametrize("path_value", ["", r"C:\Windows\System32"], ids=["path-empty", "path-minimal"])
    def test_first_check_passes_on_every_launch_path(self, machine, launch, path_value):
        machine.mp.setenv("PATH", path_value)
        site_packages = LAUNCH_PATHS[launch](machine)
        bins = _install_nvidia_wheels(site_packages)

        assert ae._cuda_runtime_ready() is True  # the first call, not a later one

        for directory in bins:
            assert str(directory) in machine.path_entries()
            assert str(directory) in machine.dll_dirs
        assert machine.ct2_device_queries == 1

    def test_bundle_with_runtime_at_its_root(self, machine):
        """The current bundle layout: the DLLs sit directly in _internal."""
        internal = _frozen_bundle(machine)
        for name in REQUIRED:
            _touch(internal / name)
        assert ae._cuda_runtime_ready() is True
        assert str(internal) in machine.path_entries()

    @pytest.mark.parametrize("launch", sorted(LAUNCH_PATHS))
    def test_truly_absent_runtime_is_still_reported(self, machine, launch, caplog):
        LAUNCH_PATHS[launch](machine)  # interpreter without the wheels
        with caplog.at_level(logging.INFO, logger="voiceflow"):
            assert ae._cuda_runtime_ready() is False
        assert "cuda_runtime_unavailable missing_dlls=cudnn_ops64_9.dll,cublas64_12.dll" in caplog.text
        assert machine.ct2_device_queries == 0

    def test_half_a_runtime_does_not_count(self, machine):
        sp = _system_python_313(machine)
        _touch(sp / "nvidia" / "cublas" / "bin" / "cublas64_12.dll")  # no cuDNN wheel
        assert ae._cuda_runtime_ready() is False
        assert machine.path_entries() == []

    def test_checkout_bundle_current_layout_is_probed_from_source(self, machine):
        """A source run next to a built bundle: the runtime is at _internal, not _internal/torch/lib."""
        _system_python_313(machine)
        internal = machine.root / "checkout" / "dist" / "VoiceFlow" / "_internal"
        for name in REQUIRED:
            _touch(internal / name)
        machine.mp.setenv("VOICEFLOW_CUDA_PROBE_BUNDLE", "1")
        assert ae._cuda_runtime_ready() is True
        assert str(internal) in machine.path_entries()

    def test_source_prefers_its_own_wheels_over_the_checkout_bundle(self, machine):
        sp = _system_python_313(machine)
        bins = _install_nvidia_wheels(sp)
        internal = machine.root / "checkout" / "dist" / "VoiceFlow" / "_internal"
        for name in REQUIRED:
            _touch(internal / name)
        machine.mp.setenv("VOICEFLOW_CUDA_PROBE_BUNDLE", "1")
        assert ae._cuda_runtime_ready() is True
        assert str(bins[0]) in machine.path_entries()
        assert str(internal) not in machine.path_entries()

    def test_explicit_override_still_wins(self, machine):
        sp = _system_python_313(machine)
        _install_nvidia_wheels(sp)
        custom = machine.root / "gpu-dlls"
        for name in REQUIRED:
            _touch(custom / name)
        machine.mp.setenv("VOICEFLOW_CUDA_DLL_DIR", str(custom))
        assert ae._cuda_runtime_ready() is True
        assert machine.path_entries()[0] == str(custom)


# ---------------------------------------------------------------------------
# 2. Engine selection: cuda when the check passes, and the CPU model is never built first.
# ---------------------------------------------------------------------------


class _RecordingModel:
    built: List[str] = []

    def __init__(self, ref, device="cpu", compute_type="int8", **kwargs):
        type(self).built.append(f"{device}/{compute_type}")

    def transcribe(self, audio, **kwargs):
        return iter(()), None


def _fake_faster_whisper(monkeypatch, model_cls) -> None:
    # A stand-in module: the real one imports PyAV, whose DLLs need the PATH these tests empty.
    monkeypatch.setitem(sys.modules, "faster_whisper", types.SimpleNamespace(WhisperModel=model_cls))


@pytest.fixture
def recording_model(monkeypatch):
    _RecordingModel.built = []
    _fake_faster_whisper(monkeypatch, _RecordingModel)
    return _RecordingModel


class TestEngineSelection:
    @pytest.mark.parametrize("device", ["auto", "cuda"])
    def test_source_start_with_wheels_loads_cuda_only(self, machine, recording_model, device):
        _install_nvidia_wheels(_system_python_313(machine))
        engine = ASREngine(model_name="distil-large-v3", device=device, compute_type="int8")
        assert engine.model_config.device == "cuda"
        assert engine.model_config.compute_type == "float16"
        assert not engine.device_status()["fell_back_to_cpu"]

        engine._backend.load()
        assert recording_model.built == ["cuda/float16"]
        assert engine.device_status()["device"] == "cuda"

    def test_bundle_start_loads_cuda_only(self, machine, recording_model):
        internal = _frozen_bundle(machine)
        for name in REQUIRED:
            _touch(internal / name)
        engine = ASREngine(model_name="distil-large-v3", device="cuda", compute_type="float16")
        engine._backend.load()
        assert recording_model.built == ["cuda/float16"]

    def test_truly_absent_runtime_falls_back_and_schedules_restore_after_preload(
        self, machine, recording_model
    ):
        _system_python_313(machine)  # no wheels
        engine = ASREngine(model_name="distil-large-v3", device="cuda", compute_type="float16")
        backend = engine._backend
        assert engine.device_status()["fell_back_to_cpu"]
        # Nothing is due until the preload has finished...
        assert backend.seconds_until_cuda_restore() is None
        backend.load()
        assert recording_model.built == ["cpu/int8"]
        # ...and the first attempt is due the moment it has.
        assert backend.seconds_until_cuda_restore() == 0.0


# ---------------------------------------------------------------------------
# 3. Restore schedule: after preload, then 15 s, 30 s, 60 s, then every 120 s.
# ---------------------------------------------------------------------------


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_restore_delay_table():
    assert [ae.cuda_restore_delay_s(n) for n in range(1, 8)] == [15, 30, 60, 120, 120, 120, 120]


def test_restore_schedule_with_a_fake_clock(monkeypatch, caplog):
    monkeypatch.setattr(ae, "_register_external_cuda_runtime_path", lambda dlls: False)
    built: List[str] = []
    state = {"gpu_ok": False}

    class Model:
        def __init__(self, ref, device="cpu", compute_type="int8", **kwargs):
            built.append(device)
            if device == "cuda" and not state["gpu_ok"]:
                raise RuntimeError("Library cublas64_12.dll is not found or cannot be loaded")

        def transcribe(self, audio, **kwargs):
            return iter(()), None

    _fake_faster_whisper(monkeypatch, Model)
    clock = FakeClock()
    backend = FasterWhisperBackend(
        ModelConfig(name="t", model_id="org/m", backend="faster-whisper", device="cuda", compute_type="float16")
    )
    backend._clock = clock
    t0 = clock.now

    with caplog.at_level(logging.INFO, logger="voiceflow"):
        backend.load()  # CUDA fails (missing runtime) -> CPU; preload done -> first attempt due now
        assert backend.fell_back_to_cpu
        built.clear()

        attempts_at: List[float] = []
        for _ in range(2000):  # walk the clock in 0.5 s steps for ~1000 s
            before = len(built)
            backend.retry_cuda_if_fallen_back()
            if len(built) > before:
                attempts_at.append(clock.now - t0)
            clock.now += 0.5

        assert attempts_at[:7] == [0.0, 15.0, 45.0, 105.0, 225.0, 345.0, 465.0]
        failed_lines = [r.getMessage() for r in caplog.records if "asr_cuda_restore_failed" in r.getMessage()]
        assert len(failed_lines) == len(attempts_at)  # one line per attempt
        assert failed_lines[0].startswith("asr_cuda_restore_failed attempt=1 kind=missing_runtime")
        assert "next_try_s=15" in failed_lines[0]
        assert "next_try_s=120" in failed_lines[3]

        state["gpu_ok"] = True
        caplog.clear()
        assert backend.retry_cuda_if_fallen_back(force=True) is True

    assert backend.config.device == "cuda"
    assert not backend.fell_back_to_cpu
    restored = [r.getMessage() for r in caplog.records if "asr_cuda_restored" in r.getMessage()]
    assert restored == ["asr_cuda_restored model=org/m compute=float16"]


def test_restore_loop_sleeps_until_the_next_due_attempt():
    from voiceflow.ui.cli_enhanced import EnhancedApp

    class Engine:
        def __init__(self, due):
            self.due = due

        def seconds_until_cuda_restore(self):
            return self.due

    def app_with(*dues):
        app = types.SimpleNamespace()
        app._fallen_back_engines = lambda: [Engine(d) for d in dues]
        app._CUDA_RESTORE_POLL_MAX_S = EnhancedApp._CUDA_RESTORE_POLL_MAX_S
        app._CUDA_RESTORE_POLL_MIN_S = EnhancedApp._CUDA_RESTORE_POLL_MIN_S
        return app

    wait = EnhancedApp._next_cuda_restore_wait_s
    assert wait(app_with()) == 30.0  # nothing fallen back
    assert wait(app_with(None)) == 30.0  # fallen back, waiting for the preload
    assert wait(app_with(12.0)) == 12.0
    assert wait(app_with(0.0)) == 1.0  # due now but busy: re-check every second
    assert wait(app_with(500.0, 15.0)) == 15.0


# ---------------------------------------------------------------------------
# 4. The launch_path line.
# ---------------------------------------------------------------------------


def test_launch_path_line_format():
    from voiceflow.utils.launch_identity import launch_path_line

    line = launch_path_line(device="cuda", compute="float16", parent="pyw.exe", kind="source", python_version="3.13.1")
    assert line == "launch_path kind=source parent=pyw.exe python=3.13.1 device=cuda compute=float16"
    line = launch_path_line(device=None, compute="", parent="", kind="bundle", python_version="3.11.9")
    assert line == "launch_path kind=bundle parent=unknown python=3.11.9 device=unknown compute=unknown"


def test_launch_kind_follows_the_frozen_flag(monkeypatch):
    from voiceflow.utils import launch_identity as li

    monkeypatch.delattr(li.sys, "frozen", raising=False)
    assert li.launch_kind() == "source"
    monkeypatch.setattr(li.sys, "frozen", True, raising=False)
    assert li.launch_kind() == "bundle"


def test_app_logs_launch_path_once(monkeypatch, caplog):
    from voiceflow.ui import cli_enhanced

    monkeypatch.setattr(cli_enhanced, "_LAUNCH_PATH_LOGGED", False)
    monkeypatch.setattr(cli_enhanced, "_LAUNCH_PARENT", "pyw.exe")
    engine = types.SimpleNamespace(device_status=lambda: {"device": "cuda", "compute_type": "float16"})
    with caplog.at_level(logging.INFO, logger="voiceflow"):
        cli_enhanced._log_launch_path(engine)
        cli_enhanced._log_launch_path(engine)
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("launch_path ")]
    assert len(lines) == 1
    assert "parent=pyw.exe" in lines[0] and "device=cuda compute=float16" in lines[0]
    assert "kind=source" in lines[0]


# ---------------------------------------------------------------------------
# 5. The instance record the watchdog reads (temporary directory only).
# ---------------------------------------------------------------------------


def test_instance_record_round_trip(tmp_path):
    from voiceflow.utils import launch_identity as li

    path = li.write_instance_record(tmp_path, pid=os.getpid())
    assert path == tmp_path / "instance.json"
    record = li.read_instance_record(path)
    assert record["pid"] == os.getpid()
    assert record["kind"] == "source"
    assert record["mutex"] == "Local\\VoiceFlow_CLI_Enhanced"
    assert record["started_unix"] > 0 and record["process_name"]

    # Another process's record is left alone; ours is removed.
    assert li.remove_instance_record(tmp_path, pid=os.getpid() + 1) is False
    assert path.exists()
    assert li.remove_instance_record(tmp_path, pid=os.getpid()) is True
    assert not path.exists()


def test_instance_record_mutex_matches_the_app():
    import inspect

    from voiceflow.ui import cli_enhanced
    from voiceflow.utils.launch_identity import SINGLE_INSTANCE_MUTEX_NAME

    assert SINGLE_INSTANCE_MUTEX_NAME.replace("\\", "\\\\") in inspect.getsource(
        cli_enhanced._acquire_single_instance_mutex
    )


def test_watchdog_script_decides_from_what_the_app_publishes():
    """Static check (the decision itself is tested by tests/ops/test_watchdog_decision.ps1)."""
    repo = Path(__file__).resolve().parents[2]
    script = (repo / "scripts" / "ops" / "voiceflow-watchdog.ps1").read_text(encoding="utf-8")
    assert "SupportsShouldProcess" in script
    assert "function Get-WatchdogDecision" in script
    assert "Local\\VoiceFlow_CLI_Enhanced" in script
    assert "instance.json" in script
    assert "exited early, code" in script
    assert "$MyInvocation.InvocationName -eq '.'" in script
    assert (repo / "tests" / "ops" / "test_watchdog_decision.ps1").is_file()
