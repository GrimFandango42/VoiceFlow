"""VF-18: fast and recorded on every launch.

Covers the model-construction race, CUDA retry/fallback policy and its
announcement, per-engine config copies, model label agreement, and the startup
self-check / history-write visibility.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from voiceflow.core import asr_engine as ae
from voiceflow.core.asr_engine import (
    ASREngine,
    FasterWhisperBackend,
    ModelConfig,
    canonical_model_key,
    classify_cuda_init_failure,
)


class LocalEntryNotFoundError(Exception):
    """Same class name huggingface_hub uses for 'not in the local cache'."""


def _backend(device: str = "cuda", compute: str = "float16") -> FasterWhisperBackend:
    cfg = ModelConfig(
        name="t",
        model_id="org/some-model",
        backend="faster-whisper",
        device=device,
        compute_type=compute,
        cpu_threads=2,
    )
    return FasterWhisperBackend(cfg)


@pytest.fixture(autouse=True)
def _no_sleep_and_clean_listeners(monkeypatch):
    monkeypatch.setattr(ae, "_CUDA_INIT_RETRY_DELAY_S", 0.0)
    before = list(ae._device_listeners)
    yield
    ae._device_listeners[:] = before


class TestClassification:
    @pytest.mark.parametrize(
        "message,expected",
        [
            ("CUDA failed with error out of memory", "out_of_memory"),
            ("Library cublas64_12.dll is not found or cannot be loaded", "missing_runtime"),
            ("cuDNN error: CUDNN_STATUS_NOT_INITIALIZED", "missing_runtime"),
            ("type object 'disabled_tqdm' has no attribute '_lock'", "transient"),
            ("some random failure", "transient"),
        ],
    )
    def test_classify(self, message, expected):
        assert classify_cuda_init_failure(RuntimeError(message)) == expected


class TestConstructionLock:
    def test_two_backends_never_construct_concurrently(self):
        """The preloader's two threads used to race inside snapshot_download."""
        state = {"active": 0, "peak": 0}
        guard = threading.Lock()

        class Slow:
            def __init__(self, ref, **kwargs):
                with guard:
                    state["active"] += 1
                    state["peak"] = max(state["peak"], state["active"])
                time.sleep(0.05)
                with guard:
                    state["active"] -= 1

        backends = [_backend(), _backend()]
        threads = [
            threading.Thread(target=b._create_model, args=(Slow, f"org/model-{i}"))
            for i, b in enumerate(backends)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        assert state["peak"] == 1


class TestLocalFirst:
    def test_cached_model_never_touches_the_network(self):
        calls = []

        class Cached:
            def __init__(self, ref, local_files_only=False, **kwargs):
                calls.append(local_files_only)

        _backend("cpu", "int8")._create_model(Cached, "org/some-model")
        assert calls == [True]

    def test_missing_model_falls_through_to_network_once(self):
        calls = []

        class Missing:
            def __init__(self, ref, local_files_only=False, **kwargs):
                calls.append(local_files_only)
                if local_files_only:
                    raise LocalEntryNotFoundError("Cannot find an appropriate cached snapshot folder")

        _backend("cpu", "int8")._create_model(Missing, "org/some-model")
        assert calls == [True, False]

    def test_non_cache_errors_are_not_retried_on_the_network(self):
        calls = []

        class Broken:
            def __init__(self, ref, local_files_only=False, **kwargs):
                calls.append(local_files_only)
                raise ValueError("bad model.bin")

        with pytest.raises(ValueError):
            _backend("cpu", "int8")._create_model(Broken, "org/some-model")
        assert calls == [True]

    def test_local_directory_is_loaded_directly(self, tmp_path):
        seen = {}

        class Dir:
            def __init__(self, ref, **kwargs):
                seen.update(kwargs)

        _backend("cpu", "int8")._create_model(Dir, str(tmp_path))
        assert "local_files_only" not in seen


class TestCudaPolicy:
    def test_transient_failure_is_retried_on_cuda_and_stays_on_gpu(self):
        events = []
        ae.add_device_listener(lambda e, d: events.append(e))
        attempts = []

        class Flaky:
            def __init__(self, ref, device="cpu", compute_type="int8", **kwargs):
                attempts.append(device)
                if len(attempts) == 1:
                    raise AttributeError("type object 'disabled_tqdm' has no attribute '_lock'")

        backend = _backend()
        backend._create_model(Flaky, "org/some-model")
        assert attempts == ["cuda", "cuda"]
        assert backend.config.device == "cuda"
        assert not backend.fell_back_to_cpu
        assert events == []

    def test_out_of_memory_goes_straight_to_cpu_and_announces(self):
        events = []
        ae.add_device_listener(lambda e, d: events.append((e, d)))
        attempts = []

        class Full:
            def __init__(self, ref, device="cpu", compute_type="int8", **kwargs):
                attempts.append(device)
                if device == "cuda":
                    raise RuntimeError("CUDA failed with error out of memory")

        backend = _backend()
        backend._create_model(Full, "org/some-model")
        assert attempts == ["cuda", "cpu"]
        assert backend.config.device == "cpu"
        assert backend.fell_back_to_cpu
        assert events and events[0][0] == "cpu_fallback"
        assert "out_of_memory" in events[0][1]

    def test_two_transient_failures_then_cpu(self):
        attempts = []

        class Bad:
            def __init__(self, ref, device="cpu", compute_type="int8", **kwargs):
                attempts.append(device)
                if device == "cuda":
                    raise RuntimeError("weird failure")

        backend = _backend()
        backend._create_model(Bad, "org/some-model")
        assert attempts == ["cuda", "cuda", "cpu"]
        assert backend.fell_back_to_cpu

    def test_cpu_fallback_is_not_permanent(self, monkeypatch):
        events = []
        ae.add_device_listener(lambda e, d: events.append(e))
        backend = _backend()
        backend._enter_cpu_fallback("float16", "out_of_memory: test")
        backend._model = object()

        class Fine:
            def __init__(self, ref, **kwargs):
                pass

            def transcribe(self, audio, **kwargs):
                return iter(()), None

        import faster_whisper

        monkeypatch.setattr(faster_whisper, "WhisperModel", Fine)
        assert backend.retry_cuda_if_fallen_back() is False  # not due yet
        assert backend.retry_cuda_if_fallen_back(force=True) is True
        assert backend.config.device == "cuda"
        assert backend.config.compute_type == "float16"
        assert not backend.fell_back_to_cpu
        assert isinstance(backend._model, Fine)
        assert events == ["cpu_fallback", "cuda_restored"]

    def test_failed_restore_keeps_the_cpu_model_running(self, monkeypatch):
        backend = _backend()
        backend._enter_cpu_fallback("float16", "out_of_memory: test")
        cpu_model = object()
        backend._model = cpu_model

        class StillFull:
            def __init__(self, ref, **kwargs):
                raise RuntimeError("CUDA failed with error out of memory")

        import faster_whisper

        monkeypatch.setattr(faster_whisper, "WhisperModel", StillFull)
        assert backend.retry_cuda_if_fallen_back(force=True) is False
        assert backend._model is cpu_model
        assert backend.fell_back_to_cpu


class TestEngineConfigIsolation:
    def test_cpu_fallback_does_not_leak_into_the_shared_entry(self):
        a = ASREngine(model_name="distil-large-v3", device="cpu", compute_type="int8")
        b = ASREngine(model_name="distil-large-v3", device="cpu", compute_type="int8")
        assert a.model_config is not b.model_config
        assert a.model_config is not ae.MODEL_CONFIGS["distil-large-v3"]
        a.model_config.device = "cpu-marker"
        assert ae.MODEL_CONFIGS["distil-large-v3"].device != "cpu-marker"
        assert b.model_config.device != "cpu-marker"

    def test_switch_model_keeps_engine_settings(self):
        engine = ASREngine(model_name="tiny.en", device="cpu", compute_type="int8", beam_size=3)
        engine.switch_model(model_name="small.en")
        assert engine.model_config.model_id == "small.en"
        assert engine.model_config.beam_size == 3
        assert engine.model_config.device == "cpu"

    def test_device_status_reports_fallback(self):
        engine = ASREngine(model_name="tiny.en", device="cpu", compute_type="int8")
        status = engine.device_status()
        assert status["fell_back_to_cpu"] is False
        assert status["device"] == "cpu"
        engine._backend._enter_cpu_fallback("float16", "missing_runtime: test")
        status = engine.device_status()
        assert status["fell_back_to_cpu"] is True
        assert "missing_runtime" in status["fallback_reason"]


class TestModelLabels:
    def test_legacy_v35_label_resolves_to_the_weights_it_loads(self):
        assert canonical_model_key("distil-large-v3.5") == "distil-large-v3"
        engine = ASREngine(model_name="distil-large-v3.5", device="cpu", compute_type="int8")
        assert engine.model_key == "distil-large-v3"
        assert engine.model_config.model_id == "Systran/faster-distil-whisper-large-v3"
        assert "v3.5" not in engine.model_config.name.replace("legacy 'v3.5' label", "")

    def test_balanced_tier_names_the_v3_weights(self):
        assert ae.TIER_MODELS[ae.ModelTier.BALANCED] == "distil-large-v3"

    def test_real_v35_is_opt_in_under_its_own_key(self):
        engine = ASREngine(model_name="distil-large-v3.5-ct2", device="cpu", compute_type="int8")
        assert engine.model_config.model_id == "distil-whisper/distil-large-v3.5-ct2"
        assert engine.model_key == "distil-large-v3.5-ct2"

    def test_wizard_repo_map_has_no_nonexistent_repo(self):
        pytest.importorskip("tkinter")
        from voiceflow.ui.setup_wizard import _HF_REPO_MAP

        assert "faster-distil-whisper-large-v3.5" not in " ".join(_HF_REPO_MAP.values())
        assert _HF_REPO_MAP["distil-large-v3.5"] == _HF_REPO_MAP["distil-large-v3"]


class TestAppDeviceWiring:
    """EnhancedApp's reaction to engine device events, with stub tray/engines."""

    def _app(self, fallen: bool):
        from voiceflow.ui.cli_enhanced import EnhancedApp

        calls = []

        class Tray:
            def show_warning(self, message, notify=True):
                calls.append(("warn", message, notify))

            def clear_warning(self):
                calls.append(("clear",))

        class Engine:
            def device_status(self):
                return {"fell_back_to_cpu": fallen}

        app = SimpleNamespace(
            _device_warning="",
            tray_controller=Tray(),
            visual_indicators_enabled=False,
            asr=Engine(),
            asr_fast=None,
            _CPU_WARNING=EnhancedApp._CPU_WARNING,
        )
        app._fallen_back_engines = lambda: EnhancedApp._fallen_back_engines(app)
        app._apply_device_warning = lambda announce=False: EnhancedApp._apply_device_warning(app, announce)
        return app, calls, EnhancedApp

    def test_cpu_fallback_event_warns_the_tray(self):
        app, calls, cls = self._app(fallen=True)
        cls._on_asr_device_event(app, "cpu_fallback", "model: out_of_memory")
        assert calls == [("warn", cls._CPU_WARNING, True)]
        assert app._device_warning == cls._CPU_WARNING

    def test_restore_clears_the_warning_once_nothing_is_on_cpu(self):
        app, calls, cls = self._app(fallen=False)
        app._device_warning = cls._CPU_WARNING
        cls._on_asr_device_event(app, "cuda_restored", "model")
        assert calls == [("clear",)]
        assert app._device_warning == ""

    def test_restore_keeps_the_warning_while_another_engine_is_still_on_cpu(self):
        app, calls, cls = self._app(fallen=True)
        cls._on_asr_device_event(app, "cuda_restored", "model")
        assert calls == [("warn", cls._CPU_WARNING, False)]


class TestStartupSelfCheck:
    def _run(self, tmp_path, log_write, **kwargs):
        from voiceflow.utils.launch_diagnostics import run_startup_selfcheck

        log_path = tmp_path / "logs" / "voiceflow.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        marker = tmp_path / "logs" / "active_log_path.txt"
        marker.write_text(str(log_path), encoding="utf-8")

        def write(msg):
            log_write(log_path, msg)

        return run_startup_selfcheck(
            log_write=write,
            active_log_path=log_path,
            marker_path=marker,
            data_dir=tmp_path,
            log_wait_s=0.3,
            **kwargs,
        )

    def test_healthy_launch_passes_and_leaves_evidence(self, tmp_path):
        report = self._run(tmp_path, lambda p, m: p.open("a").write(m + "\n"))
        assert report["ok"], report
        assert report["log_readback_ok"] and report["history_store_readback_ok"] and report["marker_ok"]
        saved = json.loads((tmp_path / "startup_selfcheck.json").read_text(encoding="utf-8"))
        assert saved["token"] == report["token"]
        rows = (tmp_path / "launch_contexts.jsonl").read_text(encoding="utf-8").splitlines()
        assert json.loads(rows[-1])["token"] == report["token"]
        # Names only: values of ordinary variables must not be recorded.
        assert "env_names" in saved["context"]
        assert "PATH" not in saved["context"]["env_values"]

    def test_a_log_that_never_arrives_fails_the_check(self, tmp_path):
        report = self._run(tmp_path, lambda p, m: None)
        assert not report["ok"]
        assert report["log_readback_ok"] is False
        assert any("log not readable" in p for p in report["problems"])
        assert (tmp_path / "startup_selfcheck.json").exists()

    def test_wrong_marker_fails_the_check(self, tmp_path):
        from voiceflow.utils.launch_diagnostics import run_startup_selfcheck

        log_path = tmp_path / "voiceflow.log"
        marker = tmp_path / "active_log_path.txt"
        marker.write_text("C:/somewhere/else.log", encoding="utf-8")
        report = run_startup_selfcheck(
            log_write=lambda m: log_path.open("a").write(m + "\n"),
            active_log_path=log_path,
            marker_path=marker,
            data_dir=tmp_path,
            log_wait_s=0.3,
        )
        assert report["marker_ok"] is False
        assert not report["ok"]

    def test_breadcrumb_survives_without_the_app(self, tmp_path):
        from voiceflow.utils.launch_diagnostics import write_boot_breadcrumb

        write_boot_breadcrumb("boot", directory=tmp_path, stdout="none", note="line\nbreak")
        text = (tmp_path / "boot_breadcrumb.log").read_text(encoding="utf-8")
        assert "boot" in text and "stdout=none" in text and text.count("\n") == 1

    def test_launch_context_records_names_not_values(self, monkeypatch):
        from voiceflow.utils.launch_diagnostics import launch_context

        monkeypatch.setenv("VF18_SECRET_TOKEN", "hunter2")
        ctx = launch_context()
        assert "VF18_SECRET_TOKEN" in ctx["env_names"]
        assert "hunter2" not in json.dumps(ctx)


class TestHistoryWriteVisibility:
    def _item(self, text="hello world", epoch=None):
        return {
            "ts": "12:00:00",
            "event_epoch": epoch if epoch is not None else time.time(),
            "audio_duration": 1.0,
            "processing_time": 0.2,
            "rtf": 5.0,
            "preview": text[:40],
            "full_text": text,
        }

    def _call(self, path: Path, item):
        from voiceflow.ui import visual_indicators as vi

        fake = SimpleNamespace(history_store_path=path)
        vi.BottomScreenIndicator._append_history_store(fake, item)
        return vi

    def test_good_write_is_recorded_and_silent(self, tmp_path):
        from voiceflow.ui import visual_indicators as vi

        seen = []
        vi.set_history_failure_handler(lambda p, r: seen.append((p, r)))
        vi._history_failure_last_report = 0.0
        try:
            self._call(tmp_path / "h.jsonl", self._item())
        finally:
            vi.set_history_failure_handler(None)
        assert seen == []
        assert "hello world" in (tmp_path / "h.jsonl").read_text(encoding="utf-8")

    def test_unwritable_store_is_reported(self, tmp_path):
        from voiceflow.ui import visual_indicators as vi

        blocker = tmp_path / "blocker"
        blocker.write_text("x", encoding="utf-8")  # a file where a directory is needed
        seen = []
        vi.set_history_failure_handler(lambda p, r: seen.append((p, r)))
        vi._history_failure_last_report = 0.0
        try:
            self._call(blocker / "h.jsonl", self._item())
        finally:
            vi.set_history_failure_handler(None)
        assert len(seen) == 1

    def test_long_dictation_is_kept_not_dropped(self, tmp_path):
        from voiceflow.ui import visual_indicators as vi

        seen = []
        vi.set_history_failure_handler(lambda p, r: seen.append((p, r)))
        vi._history_failure_last_report = 0.0
        long_text = "word " * 4000  # ~20 KB, over the per-row cap
        try:
            self._call(tmp_path / "h.jsonl", self._item(long_text))
        finally:
            vi.set_history_failure_handler(None)
        rows = (tmp_path / "h.jsonl").read_text(encoding="utf-8").splitlines()
        assert seen == [] and len(rows) == 1
        assert json.loads(rows[0])["truncated"] is True


# ---------------------------------------------------------------------------
# Review round 1 (Codex): missing-runtime fallback, lazy-decode OOM, persisted key
# ---------------------------------------------------------------------------


class TestMissingCudaRuntime:
    """An explicit CUDA request with no usable runtime is an announced fallback."""

    @pytest.fixture
    def runtime_missing(self, monkeypatch):
        monkeypatch.setattr(ae, "_cuda_runtime_ready", lambda: False)
        monkeypatch.setattr(ae, "_missing_cuda_dlls", lambda dlls: ["cublas64_12.dll"])

    def test_explicit_cuda_enters_the_announced_fallback_state(self, runtime_missing):
        events = []
        ae.add_device_listener(lambda e, d: events.append((e, d)))
        engine = ASREngine(model_name="distil-large-v3", device="cuda", compute_type="float16")
        status = engine.device_status()
        assert status["fell_back_to_cpu"] is True
        assert status["device"] == "cpu"
        assert status["fallback_reason"].startswith("missing_runtime:")
        assert "cublas64_12.dll" in status["fallback_reason"]
        assert [e for e, _ in events] == ["cpu_fallback"]
        # The wanted compute type is remembered so the idle retry restores float16.
        assert engine._backend._cuda_wanted_compute == "float16"

    def test_tier_routing_still_picks_the_cpu_model(self, runtime_missing):
        engine = ASREngine(tier=ae.ModelTier.QUICK, device="cuda", compute_type="float16")
        assert engine.model_key == "small.en"
        assert engine.device_status()["fell_back_to_cpu"] is True

    def test_auto_without_cuda_is_plain_cpu_not_a_fallback(self, runtime_missing):
        engine = ASREngine(model_name="distil-large-v3", device="auto", compute_type="float16")
        status = engine.device_status()
        assert status["device"] == "cpu"
        assert status["fell_back_to_cpu"] is False

    def test_the_idle_retry_restores_cuda_once_the_runtime_is_back(self, runtime_missing, monkeypatch):
        events = []
        ae.add_device_listener(lambda e, d: events.append(e))
        engine = ASREngine(model_name="distil-large-v3", device="cuda", compute_type="float16")
        backend = engine._backend
        backend._model = object()  # the CPU model currently serving dictation

        class Fine:
            def __init__(self, ref, **kwargs):
                self.device = kwargs.get("device")

            def transcribe(self, audio, **kwargs):
                return iter(()), None

        import faster_whisper

        monkeypatch.setattr(faster_whisper, "WhisperModel", Fine)
        assert engine.retry_cuda_if_fallen_back(force=True) is True
        assert backend.config.device == "cuda"
        assert backend.config.compute_type == "float16"
        assert engine.device_status()["fell_back_to_cpu"] is False
        assert events == ["cpu_fallback", "cuda_restored"]


class TestDecodeTimeOutOfMemory:
    """faster-whisper decodes lazily; an OOM while consuming the generator must fall back."""

    def test_oom_during_segment_iteration_falls_back_and_returns_cpu_text(self, monkeypatch):
        import numpy as np

        events = []
        ae.add_device_listener(lambda e, d: events.append((e, d)))
        info = SimpleNamespace(language="en")

        class FullCard:
            def transcribe(self, audio, **kwargs):
                def gen():
                    raise RuntimeError("CUDA failed with error out of memory")
                    yield  # pragma: no cover - makes this a generator

                return gen(), info

        class CpuModel:
            devices = []

            def __init__(self, ref, **kwargs):
                CpuModel.devices.append(kwargs.get("device"))

            def transcribe(self, audio, **kwargs):
                seg = SimpleNamespace(text=" hello world", start=0.0, end=1.0, avg_logprob=-0.1, no_speech_prob=0.01)
                return iter([seg]), info

        import faster_whisper

        monkeypatch.setattr(faster_whisper, "WhisperModel", CpuModel)
        backend = _backend()
        backend._model = FullCard()

        result = backend.transcribe(np.ones(16000, dtype=np.float32) * 0.1)

        assert result.text == "hello world"
        assert CpuModel.devices == ["cpu"]
        assert backend.config.device == "cpu"
        assert backend.fell_back_to_cpu
        assert events and events[0][0] == "cpu_fallback"
        assert "out_of_memory" in events[0][1]

    def test_non_cuda_errors_during_iteration_still_propagate(self):
        import numpy as np

        class Broken:
            def transcribe(self, audio, **kwargs):
                def gen():
                    raise ValueError("bad audio")
                    yield  # pragma: no cover

                return gen(), SimpleNamespace(language="en")

        backend = _backend()
        backend._model = Broken()
        with pytest.raises(ValueError):
            backend.transcribe(np.ones(16000, dtype=np.float32) * 0.1)
        assert not backend.fell_back_to_cpu


class TestPersistedModelKey:
    """The saved config, the label, the log key and the weights all name one model."""

    def _load(self, monkeypatch, tmp_path, saved: dict):
        from voiceflow.core.config import Config
        from voiceflow.utils import settings

        path = tmp_path / "config.json"
        path.write_text(json.dumps(saved), encoding="utf-8")
        monkeypatch.setattr(settings, "config_path", lambda: path)
        return settings.load_config(Config()), path

    def test_legacy_key_is_rewritten_on_disk_and_agrees_with_the_engine(self, monkeypatch, tmp_path):
        cfg, path = self._load(
            monkeypatch,
            tmp_path,
            {"model_name": "distil-large-v3.5", "setup_completed": True},
        )
        assert cfg.model_name == "distil-large-v3"
        assert json.loads(path.read_text(encoding="utf-8"))["model_name"] == "distil-large-v3"

        engine = ASREngine(model_name=cfg.model_name, device="cpu", compute_type="int8")
        assert engine.model_key == cfg.model_name
        assert engine.model_config.model_id == "Systran/faster-distil-whisper-large-v3"

    def test_the_real_v35_export_and_other_choices_are_left_alone(self, monkeypatch, tmp_path):
        cfg, _ = self._load(
            monkeypatch,
            tmp_path,
            {"model_name": "distil-large-v3.5-ct2", "quality_model_name": "small.en", "setup_completed": True},
        )
        assert cfg.model_name == "distil-large-v3.5-ct2"
        assert cfg.quality_model_name == "small.en"

    def test_migration_is_idempotent(self, monkeypatch, tmp_path):
        from voiceflow.utils.settings import _apply_model_key_migration

        cfg, _ = self._load(monkeypatch, tmp_path, {"model_name": "distil-large-v3.5", "setup_completed": True})
        assert _apply_model_key_migration(cfg) is False
