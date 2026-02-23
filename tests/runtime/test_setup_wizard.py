from __future__ import annotations

from voiceflow.core.config import Config
from voiceflow.ui import setup_wizard as setup_wizard_mod
from voiceflow.ui.setup_wizard import (
    SetupCapabilities,
    assess_setup_capabilities,
    apply_setup_updates,
    baseline_setup_capabilities,
    describe_setup_step_state,
    detect_setup_capabilities,
    maybe_run_startup_setup,
    profile_defaults,
    recommended_profile_key,
)


def test_recommended_profile_prefers_gpu_when_available():
    caps = SetupCapabilities(platform_name="windows", cpu_count=16, cuda_available=True)
    assert recommended_profile_key(caps) == "gpu-balanced"


def test_recommended_profile_falls_back_to_cpu_when_no_cuda():
    caps = SetupCapabilities(platform_name="windows", cpu_count=8, cuda_available=False)
    defaults = profile_defaults("recommended", caps)
    assert defaults["device"] == "cpu"
    assert defaults["compute_type"] == "int8"
    assert defaults["enable_gpu_acceleration"] is False


def test_gpu_profile_auto_falls_back_when_cuda_missing():
    caps = SetupCapabilities(platform_name="linux", cpu_count=12, cuda_available=False)
    defaults = profile_defaults("gpu-balanced", caps)
    assert defaults["device"] == "cpu"
    assert defaults["model_tier"] == "quick"


def test_apply_setup_updates_reports_restart_required_on_runtime_changes():
    cfg = Config()
    restart_required = apply_setup_updates(
        cfg,
        {
            "device": "cpu",
            "compute_type": "int8",
            "model_tier": "quick",
            "use_tray": True,
        },
    )
    assert restart_required is True


def test_apply_setup_updates_ignores_non_restart_fields():
    cfg = Config()
    restart_required = apply_setup_updates(
        cfg,
        {
            "visual_indicators_enabled": not bool(cfg.visual_indicators_enabled),
            "show_setup_on_startup": False,
        },
    )
    assert restart_required is False


def test_maybe_run_startup_setup_runs_when_incomplete(monkeypatch):
    cfg = Config()
    cfg.setup_completed = False
    cfg.show_setup_on_startup = True

    called = {"source": None}

    def _fake_launch(_cfg, source="manual"):
        called["source"] = source
        return True, False

    monkeypatch.setattr(setup_wizard_mod, "launch_setup_wizard", _fake_launch)

    saved, restart_required = maybe_run_startup_setup(cfg)
    assert saved is True
    assert restart_required is False
    assert called["source"] == "startup"


def test_maybe_run_startup_setup_skips_when_completed(monkeypatch):
    cfg = Config()
    cfg.setup_completed = True
    cfg.show_setup_on_startup = True

    def _fail_launch(_cfg, source="manual"):
        raise AssertionError("launch_setup_wizard should not be called when setup is completed")

    monkeypatch.setattr(setup_wizard_mod, "launch_setup_wizard", _fail_launch)

    saved, restart_required = maybe_run_startup_setup(cfg)
    assert saved is False
    assert restart_required is False


def test_maybe_run_startup_setup_honors_skip_env(monkeypatch):
    cfg = Config()
    cfg.setup_completed = False
    cfg.show_setup_on_startup = True
    monkeypatch.setenv("VOICEFLOW_SKIP_SETUP_UI", "1")

    def _fail_launch(_cfg, source="manual"):
        raise AssertionError("launch_setup_wizard should not be called when skip env is set")

    monkeypatch.setattr(setup_wizard_mod, "launch_setup_wizard", _fail_launch)

    saved, restart_required = maybe_run_startup_setup(cfg)
    assert saved is False
    assert restart_required is False


def test_assessment_prefers_gpu_profile_for_cuda_ready_system():
    caps = SetupCapabilities(
        platform_name="windows",
        cpu_count=16,
        cuda_available=True,
        total_ram_gb=32.0,
        gpu_name="NVIDIA RTX",
        gpu_vram_gb=12.0,
    )
    assessment = assess_setup_capabilities(caps)
    assert assessment["recommended_profile"] == "gpu-balanced"
    assert assessment["grade"] in {"Excellent", "Strong"}
    assert assessment["score"] >= 70


def test_assessment_prefers_cpu_profile_when_cuda_missing():
    caps = SetupCapabilities(
        platform_name="windows",
        cpu_count=8,
        cuda_available=False,
        total_ram_gb=16.0,
    )
    assessment = assess_setup_capabilities(caps)
    assert assessment["recommended_profile"] == "cpu-compatible"
    assert assessment["recommended_device"] == "cpu"


def test_baseline_capabilities_default_to_safe_cpu_profile():
    caps = baseline_setup_capabilities()
    assert caps.cuda_available is False
    assert caps.cpu_count >= 1
    assert caps.platform_name


def test_detect_setup_capabilities_tolerates_gpu_snapshot_failures(monkeypatch):
    from voiceflow.core import asr_engine as asr_mod

    monkeypatch.setattr(asr_mod, "_cuda_runtime_ready", lambda: True)

    def _boom():
        raise RuntimeError("nvidia probe failed")

    monkeypatch.setattr(setup_wizard_mod, "nvidia_smi_info", _boom)

    caps = detect_setup_capabilities()
    assert caps.cuda_available is True
    assert caps.gpu_name == ""


def test_describe_setup_step_state_requires_hardware_check_in_startup():
    state = describe_setup_step_state(
        is_startup_flow=True,
        hardware_checked=False,
        hardware_running=False,
        profile_selected=False,
        last_hardware_check="",
    )
    assert state["step2_locked"] is True
    assert "Only required action" in str(state["focus_state"])


def test_describe_setup_step_state_unlocks_step2_after_check():
    state = describe_setup_step_state(
        is_startup_flow=True,
        hardware_checked=True,
        hardware_running=False,
        profile_selected=False,
        last_hardware_check="14:05:12",
    )
    assert state["step2_locked"] is False
    assert "Step 2" in str(state["step_state"])
