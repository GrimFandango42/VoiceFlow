from __future__ import annotations

from voiceflow.core.config import Config
from voiceflow.ui.setup_wizard import (
    SetupCapabilities,
    apply_setup_updates,
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
