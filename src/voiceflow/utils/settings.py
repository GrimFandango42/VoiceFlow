from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from voiceflow.core.config import Config
from voiceflow.utils.logging_setup import default_log_dir


def config_dir() -> Path:
    # Place alongside logs under LocalFlow
    base = default_log_dir().parent
    base.mkdir(parents=True, exist_ok=True)
    return base


def config_path() -> Path:
    return config_dir() / "config.json"


def _is_legacy_value(current: Any, legacy: Any) -> bool:
    if isinstance(current, float) or isinstance(legacy, float):
        try:
            return abs(float(current) - float(legacy)) < 1e-9
        except Exception:
            return False
    return current == legacy


def _apply_performance_migrations(cfg: Config) -> bool:
    """
    One-time migration for legacy settings that hurt medium/long dictation latency.
    Preserves explicit non-legacy user values.
    """
    changed = False

    legacy_updates = {
        # Older defaults were conservative and made >10s dictation slower.
        "pause_compaction_min_audio_seconds": (14.0, 7.0),
        "pause_compaction_keep_silence_ms": (180, 80),
        "pause_compaction_max_reduction_pct": (60.0, 82.0),
        "ptt_tail_buffer_seconds": (0.25, 0.35),
    }

    for field, (legacy, replacement) in legacy_updates.items():
        current = getattr(cfg, field, None)
        if _is_legacy_value(current, legacy):
            setattr(cfg, field, replacement)
            changed = True

    # Prefer GPU automatically when runtime is confirmed healthy and user did not force CPU.
    force_cpu = str(os.environ.get("VOICEFLOW_FORCE_CPU", "")).strip().lower() in {"1", "true", "yes"}
    if not force_cpu:
        try:
            gpu_enabled = bool(getattr(cfg, "enable_gpu_acceleration", False))
            device = str(getattr(cfg, "device", "cpu")).strip().lower()
            compute = str(getattr(cfg, "compute_type", "int8")).strip().lower()
            if gpu_enabled and device == "cpu" and compute == "int8":
                from voiceflow.core.asr_engine import _cuda_runtime_ready

                if _cuda_runtime_ready():
                    cfg.device = "cuda"
                    cfg.compute_type = "float16"
                    changed = True
        except Exception:
            # Stay on CPU if runtime checks fail.
            pass

    return changed


def load_config(defaults: Config) -> Config:
    path = config_path()
    if not path.exists():
        if _apply_performance_migrations(defaults):
            save_config(defaults)
        return defaults
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        if _apply_performance_migrations(defaults):
            save_config(defaults)
        return defaults
    # Apply known fields only
    for field in asdict(defaults).keys():
        if field in data:
            setattr(defaults, field, data[field])
    if _apply_performance_migrations(defaults):
        save_config(defaults)
    return defaults


def save_config(cfg: Config) -> None:
    path = config_path()
    try:
        path.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")
    except Exception:
        pass
