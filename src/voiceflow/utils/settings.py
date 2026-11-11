from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from voiceflow.core.config import Config
from voiceflow.utils.logging_setup import default_log_dir


def config_dir() -> Path:
    # Place alongside logs under VoiceFlow
    base = default_log_dir().parent
    base.mkdir(parents=True, exist_ok=True)
    return base


def config_path() -> Path:
    return config_dir() / "config.json"


_DEFAULT_JSON_MAX_BYTES = 2 * 1024 * 1024


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> bool:
    """Atomically replace a text file to avoid partial writes during crashes."""
    tmp_name = f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}"
    tmp_path = path.with_name(tmp_name)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.write_text(text, encoding=encoding)
        os.replace(tmp_path, path)
        return True
    except Exception:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass
        return False


def load_json_dict_bounded(path: Path, *, max_bytes: int = _DEFAULT_JSON_MAX_BYTES) -> Optional[dict[str, Any]]:
    """Load a JSON dictionary only when the file is reasonably bounded."""
    try:
        if not path.exists():
            return None
        if int(path.stat().st_size) > max(1, int(max_bytes)):
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def read_text_tail_lines(
    path: Path,
    *,
    max_lines: int,
    max_bytes: int,
    max_line_chars: int,
) -> list[str]:
    """Read only the tail of a text file and return bounded valid lines.
    Keeps large JSONL files from causing heavy reads.
    """
    try:
        if not path.exists():
            return []
        file_size = int(path.stat().st_size)
        if file_size <= 0:
            return []
        read_size = min(file_size, max(1, int(max_bytes)))
        with path.open("rb") as handle:
            if file_size > read_size:
                handle.seek(file_size - read_size)
            raw = handle.read(read_size)
        text = raw.decode("utf-8", errors="ignore")
        lines = text.splitlines()
        if file_size > read_size and lines:
            # Drop potentially partial first line when reading file tail.
            lines = lines[1:]
    except Exception:
        return []

    bounded: list[str] = []
    cap = max(32, int(max_line_chars))
    for line in lines:
        line = line.strip()
        if not line or len(line) > cap:
            continue
        bounded.append(line)
    return bounded[-max(1, int(max_lines)) :]


def append_jsonl_bounded(
    path: Path,
    payload: dict[str, Any],
    *,
    max_file_bytes: int,
    keep_lines: int,
    max_line_chars: int = 8192,
) -> bool:
    """Append a JSONL row and trim file growth when size threshold is exceeded."""
    try:
        line = json.dumps(payload, ensure_ascii=True)
    except Exception:
        return False
    if len(line) > max(64, int(max_line_chars)):
        return False

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if int(path.stat().st_size) <= max(1, int(max_file_bytes)):
            return True
    except Exception:
        return False

    lines = read_text_tail_lines(
        path,
        max_lines=max(1, int(keep_lines)),
        max_bytes=max(1, int(max_file_bytes)),
        max_line_chars=max(64, int(max_line_chars)),
    )
    return atomic_write_text(path, ("\n".join(lines) + ("\n" if lines else "")), encoding="utf-8")


def _is_legacy_value(current: Any, legacy: Any) -> bool:
    if isinstance(current, float) or isinstance(legacy, float):
        try:
            return abs(float(current) - float(legacy)) < 1e-9
        except Exception:
            return False
    return current == legacy


def _apply_performance_migrations(cfg: Config) -> bool:
    """One-time migration for legacy settings that hurt medium/long dictation latency.
    Preserves explicit non-legacy user values.
    """
    changed = False

    legacy_updates = [
        # Older defaults were conservative and made >10s dictation slower.
        ("pause_compaction_min_audio_seconds", 14.0, 7.0),
        ("pause_compaction_keep_silence_ms", 180, 80),
        ("pause_compaction_max_reduction_pct", 60.0, 82.0),
        ("ptt_tail_buffer_seconds", 0.25, 0.35),
        # Older preview defaults were too short for useful live feedback.
        ("live_caption_words", 2, 6),
        ("live_caption_words", 6, 8),
        ("live_caption_max_chars", 110, 150),
        ("live_caption_font_size", 16, 14),
        ("live_caption_correction_window_seconds", 1.4, 2.0),
        ("live_checkpoint_preview_chars", 260, 380),
        # Legacy wrapping was too narrow and felt overly fragmented.
        ("destination_default_chars", 78, 84),
        ("destination_terminal_chars", 96, 104),
        ("destination_chat_chars", 64, 68),
        ("destination_editor_chars", 88, 94),
    ]

    for field, legacy, replacement in legacy_updates:
        current = getattr(cfg, field, None)
        if _is_legacy_value(current, legacy):
            setattr(cfg, field, replacement)
            changed = True

    # Prefer GPU automatically when runtime is confirmed healthy and user did not force CPU.
    # This also repairs legacy CPU-only configs persisted by earlier builds.
    force_cpu = str(os.environ.get("VOICEFLOW_FORCE_CPU", "")).strip().lower() in {"1", "true", "yes"}
    if not force_cpu:
        try:
            gpu_enabled = bool(getattr(cfg, "enable_gpu_acceleration", False))
            device = str(getattr(cfg, "device", "cpu")).strip().lower()
            compute = str(getattr(cfg, "compute_type", "int8")).strip().lower()
            model_tier = str(getattr(cfg, "model_tier", "quick")).strip().lower()
            tiny_cap = float(getattr(cfg, "latency_boost_tiny_max_audio_seconds", 0.0) or 0.0)

            # Heuristic for stale CPU configs from older packaged defaults.
            legacy_cpu_profile = (
                (not gpu_enabled)
                and device == "cpu"
                and compute == "int8"
                and model_tier in {"quick", "balanced"}
                and tiny_cap >= 10.0
            )

            if gpu_enabled or legacy_cpu_profile:
                from voiceflow.core.asr_engine import _cuda_runtime_ready

                if _cuda_runtime_ready():
                    if not gpu_enabled:
                        cfg.enable_gpu_acceleration = True
                        changed = True
                    if device in {"cpu", "auto"}:
                        cfg.device = "cuda"
                        changed = True
                    if compute in {"int8", "auto", ""}:
                        cfg.compute_type = "float16"
                        changed = True
        except Exception:
            # Stay on CPU if runtime checks fail.
            pass

    return changed


_MODEL_NAME_FIELDS = ("model_name", "fast_model_name", "quality_model_name")


def _apply_model_key_migration(cfg: Config) -> bool:
    """Rewrite a legacy model key to the key whose weights it actually loads (VF-18).

    ``distil-large-v3.5`` never loaded v3.5 (no CTranslate2 export existed when
    the key was added); it loaded the distil-large-v3 weights. Persisting the
    key that matches the weights keeps the saved config, the displayed label and
    the log line in agreement. The real v3.5 export is a separate opt-in key,
    ``distil-large-v3.5-ct2``, which this never touches.
    """
    from voiceflow.core.asr_engine import canonical_model_key

    changed = False
    for field in _MODEL_NAME_FIELDS:
        current = getattr(cfg, field, None)
        if not isinstance(current, str) or not current:
            continue
        canonical = canonical_model_key(current)
        if canonical != current:
            setattr(cfg, field, canonical)
            changed = True
    return changed


SINGLE_MODEL_MIGRATION_VERSION = 1


def _apply_single_model_migration(cfg: Config) -> bool:
    """Turn the tiny.en fast path off once on GPU setups (VF-18 item 7).

    ``save_config`` persists every field, so a config written while
    ``latency_boost_enabled`` defaulted to True carries it forever and flipping
    the default alone would change nothing for an existing install. On a GPU the
    main model is within ~65 ms of tiny.en on short clips, so the second model
    is dropped (one preload thread, one warmup, one set of weights in VRAM).
    CPU setups keep it: there it saves about a second per clip. The version
    marker makes this run once, so a user who later turns the fast path back on
    keeps it.

    On a GPU-configured install the marker is recorded only once the migration
    has really happened (CUDA confirmed and the fast path off). A launch where
    CUDA is unavailable (CPU fallback, forced CPU, runtime check failure) leaves
    the marker unset, so the next launch with a working GPU still migrates
    instead of keeping tiny.en loaded forever.
    """
    try:
        seen = int(getattr(cfg, "single_model_migration_version", 0) or 0)
    except Exception:
        seen = 0
    if seen >= SINGLE_MODEL_MIGRATION_VERSION:
        return False
    device = str(getattr(cfg, "device", "") or "").strip().lower()
    gpu_setup = bool(getattr(cfg, "enable_gpu_acceleration", False)) and device in {"cuda", "auto"}
    if gpu_setup and bool(getattr(cfg, "latency_boost_enabled", False)):
        # Only where CUDA actually works here; a GPU-configured machine that
        # runs on CPU keeps the fast path that makes short clips tolerable,
        # and is looked at again on the next launch.
        try:
            from voiceflow.core.asr_engine import _cuda_runtime_ready

            cuda_ok = bool(_cuda_runtime_ready())
        except Exception:
            cuda_ok = False
        if not cuda_ok:
            return False
        cfg.latency_boost_enabled = False
    cfg.single_model_migration_version = SINGLE_MODEL_MIGRATION_VERSION
    return True


CLOUD_LEARNING_CONSENT_VERSION = 1


def _apply_cloud_learning_consent_migration(cfg: Config) -> bool:
    """One-time reset of the cloud transcript analysis flag (VF-03).

    Configs saved before the setup wizard exposed the toggle carry
    ``adaptive_ai_analysis_enabled=True`` from the old default, which nobody
    consented to. Turn it off once and record that the consent flow has run;
    from then on only the wizard changes it.
    """
    try:
        seen = int(getattr(cfg, "cloud_learning_consent_version", 0) or 0)
    except Exception:
        seen = 0
    if seen >= CLOUD_LEARNING_CONSENT_VERSION:
        return False
    cfg.adaptive_ai_analysis_enabled = False
    cfg.cloud_learning_consent_version = CLOUD_LEARNING_CONSENT_VERSION
    return True


def load_config(defaults: Config) -> Config:
    path = config_path()
    if not path.exists():
        if _apply_performance_migrations(defaults):
            save_config(defaults)
        return defaults
    data = load_json_dict_bounded(path)
    if data is None:
        if _apply_performance_migrations(defaults):
            save_config(defaults)
        return defaults
    # Apply known fields only
    for field in asdict(defaults).keys():
        if field in data:
            setattr(defaults, field, data[field])

    required_setup_flow_version = int(
        getattr(getattr(Config, "__dataclass_fields__", {}).get("setup_flow_version"), "default", 1)
    )
    try:
        saved_setup_flow_version = int(data.get("setup_flow_version", 0) or 0)
    except Exception:
        saved_setup_flow_version = 0
    setup_markers_missing = "setup_completed" not in data
    setup_flow_stale = saved_setup_flow_version < required_setup_flow_version

    if setup_markers_missing or setup_flow_stale:
        # Prompt setup once when onboarding markers are missing or flow version changed.
        defaults.setup_completed = False
        defaults.show_setup_on_startup = True
        defaults.setup_profile = str(getattr(defaults, "setup_profile", "") or "recommended")
        defaults.setup_flow_version = required_setup_flow_version

    try:
        pre_validation_state = asdict(defaults)
    except Exception:
        pre_validation_state = None

    try:
        validated = defaults.validate()
        if isinstance(validated, Config):
            defaults = validated
    except Exception:
        pass

    changed = _apply_performance_migrations(defaults)
    changed = _apply_single_model_migration(defaults) or changed
    changed = _apply_cloud_learning_consent_migration(defaults) or changed
    try:
        changed = _apply_model_key_migration(defaults) or changed
    except Exception:
        # Never block startup on a label migration; the engine still aliases it.
        pass
    try:
        validation_changed = pre_validation_state is not None and asdict(defaults) != pre_validation_state
    except Exception:
        validation_changed = False

    if changed or validation_changed:
        save_config(defaults)
    return defaults


def save_config(cfg: Config) -> None:
    path = config_path()
    try:
        atomic_write_text(path, json.dumps(asdict(cfg), indent=2), encoding="utf-8")
    except Exception:
        pass
