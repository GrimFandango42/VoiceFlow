from __future__ import annotations

import os
import platform
import threading
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from voiceflow.core.config import Config
from voiceflow.utils.settings import save_config

RESTART_REQUIRED_FIELDS = {
    "model_tier",
    "model_name",
    "device",
    "compute_type",
    "enable_gpu_acceleration",
    "fast_model_name",
    "quality_model_name",
    "latency_boost_model_tier",
}

PROFILE_LABELS = {
    "recommended": "Recommended",
    "cpu-compatible": "CPU Compatible",
    "gpu-balanced": "GPU Balanced",
}

PROFILE_HELP = {
    "recommended": "Auto-picks defaults from detected hardware.",
    "cpu-compatible": "Best compatibility path across most systems.",
    "gpu-balanced": "Uses CUDA and balanced tier for faster high-quality dictation.",
}

_WIZARD_LOCK = threading.Lock()


@dataclass(frozen=True)
class SetupCapabilities:
    platform_name: str
    cpu_count: int
    cuda_available: bool


def detect_setup_capabilities() -> SetupCapabilities:
    cuda_available = False
    try:
        from voiceflow.core.asr_engine import _cuda_runtime_ready

        cuda_available = bool(_cuda_runtime_ready())
    except Exception:
        cuda_available = False
    return SetupCapabilities(
        platform_name=str(platform.system() or "unknown").lower(),
        cpu_count=max(1, int(os.cpu_count() or 1)),
        cuda_available=cuda_available,
    )


def recommended_profile_key(capabilities: SetupCapabilities) -> str:
    return "gpu-balanced" if capabilities.cuda_available else "cpu-compatible"


def profile_defaults(profile_key: str, capabilities: SetupCapabilities) -> Dict[str, Any]:
    selected = str(profile_key or "recommended").strip().lower()
    if selected == "recommended":
        selected = recommended_profile_key(capabilities)

    if selected.startswith("gpu") and not capabilities.cuda_available:
        selected = "cpu-compatible"

    if selected == "gpu-balanced":
        return {
            "model_tier": "balanced",
            "model_name": "distil-large-v3.5",
            "device": "cuda",
            "compute_type": "float16",
            "enable_gpu_acceleration": True,
            "latency_boost_enabled": True,
            "latency_boost_model_tier": "tiny",
            "fast_model_name": "tiny.en",
            "quality_model_name": "small.en",
            "paste_injection": True,
            "visual_indicators_enabled": True,
            "use_tray": True,
        }

    return {
        "model_tier": "quick",
        "model_name": "small.en",
        "device": "cpu",
        "compute_type": "int8",
        "enable_gpu_acceleration": False,
        "latency_boost_enabled": True,
        "latency_boost_model_tier": "tiny",
        "fast_model_name": "tiny.en",
        "quality_model_name": "small.en",
        "paste_injection": True,
        "visual_indicators_enabled": True,
        "use_tray": True,
    }


def apply_setup_updates(cfg: Config, updates: Dict[str, Any]) -> bool:
    before = {name: getattr(cfg, name, None) for name in RESTART_REQUIRED_FIELDS}
    for key, value in updates.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)
    after = {name: getattr(cfg, name, None) for name in RESTART_REQUIRED_FIELDS}
    return any(before[name] != after[name] for name in RESTART_REQUIRED_FIELDS)


def maybe_run_startup_setup(cfg: Config) -> Tuple[bool, bool]:
    skip_env = str(os.environ.get("VOICEFLOW_SKIP_SETUP_UI", "")).strip().lower()
    if skip_env in {"1", "true", "yes", "on"}:
        return False, False
    if not bool(getattr(cfg, "show_setup_on_startup", True)):
        return False, False
    if bool(getattr(cfg, "setup_completed", False)):
        return False, False
    return launch_setup_wizard(cfg, source="startup")


def launch_setup_wizard(cfg: Config, source: str = "manual") -> Tuple[bool, bool]:
    if not _WIZARD_LOCK.acquire(blocking=False):
        return False, False

    try:
        try:
            import tkinter as tk
            from tkinter import ttk
        except Exception:
            return False, False

        caps = detect_setup_capabilities()
        result = {"saved": False, "restart_required": False}

        class HoverHelp:
            def __init__(self, widget: Any, text: str):
                self.widget = widget
                self.text = text
                self.tip = None
                self.widget.bind("<Enter>", self.show)
                self.widget.bind("<Leave>", self.hide)

            def show(self, _event: Any = None):
                if self.tip is not None:
                    return
                try:
                    self.tip = tk.Toplevel(self.widget)
                    self.tip.wm_overrideredirect(True)
                    self.tip.attributes("-topmost", True)
                    x = self.widget.winfo_rootx() + 14
                    y = self.widget.winfo_rooty() + 22
                    self.tip.wm_geometry(f"+{x}+{y}")
                    label = tk.Label(
                        self.tip,
                        text=self.text,
                        background="#111827",
                        foreground="#E5E7EB",
                        relief="solid",
                        borderwidth=1,
                        padx=8,
                        pady=5,
                        justify="left",
                        wraplength=360,
                    )
                    label.pack()
                except Exception:
                    self.hide()

            def hide(self, _event: Any = None):
                if self.tip is not None:
                    try:
                        self.tip.destroy()
                    except Exception:
                        pass
                    self.tip = None

        try:
            root = tk.Tk()
        except Exception:
            return False, False
        root.title("VoiceFlow Setup")
        root.geometry("760x640")
        root.minsize(700, 560)

        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        main = ttk.Frame(root, padding=18)
        main.pack(fill="both", expand=True)

        title = ttk.Label(main, text="VoiceFlow First-Run Setup", font=("Segoe UI", 14, "bold"))
        title.pack(anchor="w")

        subtitle = ttk.Label(
            main,
            text="Pick defaults now. You can reopen this from the tray later.",
        )
        subtitle.pack(anchor="w", pady=(4, 12))

        detected_text = (
            f"Detected system: platform={caps.platform_name}, cpu={caps.cpu_count} cores, "
            f"cuda={'yes' if caps.cuda_available else 'no'}"
        )
        ttk.Label(main, text=detected_text).pack(anchor="w", pady=(0, 12))

        profile_var = tk.StringVar(value=str(getattr(cfg, "setup_profile", "recommended") or "recommended"))
        if profile_var.get() not in {"recommended", "cpu-compatible", "gpu-balanced"}:
            profile_var.set("recommended")

        toggles_frame = ttk.LabelFrame(main, text="Profile")
        toggles_frame.pack(fill="x", pady=(0, 12))

        for profile_key in ("recommended", "cpu-compatible", "gpu-balanced"):
            row = ttk.Frame(toggles_frame)
            row.pack(fill="x", padx=8, pady=4)
            radio = ttk.Radiobutton(
                row,
                text=PROFILE_LABELS[profile_key],
                variable=profile_var,
                value=profile_key,
            )
            radio.pack(side="left")
            help_label = ttk.Label(row, text="[?]")
            help_label.pack(side="left", padx=(6, 0))
            HoverHelp(help_label, PROFILE_HELP[profile_key])

        simple_frame = ttk.LabelFrame(main, text="Simple Settings")
        simple_frame.pack(fill="x", pady=(0, 12))

        visual_var = tk.BooleanVar(value=bool(getattr(cfg, "visual_indicators_enabled", True)))
        tray_var = tk.BooleanVar(value=bool(getattr(cfg, "use_tray", True)))
        show_startup_var = tk.BooleanVar(value=bool(getattr(cfg, "show_setup_on_startup", True)))

        ttk.Checkbutton(simple_frame, text="Enable visual indicators", variable=visual_var).pack(
            anchor="w", padx=8, pady=4
        )
        ttk.Checkbutton(simple_frame, text="Enable tray menu", variable=tray_var).pack(
            anchor="w", padx=8, pady=4
        )
        ttk.Checkbutton(simple_frame, text="Show setup on startup until saved", variable=show_startup_var).pack(
            anchor="w", padx=8, pady=4
        )

        advanced_enabled = tk.BooleanVar(value=False)
        ttk.Checkbutton(main, text="Show advanced settings", variable=advanced_enabled).pack(anchor="w")

        advanced_frame = ttk.LabelFrame(main, text="Advanced")
        advanced_frame.pack(fill="x", pady=(8, 12))

        model_tier_var = tk.StringVar(value=str(getattr(cfg, "model_tier", "quick")))
        device_var = tk.StringVar(value=str(getattr(cfg, "device", "auto")))
        compute_var = tk.StringVar(value=str(getattr(cfg, "compute_type", "int8")))
        inject_mode_var = tk.StringVar(
            value="paste" if bool(getattr(cfg, "paste_injection", True)) else "type"
        )

        def _labeled_combo(
            parent: Any,
            label: str,
            value_var: Any,
            choices: tuple[str, ...],
            help_text: str,
        ):
            row = ttk.Frame(parent)
            row.pack(fill="x", padx=8, pady=4)
            ttk.Label(row, text=label, width=24).pack(side="left")
            combo = ttk.Combobox(
                row,
                textvariable=value_var,
                values=list(choices),
                state="readonly",
                width=22,
            )
            combo.pack(side="left")
            info = ttk.Label(row, text="[?]")
            info.pack(side="left", padx=(6, 0))
            HoverHelp(info, help_text)

        _labeled_combo(
            advanced_frame,
            "Model tier",
            model_tier_var,
            ("tiny", "quick", "balanced", "quality", "voxtral"),
            "Controls speed vs quality. quick is safest default.",
        )
        _labeled_combo(
            advanced_frame,
            "Device",
            device_var,
            ("auto", "cpu", "cuda"),
            "auto chooses cuda if available, else cpu.",
        )
        _labeled_combo(
            advanced_frame,
            "Compute type",
            compute_var,
            ("int8", "float16", "float32"),
            "int8 is CPU-friendly. float16 is typical for CUDA.",
        )
        _labeled_combo(
            advanced_frame,
            "Injection mode",
            inject_mode_var,
            ("paste", "type"),
            "paste is usually more reliable for long transcripts.",
        )

        summary_var = tk.StringVar(value="")
        summary = ttk.Label(main, textvariable=summary_var, wraplength=700, foreground="#1F2937")
        summary.pack(fill="x", pady=(6, 12))

        def _refresh_summary(*_args: Any):
            defaults = profile_defaults(profile_var.get(), caps)
            summary_var.set(
                "Profile preview: "
                f"device={defaults.get('device')} compute={defaults.get('compute_type')} "
                f"model_tier={defaults.get('model_tier')} "
                f"gpu={'on' if defaults.get('enable_gpu_acceleration') else 'off'}"
            )

        profile_var.trace_add("write", _refresh_summary)
        _refresh_summary()

        def _toggle_advanced(*_args: Any):
            if advanced_enabled.get():
                advanced_frame.pack(fill="x", pady=(8, 12))
            else:
                advanced_frame.pack_forget()

        advanced_enabled.trace_add("write", _toggle_advanced)
        _toggle_advanced()

        def _normalize_advanced(updates: Dict[str, Any]) -> None:
            tier = str(model_tier_var.get() or "quick").strip().lower()
            if tier not in {"tiny", "quick", "balanced", "quality", "voxtral"}:
                tier = "quick"
            device = str(device_var.get() or "auto").strip().lower()
            if device not in {"auto", "cpu", "cuda"}:
                device = "auto"
            compute = str(compute_var.get() or "int8").strip().lower()
            if compute not in {"int8", "float16", "float32"}:
                compute = "int8"

            updates["model_tier"] = tier
            updates["device"] = device
            updates["compute_type"] = compute
            updates["paste_injection"] = str(inject_mode_var.get()).strip().lower() != "type"

            if device == "cuda":
                updates["enable_gpu_acceleration"] = True
                if compute == "int8":
                    updates["compute_type"] = "float16"
            elif device == "cpu":
                updates["enable_gpu_acceleration"] = False
                if compute in {"float16", "float32"}:
                    updates["compute_type"] = "int8"

        def _save_and_launch():
            selected_profile = str(profile_var.get() or "recommended")
            updates = profile_defaults(selected_profile, caps)
            updates["visual_indicators_enabled"] = bool(visual_var.get())
            updates["use_tray"] = bool(tray_var.get())
            updates["show_setup_on_startup"] = bool(show_startup_var.get())
            updates["setup_completed"] = True
            updates["setup_profile"] = selected_profile

            if advanced_enabled.get():
                _normalize_advanced(updates)

            restart_required = apply_setup_updates(cfg, updates)
            save_config(cfg)
            result["saved"] = True
            result["restart_required"] = restart_required
            root.destroy()

        def _launch_without_changes():
            if source == "startup":
                cfg.show_setup_on_startup = bool(show_startup_var.get())
                save_config(cfg)
            root.destroy()

        footer = ttk.Frame(main)
        footer.pack(fill="x")
        ttk.Button(footer, text="Launch Without Changes", command=_launch_without_changes).pack(
            side="left"
        )
        ttk.Button(footer, text="Save And Launch", command=_save_and_launch).pack(
            side="right"
        )

        root.protocol("WM_DELETE_WINDOW", _launch_without_changes)
        root.mainloop()

        return bool(result["saved"]), bool(result["restart_required"])
    finally:
        _WIZARD_LOCK.release()
