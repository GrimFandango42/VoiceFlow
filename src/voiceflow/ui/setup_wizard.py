from __future__ import annotations

import os
import platform
import re
import threading
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from voiceflow.core.config import Config
from voiceflow.utils.settings import save_config
from voiceflow.utils.utils import nvidia_smi_info

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
    "recommended": "Uses hardware results to pick defaults.",
    "cpu-compatible": "Safe CPU defaults.",
    "gpu-balanced": "CUDA-focused speed and quality.",
}

PROFILE_SUBTITLE = {
    "recommended": "Best starting point.",
    "cpu-compatible": "Compatibility first.",
    "gpu-balanced": "Performance first.",
}

_WIZARD_LOCK = threading.Lock()


@dataclass(frozen=True)
class SetupCapabilities:
    platform_name: str
    cpu_count: int
    cuda_available: bool
    total_ram_gb: float = 0.0
    gpu_name: str = ""
    gpu_vram_gb: float = 0.0


def describe_setup_step_state(
    *,
    is_startup_flow: bool,
    hardware_checked: bool,
    hardware_running: bool,
    profile_selected: bool,
    last_hardware_check: str = "",
) -> Dict[str, str | bool]:
    """Return startup/manual step messaging and gating hints for the setup UI."""
    if not is_startup_flow:
        if hardware_running:
            return {
                "step_state": "Running hardware check...",
                "check_status": "Running hardware check...",
                "focus_state": "Hardware check in progress...",
                "step2_hint": "Profile selection is available.",
                "step2_locked": False,
            }
        if hardware_checked and last_hardware_check:
            return {
                "step_state": "Ready to save.",
                "check_status": f"Hardware check updated at {last_hardware_check}.",
                "focus_state": "Optional: re-run hardware check after driver/hardware changes.",
                "step2_hint": "Profile selection is available.",
                "step2_locked": False,
            }
        return {
            "step_state": "Optional: run hardware check.",
            "check_status": "Run check after hardware or driver changes.",
            "focus_state": "Profile selection is available.",
            "step2_hint": "Profile selection is available.",
            "step2_locked": False,
        }

    if hardware_running:
        return {
            "step_state": "Step 1 of 2: Running hardware check...",
            "check_status": "Running hardware check...",
            "focus_state": "Step 1 in progress. Step 2 unlocks automatically when complete.",
            "step2_hint": "Step 2 is locked until hardware check finishes.",
            "step2_locked": True,
        }
    if not hardware_checked:
        return {
            "step_state": "Step 1 of 2 (Required): Run hardware check.",
            "check_status": "Run hardware check to unlock Step 2.",
            "focus_state": "Only required action right now: Run Hardware Check.",
            "step2_hint": "Step 2 is intentionally locked until Step 1 completes.",
            "step2_locked": True,
        }
    if not profile_selected:
        when = last_hardware_check or "just now"
        return {
            "step_state": "Step 2 of 2: Choose profile and save.",
            "check_status": f"Check complete ({when}). Pick profile and save.",
            "focus_state": "Step 1 complete. Step 2 is now unlocked.",
            "step2_hint": "Step 2 is unlocked. Choose a profile to continue.",
            "step2_locked": False,
        }
    return {
        "step_state": "Ready: Save and launch VoiceFlow.",
        "check_status": "Save and launch.",
        "focus_state": "All required startup steps are complete.",
        "step2_hint": "Step 2 complete.",
        "step2_locked": False,
    }


def _safe_total_ram_gb() -> float:
    try:
        import psutil  # type: ignore

        return round(float(psutil.virtual_memory().total) / (1024.0**3), 1)
    except Exception:
        return 0.0


def _parse_gpu_snapshot(snapshot: str | None) -> Tuple[str, float]:
    if not snapshot:
        return "", 0.0

    first_line = str(snapshot).splitlines()[0].strip()
    if not first_line:
        return "", 0.0

    parts = [part.strip() for part in first_line.split(",")]
    gpu_name = parts[0] if parts else ""
    vram_gb = 0.0
    if len(parts) >= 2:
        match = re.search(r"([0-9]+(?:\.[0-9]+)?)", parts[1])
        if match:
            mib = float(match.group(1))
            vram_gb = round(mib / 1024.0, 1)
    return gpu_name, vram_gb


def detect_setup_capabilities() -> SetupCapabilities:
    cuda_available = False
    try:
        from voiceflow.core.asr_engine import _cuda_runtime_ready

        cuda_available = bool(_cuda_runtime_ready())
    except Exception:
        cuda_available = False

    gpu_snapshot = None
    try:
        gpu_snapshot = nvidia_smi_info()
    except Exception:
        gpu_snapshot = None
    gpu_name, gpu_vram_gb = _parse_gpu_snapshot(gpu_snapshot)

    return SetupCapabilities(
        platform_name=str(platform.system() or "unknown").lower(),
        cpu_count=max(1, int(os.cpu_count() or 1)),
        cuda_available=cuda_available,
        total_ram_gb=_safe_total_ram_gb(),
        gpu_name=gpu_name,
        gpu_vram_gb=gpu_vram_gb,
    )


def recommended_profile_key(capabilities: SetupCapabilities) -> str:
    return "gpu-balanced" if capabilities.cuda_available else "cpu-compatible"


def baseline_setup_capabilities() -> SetupCapabilities:
    """Lightweight baseline shown before an explicit hardware check is run."""
    return SetupCapabilities(
        platform_name=str(platform.system() or "unknown").lower(),
        cpu_count=max(1, int(os.cpu_count() or 1)),
        cuda_available=False,
        total_ram_gb=_safe_total_ram_gb(),
        gpu_name="",
        gpu_vram_gb=0.0,
    )


def assess_setup_capabilities(capabilities: SetupCapabilities) -> Dict[str, Any]:
    score = 0
    reasons: list[str] = []

    if capabilities.cuda_available:
        score += 45
        if capabilities.gpu_name:
            if capabilities.gpu_vram_gb > 0:
                reasons.append(
                    f"CUDA runtime ready ({capabilities.gpu_name}, {capabilities.gpu_vram_gb:.1f} GB VRAM)"
                )
            else:
                reasons.append(f"CUDA runtime ready ({capabilities.gpu_name})")
        else:
            reasons.append("CUDA runtime ready")
    else:
        reasons.append("CUDA runtime not detected; CPU-compatible defaults are recommended")

    cpu = int(capabilities.cpu_count)
    if cpu >= 16:
        score += 25
        reasons.append(f"Strong CPU capacity ({cpu} cores)")
    elif cpu >= 12:
        score += 20
        reasons.append(f"Good CPU capacity ({cpu} cores)")
    elif cpu >= 8:
        score += 15
        reasons.append(f"Solid CPU capacity ({cpu} cores)")
    elif cpu >= 6:
        score += 10
        reasons.append(f"Moderate CPU capacity ({cpu} cores)")
    else:
        score += 6
        reasons.append(f"Limited CPU capacity ({cpu} cores)")

    ram = float(capabilities.total_ram_gb or 0.0)
    if ram >= 32.0:
        score += 20
        reasons.append(f"High RAM headroom ({ram:.1f} GB)")
    elif ram >= 16.0:
        score += 15
        reasons.append(f"Good RAM headroom ({ram:.1f} GB)")
    elif ram >= 12.0:
        score += 10
        reasons.append(f"Adequate RAM headroom ({ram:.1f} GB)")
    elif ram >= 8.0:
        score += 6
        reasons.append(f"Minimal RAM headroom ({ram:.1f} GB)")
    elif ram > 0:
        score += 3
        reasons.append(f"Low RAM headroom ({ram:.1f} GB)")

    score = max(0, min(100, score))
    if score >= 85:
        grade = "Excellent"
        use_case = "Great for fast long-form dictation and high-quality defaults."
    elif score >= 70:
        grade = "Strong"
        use_case = "Great for daily dictation, including medium/long transcripts."
    elif score >= 55:
        grade = "Good"
        use_case = "Good for short/medium dictation with stable latency."
    elif score >= 40:
        grade = "Fair"
        use_case = "Usable with CPU-compatible defaults and moderate clip lengths."
    else:
        grade = "Limited"
        use_case = "Best with CPU-compatible defaults and shorter dictation clips."

    recommended_key = recommended_profile_key(capabilities)
    defaults = profile_defaults(recommended_key, capabilities)
    return {
        "score": score,
        "grade": grade,
        "use_case": use_case,
        "reasons": reasons,
        "recommended_profile": recommended_key,
        "recommended_device": defaults.get("device", "cpu"),
        "recommended_compute": defaults.get("compute_type", "int8"),
        "recommended_tier": defaults.get("model_tier", "quick"),
    }


def _pick_theme(style: Any) -> None:
    try:
        available = set(style.theme_names())
        for candidate in ("vista", "xpnative", "winnative", "default", "clam"):
            if candidate in available:
                style.theme_use(candidate)
                return
    except Exception:
        pass


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
            print("[SETUP] Setup wizard unavailable: tkinter runtime is missing.")
            return False, False

        is_startup_flow = source == "startup"
        initial_caps = baseline_setup_capabilities() if is_startup_flow else detect_setup_capabilities()
        caps_state: Dict[str, SetupCapabilities] = {"value": initial_caps}
        assessment_state: Dict[str, Dict[str, Any]] = {"value": assess_setup_capabilities(caps_state["value"])}
        result = {"saved": False, "restart_required": False}
        hardware_checked_state = {"value": not is_startup_flow}
        hardware_check_running_state = {"value": False}
        last_hardware_check_state = {"value": ""}

        def _current_caps() -> SetupCapabilities:
            return caps_state["value"]

        def _current_assessment() -> Dict[str, Any]:
            return assessment_state["value"]

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

        def _center_window(width: int, height: int) -> str:
            screen_w = max(1, int(root.winfo_screenwidth() or width))
            screen_h = max(1, int(root.winfo_screenheight() or height))
            pos_x = max(0, int((screen_w - width) / 2))
            pos_y = max(0, int((screen_h - height) / 3))
            return f"{width}x{height}+{pos_x}+{pos_y}"

        root.title("VoiceFlow Setup")
        root.geometry(_center_window(900, 730))
        root.minsize(780, 620)
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)
        root.grid_rowconfigure(2, weight=0)
        root.grid_rowconfigure(2, minsize=108)

        style = ttk.Style(root)
        _pick_theme(style)
        try:
            style.configure("SetupPrimary.TButton", font=("Segoe UI", 10, "bold"), padding=(14, 9))
            style.configure("SetupSecondary.TButton", font=("Segoe UI", 10), padding=(12, 8))
            style.configure("SetupGhost.TButton", font=("Segoe UI", 10), padding=(10, 7))
            style.configure("SetupCard.TLabelframe", padding=(4, 4, 4, 4))
            style.configure("SetupCard.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        except Exception:
            pass

        body = ttk.Frame(root, padding=(16, 14, 12, 8))
        body.grid(row=0, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)

        canvas = tk.Canvas(body, highlightthickness=0, borderwidth=0, bg="#F7FAFC")
        canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(body, orient="vertical", command=canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns", padx=(10, 0))
        canvas.configure(yscrollcommand=scroll.set)

        main = ttk.Frame(canvas)
        canvas_window = canvas.create_window((0, 0), window=main, anchor="nw")

        def _sync_canvas(_event: Any = None) -> None:
            try:
                canvas.configure(scrollregion=canvas.bbox("all"))
                canvas.itemconfigure(canvas_window, width=canvas.winfo_width())
            except Exception:
                pass

        def _on_mousewheel(event: Any) -> None:
            try:
                delta = int(-1 * (int(event.delta) / 120))
            except Exception:
                delta = 0
            if delta == 0:
                delta = -1 if int(getattr(event, "delta", 0)) > 0 else 1
            try:
                canvas.yview_scroll(delta, "units")
            except Exception:
                pass

        main.bind("<Configure>", _sync_canvas)
        canvas.bind("<Configure>", _sync_canvas)
        root.bind_all("<MouseWheel>", _on_mousewheel)

        footer_sep = ttk.Separator(root, orient="horizontal")
        footer_sep.grid(row=1, column=0, sticky="ew")
        footer = tk.Frame(root, bg="#EEF3F8", padx=16, pady=10, highlightthickness=1, highlightbackground="#C7D2E0")
        footer.grid(row=2, column=0, sticky="ew")
        footer.tkraise()
        footer.grid_columnconfigure(0, weight=1)
        footer_hint_var = tk.StringVar(value="")
        footer_hint_label = tk.Label(
            footer,
            textvariable=footer_hint_var,
            bg="#EEF3F8",
            fg="#334155",
            font=("Segoe UI", 9, "bold"),
            anchor="w",
            justify="left",
            padx=2,
            pady=2,
        )
        footer_hint_label.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        footer_actions = tk.Frame(footer, bg="#EEF3F8")
        footer_actions.grid(row=1, column=0, sticky="ew")
        footer_actions.grid_columnconfigure(0, weight=1)

        title_text = "VoiceFlow First-Run Setup" if source == "startup" else "VoiceFlow Setup & Defaults"
        subtitle_text = (
            "Pick defaults now. You can reopen this from the tray later."
            if source == "startup"
            else "Run diagnostics and tune defaults for this machine."
        )
        header_card = tk.Frame(main, bg="#E6F4FF", highlightthickness=1, highlightbackground="#B9D9FF", bd=0)
        header_card.pack(fill="x", pady=(0, 10))
        tk.Label(
            header_card,
            text=title_text,
            bg="#E6F4FF",
            fg="#0C4A6E",
            font=("Segoe UI", 16, "bold"),
            anchor="w",
            padx=12,
            pady=8,
        ).pack(fill="x")
        tk.Label(
            header_card,
            text=subtitle_text,
            bg="#E6F4FF",
            fg="#1E3A5F",
            font=("Segoe UI", 10),
            anchor="w",
            justify="left",
            padx=12,
            pady=9,
        ).pack(fill="x")

        stepper = tk.Frame(main, bg="#F7FAFC")
        stepper.pack(fill="x", pady=(0, 10))
        step1_chip = tk.Label(
            stepper,
            text="Step 1: Hardware Check",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
            bd=0,
        )
        step1_chip.pack(side="left")
        tk.Label(stepper, text="  ->  ", bg="#F7FAFC", fg="#64748B", font=("Segoe UI", 9, "bold")).pack(side="left")
        step2_chip = tk.Label(
            stepper,
            text="Step 2: Startup Profile" if is_startup_flow else "Profile",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
            bd=0,
        )
        step2_chip.pack(side="left")

        step_state_var = tk.StringVar(value="")
        ttk.Label(main, textvariable=step_state_var, font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(0, 8)
        )
        focus_state_var = tk.StringVar(value="")
        focus_state_label = tk.Label(
            main,
            textvariable=focus_state_var,
            bg="#E8F3FF",
            fg="#0B4A6F",
            font=("Segoe UI", 10, "bold"),
            padx=10,
            pady=8,
            justify="left",
            anchor="w",
        )
        focus_state_label.pack(fill="x", pady=(0, 10))

        status_frame = ttk.LabelFrame(main, text="Step 1 - Hardware Check", style="SetupCard.TLabelframe")
        status_frame.pack(fill="x", pady=(0, 12))
        detected_var = tk.StringVar(value="")
        grade_var = tk.StringVar(value="")
        recommendation_var = tk.StringVar(value="")
        use_case_var = tk.StringVar(value="")
        check_status_var = tk.StringVar(value="")
        status_top = ttk.Frame(status_frame)
        status_top.pack(fill="x", padx=10, pady=(8, 4))
        ttk.Label(status_top, textvariable=detected_var, wraplength=620).pack(side="left", fill="x", expand=True)
        hardware_button: Any = None
        hardware_progress = ttk.Progressbar(status_top, mode="indeterminate", length=170)
        hardware_progress.pack(side="right", padx=(8, 0))
        hardware_progress.pack_forget()
        status_body = ttk.Frame(status_frame)
        status_body.pack(fill="x", padx=10, pady=(0, 8))
        ttk.Label(status_body, textvariable=grade_var, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(status_body, textvariable=recommendation_var, wraplength=800).pack(anchor="w", pady=(2, 0))
        ttk.Label(status_body, textvariable=use_case_var, wraplength=800, foreground="#4B5563").pack(
            anchor="w", pady=(2, 0)
        )
        ttk.Label(status_body, textvariable=check_status_var, foreground="#92400E").pack(anchor="w", pady=(2, 0))

        initial_profile = ""
        if not is_startup_flow:
            initial_profile = str(getattr(cfg, "setup_profile", "recommended") or "recommended")
            if initial_profile not in {"recommended", "cpu-compatible", "gpu-balanced"}:
                initial_profile = "recommended"
        profile_var = tk.StringVar(value=initial_profile)
        profile_selected_state = {"value": bool(initial_profile)}

        toggles_frame = ttk.LabelFrame(
            main,
            text="Step 2 - Choose Startup Profile" if is_startup_flow else "Profile",
            style="SetupCard.TLabelframe",
        )
        toggles_frame.pack(fill="x", pady=(0, 12))
        profile_buttons: Dict[str, Any] = {}
        profile_check_labels: Dict[str, Any] = {}
        profile_hint_var = tk.StringVar(value="")
        ttk.Label(toggles_frame, textvariable=profile_hint_var, foreground="#4B5563").pack(
            anchor="w", padx=8, pady=(4, 2)
        )
        step2_hint_var = tk.StringVar(value="")
        ttk.Label(toggles_frame, textvariable=step2_hint_var, foreground="#92400E").pack(
            anchor="w", padx=8, pady=(0, 4)
        )
        for profile_key in ("recommended", "cpu-compatible", "gpu-balanced"):
            row = ttk.Frame(toggles_frame)
            row.pack(fill="x", padx=8, pady=6)
            button = tk.Button(
                row,
                text=PROFILE_LABELS[profile_key],
                command=lambda key=profile_key: profile_var.set(key),
                width=18,
                relief="ridge",
                bd=1,
                padx=12,
                pady=7,
                anchor="w",
                cursor="hand2",
                font=("Segoe UI", 10, "bold"),
            )
            button.pack(side="left")
            profile_buttons[profile_key] = button
            detail = ttk.Frame(row)
            detail.pack(side="left", fill="x", expand=True, padx=(10, 0))
            detail_header = ttk.Frame(detail)
            detail_header.pack(fill="x")
            ttk.Label(detail_header, text=PROFILE_SUBTITLE[profile_key]).pack(side="left", anchor="w")
            check_label = tk.Label(
                detail_header,
                text="",
                fg="#15803D",
                font=("Segoe UI", 9, "bold"),
                padx=2,
            )
            try:
                check_label.configure(bg=str(detail_header.cget("background")))
            except Exception:
                pass
            check_label.pack(side="right")
            profile_check_labels[profile_key] = check_label
            ttk.Label(detail, text=PROFILE_HELP[profile_key], foreground="#6B7280").pack(anchor="w")

        simple_frame = ttk.LabelFrame(main, text="Simple Settings", style="SetupCard.TLabelframe")
        simple_frame.pack(fill="x", pady=(0, 12))

        visual_default = True if is_startup_flow else bool(getattr(cfg, "visual_indicators_enabled", True))
        tray_default = True if is_startup_flow else bool(getattr(cfg, "use_tray", True))
        visual_var = tk.BooleanVar(value=visual_default)
        tray_var = tk.BooleanVar(value=tray_default)
        show_startup_var = tk.BooleanVar(value=bool(getattr(cfg, "show_setup_on_startup", True)))

        visual_check = ttk.Checkbutton(simple_frame, text="Enable visual indicators", variable=visual_var)
        visual_check.pack(anchor="w", padx=8, pady=4)
        tray_check = ttk.Checkbutton(simple_frame, text="Enable tray menu", variable=tray_var)
        tray_check.pack(anchor="w", padx=8, pady=4)
        startup_check = ttk.Checkbutton(
            simple_frame,
            text="Show setup on startup until saved",
            variable=show_startup_var,
        )
        startup_check.pack(anchor="w", padx=8, pady=4)

        advanced_enabled = tk.BooleanVar(value=False)
        advanced_toggle = ttk.Checkbutton(main, text="Show advanced settings", variable=advanced_enabled)
        advanced_toggle.pack(anchor="w")

        advanced_frame = ttk.LabelFrame(main, text="Advanced", style="SetupCard.TLabelframe")
        advanced_frame.pack(fill="x", pady=(8, 12))

        model_tier_initial = "" if is_startup_flow else str(getattr(cfg, "model_tier", "quick"))
        device_initial = "" if is_startup_flow else str(getattr(cfg, "device", "auto"))
        compute_initial = "" if is_startup_flow else str(getattr(cfg, "compute_type", "int8"))
        inject_initial = "paste" if (is_startup_flow or bool(getattr(cfg, "paste_injection", True))) else "type"

        model_tier_var = tk.StringVar(value=model_tier_initial)
        device_var = tk.StringVar(value=device_initial)
        compute_var = tk.StringVar(value=compute_initial)
        inject_mode_var = tk.StringVar(value=inject_initial)

        def _labeled_combo(
            parent: Any,
            label: str,
            value_var: Any,
            choices: tuple[str, ...],
            help_text: str,
        ) -> Any:
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
            return combo

        advanced_combos: list[Any] = []
        advanced_combos.append(_labeled_combo(
            advanced_frame,
            "Model tier",
            model_tier_var,
            ("tiny", "quick", "balanced", "quality", "voxtral"),
            "Controls speed vs quality. quick is safest default.",
        ))
        advanced_combos.append(_labeled_combo(
            advanced_frame,
            "Device",
            device_var,
            ("auto", "cpu", "cuda"),
            "auto chooses cuda if available, else cpu.",
        ))
        advanced_combos.append(_labeled_combo(
            advanced_frame,
            "Compute type",
            compute_var,
            ("int8", "float16", "float32"),
            "int8 is CPU-friendly. float16 is typical for CUDA.",
        ))
        advanced_combos.append(_labeled_combo(
            advanced_frame,
            "Injection mode",
            inject_mode_var,
            ("paste", "type"),
            "paste is usually more reliable for long transcripts.",
        ))

        summary_var = tk.StringVar(value="")
        summary_frame = ttk.LabelFrame(main, text="Summary", style="SetupCard.TLabelframe")
        summary_frame.pack(fill="x", pady=(6, 12))
        summary = ttk.Label(
            summary_frame,
            textvariable=summary_var,
            wraplength=780,
            foreground="#1F2937",
            justify="left",
            anchor="w",
        )
        summary.pack(fill="x", padx=8, pady=(6, 8))
        save_button: Any = None

        def _format_detected_text(caps: SetupCapabilities) -> str:
            ram_text = f"{caps.total_ram_gb:.1f} GB RAM" if caps.total_ram_gb > 0 else "RAM unknown"
            gpu_text = ""
            if caps.gpu_name:
                if caps.gpu_vram_gb > 0:
                    gpu_text = f" | {caps.gpu_name} ({caps.gpu_vram_gb:.1f} GB)"
                else:
                    gpu_text = f" | {caps.gpu_name}"
            return (
                f"Detected: {caps.platform_name.title()} | {caps.cpu_count} cores | "
                f"{ram_text} | CUDA={'yes' if caps.cuda_available else 'no'}{gpu_text}"
            )

        def _clear_profile_choice_controls() -> None:
            model_tier_var.set("")
            device_var.set("")
            compute_var.set("")
            inject_mode_var.set("paste")

        def _apply_profile_defaults_to_controls(profile_key: str, caps: SetupCapabilities) -> None:
            selected = str(profile_key or "").strip().lower()
            if selected not in {"recommended", "cpu-compatible", "gpu-balanced"}:
                _clear_profile_choice_controls()
                return
            defaults = profile_defaults(selected, caps)
            model_tier_var.set(str(defaults.get("model_tier", "quick")))
            device_var.set(str(defaults.get("device", "cpu")))
            compute_var.set(str(defaults.get("compute_type", "int8")))
            inject_mode_var.set("paste" if bool(defaults.get("paste_injection", True)) else "type")
            visual_var.set(bool(defaults.get("visual_indicators_enabled", True)))
            tray_var.set(bool(defaults.get("use_tray", True)))

        def _set_profile_button_style(profile_key: str, enabled: bool, selected: bool) -> None:
            button = profile_buttons.get(profile_key)
            if button is None:
                return
            check_label = profile_check_labels.get(profile_key)
            if check_label is not None:
                if enabled and selected:
                    check_label.configure(text="✓ Selected", fg="#15803D")
                else:
                    check_label.configure(text="")
            if not enabled:
                button.configure(
                    state="disabled",
                    bg="#ECEFF3",
                    fg="#97A0AD",
                    activebackground="#ECEFF3",
                    activeforeground="#97A0AD",
                    relief="groove",
                )
                return
            if selected:
                button.configure(
                    state="normal",
                    bg="#0A7AAA",
                    fg="#FFFFFF",
                    activebackground="#09638A",
                    activeforeground="#FFFFFF",
                    relief="solid",
                )
                return
            button.configure(
                state="normal",
                bg="#EEF2F6",
                fg="#233042",
                activebackground="#E3E8EE",
                activeforeground="#233042",
                relief="ridge",
            )

        def _sync_profile_availability() -> None:
            selected = str(profile_var.get() or "").strip().lower()
            selection_allowed = (not is_startup_flow) or bool(hardware_checked_state["value"])

            if selected == "gpu-balanced" and not _current_caps().cuda_available:
                profile_var.set("")
                selected = ""

            for profile_key in ("recommended", "cpu-compatible", "gpu-balanced"):
                enabled = selection_allowed
                if profile_key == "gpu-balanced" and not _current_caps().cuda_available:
                    enabled = False
                _set_profile_button_style(profile_key, enabled=enabled, selected=selected == profile_key)

            if not selection_allowed:
                profile_hint_var.set("Step 2 locked until hardware check completes.")
                step2_hint_var.set("Complete Step 1 to unlock profile selection.")
            elif not selected:
                profile_hint_var.set("Pick a profile.")
                step2_hint_var.set("Step 2 unlocked. Choose one startup profile.")
            else:
                profile_hint_var.set("Profile selected.")
                step2_hint_var.set("Profile selected. Save to continue.")

        def _update_control_lock_state() -> None:
            locked = is_startup_flow and (
                not bool(hardware_checked_state["value"]) or not bool(profile_selected_state["value"])
            )
            simple_state = "disabled" if locked else "normal"
            try:
                if is_startup_flow and not bool(hardware_checked_state["value"]):
                    simple_frame.configure(text="Simple Settings (locked until Step 1 completes)")
                    advanced_frame.configure(text="Advanced (locked until Step 1 completes)")
                else:
                    simple_frame.configure(text="Simple Settings")
                    advanced_frame.configure(text="Advanced")
            except Exception:
                pass
            for control in (visual_check, tray_check):
                try:
                    control.configure(state=simple_state)
                except Exception:
                    pass
            try:
                advanced_toggle.configure(state=simple_state)
            except Exception:
                pass
            combo_state = "disabled" if locked else "readonly"
            for combo in advanced_combos:
                try:
                    combo.configure(state=combo_state)
                except Exception:
                    pass

        def _update_save_state() -> None:
            if save_button is None:
                return

            def _set_footer_hint(text: str, *, ready: bool = False, blocked: bool = False) -> None:
                footer_hint_var.set(text)
                if ready:
                    footer_hint_label.configure(bg="#EAFBF2", fg="#0F5132")
                elif blocked:
                    footer_hint_label.configure(bg="#FFF6E6", fg="#8A4B00")
                else:
                    footer_hint_label.configure(bg="#EEF3F8", fg="#334155")

            def _set_save_button_visual(enabled: bool) -> None:
                if enabled:
                    save_button.configure(
                        state="normal",
                        bg="#0A7AAA",
                        fg="#FFFFFF",
                        activebackground="#09638A",
                        activeforeground="#FFFFFF",
                        disabledforeground="#D1D5DB",
                    )
                else:
                    save_button.configure(
                        state="disabled",
                        bg="#CBD5E1",
                        fg="#4B5563",
                        activebackground="#CBD5E1",
                        activeforeground="#4B5563",
                        disabledforeground="#4B5563",
                    )

            if not is_startup_flow:
                _set_save_button_visual(True)
                _set_footer_hint("Ready. Save applies your selections immediately.", ready=True)
                return

            allow_save = (
                bool(hardware_checked_state["value"])
                and bool(profile_selected_state["value"])
                and not bool(hardware_check_running_state["value"])
            )
            _set_save_button_visual(allow_save)
            if allow_save:
                _set_footer_hint("All required steps complete. Click Save And Launch.", ready=True)
            elif bool(hardware_check_running_state["value"]):
                _set_footer_hint("Running hardware check... Save will enable when complete.", blocked=True)
            elif not bool(hardware_checked_state["value"]):
                _set_footer_hint("Save is disabled until Step 1 hardware check completes.", blocked=True)
            else:
                _set_footer_hint("Choose a startup profile in Step 2 to enable Save.", blocked=True)

        def _set_hardware_button_emphasis() -> None:
            if hardware_button is None:
                return
            if hardware_check_running_state["value"]:
                hardware_button.configure(
                    text="Running Hardware Check...",
                    state="disabled",
                    bg="#94A3B8",
                    fg="#FFFFFF",
                    activebackground="#94A3B8",
                    activeforeground="#FFFFFF",
                )
                return
            if is_startup_flow and not hardware_checked_state["value"]:
                hardware_button.configure(
                    text="Step 1: Run Hardware Check (Required)",
                    state="normal",
                    bg="#0A7AAA",
                    fg="#FFFFFF",
                    activebackground="#09638A",
                    activeforeground="#FFFFFF",
                )
                return
            hardware_button.configure(
                text="Re-run Hardware Check",
                state="normal",
                bg="#334155",
                fg="#FFFFFF",
                activebackground="#1E293B",
                activeforeground="#FFFFFF",
            )

        def _set_step_chip_style(chip: Any, state: str) -> None:
            palette = {
                "active": ("#0A7AAA", "#FFFFFF"),
                "done": ("#15803D", "#FFFFFF"),
                "blocked": ("#DCE4EE", "#475569"),
                "idle": ("#E8EDF3", "#334155"),
            }
            bg, fg = palette.get(state, palette["idle"])
            try:
                chip.configure(bg=bg, fg=fg)
            except Exception:
                pass

        def _refresh_step_chips() -> None:
            checked = bool(hardware_checked_state["value"])
            running = bool(hardware_check_running_state["value"])
            profile_selected = bool(profile_selected_state["value"])

            if is_startup_flow:
                if running or not checked:
                    _set_step_chip_style(step1_chip, "active")
                    _set_step_chip_style(step2_chip, "blocked")
                elif not profile_selected:
                    _set_step_chip_style(step1_chip, "done")
                    _set_step_chip_style(step2_chip, "active")
                else:
                    _set_step_chip_style(step1_chip, "done")
                    _set_step_chip_style(step2_chip, "done")
                return

            if running:
                _set_step_chip_style(step1_chip, "active")
            elif checked:
                _set_step_chip_style(step1_chip, "done")
            else:
                _set_step_chip_style(step1_chip, "idle")
            _set_step_chip_style(step2_chip, "done" if profile_selected else "idle")

        def _refresh_check_status() -> None:
            state = describe_setup_step_state(
                is_startup_flow=is_startup_flow,
                hardware_checked=bool(hardware_checked_state["value"]),
                hardware_running=bool(hardware_check_running_state["value"]),
                profile_selected=bool(profile_selected_state["value"]),
                last_hardware_check=str(last_hardware_check_state["value"] or ""),
            )
            step_state_var.set(str(state["step_state"]))
            check_status_var.set(str(state["check_status"]))
            focus_state_var.set(str(state["focus_state"]))
            step2_hint_var.set(str(state["step2_hint"]))

            if is_startup_flow and bool(state["step2_locked"]):
                focus_state_label.configure(bg="#E6F2FF", fg="#0B4A6F")
            else:
                focus_state_label.configure(bg="#EAFBF2", fg="#0F5132")

            _set_hardware_button_emphasis()
            _refresh_step_chips()
            if is_startup_flow and not hardware_checked_state["value"] and not hardware_check_running_state["value"]:
                try:
                    hardware_button.focus_set()
                except Exception:
                    pass

        def _refresh_summary(*_args: Any) -> None:
            if is_startup_flow and not bool(hardware_checked_state["value"]):
                summary_var.set("Step 2 is locked. Run Step 1 hardware check first.")
                return
            caps = _current_caps()
            selected_profile = str(profile_var.get() or "").strip().lower()
            if selected_profile not in {"recommended", "cpu-compatible", "gpu-balanced"}:
                summary_var.set("No profile selected.")
                return
            resolved_profile = selected_profile
            if selected_profile == "recommended":
                resolved_profile = recommended_profile_key(caps)
            defaults = profile_defaults(selected_profile, caps)
            summary_var.set(
                "Selection: "
                f"{PROFILE_LABELS.get(selected_profile, selected_profile)} -> "
                f"{PROFILE_LABELS.get(resolved_profile, resolved_profile)} "
                f"(tier={defaults.get('model_tier')}, device={defaults.get('device')}, "
                f"compute={defaults.get('compute_type')})"
            )

        def _on_profile_selected(*_args: Any) -> None:
            selected_profile = str(profile_var.get() or "").strip().lower()
            if selected_profile not in {"recommended", "cpu-compatible", "gpu-balanced"}:
                profile_selected_state["value"] = False
                _clear_profile_choice_controls()
            else:
                profile_selected_state["value"] = True
                _apply_profile_defaults_to_controls(selected_profile, _current_caps())
            _sync_profile_availability()
            _refresh_summary()
            _refresh_check_status()
            _update_control_lock_state()
            _update_save_state()

        def _refresh_hardware_recommendation() -> None:
            caps = _current_caps()
            assessment = _current_assessment()
            detected_var.set(_format_detected_text(caps))
            grade_var.set(f"System assessment: {assessment['grade']} ({assessment['score']}/100)")
            recommendation_var.set(
                "Recommended: "
                f"{PROFILE_LABELS.get(assessment['recommended_profile'], assessment['recommended_profile'])} "
                f"(tier={assessment['recommended_tier']}, "
                f"{assessment['recommended_device']}, {assessment['recommended_compute']})"
            )
            reason_bits: list[str] = []
            if caps.cuda_available:
                reason_bits.append("CUDA")
            reason_bits.append(f"{caps.cpu_count} cores")
            if caps.total_ram_gb > 0:
                reason_bits.append(f"{caps.total_ram_gb:.1f} GB RAM")
            use_case = str(assessment.get("use_case", "")).split(".")[0].strip()
            if use_case:
                use_case_var.set(f"{use_case}. Why: {', '.join(reason_bits)}.")
            else:
                use_case_var.set(f"Why: {', '.join(reason_bits)}.")
            _sync_profile_availability()
            _refresh_summary()
            _refresh_check_status()
            _update_control_lock_state()
            _update_save_state()

        def _run_hardware_check() -> None:
            if hardware_check_running_state["value"]:
                return
            hardware_check_running_state["value"] = True
            if hardware_button is not None:
                hardware_button.configure(state="disabled")
            try:
                if not hardware_progress.winfo_manager():
                    hardware_progress.pack(side="right", padx=(8, 0))
                hardware_progress.start(11)
            except Exception:
                pass
            _refresh_check_status()
            _update_save_state()
            root.update_idletasks()

            def _worker() -> None:
                new_caps: Optional[SetupCapabilities] = None
                new_assessment: Optional[Dict[str, Any]] = None
                error_text = ""
                try:
                    new_caps = detect_setup_capabilities()
                    new_assessment = assess_setup_capabilities(new_caps)
                except Exception as exc:
                    error_text = f"Hardware check failed ({type(exc).__name__}). Keeping previous values."

                def _finish() -> None:
                    hardware_check_running_state["value"] = False
                    if hardware_button is not None:
                        hardware_button.configure(state="normal")
                    try:
                        hardware_progress.stop()
                        hardware_progress.pack_forget()
                    except Exception:
                        pass
                    if error_text:
                        _refresh_check_status()
                        check_status_var.set(error_text)
                        _update_save_state()
                        return
                    if new_caps is not None and new_assessment is not None:
                        caps_state["value"] = new_caps
                        assessment_state["value"] = new_assessment
                        hardware_checked_state["value"] = True
                        last_hardware_check_state["value"] = datetime.now().strftime("%H:%M:%S")
                        if is_startup_flow:
                            profile_var.set("recommended")
                        else:
                            selected = str(profile_var.get() or "recommended").strip().lower()
                            if selected not in {"recommended", "cpu-compatible", "gpu-balanced"}:
                                selected = "recommended"
                                profile_var.set(selected)
                            _apply_profile_defaults_to_controls(selected, new_caps)
                    _refresh_hardware_recommendation()

                try:
                    root.after(0, _finish)
                except Exception:
                    pass

            threading.Thread(target=_worker, daemon=True).start()

        hardware_button = tk.Button(
            status_top,
            text="Run Hardware Check",
            command=_run_hardware_check,
            padx=14,
            pady=8,
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
        )
        hardware_button.pack(side="right")

        profile_var.trace_add("write", _on_profile_selected)
        _refresh_hardware_recommendation()

        def _toggle_advanced(*_args: Any):
            if advanced_enabled.get():
                advanced_frame.pack(fill="x", pady=(8, 12))
            else:
                advanced_frame.pack_forget()
            _update_control_lock_state()

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

        def _validate_setup_save_state(selected_profile: str) -> Tuple[bool, str]:
            if selected_profile not in {"recommended", "cpu-compatible", "gpu-balanced"}:
                return False, "Choose a startup profile before saving."
            if is_startup_flow:
                if bool(hardware_check_running_state["value"]):
                    return False, "Hardware check is still running. Wait until Step 1 completes."
                if not bool(hardware_checked_state["value"]):
                    return False, "Run Step 1 hardware check before saving."
                if not bool(profile_selected_state["value"]):
                    return False, "Select a startup profile in Step 2 before saving."
            if selected_profile == "gpu-balanced" and not bool(_current_caps().cuda_available):
                return False, "GPU Balanced requires CUDA. Run hardware check or choose a different profile."
            return True, ""

        def _save_and_launch():
            selected_profile = str(profile_var.get() or "").strip().lower()
            is_valid_save, validation_message = _validate_setup_save_state(selected_profile)
            if not is_valid_save:
                check_status_var.set(validation_message)
                return
            updates = profile_defaults(selected_profile, _current_caps())
            updates["visual_indicators_enabled"] = bool(visual_var.get())
            updates["use_tray"] = bool(tray_var.get())
            updates["show_setup_on_startup"] = bool(show_startup_var.get())
            updates["setup_completed"] = True
            updates["setup_profile"] = selected_profile
            updates["setup_flow_version"] = int(getattr(cfg, "setup_flow_version", 3) or 3)

            if advanced_enabled.get():
                _normalize_advanced(updates)

            restart_required = apply_setup_updates(cfg, updates)
            save_config(cfg)
            result["saved"] = True
            result["restart_required"] = restart_required
            try:
                root.unbind_all("<MouseWheel>")
            except Exception:
                pass
            root.destroy()

        def _launch_without_changes():
            if is_startup_flow:
                cfg.show_setup_on_startup = bool(show_startup_var.get())
                save_config(cfg)
            try:
                root.unbind_all("<MouseWheel>")
            except Exception:
                pass
            root.destroy()

        if is_startup_flow:
            ttk.Button(
                footer_actions,
                text="Exit VoiceFlow",
                command=_launch_without_changes,
                style="SetupSecondary.TButton",
            ).grid(row=0, column=0, sticky="w")
        else:
            ttk.Button(
                footer_actions,
                text="Launch Without Changes",
                command=_launch_without_changes,
                style="SetupSecondary.TButton",
            ).grid(row=0, column=0, sticky="w")
        save_button = tk.Button(
            footer_actions,
            text="Save And Launch",
            command=_save_and_launch,
            font=("Segoe UI", 10, "bold"),
            padx=16,
            pady=8,
            relief="flat",
            bd=0,
            cursor="hand2",
            width=19,
        )
        save_button.grid(row=0, column=1, sticky="e")
        _refresh_check_status()
        _update_save_state()

        root.protocol("WM_DELETE_WINDOW", _launch_without_changes)
        root.mainloop()

        return bool(result["saved"]), bool(result["restart_required"])
    finally:
        _WIZARD_LOCK.release()
