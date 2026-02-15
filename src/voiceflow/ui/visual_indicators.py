#!/usr/bin/env python3
"""
VoiceFlow Visual Indicators
===========================
Bottom-screen transcription status overlay similar to Wispr Flow
"""

import logging
import tkinter as tk
from tkinter import ttk
import threading
import time
import math
import random
from datetime import datetime
from collections import deque
from typing import Optional, Callable, Dict, Any
from enum import Enum
from .visual_config import get_visual_config, VisualConfigManager
from ..utils.guardrails import safe_visual_update, process_visual_update_queue, with_error_recovery

logger = logging.getLogger(__name__)

class TranscriptionStatus(Enum):
    """Status states for visual indication"""
    IDLE = "idle"
    LISTENING = "listening" 
    PROCESSING = "processing"
    TRANSCRIBING = "transcribing"
    COMPLETE = "complete"
    ERROR = "error"

class BottomScreenIndicator:
    """
    Bottom-screen overlay indicator for transcription status
    Similar to Wispr Flow - small, unobtrusive, informative
    Thread-safe for background hotkey calls
    """

    def __init__(self):
        self.window: Optional[tk.Toplevel] = None
        self.dock_window: Optional[tk.Toplevel] = None
        self.history_window: Optional[tk.Toplevel] = None
        self.root: Optional[tk.Tk] = None
        self.status_var: Optional[tk.StringVar] = None
        self.progress_var: Optional[tk.DoubleVar] = None
        self.dock_var: Optional[tk.StringVar] = None
        self.history_text: Optional[tk.Text] = None
        self.current_status = TranscriptionStatus.IDLE
        self.auto_hide_timer: Optional[threading.Timer] = None
        self.lock = threading.Lock()
        self.gui_thread: Optional[threading.Thread] = None
        self.gui_running = False
        self.gui_ready = False
        self.command_queue = None
        self.ready_event = threading.Event()
        self.animation_job = None
        self.animation_step = 0.0
        self.transparent_key = "#010203"
        self.status_icon_canvas = None
        self.status_icon_bg = None
        self.status_icon_ring = None
        self.status_icon_center = None
        self.status_audio_bars = []
        self.geo_canvas = None
        self.geo_nodes = []
        self.geo_lines = []
        self.geo_params = []
        self.geo_seed = int(time.time() * 1000) & 0xFFFF
        self.wave_canvas = None
        self.wave_line = None
        self.wave_line_glow = None
        self.wave_fill = None
        self.wave_baseline = None
        self.wave_sparks = []
        self.wave_bars = []
        self.wave_scan = None
        self.space_star_ids = []
        self.space_star_meta = []
        self.space_core = None
        self.space_glow = None
        self.space_ring = None
        self.space_arcs = []
        self.wave_phase = 0.0
        self.audio_level = 0.0
        self.audio_level_target = 0.0
        self.audio_level_smoothed = 0.0
        self.audio_features_target = {"low": 0.34, "mid": 0.33, "high": 0.33, "centroid": 0.5}
        self.audio_features_smoothed = {"low": 0.34, "mid": 0.33, "high": 0.33, "centroid": 0.5}
        self._visual_agc = 0.18
        self.recent_transcriptions = deque(maxlen=50)
        self.history_visible = False
        self.history_expanded = False
        self.history_geometry_compact = None
        self.history_geometry_expanded = None
        self.dock_enabled = False
        self.noise_floor = 0.0
        self.wave_energy_history = deque([0.0] * 42, maxlen=42)
        self.icon_size = 0
        self.geo_w = 0
        self.geo_h = 0
        self.wave_w = 460
        self.wave_h = 112
        self.word_stream_canvas = None
        self._bubble_tokens = deque(maxlen=16)
        self._last_stream_word_count = 0

        # Configuration manager
        self.config_manager = get_visual_config()
        self._update_visual_settings()
        self.visual_theme = self._select_daily_visual_theme()

        # Start GUI in separate thread for background compatibility
        self._start_gui_thread()

        # Wait for GUI to be ready
        self._wait_for_gui_ready()

    def _update_visual_settings(self):
        """Update visual settings from configuration"""
        self.width, self.height = self.config_manager.get_overlay_dimensions()
        self.width = max(self.width, 500)
        self.height = max(self.height, 300)
        colors = self.config_manager.get_color_scheme()

        self.bg_color = colors['bg_color']
        self.text_color = colors['text_color']
        self.accent_color = colors['accent_color']
        self.error_color = colors['error_color']

    def _select_daily_visual_theme(self) -> Dict[str, str]:
        """Rotate playful indicator theme by day to keep the experience fresh."""
        themes = [
            {"name": "aqua", "glyph": "~", "accent": "#00B4D8", "orb": "#90E0EF"},
            {"name": "mint", "glyph": "*", "accent": "#2EC4B6", "orb": "#CBF3F0"},
            {"name": "nova", "glyph": "x", "accent": "#8ECAE6", "orb": "#BDE0FE"},
            {"name": "ice", "glyph": "o", "accent": "#7DD3FC", "orb": "#DBEAFE"},
            {"name": "teal", "glyph": "+", "accent": "#14B8A6", "orb": "#A7F3D0"},
        ]
        idx = datetime.now().timetuple().tm_yday % len(themes)
        return themes[idx]
    
    def _start_gui_thread(self):
        """Start GUI thread for thread-safe visual indicators"""
        import queue
        self.command_queue = queue.Queue()
        self.gui_thread = threading.Thread(target=self._gui_thread_worker, daemon=True)
        self.gui_thread.start()

    def _wait_for_gui_ready(self):
        """Wait for GUI thread to be ready"""
        try:
            # Wait up to 5 seconds for GUI to be ready
            if self.ready_event.wait(timeout=5.0):
                print("[VisualIndicator] GUI ready for use")
            else:
                print("[VisualIndicator] Warning: GUI startup timeout")
        except Exception as e:
            print(f"[VisualIndicator] GUI ready wait error: {e}")

    def _gui_thread_worker(self):
        """GUI thread worker - runs Tkinter mainloop"""
        try:
            # Create root window in this thread
            self.root = tk.Tk()
            self.root.withdraw()  # Hide main window
            self.gui_running = True

            # Setup window
            self._setup_window()

            # Mark as ready
            self.gui_ready = True
            self.ready_event.set()

            # Process commands from queue
            self.root.after(50, self._process_command_queue)

            # Run mainloop
            self.root.mainloop()

        except Exception as e:
            print(f"[VisualIndicator] GUI thread error: {e}")
            self.ready_event.set()  # Signal ready even on error
        finally:
            self.gui_running = False
            self.gui_ready = False

    def _process_command_queue(self):
        """Process commands from other threads"""
        try:
            import queue
            while not self.command_queue.empty():
                try:
                    command, args, kwargs = self.command_queue.get_nowait()
                    command(*args, **kwargs)
                except queue.Empty:
                    break
                except Exception as e:
                    print(f"[VisualIndicator] Command error: {e}")
        except Exception as e:
            print(f"[VisualIndicator] Queue processing error: {e}")
        finally:
            # Schedule next check
            if self.gui_running and self.root:
                self.root.after(50, self._process_command_queue)

    def _setup_window(self):
        """Initialize the bottom overlay window"""
        try:
            if not self.root:
                return

            # Create overlay window
            self.window = tk.Toplevel(self.root)
            self.window.title("VoiceFlow Status")

            # Get screen dimensions
            screen_width = self.window.winfo_screenwidth()
            screen_height = self.window.winfo_screenheight()

            # Window properties for overlay behavior
            config = self.config_manager.config
            self.window.wm_attributes("-topmost", config.always_on_top)
            self.window.wm_attributes("-alpha", min(0.84, config.opacity))
            self.window.overrideredirect(True)  # No title bar
            self.window.configure(bg=self.transparent_key)
            try:
                # Windows transparency-key: remove rectangular box feel.
                self.window.wm_attributes("-transparentcolor", self.transparent_key)
            except Exception:
                pass

            # Create UI elements
            self._create_ui()
            self._setup_dock_window(screen_width, screen_height)
            self._setup_history_panel(screen_width, screen_height)
            self._position_overlay(screen_width, screen_height)

            # Start hidden
            self.window.withdraw()

        except (tk.TclError, AttributeError, ValueError) as e:
            print(f"[VisualIndicator] Failed to setup window: {e}")
            self.window = None
        except Exception as e:
            print(f"[VisualIndicator] Unexpected error during window setup: {type(e).__name__}: {e}")
            self.window = None

    def _position_overlay(self, screen_width: int, screen_height: int):
        """Position overlay safely above tray/dock region."""
        if not self.window:
            return
        x, y = self.config_manager.get_position_coordinates(screen_width, screen_height)
        reserved_bottom = 138 if self.dock_enabled else 86
        y = min(y - 8, screen_height - self.height - reserved_bottom)
        y = max(10, y)
        self.window.geometry(f"{self.width}x{self.height}+{x}+{y}")
    
    def _create_ui(self):
        """Create the UI elements for the status display"""
        if not self.window:
            return

        # Main frame
        main_frame = tk.Frame(
            self.window,
            bg="#0B1220",
            highlightthickness=1,
            highlightbackground="#1E293B",
        )
        main_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Remove static icon/geometric strip; keep a single audio-reactive animation.
        self.status_icon_canvas = None
        self.geo_canvas = None

        # Recorder-style amplitude bars (UI-only, no ASR impact).
        self.wave_canvas = tk.Canvas(
            main_frame,
            width=self.wave_w,
            height=126,
            bg="#0B1220",
            highlightthickness=0,
            bd=0,
        )
        self.wave_canvas.pack(pady=(2, 6))
        self._init_waveform_strip()

        # Status text
        self.status_var = tk.StringVar(value="VoiceFlow Ready")
        status_label = tk.Label(
            main_frame,
            textvariable=self.status_var,
            bg="#0B1220",
            fg="#D8E3F0",
            font=("Segoe UI", 11, "bold")
        )
        # Dock already carries status; keep overlay focused on waveform/preview.
        # status_label.pack(pady=(0, 5))

        # Preview text for streaming transcription
        self.preview_var = tk.StringVar(value="")
        self.preview_label = tk.Label(
            main_frame,
            textvariable=self.preview_var,
            bg="#0B1220",
            fg="#E2E8F0",
            font=("Segoe UI", 24, "bold"),
            wraplength=self.wave_w - 24,
            justify=tk.CENTER,
        )
        self.preview_label.pack(pady=(0, 5))
        self.word_stream_canvas = tk.Canvas(
            main_frame,
            width=self.wave_w,
            height=52,
            bg="#0B1220",
            highlightthickness=0,
            bd=0,
        )
        self.word_stream_canvas.pack(pady=(0, 4))

        # Disable progress bar (was perceived as non-audio green block movement).
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = None
        self.preview_label.configure(wraplength=self.wave_w)

        # Keep waveform bars close to captions.

    def _init_geometric_motif(self, seed: Optional[int] = None):
        if not self.geo_canvas:
            return
        if seed is not None:
            self.geo_seed = int(seed)
        rng = random.Random(self.geo_seed)

        self.geo_canvas.delete("all")
        self.geo_nodes.clear()
        self.geo_lines.clear()
        self.geo_params.clear()

        node_count = 10
        left = 18
        right = self.geo_w - 18
        step = (right - left) / max(1, node_count - 1)
        mid_y = self.geo_h / 2
        for i in range(node_count):
            x = left + i * step + rng.uniform(-8, 8)
            y = mid_y + rng.uniform(-10, 10)
            radius = 1.6 + rng.uniform(0.4, 1.2)
            node = self.geo_canvas.create_oval(
                x - radius,
                y - radius,
                x + radius,
                y + radius,
                fill=self.visual_theme["accent"],
                outline="",
            )
            self.geo_nodes.append(node)
            self.geo_params.append(
                {
                    "base_x": x,
                    "base_y": y,
                    "amp_x": rng.uniform(1.4, 4.0),
                    "amp_y": rng.uniform(1.0, 3.2),
                    "freq": rng.uniform(0.7, 1.8),
                    "phase": rng.uniform(0.0, math.pi * 2),
                }
            )

        for i in range(node_count - 1):
            line = self.geo_canvas.create_line(0, 0, 0, 0, fill="#334155", width=1.2)
            self.geo_lines.append(line)

        # Subtle baseline for a cleaner, more professional look.
        self.geo_canvas.create_line(8, self.geo_h - 6, self.geo_w - 8, self.geo_h - 6, fill="#1E293B", width=1)

    def _init_waveform_strip(self):
        if not self.wave_canvas:
            return
        self.wave_canvas.delete("all")
        self.wave_h = int(max(96, self.wave_canvas.winfo_reqheight()))
        left = 8
        right = self.wave_w - 8
        base = self.wave_h // 2
        self.wave_baseline = self.wave_canvas.create_line(left, base, right, base, fill="#1F2937", width=1)
        self.wave_line = None
        self.wave_line_glow = None
        self.wave_fill = None
        self.wave_scan = None
        self.space_star_ids = []
        self.space_star_meta = []
        self.space_core = None
        self.space_glow = None
        self.space_ring = None
        self.space_arcs = []
        self.wave_bars = []

        bar_count = 64
        gap = 1
        bar_w = max(4, int((right - left - ((bar_count - 1) * gap)) / bar_count))
        x = left
        for _ in range(bar_count):
            bar = self.wave_canvas.create_rectangle(
                x,
                base - 1,
                x + bar_w,
                base + 1,
                fill="#38BDF8",
                outline="",
            )
            self.wave_bars.append(bar)
            x += bar_w + gap

    def _animate_waveform(self, mode: str = "listening"):
        if not self.wave_canvas or not self.wave_bars:
            return

        # Envelope smoothing: quick attack, slower release for natural feel.
        target = max(0.0, min(1.0, float(self.audio_level_target)))
        delta = target - self.audio_level_smoothed
        alpha = 0.55 if delta > 0 else 0.30
        self.audio_level_smoothed += alpha * delta
        if target <= 0.001 and self.audio_level_smoothed < 0.08:
            self.audio_level_smoothed *= 0.58
        lvl = self.audio_level_smoothed

        # Smooth frequency-profile features.
        for key in ("low", "mid", "high", "centroid"):
            tv = max(0.0, min(1.0, float(self.audio_features_target.get(key, 0.0))))
            sv = float(self.audio_features_smoothed.get(key, tv))
            blend = 0.42 if tv > sv else 0.28
            self.audio_features_smoothed[key] = sv + (tv - sv) * blend

        low = float(self.audio_features_smoothed["low"])
        mid = float(self.audio_features_smoothed["mid"])
        high = float(self.audio_features_smoothed["high"])
        centroid = float(self.audio_features_smoothed["centroid"])

        if mode == "idle":
            lvl *= 0.20

        # Recorder/radio style bars.
        self.wave_phase += 0.22 + 1.1 * lvl
        base = self.wave_h // 2
        max_h = max(18, (self.wave_h // 2) - 10)

        # AGC prevents "too zoomed in" or "too flat" look as mic level changes.
        target_agc = max(0.04, min(1.0, lvl))
        self._visual_agc = (self._visual_agc * 0.94) + (target_agc * 0.06)
        agc_scale = 0.85 + (0.95 / max(0.08, self._visual_agc))
        agc_scale = max(0.9, min(2.6, agc_scale))

        n = len(self.wave_bars)
        center = (n - 1) / 2.0
        for i, bar in enumerate(self.wave_bars):
            p = i / max(1.0, n - 1.0)  # 0..1 (left=low freq, right=high freq)

            # Blend low/mid/high energies by bar position.
            w_low = max(0.0, 1.0 - abs(p - 0.15) / 0.26)
            w_mid = max(0.0, 1.0 - abs(p - 0.50) / 0.30)
            w_high = max(0.0, 1.0 - abs(p - 0.85) / 0.26)
            w_sum = max(1e-6, w_low + w_mid + w_high)
            band_energy = ((low * w_low) + (mid * w_mid) + (high * w_high)) / w_sum

            falloff = 1.0 - min(1.0, abs(i - center) / (center + 0.001))
            osc = 0.66 + 0.34 * math.sin((self.wave_phase * (1.1 + centroid * 1.3)) + (i * 0.38))
            combined = (0.28 + 0.72 * falloff) * (0.20 + 0.80 * band_energy)
            voiced = min(1.0, lvl * agc_scale)
            h = 2 + (max_h * voiced * combined * osc)
            x0, _, x1, _ = self.wave_canvas.coords(bar)
            top = base - h
            bottom = base + (h * 0.72)
            self.wave_canvas.coords(bar, x0, top, x1, bottom)
            color = "#0891B2" if h < 10 else ("#06B6D4" if h < 22 else "#67E8F9")
            self.wave_canvas.itemconfig(bar, fill=color)

    def update_audio_level(self, level: float):
        """Thread-safe live amplitude input from recorder loop."""
        if not self.gui_ready or not self.command_queue:
            return
        try:
            self.command_queue.put((self._update_audio_level_ui, (level,), {}))
        except Exception:
            pass

    def _update_audio_level_ui(self, level: float):
        try:
            val = max(0.0, min(1.0, float(level)))
            boosted = min(1.0, (val ** 0.85) * 1.35)
            self.audio_level_target = 0.0 if boosted < 0.006 else boosted
            self.audio_level = self.audio_level_target
        except Exception:
            self.audio_level = 0.0
            self.audio_level_target = 0.0

    def update_audio_features(self, features: Dict[str, float]):
        """Thread-safe audio feature update for frequency-reactive bars."""
        if not self.gui_ready or not self.command_queue:
            return
        try:
            self.command_queue.put((self._update_audio_features_ui, (features,), {}))
        except Exception:
            pass

    def _update_audio_features_ui(self, features: Dict[str, float]):
        try:
            if not isinstance(features, dict):
                return
            self._update_audio_level_ui(float(features.get("level", self.audio_level_target)))
            for key in ("low", "mid", "high", "centroid"):
                val = max(0.0, min(1.0, float(features.get(key, self.audio_features_target.get(key, 0.0)))))
                self.audio_features_target[key] = val
        except Exception:
            pass

    def _setup_dock_window(self, screen_width: int, screen_height: int):
        """Always-on minimal dock for quick glance and history toggle."""
        if not self.root:
            return
        self.dock_window = tk.Toplevel(self.root)
        self.dock_window.overrideredirect(True)
        self.dock_window.wm_attributes("-topmost", True)
        self.dock_window.wm_attributes("-alpha", 0.88)
        self.dock_window.configure(bg="#0B1220")

        dock_w, dock_h = 430, 30
        x = (screen_width - dock_w) // 2
        y = screen_height - dock_h - 72
        self.dock_window.geometry(f"{dock_w}x{dock_h}+{x}+{y}")

        dock_frame = tk.Frame(self.dock_window, bg="#0B1220", highlightthickness=1, highlightbackground="#1E293B")
        dock_frame.pack(fill=tk.BOTH, expand=True)

        self.dock_var = tk.StringVar(value="vf ready")
        dock_label = tk.Label(
            dock_frame,
            textvariable=self.dock_var,
            bg="#0B1220",
            fg="#B6C2CF",
            font=("Segoe UI", 9, "bold"),
            anchor="w",
            padx=10,
        )
        dock_label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        history_btn = tk.Button(
            dock_frame,
            text="Recent History",
            command=self._toggle_history_panel,
            bg="#111827",
            fg="#D1D5DB",
            activebackground="#1F2937",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            padx=10,
            pady=2,
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
        )
        history_btn.pack(side=tk.RIGHT, padx=(0, 6), pady=3)

        minimize_btn = tk.Button(
            dock_frame,
            text="Minimize to Tray",
            command=lambda: self._set_dock_enabled_ui(False),
            bg="#111827",
            fg="#D1D5DB",
            activebackground="#1F2937",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            padx=10,
            pady=2,
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
        )
        minimize_btn.pack(side=tk.RIGHT, padx=(0, 6), pady=3)
        if not self.dock_enabled:
            self.dock_window.withdraw()

    def _setup_history_panel(self, screen_width: int, screen_height: int):
        """Quick recent-transcription panel opened from the dock."""
        if not self.root:
            return
        self.history_window = tk.Toplevel(self.root)
        self.history_window.overrideredirect(True)
        self.history_window.wm_attributes("-topmost", True)
        self.history_window.wm_attributes("-alpha", 0.95)
        self.history_window.configure(bg="#0B1220")

        panel_w, panel_h = 560, 240
        x = (screen_width - panel_w) // 2
        y = screen_height - panel_h - 58
        self.history_geometry_compact = f"{panel_w}x{panel_h}+{x}+{y}"
        self.history_geometry_expanded = f"{panel_w}x460+{x}+{max(20, y - 220)}"
        self.history_window.geometry(self.history_geometry_compact)

        frame = tk.Frame(self.history_window, bg="#0B1220", highlightthickness=1, highlightbackground="#1E293B")
        frame.pack(fill=tk.BOTH, expand=True)

        header = tk.Label(
            frame,
            text="Recent Transcriptions",
            bg="#0B1220",
            fg="#C7D2FE",
            font=("Segoe UI", 10, "bold"),
            anchor="w",
            padx=10,
            pady=6,
        )
        header.pack(fill=tk.X)

        actions = tk.Frame(frame, bg="#0B1220")
        actions.pack(fill=tk.X, padx=8, pady=(0, 6))

        self.history_toggle_btn = tk.Button(
            actions,
            text="More",
            command=self._toggle_history_expanded,
            bg="#111827",
            fg="#D1D5DB",
            activebackground="#1F2937",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            padx=10,
            pady=2,
            font=("Segoe UI", 9, "bold"),
        )
        self.history_toggle_btn.pack(side=tk.LEFT)

        close_btn = tk.Button(
            actions,
            text="Close",
            command=self._toggle_history_panel,
            bg="#111827",
            fg="#D1D5DB",
            activebackground="#1F2937",
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            padx=10,
            pady=2,
            font=("Segoe UI", 9, "bold"),
        )
        close_btn.pack(side=tk.RIGHT)

        self.history_text = tk.Text(
            frame,
            bg="#0F172A",
            fg="#D1D5DB",
            font=("Consolas", 9),
            relief=tk.FLAT,
            wrap=tk.WORD,
            height=10,
        )
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.history_text.configure(state=tk.DISABLED)

        self.history_window.withdraw()

    def set_dock_enabled(self, enabled: bool):
        if not self.gui_ready or not self.command_queue:
            return
        try:
            self.command_queue.put((self._set_dock_enabled_ui, (bool(enabled),), {}))
        except Exception:
            pass

    def _set_dock_enabled_ui(self, enabled: bool):
        self.dock_enabled = bool(enabled)
        if self.dock_window:
            if self.dock_enabled:
                self.dock_window.deiconify()
                self.dock_window.lift()
            else:
                self.dock_window.withdraw()
        if not self.dock_enabled:
            self.history_visible = False
            if self.history_window:
                self.history_window.withdraw()
        if self.window:
            self._position_overlay(self.window.winfo_screenwidth(), self.window.winfo_screenheight())
        self._refresh_dock_text()

    def get_dock_enabled(self) -> bool:
        return bool(self.dock_enabled)

    def toggle_recent_history(self):
        if not self.gui_ready or not self.command_queue:
            return
        try:
            self.command_queue.put((self._toggle_history_panel, (), {}))
        except Exception:
            pass

    def _start_animation(self, status: TranscriptionStatus):
        if self.animation_job and self.window:
            self.window.after_cancel(self.animation_job)
            self.animation_job = None
        self.animation_step = 0.0
        self._animate_status_icon(status)

    def _stop_animation(self):
        if self.animation_job and self.window:
            self.window.after_cancel(self.animation_job)
        self.animation_job = None
        self.animation_step = 0.0
        self._set_icon_idle()

    def _set_icon_idle(self):
        if self.status_icon_canvas:
            bg_margin = 6
            ring_margin = 10
            self.status_icon_canvas.coords(self.status_icon_bg, bg_margin, bg_margin, self.icon_size - bg_margin, self.icon_size - bg_margin)
            self.status_icon_canvas.coords(self.status_icon_ring, ring_margin, ring_margin, self.icon_size - ring_margin, self.icon_size - ring_margin)
            # Keep idle icon subtle; avoid static bright logo effect.
            self.status_icon_canvas.itemconfig(self.status_icon_bg, fill="#0B1220")
            self.status_icon_canvas.itemconfig(self.status_icon_ring, outline=self.visual_theme["accent"])
            self.status_icon_canvas.itemconfig(self.status_icon_center, text="", fill="#1f2937")
            for bar in self.status_audio_bars:
                self.status_icon_canvas.coords(bar, -10, -10, -10, -10)
        self._animate_geometric_strip(mode="idle")
        self._animate_waveform(mode="idle")

    def _animate_geometric_strip(self, mode: str = "listening"):
        if not self.geo_canvas or not self.geo_nodes:
            return

        lvl = max(0.0, min(1.0, self.audio_level_smoothed))
        points = []
        for i, node in enumerate(self.geo_nodes):
            p = self.geo_params[i]
            if mode == "listening":
                speed_scale = 0.45 + (1.9 * (lvl ** 0.9))
                damp = 0.3 + (1.5 * (lvl ** 0.8))
            else:
                speed_scale = 1.0 if mode == "idle" else (1.7 if mode == "transcribing" else 1.3)
                damp = 0.45 if mode == "idle" else 1.0
            x = p["base_x"] + damp * p["amp_x"] * math.sin((self.animation_step * p["freq"] * speed_scale) + p["phase"])
            y = p["base_y"] + damp * p["amp_y"] * math.cos((self.animation_step * 0.8 * speed_scale) + p["phase"])
            r = 2.0 if mode == "idle" else 2.4
            self.geo_canvas.coords(node, x - r, y - r, x + r, y + r)
            points.append((x, y))

        for i, line in enumerate(self.geo_lines):
            x1, y1 = points[i]
            x2, y2 = points[i + 1]
            self.geo_canvas.coords(line, x1, y1, x2, y2)
            line_color = "#334155" if mode == "idle" else self.visual_theme["accent"]
            self.geo_canvas.itemconfig(line, fill=line_color, width=(1.1 if mode == "idle" else 1.4))

    def _animate_status_icon(self, status: TranscriptionStatus):
        if not self.window:
            return

        self.animation_step += 0.28

        if status == TranscriptionStatus.LISTENING:
            self._animate_geometric_strip(mode="listening")
            self._animate_waveform(mode="listening")
            interval = 48
        elif status == TranscriptionStatus.PROCESSING:
            self._animate_geometric_strip(mode="processing")
            self._animate_waveform(mode="processing")
            interval = 42
        elif status == TranscriptionStatus.TRANSCRIBING:
            self._animate_geometric_strip(mode="transcribing")
            self._animate_waveform(mode="transcribing")
            interval = 36
        else:
            self._set_icon_idle()
            return

        self.animation_job = self.window.after(interval, lambda: self._animate_status_icon(status))

    def _toggle_history_panel(self):
        if not self.history_window or not self.dock_enabled:
            return
        self.history_visible = not self.history_visible
        if self.history_visible:
            if self.history_geometry_compact:
                self.history_window.geometry(self.history_geometry_compact)
            self.history_expanded = False
            if hasattr(self, "history_toggle_btn") and self.history_toggle_btn:
                self.history_toggle_btn.configure(text="More")
            self._render_history_panel()
            self.history_window.deiconify()
            self.history_window.lift()
        else:
            self.history_window.withdraw()

    def _toggle_history_expanded(self):
        if not self.history_window:
            return
        self.history_expanded = not self.history_expanded
        if self.history_expanded and self.history_geometry_expanded:
            self.history_window.geometry(self.history_geometry_expanded)
        elif self.history_geometry_compact:
            self.history_window.geometry(self.history_geometry_compact)
        if hasattr(self, "history_toggle_btn") and self.history_toggle_btn:
            self.history_toggle_btn.configure(text=("Less" if self.history_expanded else "More"))
        self._render_history_panel()

    def _render_history_panel(self):
        if not self.history_text:
            return

        if not self.recent_transcriptions:
            body = "No transcriptions yet in this session."
        else:
            lines = []
            rows = list(self.recent_transcriptions)[::-1]
            if not self.history_expanded:
                rows = rows[:8]
            for item in rows:
                txt = item["full_text"] if self.history_expanded else item["preview"]
                lines.append(
                    "[{ts}] dur={dur:.1f}s proc={proc:.2f}s rtf={rtf:.2f}x\n{txt}\n".format(
                        ts=item["ts"],
                        dur=item["audio_duration"],
                        proc=item["processing_time"],
                        rtf=item["rtf"],
                        txt=txt,
                    )
                )
            body = "\n".join(lines)

        self.history_text.configure(state=tk.NORMAL)
        self.history_text.delete("1.0", tk.END)
        self.history_text.insert(tk.END, body)
        self.history_text.configure(state=tk.DISABLED)

    def record_transcription_event(self, text: str, audio_duration: float, processing_time: float):
        """Record summary for always-on dock/history panel."""
        if not self.gui_ready or not self.command_queue:
            return
        try:
            self.command_queue.put(
                (self._record_transcription_event_ui, (text, audio_duration, processing_time), {})
            )
        except Exception as e:
            logger.debug(f"Failed to queue transcription event: {e}")

    def _record_transcription_event_ui(self, text: str, audio_duration: float, processing_time: float):
        safe_text = (text or "").strip().replace("\n", " ")
        if not safe_text:
            return
        preview = safe_text[:140] + ("..." if len(safe_text) > 140 else "")
        proc = max(0.001, float(processing_time))
        rtf = float(audio_duration) / proc if audio_duration > 0 else 0.0
        item = {
            "ts": datetime.now().strftime("%H:%M:%S"),
            "audio_duration": float(audio_duration),
            "processing_time": float(processing_time),
            "rtf": float(rtf),
            "preview": preview,
            "full_text": safe_text,
        }
        self.recent_transcriptions.append(item)
        self._refresh_dock_text(last_item=item)

        if self.history_visible:
            self._render_history_panel()

    def _refresh_dock_text(self, status: Optional[TranscriptionStatus] = None, last_item: Optional[Dict[str, Any]] = None):
        if not self.dock_var:
            return
        if not self.dock_enabled:
            self.dock_var.set("")
            return
        status_value = (status or self.current_status).value
        status_label = "ready" if status_value == "idle" else status_value
        tail = "use buttons"
        if last_item:
            tail = "last: {dur:.1f}s->{proc:.2f}s ({rtf:.2f}x)".format(
                dur=last_item["audio_duration"],
                proc=last_item["processing_time"],
                rtf=last_item["rtf"],
            )
        elif status_value in ("listening", "processing", "transcribing", "complete"):
            tail = "live"
        self.dock_var.set(f"vf {status_label}  |  {tail}")
    
    @with_error_recovery(fallback_value=None)
    def show_status(self, status: TranscriptionStatus, message: str = None, duration: float = None):
        """
        Show status indicator with message - Thread-safe with CRITICAL GUARDRAILS

        Args:
            status: TranscriptionStatus enum
            message: Custom message (optional)
            duration: Auto-hide after seconds (optional)
        """
        # CRITICAL GUARDRAIL: Use safe visual update wrapper
        def _safe_status_update():
            if not self.gui_ready or not self.command_queue:
                logger.debug(f"GUI not ready, status: {status.value}")
                return

            with self.lock:
                self.current_status = status

                # Cancel existing auto-hide timer
                if self.auto_hide_timer:
                    self.auto_hide_timer.cancel()

                # Update message
                if message:
                    display_message = message
                else:
                    display_message = self._get_default_message(status)

                # Queue command for GUI thread with error protection
                try:
                    self.command_queue.put((self._update_ui, (status, display_message), {}))

                    # Auto-hide timer
                    if duration:
                        self.auto_hide_timer = threading.Timer(duration, self.hide)
                        self.auto_hide_timer.start()

                except Exception as e:
                    logger.error(f"Failed to queue status update: {e}")

        return safe_visual_update(_safe_status_update)
    
    @with_error_recovery(fallback_value=None)
    def _update_ui(self, status: TranscriptionStatus, message: str):
        """Update UI elements (must run on main thread) - CRITICAL GUARDRAIL PROTECTED"""
        if not self.window or not self.status_var:
            logger.debug("Window or status_var not available for UI update")
            return

        try:
            # Show window
            self.window.deiconify()
            self.window.lift()
            
            # Update text
            self.status_var.set(message)
            self._refresh_dock_text(status=status)
            
            # Update progress bar based on status
            pb = getattr(self, "progress_bar", None)
            if status == TranscriptionStatus.LISTENING:
                # Fresh motif each listening cycle for a "unique every time" feel.
                self._init_geometric_motif(seed=(time.time_ns() & 0xFFFF))
                if pb:
                    pb.configure(mode='indeterminate')
                    pb.start(10)  # Slow pulse
                self._start_animation(status)
            elif status == TranscriptionStatus.PROCESSING:
                if pb:
                    pb.configure(mode='indeterminate') 
                    pb.start(5)   # Fast pulse
                self._start_animation(status)
            elif status == TranscriptionStatus.TRANSCRIBING:
                if pb:
                    pb.configure(mode='indeterminate')
                    pb.start(3)   # Very fast pulse
                self._start_animation(status)
            else:
                self._stop_animation()
                if pb:
                    pb.stop()
                if status == TranscriptionStatus.COMPLETE:
                    if pb:
                        pb.configure(mode='determinate')
                    self.progress_var.set(100)
                    if self.status_icon_canvas:
                        self.status_icon_canvas.itemconfig(self.status_icon_center, text="OK", fill="#16A34A")
                else:
                    self.progress_var.set(0)
                    if status == TranscriptionStatus.ERROR and self.status_icon_canvas:
                        self.status_icon_canvas.itemconfig(self.status_icon_center, text="!", fill=self.error_color)
            
            # Update colors based on status
            color = self.text_color
            if status == TranscriptionStatus.ERROR:
                color = self.error_color
            elif status in [TranscriptionStatus.LISTENING, TranscriptionStatus.PROCESSING, TranscriptionStatus.TRANSCRIBING]:
                color = self.accent_color
            
            # Apply color (find the label widget)
            for widget in self.window.winfo_children():
                if isinstance(widget, tk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Label):
                            child.configure(fg=color)
                            break
                    break
        
        except Exception as e:
            print(f"[VisualIndicator] UI update error: {e}")
    
    def _get_default_message(self, status: TranscriptionStatus) -> str:
        """Get default message for status"""
        messages = {
            TranscriptionStatus.IDLE: "VoiceFlow Ready",
            TranscriptionStatus.LISTENING: "Listening...",
            TranscriptionStatus.PROCESSING: "🔄 Processing audio...",
            TranscriptionStatus.TRANSCRIBING: "✍️ Transcribing...",
            TranscriptionStatus.COMPLETE: "✅ Transcription complete",
            TranscriptionStatus.ERROR: "❌ Transcription failed"
        }
        return messages.get(status, "VoiceFlow")
    
    def hide(self):
        """Hide the status indicator - Thread-safe"""
        if not self.gui_ready or not self.command_queue:
            return

        try:
            self.command_queue.put((self._hide_window, (), {}))
        except Exception as e:
            print(f"[VisualIndicator] Failed to queue hide command: {e}")

    def _hide_window(self):
        """Hide window on GUI thread and reset all state"""
        try:
            # CRITICAL: Cancel any pending auto-hide timer
            if self.auto_hide_timer:
                self.auto_hide_timer.cancel()
                self.auto_hide_timer = None

            # Reset status to idle to prevent persistence
            self.current_status = TranscriptionStatus.IDLE

            # Hide the window
            if self.window:
                self.window.withdraw()

            # Stop any progress animations
            pb = getattr(self, 'progress_bar', None)
            if pb:
                pb.stop()
            self._stop_animation()

            # Clear status text to ensure overlay doesn't persist
            if self.status_var:
                self.status_var.set("")

            # Clear preview text
            if hasattr(self, 'preview_var') and self.preview_var:
                self.preview_var.set("")
            self._bubble_tokens.clear()
            self._last_stream_word_count = 0
            if self.word_stream_canvas:
                self.word_stream_canvas.delete("all")

        except Exception as e:
            print(f"[VisualIndicator] Hide error: {e}")

    def show_preview(self, text: str):
        """Show streaming transcription preview text - Thread-safe"""
        if not self.gui_ready or not self.command_queue:
            return

        try:
            self.command_queue.put((self._update_preview, (text,), {}))
        except Exception as e:
            print(f"[VisualIndicator] Failed to queue preview update: {e}")

    def _update_preview(self, text: str):
        """Update preview text on GUI thread"""
        try:
            if hasattr(self, 'preview_var') and self.preview_var:
                words = [w for w in text.strip().split() if w]
                if not words:
                    self.preview_var.set("")
                    return

                # Large caption text: latest 1-2 words.
                caption = " ".join(words[-2:])
                if len(caption) > 42:
                    caption = caption[-42:]
                self.preview_var.set(caption)

                # Bubble stream: append only newly observed words from cumulative partial text.
                if len(words) < self._last_stream_word_count:
                    # Partial reset/new phrase.
                    self._bubble_tokens.clear()
                new_words = words[self._last_stream_word_count:]
                for token in new_words:
                    if token:
                        self._bubble_tokens.append(token[:24])
                self._last_stream_word_count = len(words)
                self._render_word_stream()
        except Exception as e:
            print(f"[VisualIndicator] Preview update error: {e}")

    def _render_word_stream(self):
        if not self.word_stream_canvas:
            return
        c = self.word_stream_canvas
        c.delete("all")
        if not self._bubble_tokens:
            return

        x = self.wave_w - 8
        y_mid = 26
        for i, token in enumerate(reversed(self._bubble_tokens)):
            age = i / max(1, len(self._bubble_tokens) - 1)
            txt_color = "#E2E8F0" if age < 0.33 else ("#C7D2FE" if age < 0.66 else "#94A3B8")
            bg_color = "#1E293B" if age < 0.5 else "#0F172A"
            pad_x = 8
            # Width estimate avoids expensive font metrics and keeps updates cheap.
            width = (len(token) * 8) + (pad_x * 2)
            x0 = x - width
            x1 = x
            if x1 < 6:
                break
            y = y_mid - 10 if (i % 2 == 0) else y_mid + 10
            c.create_rectangle(x0, y - 11, x1, y + 11, fill=bg_color, outline="#334155", width=1)
            c.create_text((x0 + x1) / 2, y, text=token, fill=txt_color, font=("Segoe UI", 10, "bold"))
            x = x0 - 8

    def clear_preview(self):
        """Clear the preview text - Thread-safe"""
        if not self.gui_ready or not self.command_queue:
            return

        try:
            self.command_queue.put((self._clear_preview, (), {}))
        except Exception as e:
            print(f"[VisualIndicator] Failed to queue preview clear: {e}")

    def _clear_preview(self):
        """Clear preview text on GUI thread"""
        try:
            if hasattr(self, 'preview_var') and self.preview_var:
                self.preview_var.set("")
            self._bubble_tokens.clear()
            self._last_stream_word_count = 0
            if self.word_stream_canvas:
                self.word_stream_canvas.delete("all")
        except Exception as e:
            print(f"[VisualIndicator] Preview clear error: {e}")

    def destroy(self):
        """Clean up the indicator"""
        with self.lock:
            if self.auto_hide_timer:
                self.auto_hide_timer.cancel()
            
            if self.window:
                try:
                    self.window.after(0, self._destroy_window)
                except Exception:
                    pass
    
    def _destroy_window(self):
        """Destroy window on main thread"""
        try:
            if self.history_window:
                self.history_window.destroy()
            if self.dock_window:
                self.dock_window.destroy()
            if self.window:
                self.window.destroy()
            if hasattr(self, 'root'):
                self.root.destroy()
        except Exception:
            pass

# Global indicator instance
_indicator: Optional[BottomScreenIndicator] = None
_indicator_lock = threading.Lock()

def get_indicator() -> BottomScreenIndicator:
    """Get or create the global status indicator"""
    global _indicator
    
    with _indicator_lock:
        if _indicator is None:
            _indicator = BottomScreenIndicator()
    
    return _indicator

@with_error_recovery(fallback_value=None)
def show_transcription_status(status: TranscriptionStatus, message: str = None, duration: float = None):
    """Convenient function to show transcription status - CRITICAL GUARDRAIL PROTECTED"""
    def _safe_show():
        indicator = get_indicator()
        indicator.show_status(status, message, duration)

    return safe_visual_update(_safe_show)

@with_error_recovery(fallback_value=None)
def hide_status():
    """Hide the status indicator - CRITICAL GUARDRAIL PROTECTED"""
    def _safe_hide():
        if _indicator:
            _indicator.hide()

    return safe_visual_update(_safe_hide)

def cleanup_indicators():
    """Clean up visual indicators"""
    global _indicator
    with _indicator_lock:
        if _indicator:
            _indicator.destroy()
            _indicator = None

def force_cleanup_all():
    """Force cleanup of all persistent visual state - EMERGENCY CLEANUP"""
    try:
        # Force hide any visible indicators
        hide_status()

        # Wait a moment for GUI thread to process
        time.sleep(0.1)

        # Destroy everything
        cleanup_indicators()

        print("[VisualIndicator] Force cleanup completed")
    except Exception as e:
        print(f"[VisualIndicator] Force cleanup error: {e}")

def ensure_clean_startup():
    """Ensure clean startup by clearing any persistent state"""
    try:
        force_cleanup_all()
        # Small delay to let any GUI threads settle
        time.sleep(0.2)
        print("[VisualIndicator] Clean startup ensured")
    except Exception as e:
        print(f"[VisualIndicator] Startup cleanup error: {e}")

# Convenience functions for common status updates
def show_listening():
    show_transcription_status(TranscriptionStatus.LISTENING)

def show_processing():
    show_transcription_status(TranscriptionStatus.PROCESSING)

def show_transcribing():
    show_transcription_status(TranscriptionStatus.TRANSCRIBING)

def show_complete(message: str = None):
    show_transcription_status(TranscriptionStatus.COMPLETE, message, duration=2.0)

def show_error(message: str = None):
    show_transcription_status(TranscriptionStatus.ERROR, message, duration=3.0)

def show_preview(text: str):
    """Show streaming transcription preview"""
    indicator = get_indicator()
    if indicator:
        indicator.show_preview(text)

def clear_preview():
    """Clear the streaming transcription preview"""
    indicator = get_indicator()
    if indicator:
        indicator.clear_preview()

def record_transcription_event(text: str, audio_duration: float, processing_time: float):
    """Record recent transcription item for dock/history display."""
    indicator = get_indicator()
    if indicator:
        indicator.record_transcription_event(text, audio_duration, processing_time)

def update_audio_level(level: float):
    """Push live voice amplitude to waveform animation (0..1)."""
    indicator = get_indicator()
    if indicator:
        indicator.update_audio_level(level)

def update_audio_features(features: Dict[str, float]):
    """Push live amplitude + frequency features to waveform animation."""
    indicator = get_indicator()
    if indicator:
        indicator.update_audio_features(features)

def set_dock_enabled(enabled: bool):
    """Show/hide the always-on dock without affecting status overlay."""
    indicator = get_indicator()
    if indicator:
        indicator.set_dock_enabled(enabled)

def get_dock_enabled() -> bool:
    """Return current dock visibility state."""
    indicator = get_indicator()
    if indicator:
        return indicator.get_dock_enabled()
    return True

def toggle_recent_history():
    """Toggle recent transcription history panel."""
    indicator = get_indicator()
    if indicator:
        indicator.toggle_recent_history()

# Test function
def test_visual_indicators():
    """Test the visual indicators"""
    print("Testing VoiceFlow Visual Indicators...")
    
    # Test sequence
    show_listening()
    time.sleep(2)
    
    show_processing() 
    time.sleep(2)
    
    show_transcribing()
    time.sleep(2)
    
    show_complete("Test transcription complete!")
    time.sleep(3)
    
    show_error("Test error message")
    time.sleep(3)
    
    hide_status()
    print("Visual indicator test complete")

if __name__ == "__main__":
    test_visual_indicators()
