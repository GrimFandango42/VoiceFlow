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
        self.history_canvas: Optional[tk.Canvas] = None
        self.history_items_frame: Optional[tk.Frame] = None
        self.history_feedback_var: Optional[tk.StringVar] = None
        self.history_feedback_job = None
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
        self.wave_trail_line = None
        self.wave_trail_glow = None
        self.wave_orb = None
        self.wave_orb_glow = None
        self.wave_left = 8
        self.wave_right = 452
        self.space_star_ids = []
        self.space_star_meta = []
        self.space_core = None
        self.space_glow = None
        self.space_ring = None
        self.space_arcs = []
        self.wave_phase = 0.0
        self._color_phase = random.random() * (math.pi * 2.0)
        self._speech_active = False
        self._burst_energy = 0.0
        self._speech_level = 0.0
        self._silence_floor_est = 0.0
        self.audio_level = 0.0
        self.audio_level_target = 0.0
        self.audio_level_smoothed = 0.0
        self.audio_features_target = {"low": 0.34, "mid": 0.33, "high": 0.33, "centroid": 0.5}
        self.audio_features_smoothed = {"low": 0.34, "mid": 0.33, "high": 0.33, "centroid": 0.5}
        self._visual_agc = 0.18
        self.recent_transcriptions = deque(maxlen=50)
        self.history_item_expanded_ids = set()
        self.history_event_seq = 0
        self.history_visible = False
        self.history_expanded = False
        self.history_geometry_compact = None
        self.history_geometry_expanded = None
        self.dock_enabled = False
        self.noise_floor = 0.0
        self.wave_energy_history = deque([0.0] * 84, maxlen=84)
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
        req_w, req_h = self.config_manager.get_overlay_dimensions()
        # Compact overlay profile: small, centered, and visually lighter.
        self.width = int(min(460, max(340, req_w)))
        self.height = int(min(240, max(170, req_h)))
        self.wave_w = max(280, self.width - 24)
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

        # Keep overlay strictly centered when dock is enabled.
        if self.dock_enabled and self.dock_window:
            x = int((screen_width - self.width) / 2)
            try:
                geo = self.dock_window.geometry()  # e.g. 430x30+745+1008
                dock_y = int(geo.rsplit("+", 1)[-1])
                # Keep animation close to the dock for a tighter visual stack.
                y = int(dock_y - self.height - 1)
            except Exception:
                y = min(y - 5, screen_height - self.height - reserved_bottom)
        else:
            y = min(y - 6, screen_height - self.height - reserved_bottom)

        x = max(8, min(screen_width - self.width - 8, x))
        y = max(10, y)
        self.window.geometry(f"{self.width}x{self.height}+{x}+{y}")
    
    def _create_ui(self):
        """Create the UI elements for the status display"""
        if not self.window:
            return

        # Main frame
        main_frame = tk.Frame(
            self.window,
            bg=self.transparent_key,
            highlightthickness=0,
            bd=0,
        )
        main_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        # Remove static icon/geometric strip; keep a single audio-reactive animation.
        self.status_icon_canvas = None
        self.geo_canvas = None

        # Recorder-style amplitude bars (UI-only, no ASR impact).
        self.wave_canvas = tk.Canvas(
            main_frame,
            width=self.wave_w,
            height=114,
            bg=self.transparent_key,
            highlightthickness=0,
            bd=0,
        )
        self.wave_canvas.pack(pady=(6, 4))
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
            bg=self.transparent_key,
            fg="#E6F3FF",
            font=("Segoe UI", 20, "bold"),
            wraplength=self.wave_w - 24,
            justify=tk.CENTER,
        )
        self.preview_label.pack(pady=(0, 4))
        self.word_stream_canvas = tk.Canvas(
            main_frame,
            width=self.wave_w,
            height=38,
            bg=self.transparent_key,
            highlightthickness=0,
            bd=0,
        )
        self.word_stream_canvas.pack(pady=(0, 2))

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
        self.wave_h = int(max(92, self.wave_canvas.winfo_reqheight()))
        left = 8
        right = self.wave_w - 8
        self.wave_left = left
        self.wave_right = right
        base = self.wave_h // 2
        self.wave_energy_history = deque([0.0] * self.wave_energy_history.maxlen, maxlen=self.wave_energy_history.maxlen)
        self._speech_level = 0.0
        self._silence_floor_est = 0.0

        self.wave_baseline = self.wave_canvas.create_line(left, base, right, base, fill="#1F2937", width=1)
        self.wave_line = None
        self.wave_line_glow = None
        self.wave_fill = None
        self.wave_scan = None
        self.wave_trail_line = self.wave_canvas.create_line(
            left,
            base,
            right,
            base,
            smooth=True,
            splinesteps=22,
            width=2,
            fill="#67E8F9",
        )
        self.wave_trail_glow = self.wave_canvas.create_line(
            left,
            base,
            right,
            base,
            smooth=True,
            splinesteps=22,
            width=8,
            fill="#0EA5E9",
        )
        self.wave_line_glow = self.wave_canvas.create_line(
            left,
            base,
            right,
            base,
            smooth=True,
            splinesteps=24,
            width=6,
            fill="#0EA5E9",
        )
        self.wave_line = self.wave_canvas.create_line(
            left,
            base,
            right,
            base,
            smooth=True,
            splinesteps=24,
            width=2,
            fill="#BAE6FD",
        )
        self.wave_orb_glow = self.wave_canvas.create_oval(left - 6, base - 6, left + 6, base + 6, fill="#0EA5E9", outline="")
        self.wave_orb = self.wave_canvas.create_oval(left - 3, base - 3, left + 3, base + 3, fill="#38BDF8", outline="")
        self.space_star_ids = []
        self.space_star_meta = []
        self.space_core = None
        self.space_glow = None
        self.space_ring = None
        self.space_arcs = []
        self.wave_pulse_rings = []
        self.wave_spark_meta = []
        self.wave_bars = []

        bar_count = 64
        gap = 2
        bar_w = max(3, int((right - left - ((bar_count - 1) * gap)) / bar_count))
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

        # Pulse rings around the orb for stronger speech-reactive feel.
        for _ in range(3):
            ring = self.wave_canvas.create_oval(
                left - 2,
                base - 2,
                left + 2,
                base + 2,
                outline="#334155",
                width=1,
            )
            self.wave_pulse_rings.append(ring)

        # Spark particles riding the waveform.
        self.wave_sparks = []
        self.wave_spark_meta = []
        spark_count = 12
        span = max(1.0, float(right - left))
        for i in range(spark_count):
            px = left + ((i + 1) / (spark_count + 1)) * span
            py = base + random.uniform(-6.0, 6.0)
            spark = self.wave_canvas.create_oval(px - 2, py - 2, px + 2, py + 2, fill="#38BDF8", outline="")
            self.wave_sparks.append(spark)
            self.wave_spark_meta.append(
                {
                    "x": px,
                    "y": py,
                    "vx": random.uniform(-0.2, 0.2),
                    "phase": random.uniform(0.0, math.pi * 2.0),
                    "amp": random.uniform(6.0, 18.0),
                }
            )

        # Layer order for "space HUD" look.
        if self.wave_trail_glow:
            self.wave_canvas.tag_raise(self.wave_trail_glow)
        if self.wave_trail_line:
            self.wave_canvas.tag_raise(self.wave_trail_line)
        if self.wave_line_glow:
            self.wave_canvas.tag_raise(self.wave_line_glow)
        if self.wave_line:
            self.wave_canvas.tag_raise(self.wave_line)
        for ring in self.wave_pulse_rings:
            self.wave_canvas.tag_raise(ring)
        for bar in self.wave_bars:
            self.wave_canvas.tag_raise(bar)
        for spark in self.wave_sparks:
            self.wave_canvas.tag_raise(spark)
        if self.wave_baseline:
            self.wave_canvas.tag_raise(self.wave_baseline)
        if self.wave_orb_glow:
            self.wave_canvas.tag_raise(self.wave_orb_glow)
        if self.wave_orb:
            self.wave_canvas.tag_raise(self.wave_orb)

    def _animate_waveform(self, mode: str = "listening"):
        if not self.wave_canvas or not self.wave_bars:
            return

        # Envelope smoothing: quick attack, slower release for natural feel.
        target = max(0.0, min(1.0, float(self.audio_level_target)))
        delta = target - self.audio_level_smoothed
        alpha = 0.72 if delta > 0 else 0.26
        self.audio_level_smoothed += alpha * delta
        if target <= 0.001 and self.audio_level_smoothed < 0.08:
            self.audio_level_smoothed *= 0.56
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
            lvl *= 0.08

        # Recorder/radio style bars.
        base = self.wave_h // 2
        max_h = max(18, (self.wave_h // 2) - 10)

        # AGC prevents "too zoomed in" or "too flat" look as mic level changes.
        target_agc = max(0.04, min(1.0, lvl))
        self._visual_agc = (self._visual_agc * 0.94) + (target_agc * 0.06)
        agc_scale = 0.85 + (0.95 / max(0.08, self._visual_agc))
        agc_scale = max(0.95, min(2.35, agc_scale))
        voiced_raw = min(1.0, lvl * agc_scale)

        # Dynamic silence-floor estimation makes idle state visibly calmer.
        if voiced_raw < 0.18:
            self._silence_floor_est = (self._silence_floor_est * 0.97) + (voiced_raw * 0.03)
        floor = max(0.012, min(0.18, self._silence_floor_est))
        voiced = max(0.0, min(1.0, (voiced_raw - floor) / max(0.12, 1.0 - floor)))

        # Additional smoothing to avoid jitter while preserving speech swings.
        self._speech_level = (self._speech_level * 0.78) + (voiced * 0.22)
        voiced = self._speech_level
        voiced_drive = max(0.0, min(1.0, voiced ** 0.86))
        self.wave_phase += 0.05 + (1.75 * voiced_drive)

        speech_now = voiced > 0.12
        if speech_now and not self._speech_active:
            self._burst_energy = 1.0
        self._speech_active = speech_now
        self._burst_energy = max(0.0, (self._burst_energy * 0.91) - 0.010)

        # Reactive spectral trail to make the overlay feel alive and speech-driven.
        self.wave_energy_history.append(voiced)
        hist = list(self.wave_energy_history)
        accent_r = int(max(26, min(220, 40 + (110 * high) + (22 * centroid) + (22 * self._burst_energy))))
        accent_g = int(max(74, min(230, 100 + (90 * mid) + (42 * voiced))))
        accent_b = int(max(108, min(250, 136 + (80 * low) + (20 * (1.0 - centroid)))))
        trail_color = "#{:02X}{:02X}{:02X}".format(accent_r, accent_g, accent_b)
        glow_color = "#{:02X}{:02X}{:02X}".format(
            min(255, accent_r + 18),
            min(255, accent_g + 28),
            min(255, accent_b + 36),
        )

        if self.wave_trail_line and self.wave_trail_glow and len(hist) >= 4:
            points = []
            span = max(1.0, float(self.wave_right - self.wave_left))
            total = len(hist) - 1
            for idx, sample in enumerate(hist):
                x = self.wave_left + (span * (idx / max(1, total)))
                harmonic = 0.62 + (0.38 * math.sin((idx * 0.19) + (self.wave_phase * 0.95) + (centroid * 1.7)))
                carrier = math.sin((idx * 0.34) + (self.wave_phase * 1.55) + (centroid * 2.2))
                y = base + (sample * max_h * harmonic * carrier)
                points.extend((x, y))
            self.wave_canvas.coords(self.wave_trail_line, *points)
            self.wave_canvas.coords(self.wave_trail_glow, *points)
            self.wave_canvas.itemconfig(self.wave_trail_line, fill=trail_color, width=(1 + (1.8 * voiced_drive)))
            self.wave_canvas.itemconfig(
                self.wave_trail_glow,
                fill=glow_color,
                width=(4 + (4.2 * voiced_drive) + (2.4 * self._burst_energy)),
            )

        if self.wave_line and self.wave_line_glow:
            points = []
            point_count = 72
            span = max(1.0, float(self.wave_right - self.wave_left))
            wave_amp = 1.2 + (voiced_drive * max_h * (0.58 + (0.32 * mid)))
            base_freq = 1.4 + (4.8 * centroid) + (0.8 * high)
            texture_freq = (base_freq * 0.47) + 0.60
            for idx in range(point_count):
                p = idx / max(1, point_count - 1)
                x = self.wave_left + (span * p)
                envelope = 0.25 + (0.75 * ((1.0 - abs((p * 2.0) - 1.0)) ** 1.35))
                carrier = math.sin((p * math.pi * 2.0 * base_freq) + (self.wave_phase * 2.2))
                texture = math.sin((p * math.pi * 2.0 * texture_freq) - (self.wave_phase * 1.4))
                y = base + (wave_amp * envelope * ((0.74 * carrier) + (0.26 * texture)))
                points.extend((x, y))
            self.wave_canvas.coords(self.wave_line, *points)
            self.wave_canvas.coords(self.wave_line_glow, *points)
            self.wave_canvas.itemconfig(self.wave_line, fill=trail_color, width=(1.1 + (2.2 * voiced_drive)))
            self.wave_canvas.itemconfig(
                self.wave_line_glow,
                fill=glow_color,
                width=(3.0 + (7.5 * voiced_drive) + (2.0 * self._burst_energy)),
            )

        n = len(self.wave_bars)
        center = (n - 1) / 2.0
        wave_front = 0.5 + (0.5 * math.sin((self.wave_phase * (0.40 + (0.35 * voiced_drive))) + centroid))
        for i, bar in enumerate(self.wave_bars):
            p = i / max(1.0, n - 1.0)  # 0..1 (left=low freq, right=high freq)

            # Blend low/mid/high energies by bar position.
            w_low = max(0.0, 1.0 - abs(p - 0.15) / 0.26)
            w_mid = max(0.0, 1.0 - abs(p - 0.50) / 0.30)
            w_high = max(0.0, 1.0 - abs(p - 0.85) / 0.26)
            w_sum = max(1e-6, w_low + w_mid + w_high)
            band_energy = ((low * w_low) + (mid * w_mid) + (high * w_high)) / w_sum

            falloff = 1.0 - min(1.0, abs(i - center) / (center + 0.001))
            osc = 0.52 + (0.48 * math.sin((self.wave_phase * (0.95 + (band_energy * 0.75))) + (i * (0.18 + (0.28 * centroid)))))
            front_dist = abs(p - wave_front)
            front_boost = max(0.0, 1.0 - (front_dist / 0.24))
            combined = (0.20 + (0.80 * falloff)) * (0.16 + (0.84 * band_energy)) * (0.72 + (0.38 * front_boost))
            amplitude = voiced_drive * (0.12 + (0.88 * band_energy))
            h = 1.8 + (max_h * amplitude * combined * osc)
            x0, _, x1, _ = self.wave_canvas.coords(bar)
            top = base - h
            bottom = base + (h * (0.54 + (0.14 * front_boost)))
            self.wave_canvas.coords(bar, x0, top, x1, bottom)
            bar_r = int(max(24, min(200, 34 + (88 * band_energy) + (62 * voiced))))
            bar_g = int(max(82, min(220, 106 + (76 * mid) + (34 * falloff))))
            bar_b = int(max(120, min(240, 146 + (76 * high) + (28 * low))))
            color = "#{:02X}{:02X}{:02X}".format(bar_r, bar_g, bar_b)
            self.wave_canvas.itemconfig(bar, fill=color)

        if self.wave_baseline:
            base_color = "#1F2937" if voiced < 0.08 else "#334155"
            self.wave_canvas.itemconfig(self.wave_baseline, fill=base_color, width=(1 if voiced < 0.2 else 2))

        if self.wave_orb and self.wave_orb_glow:
            span = max(1.0, float(self.wave_right - self.wave_left))
            orb_x = self.wave_left + ((0.20 + (0.64 * centroid) + (0.03 * math.sin(self.wave_phase * 0.72))) * span)
            orb_y = base + (math.sin(self.wave_phase * (0.60 + (0.40 * voiced_drive))) * (1 + (11 * voiced_drive)))
            core_r = 2.8 + (5.8 * voiced_drive) + (4 * self._burst_energy)
            glow_r = core_r + 6 + (7 * voiced_drive)
            self.wave_canvas.coords(self.wave_orb, orb_x - core_r, orb_y - core_r, orb_x + core_r, orb_y + core_r)
            self.wave_canvas.coords(
                self.wave_orb_glow,
                orb_x - glow_r,
                orb_y - glow_r,
                orb_x + glow_r,
                orb_y + glow_r,
            )
            self.wave_canvas.itemconfig(self.wave_orb, fill=trail_color)
            self.wave_canvas.itemconfig(self.wave_orb_glow, fill=glow_color)

            # Orb pulse rings for stronger speech reactivity cues.
            for idx, ring in enumerate(self.wave_pulse_rings):
                phase = (self.wave_phase * (0.34 + (idx * 0.08))) + (idx * 1.7)
                pulse = (0.5 + 0.5 * math.sin(phase))
                ring_r = glow_r + 5 + (idx * 8) + (pulse * 6) + (voiced_drive * 14)
                self.wave_canvas.coords(
                    ring,
                    orb_x - ring_r,
                    orb_y - ring_r,
                    orb_x + ring_r,
                    orb_y + ring_r,
                )
                rc_r = min(255, accent_r + 10 + (idx * 6))
                rc_g = min(255, accent_g + 8 + (idx * 4))
                rc_b = min(255, accent_b + 18 + (idx * 3))
                ring_color = "#{:02X}{:02X}{:02X}".format(rc_r, rc_g, rc_b)
                ring_w = max(1, int(1 + voiced_drive + (0.4 * (2 - idx)) + (0.4 * self._burst_energy)))
                self.wave_canvas.itemconfig(ring, outline=ring_color, width=ring_w)

        # Spark particles orbiting the waveform path.
        if self.wave_sparks and self.wave_spark_meta:
            span = max(1.0, float(self.wave_right - self.wave_left))
            speed = 0.02 + (1.05 * voiced_drive)
            drift = 0.02 + (0.20 * voiced_drive)
            spark_base = 1.6 + (2.8 * voiced_drive) + (1.4 * self._burst_energy)
            for idx, spark in enumerate(self.wave_sparks):
                meta = self.wave_spark_meta[idx]
                meta["phase"] += 0.08 + (0.03 * idx) + (0.05 * speed)
                meta["x"] += (meta["vx"] * speed) + (drift * math.sin(meta["phase"] * 0.7))
                if meta["x"] < self.wave_left:
                    meta["x"] = self.wave_right
                elif meta["x"] > self.wave_right:
                    meta["x"] = self.wave_left
                y_wave = base + (voiced_drive * max_h * 0.44 * math.sin((meta["x"] / span) * 8.6 + self.wave_phase))
                meta["y"] = y_wave + (meta["amp"] * 0.06 * math.sin(meta["phase"] * 1.5))
                r = spark_base * (0.72 + 0.28 * math.sin(meta["phase"] + (idx * 0.21)))
                self.wave_canvas.coords(spark, meta["x"] - r, meta["y"] - r, meta["x"] + r, meta["y"] + r)
                s_r = min(255, accent_r + 18 + (idx % 3) * 10)
                s_g = min(255, accent_g + 24)
                s_b = min(255, accent_b + 30)
                spark_color = "#{:02X}{:02X}{:02X}".format(s_r, s_g, s_b)
                self.wave_canvas.itemconfig(spark, fill=spark_color)

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
            # Stronger mapping for clearer quiet-vs-speaking contrast.
            boosted = min(1.0, (val ** 0.72) * 1.75)
            self.audio_level_target = 0.0 if boosted < 0.012 else boosted
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
            if self.audio_level_target <= 0.001:
                self.audio_features_target["low"] = 0.34
                self.audio_features_target["mid"] = 0.33
                self.audio_features_target["high"] = 0.33
                self.audio_features_target["centroid"] = 0.50
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
            text="Expand",
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

        self.history_feedback_var = tk.StringVar(value="")
        feedback_label = tk.Label(
            frame,
            textvariable=self.history_feedback_var,
            bg="#0B1220",
            fg="#93C5FD",
            font=("Segoe UI", 8),
            anchor="w",
            padx=10,
            pady=2,
        )
        feedback_label.pack(fill=tk.X)

        list_container = tk.Frame(frame, bg="#0F172A")
        list_container.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self.history_canvas = tk.Canvas(
            list_container,
            bg="#0F172A",
            highlightthickness=0,
            bd=0,
        )
        scrollbar = tk.Scrollbar(list_container, orient=tk.VERTICAL, command=self.history_canvas.yview)
        self.history_canvas.configure(yscrollcommand=scrollbar.set)

        self.history_items_frame = tk.Frame(self.history_canvas, bg="#0F172A")
        history_window_id = self.history_canvas.create_window((0, 0), window=self.history_items_frame, anchor="nw")

        def _on_items_configure(_event):
            if self.history_canvas:
                self.history_canvas.configure(scrollregion=self.history_canvas.bbox("all"))

        def _on_canvas_configure(event):
            if self.history_canvas:
                self.history_canvas.itemconfigure(history_window_id, width=event.width)

        self.history_items_frame.bind("<Configure>", _on_items_configure)
        self.history_canvas.bind("<Configure>", _on_canvas_configure)

        self.history_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

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
            interval = 36
        elif status == TranscriptionStatus.PROCESSING:
            self._animate_geometric_strip(mode="processing")
            self._animate_waveform(mode="processing")
            interval = 32
        elif status == TranscriptionStatus.TRANSCRIBING:
            self._animate_geometric_strip(mode="transcribing")
            self._animate_waveform(mode="transcribing")
            interval = 30
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
                self.history_toggle_btn.configure(text="Expand")
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
            self.history_toggle_btn.configure(text=("Compact" if self.history_expanded else "Expand"))
        self._render_history_panel()

    def _toggle_history_item_details(self, item_id: int):
        if item_id in self.history_item_expanded_ids:
            self.history_item_expanded_ids.discard(item_id)
        else:
            self.history_item_expanded_ids.add(item_id)
        self._render_history_panel()

    def _show_history_feedback(self, message: str, clear_after_ms: int = 1400):
        if not self.history_feedback_var:
            return
        self.history_feedback_var.set(message)
        if self.history_feedback_job and self.history_window:
            try:
                self.history_window.after_cancel(self.history_feedback_job)
            except Exception:
                pass
        if self.history_window:
            self.history_feedback_job = self.history_window.after(
                max(500, int(clear_after_ms)),
                lambda: self.history_feedback_var.set(""),
            )

    def _copy_history_item(self, text: str):
        safe_text = (text or "").strip()
        if not safe_text or not self.root:
            self._show_history_feedback("Nothing to copy.")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(safe_text)
            self.root.update_idletasks()
            self._show_history_feedback("Copied full transcript.")
        except Exception:
            self._show_history_feedback("Copy failed.")

    def _render_history_panel(self):
        if not self.history_items_frame:
            return

        for child in self.history_items_frame.winfo_children():
            child.destroy()

        if not self.recent_transcriptions:
            empty = tk.Label(
                self.history_items_frame,
                text="No transcriptions yet in this session.",
                bg="#0F172A",
                fg="#9CA3AF",
                font=("Segoe UI", 9),
                anchor="w",
                justify=tk.LEFT,
                padx=10,
                pady=8,
            )
            empty.pack(fill=tk.X)
            return

        rows = list(self.recent_transcriptions)[::-1]
        if not self.history_expanded:
            rows = rows[:8]

        for item in rows:
            item_id = int(item.get("id", 0))
            full_text = str(item.get("full_text", "")).strip()
            preview = str(item.get("preview", "")).strip()
            show_full = item_id in self.history_item_expanded_ids
            display_text = full_text if show_full else preview
            can_expand = len(full_text) > len(preview)

            card = tk.Frame(
                self.history_items_frame,
                bg="#111827",
                highlightthickness=1,
                highlightbackground="#1E293B",
            )
            card.pack(fill=tk.X, padx=0, pady=4)

            header = tk.Frame(card, bg="#111827")
            header.pack(fill=tk.X, padx=8, pady=(6, 2))

            meta = tk.Label(
                header,
                text="[{ts}] dur={dur:.1f}s proc={proc:.2f}s rtf={rtf:.2f}x".format(
                    ts=item["ts"],
                    dur=item["audio_duration"],
                    proc=item["processing_time"],
                    rtf=item["rtf"],
                ),
                bg="#111827",
                fg="#93C5FD",
                font=("Consolas", 8, "bold"),
                anchor="w",
                justify=tk.LEFT,
                pady=0,
            )
            meta.pack(side=tk.LEFT, fill=tk.X, expand=True)

            copy_btn = tk.Button(
                header,
                text="⧉",
                command=lambda txt=full_text: self._copy_history_item(txt),
                bg="#111827",
                fg="#C4D9F2",
                activebackground="#111827",
                activeforeground="#FFFFFF",
                relief=tk.FLAT,
                bd=0,
                highlightthickness=0,
                padx=2,
                pady=0,
                font=("Segoe UI Symbol", 10, "bold"),
                cursor="hand2",
            )
            copy_btn.pack(side=tk.RIGHT)

            message = tk.Label(
                card,
                text=display_text,
                bg="#111827",
                fg="#D1D5DB",
                font=("Segoe UI", 9),
                anchor="w",
                justify=tk.LEFT,
                wraplength=520,
                padx=8,
                pady=(0, 6),
            )
            message.pack(fill=tk.X)

            if can_expand:
                actions = tk.Frame(card, bg="#111827")
                actions.pack(fill=tk.X, padx=8, pady=(0, 6))
                expand_btn = tk.Button(
                    actions,
                    text=("Less" if show_full else "More"),
                    command=lambda i=item_id: self._toggle_history_item_details(i),
                    bg="#111827",
                    fg="#60A5FA",
                    activebackground="#111827",
                    activeforeground="#93C5FD",
                    relief=tk.FLAT,
                    bd=0,
                    highlightthickness=0,
                    padx=0,
                    pady=2,
                    font=("Segoe UI", 8, "bold"),
                    cursor="hand2",
                )
                expand_btn.pack(side=tk.LEFT)

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
        safe_text = (text or "").strip()
        if not safe_text:
            return
        preview_source = safe_text.replace("\n", " ")
        preview = preview_source[:140] + ("..." if len(preview_source) > 140 else "")
        proc = max(0.001, float(processing_time))
        rtf = float(audio_duration) / proc if audio_duration > 0 else 0.0
        self.history_event_seq += 1
        item = {
            "id": self.history_event_seq,
            "ts": datetime.now().strftime("%H:%M:%S"),
            "audio_duration": float(audio_duration),
            "processing_time": float(processing_time),
            "rtf": float(rtf),
            "preview": preview,
            "full_text": safe_text,
        }
        self.recent_transcriptions.append(item)
        valid_ids = {int(entry.get("id", -1)) for entry in self.recent_transcriptions}
        self.history_item_expanded_ids.intersection_update(valid_ids)
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
            # Update text
            self.status_var.set(message)
            self._refresh_dock_text(status=status)

            # Update progress bar based on status
            pb = getattr(self, "progress_bar", None)
            if status == TranscriptionStatus.LISTENING:
                # Show only while actively listening.
                self.window.deiconify()
                self.window.lift()
                # Fresh motif each listening cycle for a "unique every time" feel.
                self._init_geometric_motif(seed=(time.time_ns() & 0xFFFF))
                if pb:
                    pb.configure(mode='indeterminate')
                    pb.start(10)  # Slow pulse
                self._start_animation(status)
            else:
                # Hide overlay once listening stops; dock/tray already show processing/transcribing states.
                self.window.withdraw()
                self._stop_animation()
                if pb:
                    pb.stop()
                self.progress_var.set(0)
                if self.preview_var:
                    self.preview_var.set("")
                self._bubble_tokens.clear()
                self._last_stream_word_count = 0
                if self.word_stream_canvas:
                    self.word_stream_canvas.delete("all")
             
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
        y_mid = 18
        for i, token in enumerate(reversed(self._bubble_tokens)):
            age = i / max(1, len(self._bubble_tokens) - 1)
            txt_color = "#EAF4FF" if age < 0.33 else ("#CFE3F7" if age < 0.66 else "#9DB8D2")
            pad_x = 6
            # Width estimate avoids expensive font metrics and keeps updates cheap.
            width = (len(token) * 8) + (pad_x * 2)
            x0 = x - width
            x1 = x
            if x1 < 6:
                break
            y = y_mid - 7 if (i % 2 == 0) else y_mid + 7
            # Soft shadow + text only (no box) for a cleaner transparent look.
            c.create_text((x0 + x1) / 2 + 1, y + 1, text=token, fill="#1E293B", font=("Segoe UI", 10, "bold"))
            c.create_text((x0 + x1) / 2, y, text=token, fill=txt_color, font=("Segoe UI", 10, "bold"))
            x = x0 - 10

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
            if self.history_feedback_job and self.history_window:
                try:
                    self.history_window.after_cancel(self.history_feedback_job)
                except Exception:
                    pass
                self.history_feedback_job = None
            
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
