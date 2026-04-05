#!/usr/bin/env python3
"""VoiceFlow Visual Indicators
===========================
Bottom-screen transcription status overlay similar to Wispr Flow
"""

import json
import logging
import math
import os
import random
import re
import threading
import time
import tkinter as tk
from collections import deque
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from ..utils.guardrails import (
    safe_visual_update,
    with_error_recovery,
)
from ..utils.settings import (
    append_jsonl_bounded,
    config_dir,
    config_path,
    load_json_dict_bounded,
    read_text_tail_lines,
)
from .visual_config import ColorTheme, get_visual_config

logger = logging.getLogger(__name__)

_ANIMATION_PREFS: Dict[str, Any] = {
    "quality": "auto",
    "reduced_motion": False,
    "target_fps": 28,
}

_UI_NEUTRAL_PALETTE: Dict[str, str] = {
    "panel_bg": "#10161D",
    "panel_surface": "#151C25",
    "panel_surface_alt": "#1A2330",
    "panel_border": "#253445",
    "panel_border_soft": "#31445A",
    "text_primary": "#E8EEF5",
    "text_secondary": "#BECAD7",
    "text_muted": "#8596A9",
    "accent": "#86AEE3",
    "accent_strong": "#5B84BC",
    "accent_soft": "#E4EDF9",
    "success": "#7EAD8A",
    "warning": "#B99B66",
    "badge_live_bg": "#1B2A22",
    "badge_live_fg": "#B8D8C1",
    "badge_correction_bg": "#1A2533",
    "badge_correction_fg": "#B7D0EE",
    "badge_retry_bg": "#2B2418",
    "badge_retry_fg": "#E1CFAD",
    "success_bg": "#203629",
    "success_fg": "#CAE7D2",
}

_UI_LIGHT_PALETTE: Dict[str, str] = {
    "panel_bg": "#F3F6FA",
    "panel_surface": "#FFFFFF",
    "panel_surface_alt": "#EAF0F7",
    "panel_border": "#CCD7E3",
    "panel_border_soft": "#B5C6D8",
    "text_primary": "#18222C",
    "text_secondary": "#415163",
    "text_muted": "#6E8094",
    "accent": "#477FC9",
    "accent_strong": "#2F66AD",
    "accent_soft": "#F2F7FF",
    "success": "#46765B",
    "warning": "#936A32",
    "badge_live_bg": "#E4EFE7",
    "badge_live_fg": "#365744",
    "badge_correction_bg": "#E6EEF8",
    "badge_correction_fg": "#35547A",
    "badge_retry_bg": "#F3EBDD",
    "badge_retry_fg": "#735426",
    "success_bg": "#DDECDF",
    "success_fg": "#2D533A",
}

_HISTORY_FILTER_OPTIONS: tuple[tuple[str, str], ...] = (
    ("all", "All"),
    ("live", "Live"),
    ("corrections", "Corrections"),
    ("retries", "Retries"),
)
_CORRECTION_FEEDBACK_HANDLER: Optional[Callable[[str, str, Dict[str, Any]], None]] = None


def _hex_to_rgb(color: str) -> tuple[int, int, int]:
    safe = str(color or "").strip().lstrip("#")
    if len(safe) != 6:
        return 255, 255, 255
    try:
        return int(safe[0:2], 16), int(safe[2:4], 16), int(safe[4:6], 16)
    except Exception:
        return 255, 255, 255


def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
    r, g, b = [max(0, min(255, int(channel))) for channel in rgb]
    return f"#{r:02X}{g:02X}{b:02X}"


def _mix_color(color_a: str, color_b: str, ratio: float) -> str:
    ratio = max(0.0, min(1.0, float(ratio)))
    r1, g1, b1 = _hex_to_rgb(color_a)
    r2, g2, b2 = _hex_to_rgb(color_b)
    mixed = (
        round(r1 + ((r2 - r1) * ratio)),
        round(g1 + ((g2 - g1) * ratio)),
        round(b1 + ((b2 - b1) * ratio)),
    )
    return _rgb_to_hex(mixed)


def _build_ui_palette(color_scheme: Dict[str, str], theme_value: str) -> Dict[str, str]:
    light_mode = str(theme_value or "").strip().lower() == ColorTheme.LIGHT_MODE.value
    palette = dict(_UI_LIGHT_PALETTE if light_mode else _UI_NEUTRAL_PALETTE)
    accent_source = str((color_scheme or {}).get("accent_color", palette["accent"]) or palette["accent"]).strip()
    success_source = str((color_scheme or {}).get("success_color", palette["success"]) or palette["success"]).strip()
    warning_source = str((color_scheme or {}).get("warning_color", palette["warning"]) or palette["warning"]).strip()

    if light_mode:
        palette["accent"] = _mix_color(accent_source, "#FFFFFF", 0.10)
        palette["accent_strong"] = _mix_color(accent_source, "#000000", 0.12)
        palette["accent_soft"] = _mix_color(accent_source, "#FFFFFF", 0.84)
        palette["success"] = _mix_color(success_source, "#000000", 0.08)
        palette["warning"] = _mix_color(warning_source, "#000000", 0.06)
    else:
        palette["accent"] = _mix_color(accent_source, "#FFFFFF", 0.18)
        palette["accent_strong"] = _mix_color(accent_source, "#000000", 0.24)
        palette["accent_soft"] = _mix_color(accent_source, "#FFFFFF", 0.80)
        palette["success"] = _mix_color(success_source, "#FFFFFF", 0.16)
        palette["warning"] = _mix_color(warning_source, "#FFFFFF", 0.08)

    palette["badge_live_bg"] = _mix_color(palette["success"], palette["panel_surface"], 0.78)
    palette["badge_live_fg"] = _mix_color(palette["success"], palette["text_primary"], 0.36)
    palette["badge_correction_bg"] = _mix_color(palette["accent"], palette["panel_surface"], 0.74)
    palette["badge_correction_fg"] = _mix_color(palette["accent"], palette["text_primary"], 0.28)
    palette["badge_retry_bg"] = _mix_color(palette["warning"], palette["panel_surface"], 0.72)
    palette["badge_retry_fg"] = _mix_color(palette["warning"], palette["text_primary"], 0.34)
    palette["success_bg"] = _mix_color(palette["success"], palette["panel_surface"], 0.64)
    palette["success_fg"] = _mix_color(palette["success"], palette["text_primary"], 0.40)
    return palette


def set_correction_feedback_handler(handler: Optional[Callable[[str, str, Dict[str, Any]], None]]) -> None:
    global _CORRECTION_FEEDBACK_HANDLER
    _CORRECTION_FEEDBACK_HANDLER = handler


def _emit_correction_feedback_learning(original_text: str, corrected_text: str, metadata: Dict[str, Any]) -> None:
    handler = _CORRECTION_FEEDBACK_HANDLER
    if not handler:
        return
    try:
        handler(str(original_text or ""), str(corrected_text or ""), dict(metadata or {}))
    except Exception as exc:
        logger.debug("Correction feedback learning dispatch failed: %s", exc)

class TranscriptionStatus(Enum):
    """Status states for visual indication"""
    IDLE = "idle"
    LISTENING = "listening"
    PROCESSING = "processing"
    TRANSCRIBING = "transcribing"
    COMPLETE = "complete"
    ERROR = "error"

class BottomScreenIndicator:
    """Bottom-screen overlay indicator for transcription status
    Similar to Wispr Flow - small, unobtrusive, informative
    Thread-safe for background hotkey calls
    """

    def __init__(self):
        self.window: Optional[tk.Toplevel] = None
        self.dock_window: Optional[tk.Toplevel] = None
        self.history_window: Optional[tk.Toplevel] = None
        self.root: Optional[tk.Tk] = None
        self.status_var: Optional[tk.StringVar] = None
        self.status_label = None
        self.progress_var: Optional[tk.DoubleVar] = None
        self.dock_var: Optional[tk.StringVar] = None
        self.history_canvas: Optional[tk.Canvas] = None
        self.history_items_frame: Optional[tk.Frame] = None
        self.history_feedback_var: Optional[tk.StringVar] = None
        self.history_summary_var: Optional[tk.StringVar] = None
        self.history_feedback_job = None
        self.history_correction_btn: Optional[tk.Button] = None
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
        self.animation_quality = "auto"
        self.reduced_motion = False
        self.target_fps = 28
        self._anim_last_frame_ms = 0.0
        self._anim_load_factor = 1.0
        self._overlay_visible = False
        self._fade_job = None
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
        self.ripple_rings = []
        self.ripple_phases = [0.0, 0.25, 0.5, 0.75]
        self.ripple_orb = None
        self.ripple_orb_glow = None
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
        self.pending_history_events = deque(maxlen=200)
        self.history_item_expanded_ids = set()
        self.history_event_seq = 0
        self.history_visible = False
        self.history_expanded = False
        self.history_geometry_compact = None
        self.history_geometry_expanded = None
        self.history_correction_mode = False
        self.history_correction_target_id: Optional[int] = None
        self.history_correction_drafts: Dict[int, str] = {}
        self.history_review_pinned = False
        self.history_last_saved_corrections: Dict[int, tuple[str, str]] = {}
        self.history_correction_feedback_path: Path = config_dir() / "transcription_corrections.jsonl"
        self.history_store_path: Path = config_dir() / "recent_history_events.jsonl"
        self.history_seen_fingerprints = set()
        self.history_seen_fingerprint_order = deque(maxlen=1200)
        self.history_session_started_at = time.time()
        self.history_active_filter = "all"
        self.history_filter_buttons: Dict[str, tk.Button] = {}
        self.ui_actions_path: Path = config_dir() / "ui_actions.jsonl"
        self.ui_action_last_processed_ts = time.time()
        self.ui_action_seen = deque(maxlen=240)
        self.ui_action_allowed = {"open_recent_history", "open_correction_review"}
        self.ui_action_max_age_seconds = 180.0
        self.ui_action_future_skew_seconds = 5.0
        self.ui_action_session_floor = self.history_session_started_at - 2.0
        self.dock_enabled = False
        self.noise_floor = 0.0
        self.wave_energy_history = deque([0.0] * 84, maxlen=84)
        self.icon_size = 0
        self.geo_w = 0
        self.geo_h = 0
        self.wave_w = 460
        self.wave_h = 112
        self.word_stream_canvas = None
        self.status_badge_frame = None
        self._bubble_tokens = deque(maxlen=16)
        self._last_stream_word_count = 0
        self._last_preview_words: list[str] = []
        self._preview_correction_tokens: Dict[str, float] = {}
        self.live_caption_words = 8
        self.live_caption_max_chars = 150
        self.live_caption_font_size = 14
        self.live_caption_correction_window_seconds = 2.0

        # Configuration manager
        self.config_manager = get_visual_config()
        self.ui_palette: Dict[str, str] = dict(_UI_NEUTRAL_PALETTE)
        self._load_live_caption_preferences()
        self._update_visual_settings()
        self.set_animation_preferences(
            quality=_ANIMATION_PREFS.get("quality", "auto"),
            reduced_motion=bool(_ANIMATION_PREFS.get("reduced_motion", False)),
            target_fps=int(_ANIMATION_PREFS.get("target_fps", 28) or 28),
        )
        self.visual_theme = self._default_visual_theme()

        # Start GUI in separate thread for background compatibility
        self._start_gui_thread()

        # Wait for GUI to be ready
        self._wait_for_gui_ready()

    def _update_visual_settings(self):
        """Update visual settings from configuration"""
        req_w, req_h = self.config_manager.get_overlay_dimensions()
        # Compact overlay profile: small, centered, and visually lighter.
        self.width = int(min(500, max(332, req_w + 20)))
        self.height = int(min(220, max(168, req_h + 28)))
        self.wave_w = max(272, self.width - 20)
        colors = self.config_manager.get_color_scheme()
        theme_value = getattr(getattr(self.config_manager, "config", None), "theme", ColorTheme.DEFAULT)
        theme_name = getattr(theme_value, "value", str(theme_value))
        self.ui_palette = _build_ui_palette(colors, theme_name)

        self.bg_color = self.ui_palette["panel_bg"]
        self.text_color = self.ui_palette["text_primary"]
        self.accent_color = self.ui_palette["accent"]
        self.error_color = colors['error_color']
        self.visual_theme = self._default_visual_theme()

    def _ui(self, key: str) -> str:
        return str(self.ui_palette.get(key, _UI_NEUTRAL_PALETTE.get(key, "#FFFFFF")))

    def _load_live_caption_preferences(self) -> None:
        """Load preview presentation options from persisted runtime config."""
        try:
            payload = load_json_dict_bounded(config_path()) or {}
        except Exception:
            payload = {}

        def _bounded_int(name: str, default: int, *, min_value: int, max_value: int) -> int:
            try:
                parsed = int(payload.get(name, default))
            except Exception:
                parsed = default
            return max(min_value, min(max_value, parsed))

        def _bounded_float(name: str, default: float, *, min_value: float, max_value: float) -> float:
            try:
                parsed = float(payload.get(name, default))
            except Exception:
                parsed = default
            return max(min_value, min(max_value, parsed))

        self.live_caption_words = _bounded_int("live_caption_words", 8, min_value=1, max_value=20)
        self.live_caption_max_chars = _bounded_int("live_caption_max_chars", 150, min_value=40, max_value=400)
        self.live_caption_font_size = _bounded_int("live_caption_font_size", 14, min_value=10, max_value=32)
        self.live_caption_correction_window_seconds = _bounded_float(
            "live_caption_correction_window_seconds",
            2.0,
            min_value=0.0,
            max_value=8.0,
        )

    def _default_visual_theme(self) -> Dict[str, str]:
        """Use a restrained, stable palette instead of rotating accents."""
        return {
            "name": "studio",
            "glyph": "",
            "accent": self._ui("accent"),
            "orb": self._ui("accent_soft"),
        }

    def set_animation_preferences(
        self,
        *,
        quality: Optional[str] = None,
        reduced_motion: Optional[bool] = None,
        target_fps: Optional[int] = None,
    ) -> None:
        allowed = {"auto", "high", "balanced", "low"}
        if quality is not None:
            normalized_quality = str(quality or "auto").strip().lower()
            if normalized_quality not in allowed:
                normalized_quality = "auto"
            self.animation_quality = normalized_quality
        if reduced_motion is not None:
            self.reduced_motion = bool(reduced_motion)
        if target_fps is not None:
            try:
                fps_val = int(target_fps)
            except Exception:
                fps_val = 28
            self.target_fps = max(12, min(60, fps_val))

    def _resolve_animation_interval(self, status: TranscriptionStatus) -> int:
        fps = int(max(12, min(60, self.target_fps)))
        quality = self.animation_quality
        if self.reduced_motion:
            fps = min(fps, 18)
        if quality == "high":
            fps = max(fps, 34)
        elif quality == "balanced":
            fps = min(max(fps, 24), 32)
        elif quality == "low":
            fps = min(fps, 18)
        else:
            # Auto mode: adapt gently to frame load.
            if self._anim_load_factor > 1.30:
                fps = max(12, int(fps * 0.72))
            elif self._anim_load_factor > 1.12:
                fps = max(12, int(fps * 0.84))
            elif self._anim_load_factor < 0.70:
                fps = min(40, int(fps * 1.12))

        if status == TranscriptionStatus.LISTENING:
            pass
        elif status == TranscriptionStatus.PROCESSING:
            fps = min(fps + 2, 42)
        elif status == TranscriptionStatus.TRANSCRIBING:
            fps = min(fps + 3, 44)
        return int(max(16, min(84, round(1000.0 / max(12.0, float(fps))))))

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
            self.root.after(300, self._poll_ui_action_requests)

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

    def _poll_ui_action_requests(self):
        """Process tray actions forwarded via shared local queue across runtime processes."""
        if not self.gui_running or not self.root:
            return
        try:
            lines = read_text_tail_lines(
                self.ui_actions_path,
                max_lines=120,
                max_bytes=262144,
                max_line_chars=2048,
            )
            if not lines:
                return

            latest_ts = float(self.ui_action_last_processed_ts)
            now = time.time()
            for raw in lines:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception:
                    continue
                if not isinstance(payload, dict):
                    continue
                action = str(payload.get("action", "")).strip().lower()
                if action not in self.ui_action_allowed:
                    continue
                try:
                    event_ts = float(payload.get("ts", 0.0))
                except Exception:
                    event_ts = 0.0
                if event_ts < self.ui_action_session_floor:
                    continue
                if event_ts > (now + self.ui_action_future_skew_seconds):
                    continue
                if (now - event_ts) > self.ui_action_max_age_seconds:
                    continue
                if event_ts <= self.ui_action_last_processed_ts:
                    continue
                src_pid = int(payload.get("pid", 0) or 0)
                event_key = f"{event_ts:.6f}:{src_pid}:{action}"
                if event_key in self.ui_action_seen:
                    continue
                self.ui_action_seen.append(event_key)
                latest_ts = max(latest_ts, event_ts)

                # Skip local echo; local caller already invoked the same action directly.
                if src_pid == os.getpid():
                    continue
                if action == "open_recent_history":
                    self._open_recent_history_ui()
                elif action == "open_correction_review":
                    self._open_correction_review_ui()
            self.ui_action_last_processed_ts = latest_ts
        except Exception:
            pass
        finally:
            if self.gui_running and self.root:
                self.root.after(300, self._poll_ui_action_requests)

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
            self._overlay_visible = False

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
        reserved_bottom = 138 if self.dock_enabled else 98

        # Keep overlay strictly centered when dock is enabled.
        if self.dock_enabled and self.dock_window:
            x = int((screen_width - self.width) / 2)
            try:
                geo = self.dock_window.geometry()  # e.g. 430x30+745+1008
                dock_y = int(geo.rsplit("+", 1)[-1])
                # Keep animation close to the dock for a tighter visual stack.
                y = int(dock_y - self.height - 1)
            except Exception:
                y = min(y - 8, screen_height - self.height - reserved_bottom)
        else:
            y = min(y - 8, screen_height - self.height - reserved_bottom)

        x = max(8, min(screen_width - self.width - 8, x))
        y = max(10, min(y, screen_height - self.height - reserved_bottom))
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
            height=74,
            bg=self.transparent_key,
            highlightthickness=0,
            bd=0,
        )
        self.wave_canvas.pack(pady=(1, 0))
        self._init_waveform_strip()

        # Status badge row — shows current state (Listening / Processing / Transcribing / Done)
        status_row = tk.Frame(main_frame, bg=self.transparent_key, highlightthickness=0, bd=0)
        status_row.pack(fill=tk.X, padx=6, pady=(0, 1))

        self.status_badge_frame = tk.Frame(
            status_row,
            bg=self._ui("panel_surface"),
            highlightthickness=1,
            highlightbackground=self._ui("panel_border"),
            bd=0,
            padx=8,
            pady=2,
        )
        self.status_badge_frame.pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="")
        self.status_label = tk.Label(
            self.status_badge_frame,
            textvariable=self.status_var,
            bg=self._ui("panel_surface"),
            fg=self._ui("text_muted"),
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        )
        self.status_label.pack()

        hotkey_hint = tk.Label(
            status_row,
            text="Ctrl+Shift to record",
            bg=self.transparent_key,
            fg=self._ui("text_muted"),
            font=("Segoe UI", 7),
            anchor="e",
        )
        hotkey_hint.pack(side=tk.RIGHT, padx=4)

        # Preview text for streaming transcription
        preview_card = tk.Frame(
            main_frame,
            bg=self._ui("panel_surface"),
            highlightbackground=self._ui("panel_border"),
            highlightthickness=1,
            bd=0,
            padx=7,
            pady=4,
        )
        preview_card.pack(fill=tk.X, padx=6, pady=(0, 0))
        self.preview_var = tk.StringVar(value="")
        self.preview_label = tk.Label(
            preview_card,
            textvariable=self.preview_var,
            bg=self._ui("panel_surface"),
            fg=self._ui("text_primary"),
            font=("Segoe UI", max(10, int(self.live_caption_font_size) - 1), "bold"),
            wraplength=self.wave_w - 36,
            justify=tk.LEFT,
            anchor="nw",
            height=5,
        )
        self.preview_label.pack(fill=tk.X)
        self.word_stream_canvas = None

        # Disable progress bar (was perceived as non-audio green block movement).
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = None
        self.preview_label.configure(wraplength=max(120, self.wave_w - 36))

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
        self.wave_h = int(max(74, self.wave_canvas.winfo_reqheight()))
        self.wave_energy_history = deque([0.0] * self.wave_energy_history.maxlen, maxlen=self.wave_energy_history.maxlen)
        self._speech_level = 0.0
        self._silence_floor_est = 0.0
        # Clear old refs
        self.wave_bars = []
        self.wave_baseline = None
        self.wave_line = None
        self.wave_line_glow = None
        self.wave_fill = None
        self.wave_scan = None
        self.wave_trail_line = None
        self.wave_trail_glow = None
        self.wave_orb = None
        self.wave_orb_glow = None
        self.wave_pulse_rings = []
        self.wave_sparks = []
        self.wave_spark_meta = []
        self.space_star_ids = []
        self.space_star_meta = []
        self.space_core = None
        self.space_glow = None
        self.space_ring = None
        self.space_arcs = []

        cx = self.wave_w // 2
        cy = self.wave_h // 2

        # Soft background glow behind orb
        self.ripple_orb_glow = self.wave_canvas.create_oval(
            cx - 14, cy - 10, cx + 14, cy + 10,
            fill=_mix_color(self._ui("accent"), self.transparent_key, 0.72),
            outline="",
        )
        # Center orb — bright core
        self.ripple_orb = self.wave_canvas.create_oval(
            cx - 4, cy - 3, cx + 4, cy + 3,
            fill=self._ui("accent"),
            outline="",
        )
        # 4 ripple rings — staggered phases
        self.ripple_rings = []
        self.ripple_phases = [0.0, 0.25, 0.5, 0.75]
        for _ in range(4):
            ring = self.wave_canvas.create_oval(
                cx - 2, cy - 2, cx + 2, cy + 2,
                outline=self._ui("accent"),
                fill="",
                width=2,
            )
            self.ripple_rings.append(ring)
        # Layer: glow behind orb, orb in front, rings in front
        self.wave_canvas.tag_raise(self.ripple_orb_glow)
        for ring in self.ripple_rings:
            self.wave_canvas.tag_raise(ring)
        self.wave_canvas.tag_raise(self.ripple_orb)

    def _animate_waveform(self, mode: str = "listening"):
        if not self.wave_canvas or not self.ripple_rings:
            return

        # --- Signal processing (unchanged) ---
        target = max(0.0, min(1.0, float(self.audio_level_target)))
        delta = target - self.audio_level_smoothed
        alpha = 0.82 if delta > 0 else 0.34
        self.audio_level_smoothed += alpha * delta
        if target <= 0.001 and self.audio_level_smoothed < 0.08:
            self.audio_level_smoothed *= 0.56
        lvl = self.audio_level_smoothed

        for key in ("low", "mid", "high", "centroid"):
            tv = max(0.0, min(1.0, float(self.audio_features_target.get(key, 0.0))))
            sv = float(self.audio_features_smoothed.get(key, tv))
            blend = 0.42 if tv > sv else 0.28
            self.audio_features_smoothed[key] = sv + (tv - sv) * blend

        if mode == "idle":
            lvl *= 0.08

        target_agc = max(0.04, min(1.0, lvl))
        self._visual_agc = (self._visual_agc * 0.94) + (target_agc * 0.06)
        agc_scale = 0.85 + (0.95 / max(0.08, self._visual_agc))
        agc_scale = max(0.95, min(2.35, agc_scale))
        voiced_raw = min(1.0, lvl * agc_scale)

        if voiced_raw < 0.18:
            self._silence_floor_est = (self._silence_floor_est * 0.97) + (voiced_raw * 0.03)
        floor = max(0.012, min(0.18, self._silence_floor_est))
        voiced = max(0.0, min(1.0, (voiced_raw - floor) / max(0.12, 1.0 - floor)))

        self._speech_level = (self._speech_level * 0.78) + (voiced * 0.22)
        voiced = self._speech_level
        voiced_drive = max(0.0, min(1.0, voiced ** 0.86))
        self.wave_phase += 0.06 + (2.0 * voiced_drive)
        self._color_phase += 0.015 + (0.10 * voiced_drive)

        speech_now = voiced > 0.12
        if speech_now and not self._speech_active:
            self._burst_energy = 1.0
        self._speech_active = speech_now
        self._burst_energy = max(0.0, (self._burst_energy * 0.91) - 0.010)
        self.wave_energy_history.append(voiced)

        # --- Ripple ring animation ---
        cx = self.wave_w // 2
        cy = self.wave_h // 2
        max_rx = cx - 5
        max_ry = cy - 4

        # Phase advance: slow idle pulse, dramatically faster during speech/burst
        phase_rate = 0.003 + 0.062 * voiced_drive + 0.028 * self._burst_energy

        # Spectrum palette: each ring has its own hue, rotates slowly with _color_phase
        # Hue offsets (in radians): blue, teal, violet, amber — visually distinct
        _RING_HUE_BASES = [
            ("#5B9EE8", "#60E8D8"),   # ring 0: blue → teal
            ("#A060E8", "#E060B8"),   # ring 1: violet → pink
            ("#E8A060", "#E8D460"),   # ring 2: amber → gold
            ("#60E880", "#60C8E8"),   # ring 3: green → sky
        ]
        color_phase_offset = self._color_phase % (math.pi * 2.0)
        color_lift = min(1.0, 0.18 * voiced_drive + 0.22 * self._burst_energy)

        for i, ring in enumerate(self.ripple_rings):
            self.ripple_phases[i] = (self.ripple_phases[i] + phase_rate) % 1.0
            phase = self.ripple_phases[i]

            # Ease-out expansion: fast start, slows near edge
            ease = phase ** 0.55

            rx = max(2.0, max_rx * ease)
            ry = max(1.5, max_ry * ease)

            # Opacity: fades as ring expands; burst dramatically boosts early opacity
            opacity = max(0.0, 1.0 - phase)
            opacity = min(1.0, opacity + 0.30 * self._burst_energy * (1.0 - phase))

            if opacity < 0.04:
                self.wave_canvas.coords(ring, -20, -20, -18, -18)
                continue

            # Each ring cycles between its two hue endpoints, driven by color_phase
            hue_a, hue_b = _RING_HUE_BASES[i]
            hue_cycle = (math.sin(color_phase_offset + i * math.pi * 0.5) + 1.0) * 0.5
            ring_base = _mix_color(hue_a, hue_b, hue_cycle)
            # Brighten with voice level
            ring_bright = _mix_color(ring_base, "#FFFFFF", color_lift)
            ring_color = _mix_color(ring_bright, self.transparent_key, 1.0 - opacity)
            ring_w = max(1, int((2.0 + voiced_drive * 2.5 + self._burst_energy * 1.5) * opacity))

            self.wave_canvas.coords(ring, cx - rx, cy - ry, cx + rx, cy + ry)
            self.wave_canvas.itemconfig(ring, outline=ring_color, width=ring_w)

        # Use ring 2 (amber/gold) as orb base, brightens with voice
        accent_warm = _mix_color(self._ui("accent"), "#E8A060", min(1.0, voiced_drive * 0.75))

        # --- Center orb ---
        if self.ripple_orb and self.ripple_orb_glow:
            orb_r_x = 3 + 10 * voiced_drive + 4 * self._burst_energy
            orb_r_y = 2.5 + 7 * voiced_drive + 3 * self._burst_energy
            orb_color = _mix_color(accent_warm, "#FFFFFF", 0.15 + 0.60 * voiced_drive)
            self.wave_canvas.coords(
                self.ripple_orb,
                cx - orb_r_x, cy - orb_r_y,
                cx + orb_r_x, cy + orb_r_y,
            )
            self.wave_canvas.itemconfig(self.ripple_orb, fill=orb_color)

            glow_r_x = orb_r_x + 7 + 16 * voiced_drive + 8 * self._burst_energy
            glow_r_y = orb_r_y + 5 + 12 * voiced_drive + 6 * self._burst_energy
            glow_opacity = 0.32 + 0.58 * voiced_drive + 0.20 * self._burst_energy
            glow_color = _mix_color(accent_warm, self.transparent_key, 1.0 - min(1.0, glow_opacity))
            self.wave_canvas.coords(
                self.ripple_orb_glow,
                cx - glow_r_x, cy - glow_r_y,
                cx + glow_r_x, cy + glow_r_y,
            )
            self.wave_canvas.itemconfig(self.ripple_orb_glow, fill=glow_color)

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
            boosted = min(1.0, (val ** 0.60) * 2.05)
            if val > 0.18:
                boosted = min(1.0, boosted + ((val - 0.18) * 0.28))
            self.audio_level_target = 0.0 if boosted < 0.010 else boosted
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
        self.dock_window.wm_attributes("-alpha", 0.92)
        self.dock_window.configure(bg=self._ui("panel_bg"))

        dock_w, dock_h = 372, 26
        x = (screen_width - dock_w) // 2
        y = screen_height - dock_h - 80
        self.dock_window.geometry(f"{dock_w}x{dock_h}+{x}+{y}")

        dock_frame = tk.Frame(
            self.dock_window,
            bg=self._ui("panel_bg"),
            highlightthickness=1,
            highlightbackground=self._ui("panel_border"),
        )
        dock_frame.pack(fill=tk.BOTH, expand=True)

        self.dock_var = tk.StringVar(value="Ready")
        dock_label = tk.Label(
            dock_frame,
            textvariable=self.dock_var,
            bg=self._ui("panel_bg"),
            fg=self._ui("text_secondary"),
            font=("Segoe UI", 8, "bold"),
            anchor="w",
            padx=8,
        )
        dock_label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        history_btn = tk.Button(
            dock_frame,
            text="History",
            command=self._toggle_history_panel,
            bg=self._ui("panel_surface"),
            fg=self._ui("text_secondary"),
            activebackground=self._ui("panel_surface_alt"),
            activeforeground=self._ui("text_primary"),
            relief=tk.FLAT,
            padx=8,
            pady=1,
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
            highlightthickness=0,
            bd=0,
        )
        history_btn.pack(side=tk.RIGHT, padx=(0, 4), pady=2)

        minimize_btn = tk.Button(
            dock_frame,
            text="Hide",
            command=lambda: self._set_dock_enabled_ui(False),
            bg=self._ui("panel_surface"),
            fg=self._ui("text_secondary"),
            activebackground=self._ui("panel_surface_alt"),
            activeforeground=self._ui("text_primary"),
            relief=tk.FLAT,
            padx=8,
            pady=1,
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
            highlightthickness=0,
            bd=0,
        )
        minimize_btn.pack(side=tk.RIGHT, padx=(0, 4), pady=2)
        if not self.dock_enabled:
            self.dock_window.withdraw()

    def _setup_history_panel(self, screen_width: int, screen_height: int):
        """Quick recent-transcription panel opened from the dock."""
        if not self.root:
            return
        self.history_window = tk.Toplevel(self.root)
        self.history_window.overrideredirect(True)
        self.history_window.wm_attributes("-topmost", True)
        self.history_window.wm_attributes("-alpha", 0.97)
        self.history_window.configure(bg=self._ui("panel_bg"))

        panel_w, panel_h = 500, 208
        x = (screen_width - panel_w) // 2
        y = screen_height - panel_h - 58
        self.history_geometry_compact = f"{panel_w}x{panel_h}+{x}+{y}"
        self.history_geometry_expanded = f"{panel_w}x392+{x}+{max(20, y - 184)}"
        self.history_window.geometry(self.history_geometry_compact)

        frame = tk.Frame(
            self.history_window,
            bg=self._ui("panel_bg"),
            highlightthickness=1,
            highlightbackground=self._ui("panel_border"),
        )
        frame.pack(fill=tk.BOTH, expand=True)

        header = tk.Label(
            frame,
            text="Recent History",
            bg=self._ui("panel_bg"),
            fg=self._ui("text_primary"),
            font=("Segoe UI", 9, "bold"),
            anchor="w",
            padx=8,
            pady=4,
        )
        header.pack(fill=tk.X)

        actions = tk.Frame(frame, bg=self._ui("panel_bg"))
        actions.pack(fill=tk.X, padx=8, pady=(0, 4))

        self.history_toggle_btn = tk.Button(
            actions,
            text="Expand",
            command=self._toggle_history_expanded,
            bg=self._ui("panel_surface"),
            fg=self._ui("text_secondary"),
            activebackground=self._ui("panel_surface_alt"),
            activeforeground=self._ui("text_primary"),
            relief=tk.FLAT,
            padx=8,
            pady=1,
            font=("Segoe UI", 8, "bold"),
            bd=0,
            highlightthickness=0,
        )
        self.history_toggle_btn.pack(side=tk.LEFT)

        self.history_correction_btn = tk.Button(
            actions,
            text="Review",
            command=self._toggle_history_correction_mode,
            bg=self._ui("panel_surface"),
            fg=self._ui("text_secondary"),
            activebackground=self._ui("panel_surface_alt"),
            activeforeground=self._ui("text_primary"),
            relief=tk.FLAT,
            padx=8,
            pady=1,
            font=("Segoe UI", 8, "bold"),
            bd=0,
            highlightthickness=0,
        )
        self.history_correction_btn.pack(side=tk.LEFT, padx=(4, 0))

        close_btn = tk.Button(
            actions,
            text="Close",
            command=self._toggle_history_panel,
            bg=self._ui("panel_surface"),
            fg=self._ui("text_secondary"),
            activebackground=self._ui("panel_surface_alt"),
            activeforeground=self._ui("text_primary"),
            relief=tk.FLAT,
            padx=8,
            pady=1,
            font=("Segoe UI", 8, "bold"),
            bd=0,
            highlightthickness=0,
        )
        close_btn.pack(side=tk.RIGHT)

        filters = tk.Frame(frame, bg=self._ui("panel_bg"))
        filters.pack(fill=tk.X, padx=8, pady=(0, 4))
        self.history_filter_buttons = {}
        for key, label in _HISTORY_FILTER_OPTIONS:
            btn = tk.Button(
                filters,
                text=label,
                command=lambda value=key: self._set_history_filter(value),
                bg=self._ui("panel_surface"),
                fg=self._ui("text_muted"),
                activebackground=self._ui("panel_surface_alt"),
                activeforeground=self._ui("text_primary"),
                relief=tk.FLAT,
                padx=7,
                pady=1,
                font=("Segoe UI", 8, "bold"),
                bd=0,
                highlightthickness=0,
                cursor="hand2",
            )
            btn.pack(side=tk.LEFT, padx=(0, 4))
            self.history_filter_buttons[key] = btn
        self._refresh_history_filter_buttons()

        self.history_summary_var = tk.StringVar(value="")
        summary_label = tk.Label(
            frame,
            textvariable=self.history_summary_var,
            bg=self._ui("panel_bg"),
            fg=self._ui("text_muted"),
            font=("Segoe UI", 8),
            anchor="w",
            padx=8,
            pady=1,
        )
        summary_label.pack(fill=tk.X)

        self.history_feedback_var = tk.StringVar(value="")
        feedback_label = tk.Label(
            frame,
            textvariable=self.history_feedback_var,
            bg=self._ui("panel_bg"),
            fg=self._ui("text_muted"),
            font=("Segoe UI", 8),
            anchor="w",
            padx=8,
            pady=1,
        )
        feedback_label.pack(fill=tk.X)

        list_container = tk.Frame(frame, bg=self._ui("panel_surface"))
        list_container.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self.history_canvas = tk.Canvas(
            list_container,
            bg=self._ui("panel_surface"),
            highlightthickness=0,
            bd=0,
        )
        scrollbar = tk.Scrollbar(list_container, orient=tk.VERTICAL, command=self.history_canvas.yview)
        self.history_canvas.configure(yscrollcommand=scrollbar.set)

        self.history_items_frame = tk.Frame(self.history_canvas, bg=self._ui("panel_surface"))
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
        if not self.dock_enabled and not self.history_review_pinned:
            self.history_visible = False
            if self.history_window:
                self.history_window.withdraw()
        if self.window:
            self._position_overlay(self.window.winfo_screenwidth(), self.window.winfo_screenheight())
        self._refresh_dock_text()

    def get_dock_enabled(self) -> bool:
        return bool(self.dock_enabled)

    @staticmethod
    def _window_exists(window: Optional[tk.Toplevel]) -> bool:
        if not window:
            return False
        try:
            return bool(window.winfo_exists())
        except Exception:
            return False

    def _ensure_history_panel_ui(self) -> bool:
        if self._window_exists(self.history_window):
            return True
        if not self.root:
            return False
        try:
            screen_width = int(self.root.winfo_screenwidth())
            screen_height = int(self.root.winfo_screenheight())
            if not self._window_exists(self.dock_window):
                self._setup_dock_window(screen_width, screen_height)
            self._setup_history_panel(screen_width, screen_height)
            return self._window_exists(self.history_window)
        except Exception as e:
            logger.debug(f"Failed to rebuild history panel UI: {e}")
            return False

    def _queue_ui_action(self, command: Callable, args: tuple = (), kwargs: Optional[Dict[str, Any]] = None) -> None:
        payload_kwargs = kwargs or {}
        if self.command_queue is None:
            return
        if self.gui_ready:
            try:
                self.command_queue.put((command, args, payload_kwargs))
            except Exception:
                pass
            return

        # First tray click can arrive before GUI thread is fully ready; retry briefly.
        def _deferred_enqueue():
            deadline = time.time() + 6.0
            while time.time() < deadline:
                if self.gui_ready and self.command_queue is not None:
                    try:
                        self.command_queue.put((command, args, payload_kwargs))
                    except Exception:
                        pass
                    return
                time.sleep(0.1)

        threading.Thread(target=_deferred_enqueue, daemon=True).start()

    def toggle_recent_history(self):
        self._queue_ui_action(self._toggle_history_panel, (), {})

    def _set_history_filter(self, filter_key: str) -> None:
        candidate = str(filter_key or "all").strip().lower()
        allowed = {key for key, _label in _HISTORY_FILTER_OPTIONS}
        if candidate not in allowed:
            candidate = "all"
        self.history_active_filter = candidate
        self._refresh_history_filter_buttons()
        self._render_history_panel()

    def _refresh_history_filter_buttons(self) -> None:
        for key, button in self.history_filter_buttons.items():
            active = key == self.history_active_filter
            try:
                button.configure(
                    bg=(self._ui("accent_strong") if active else self._ui("panel_surface")),
                    fg=(self._ui("accent_soft") if active else self._ui("text_muted")),
                    activebackground=(
                        _mix_color(self._ui("accent_strong"), "#FFFFFF", 0.08)
                        if active
                        else self._ui("panel_surface_alt")
                    ),
                    activeforeground=(
                        self._ui("accent_soft") if active else self._ui("text_primary")
                    ),
                )
            except Exception:
                pass

    def open_recent_history(self):
        """Open history panel without toggle side-effects."""
        self._queue_ui_action(self._open_recent_history_ui, (), {})

    def _open_recent_history_ui(self):
        if not self._ensure_history_panel_ui():
            return
        if not self.dock_enabled:
            self._set_dock_enabled_ui(True)
        self.history_visible = True
        self._flush_pending_history_events_ui()
        if self.history_geometry_compact:
            self.history_window.geometry(self.history_geometry_compact)
        self.history_expanded = False
        if hasattr(self, "history_toggle_btn") and self.history_toggle_btn:
            self.history_toggle_btn.configure(text="Expand")
        self._render_history_panel()
        self.history_window.deiconify()
        self.history_window.lift()

    def _fade_in(self) -> None:
        """Animate the overlay from transparent to full opacity."""
        if not self.window:
            return
        if self._overlay_visible:
            # Already visible — just ensure it's on top.
            self.window.lift()
            return
        self._overlay_visible = True
        if self._fade_job:
            try:
                self.window.after_cancel(self._fade_job)
            except Exception:
                pass
            self._fade_job = None
        target = min(0.84, self.config_manager.config.opacity)
        try:
            self.window.wm_attributes("-alpha", 0.0)
            self.window.deiconify()
            self.window.lift()
        except Exception:
            return
        self._do_fade_step(0.0, target, steps=6, interval=14, step=0)

    def _fade_out(self) -> None:
        """Animate the overlay to transparent then hide it."""
        if not self.window:
            return
        if not self._overlay_visible:
            return
        self._overlay_visible = False
        if self._fade_job:
            try:
                self.window.after_cancel(self._fade_job)
            except Exception:
                pass
            self._fade_job = None
        try:
            current = float(self.window.wm_attributes("-alpha"))
        except Exception:
            current = 0.84
        self._do_fade_step(current, 0.0, steps=10, interval=22, step=0, hide_after=True)

    def _do_fade_step(
        self,
        from_alpha: float,
        to_alpha: float,
        steps: int,
        interval: int,
        step: int,
        hide_after: bool = False,
    ) -> None:
        if not self.window:
            return
        progress = step / max(1, steps)
        # Ease-out for fade-in, linear for fade-out
        eased = progress * (2.0 - progress) if to_alpha > from_alpha else progress
        alpha = from_alpha + (to_alpha - from_alpha) * eased
        try:
            self.window.wm_attributes("-alpha", max(0.0, min(1.0, alpha)))
        except Exception:
            pass
        if step < steps:
            self._fade_job = self.window.after(
                interval,
                lambda: self._do_fade_step(from_alpha, to_alpha, steps, interval, step + 1, hide_after),
            )
        else:
            self._fade_job = None
            if hide_after:
                try:
                    self.window.withdraw()
                except Exception:
                    pass

    def _set_waveform_theme(self, status: TranscriptionStatus) -> None:
        """Update waveform accent colors to signal the current state.

        The animation loop reads self.visual_theme each frame so just
        updating it here causes the colors to shift on the next tick.
        """
        if status == TranscriptionStatus.LISTENING:
            # Blue/accent — ready and capturing
            self.visual_theme = {
                "name": "listening",
                "glyph": "",
                "accent": self._ui("accent"),
                "orb": self._ui("accent_soft"),
            }
        elif status == TranscriptionStatus.PROCESSING:
            # Amber/warm — crunching audio
            w = self._ui("warning")
            self.visual_theme = {
                "name": "processing",
                "glyph": "",
                "accent": w,
                "orb": _mix_color(w, "#FFFFFF", 0.60),
            }
        elif status == TranscriptionStatus.TRANSCRIBING:
            # Green — writing the words out
            s = self._ui("success")
            self.visual_theme = {
                "name": "transcribing",
                "glyph": "",
                "accent": s,
                "orb": _mix_color(s, "#FFFFFF", 0.60),
            }
        elif status == TranscriptionStatus.COMPLETE:
            s = self._ui("success")
            self.visual_theme = {
                "name": "complete",
                "glyph": "",
                "accent": s,
                "orb": _mix_color(s, "#FFFFFF", 0.80),
            }
        elif status == TranscriptionStatus.ERROR:
            self.visual_theme = {
                "name": "error",
                "glyph": "",
                "accent": self.error_color,
                "orb": _mix_color(self.error_color, "#FFFFFF", 0.60),
            }
        else:
            self.visual_theme = self._default_visual_theme()

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

        frame_start = time.perf_counter()
        self.animation_step += 0.28

        if status == TranscriptionStatus.LISTENING:
            if not self.reduced_motion:
                self._animate_geometric_strip(mode="listening")
            self._animate_waveform(mode="listening")
        elif status == TranscriptionStatus.PROCESSING:
            if not self.reduced_motion:
                self._animate_geometric_strip(mode="processing")
            self._animate_waveform(mode="processing")
        elif status == TranscriptionStatus.TRANSCRIBING:
            if not self.reduced_motion:
                self._animate_geometric_strip(mode="transcribing")
            self._animate_waveform(mode="transcribing")
        else:
            self._set_icon_idle()
            return

        interval = self._resolve_animation_interval(status)
        frame_ms = max(0.01, (time.perf_counter() - frame_start) * 1000.0)
        self._anim_last_frame_ms = frame_ms
        self._anim_load_factor = frame_ms / max(1.0, float(interval))
        self.animation_job = self.window.after(interval, lambda: self._animate_status_icon(status))

    def _toggle_history_panel(self):
        if not self._ensure_history_panel_ui():
            return
        self.history_visible = not self.history_visible
        if self.history_visible:
            self._flush_pending_history_events_ui()
            if self.history_geometry_compact:
                self.history_window.geometry(self.history_geometry_compact)
            self.history_expanded = False
            if hasattr(self, "history_toggle_btn") and self.history_toggle_btn:
                self.history_toggle_btn.configure(text="Expand")
            self._render_history_panel()
            self.history_window.deiconify()
            self.history_window.lift()
        else:
            # Treat manual close as opt-out from persistent correction review.
            self.history_review_pinned = False
            self.history_window.withdraw()

    def _toggle_history_expanded(self):
        if not self._ensure_history_panel_ui():
            return
        self.history_expanded = not self.history_expanded
        if self.history_expanded and self.history_geometry_expanded:
            self.history_window.geometry(self.history_geometry_expanded)
        elif self.history_geometry_compact:
            self.history_window.geometry(self.history_geometry_compact)
        if hasattr(self, "history_toggle_btn") and self.history_toggle_btn:
            self.history_toggle_btn.configure(text=("Compact" if self.history_expanded else "Expand"))
        self._render_history_panel()

    def _toggle_history_correction_mode(self):
        self.history_correction_mode = not self.history_correction_mode
        if not self.history_correction_mode:
            self.history_correction_target_id = None
            self.history_review_pinned = False
        if self.history_correction_btn:
            self.history_correction_btn.configure(
                text=("Review On" if self.history_correction_mode else "Review")
            )
        self._render_history_panel()

    def _select_history_correction_item(self, item_id: int):
        self.history_correction_target_id = int(item_id)
        self._render_history_panel()

    def _capture_history_correction_draft(self, item_id: int, editor: tk.Text):
        try:
            self.history_correction_drafts[int(item_id)] = editor.get("1.0", "end-1c")
        except Exception:
            pass

    def _copy_history_text_widget(self, editor: tk.Text):
        if not self.root:
            return
        try:
            text = editor.get("1.0", "end-1c").strip()
            if not text:
                self._show_history_feedback("Nothing to copy.")
                return
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update_idletasks()
            self._show_history_feedback("Copied corrected text.")
        except Exception:
            self._show_history_feedback("Copy failed.")

    def _append_correction_feedback(self, payload: Dict[str, Any]) -> bool:
        try:
            return append_jsonl_bounded(
                self.history_correction_feedback_path,
                payload,
                max_file_bytes=786432,
                keep_lines=1000,
                max_line_chars=8192,
            )
        except Exception as e:
            logger.debug(f"Failed to append correction feedback: {e}")
            return False

    @staticmethod
    def _history_item_fingerprint(item: Dict[str, Any]) -> str:
        return json.dumps(
            {
                "audio_duration": round(float(item.get("audio_duration", 0.0)), 3),
                "processing_time": round(float(item.get("processing_time", 0.0)), 3),
                "full_text": str(item.get("full_text", "")),
                "retry_used": bool(item.get("retry_used", False)),
                "source_kind": str(item.get("source_kind", "live")),
            },
            ensure_ascii=True,
            sort_keys=True,
        )

    def _remember_history_fingerprint(self, fingerprint: str) -> None:
        if not fingerprint:
            return
        if fingerprint in self.history_seen_fingerprints:
            return
        if len(self.history_seen_fingerprint_order) >= self.history_seen_fingerprint_order.maxlen:
            try:
                evicted = self.history_seen_fingerprint_order.popleft()
                self.history_seen_fingerprints.discard(evicted)
            except Exception:
                pass
        self.history_seen_fingerprints.add(fingerprint)
        self.history_seen_fingerprint_order.append(fingerprint)

    @staticmethod
    def _history_preview_text(text: str, max_len: int = 140) -> str:
        flat = " ".join(str(text or "").replace("\n", " ").split())
        if len(flat) <= max_len:
            return flat
        tail_len = max(12, max_len - 3)
        return "..." + flat[-tail_len:]

    @staticmethod
    def _normalize_history_seed_rows(
        history_lines: list[str],
        correction_lines: list[str],
        *,
        session_started_at: float,
    ) -> list[Dict[str, Any]]:
        records: list[tuple[str, str]] = [("live", raw) for raw in history_lines]
        records.extend(("correction", raw) for raw in correction_lines)
        if not records:
            return []

        window = list(records[-220:])
        fallback_base_epoch = float(session_started_at) - max(1.0, len(window) * 0.01 + 1.0)
        normalized: list[Dict[str, Any]] = []
        for idx, (source_kind, raw) in enumerate(window):
            line = str(raw or "").strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue

            full_text = str(
                payload.get("full_text")
                or payload.get("corrected_text")
                or payload.get("original_text")
                or ""
            ).strip()
            if not full_text:
                continue

            preview = str(payload.get("preview", "")).strip()
            try:
                event_epoch = float(payload.get("event_epoch", 0.0) or 0.0)
            except Exception:
                event_epoch = 0.0
            if event_epoch <= 0.0:
                event_epoch = BottomScreenIndicator._infer_event_epoch(
                    payload.get("local_ts") or payload.get("ts")
                )
            if event_epoch <= 0.0:
                event_epoch = fallback_base_epoch + (idx * 0.01)

            ts_value = payload.get("local_ts") or payload.get("ts") or datetime.now().strftime("%H:%M:%S")
            normalized.append(
                {
                    "ts": str(ts_value),
                    "event_epoch": event_epoch,
                    "updated_epoch": event_epoch,
                    "audio_duration": float(payload.get("audio_duration", 0.0) or 0.0),
                    "processing_time": float(payload.get("processing_time", 0.0) or 0.0),
                    "rtf": float(payload.get("rtf", 0.0) or 0.0),
                    "preview": preview if preview else BottomScreenIndicator._history_preview_text(full_text),
                    "full_text": full_text,
                    "retry_used": bool(payload.get("retry_used", False)),
                    "source_kind": source_kind,
                }
            )

        normalized.sort(key=lambda item: (float(item.get("event_epoch", 0.0) or 0.0), str(item.get("ts", ""))))
        return normalized

    @staticmethod
    def _filter_history_rows(rows: list[Dict[str, Any]], filter_key: str) -> list[Dict[str, Any]]:
        selected = str(filter_key or "all").strip().lower()
        if selected == "live":
            return [row for row in rows if str(row.get("source_kind", "live")) == "live"]
        if selected == "corrections":
            return [row for row in rows if str(row.get("source_kind", "")) == "correction"]
        if selected == "retries":
            return [row for row in rows if bool(row.get("retry_used", False))]
        return list(rows)

    @staticmethod
    def _describe_history_rows(rows: list[Dict[str, Any]], filter_key: str) -> str:
        selected = str(filter_key or "all").strip().lower()
        total = len(rows)
        live_count = sum(1 for row in rows if str(row.get("source_kind", "live")) == "live")
        correction_count = sum(1 for row in rows if str(row.get("source_kind", "")) == "correction")
        retry_count = sum(1 for row in rows if bool(row.get("retry_used", False)))

        if total <= 0:
            if selected == "corrections":
                return "No saved corrections yet."
            if selected == "retries":
                return "No retry-backed captures yet."
            if selected == "live":
                return "No live captures yet."
            return "No recent items yet."

        if selected == "live":
            return f"Showing {live_count} live capture{'s' if live_count != 1 else ''}."
        if selected == "corrections":
            return f"Showing {correction_count} saved correction{'s' if correction_count != 1 else ''}."
        if selected == "retries":
            return f"Showing {retry_count} retry-backed capture{'s' if retry_count != 1 else ''}."

        return (
            f"{total} item{'s' if total != 1 else ''}: "
            f"{live_count} live, {correction_count} correction{'s' if correction_count != 1 else ''}, "
            f"{retry_count} retr{'ies' if retry_count != 1 else 'y'}."
        )

    def _history_source_badge(self, item: Dict[str, Any]) -> tuple[str, str, str]:
        if str(item.get("source_kind", "live")) == "correction":
            return "Correction", self._ui("badge_correction_bg"), self._ui("badge_correction_fg")
        if bool(item.get("retry_used", False)):
            return "Retry", self._ui("badge_retry_bg"), self._ui("badge_retry_fg")
        return "Live", self._ui("badge_live_bg"), self._ui("badge_live_fg")

    @staticmethod
    def _infer_event_epoch(ts_value: Any) -> float:
        if isinstance(ts_value, (int, float)):
            ts_num = float(ts_value)
            if ts_num > 0:
                return ts_num

        ts_text = str(ts_value or "").strip()
        if not ts_text:
            return 0.0

        # ISO timestamps from correction payloads.
        try:
            if "T" in ts_text or "-" in ts_text:
                return datetime.fromisoformat(ts_text).timestamp()
        except Exception:
            pass

        return 0.0

    def _get_history_item_by_id(self, item_id: int) -> Optional[Dict[str, Any]]:
        wanted = int(item_id)
        for entry in self.recent_transcriptions:
            try:
                if int(entry.get("id", -1)) == wanted:
                    return entry
            except Exception:
                continue
        return None

    def _get_active_correction_target(self) -> Optional[Dict[str, Any]]:
        if not (self.history_review_pinned and self.history_correction_mode):
            return None
        if self.history_correction_target_id is None:
            candidates = list(self.recent_transcriptions)
            if not candidates:
                return None
            latest = sorted(
                candidates,
                key=lambda entry: (
                    float(entry.get("updated_epoch", 0.0) or 0.0),
                    int(entry.get("id", 0) or 0),
                ),
            )[-1]
            self.history_correction_target_id = int(latest.get("id", 0))
        return self._get_history_item_by_id(int(self.history_correction_target_id or 0))

    def _merge_history_item(
        self,
        item: Dict[str, Any],
        incoming_text: str,
        audio_duration: float,
        processing_time: float,
        event_ts: Optional[str] = None,
        event_epoch: Optional[float] = None,
    ) -> Dict[str, Any]:
        base_text = str(item.get("full_text", "")).strip()
        addition = str(incoming_text or "").strip()
        if not addition:
            return item

        merged_text = addition if not base_text else f"{base_text}\n\n{addition}"
        total_audio = max(0.0, float(item.get("audio_duration", 0.0))) + max(0.0, float(audio_duration))
        total_processing = max(0.0, float(item.get("processing_time", 0.0))) + max(0.0, float(processing_time))
        merged_epoch = float(event_epoch if event_epoch is not None else time.time())

        item["full_text"] = merged_text
        item["preview"] = self._history_preview_text(merged_text)
        item["audio_duration"] = total_audio
        item["processing_time"] = total_processing
        item["rtf"] = total_audio / max(0.001, total_processing) if total_audio > 0 else 0.0
        item["ts"] = str(event_ts or datetime.now().strftime("%H:%M:%S"))
        item["updated_epoch"] = merged_epoch
        item["segments"] = int(item.get("segments", 1) or 1) + 1

        item_id = int(item.get("id", 0))
        prior_draft = self.history_correction_drafts.get(item_id)
        if prior_draft is None or prior_draft.strip() == base_text:
            self.history_correction_drafts[item_id] = merged_text

        return item

    def _append_history_store(self, item: Dict[str, Any]) -> None:
        try:
            payload = {
                "ts": str(item.get("ts", "")),
                "event_epoch": float(item.get("event_epoch", time.time())),
                "audio_duration": float(item.get("audio_duration", 0.0)),
                "processing_time": float(item.get("processing_time", 0.0)),
                "rtf": float(item.get("rtf", 0.0)),
                "preview": str(item.get("preview", "")),
                "full_text": str(item.get("full_text", "")),
                "retry_used": bool(item.get("retry_used", False)),
                "source_kind": str(item.get("source_kind", "live")),
            }
            append_jsonl_bounded(
                self.history_store_path,
                payload,
                max_file_bytes=1048576,
                keep_lines=1200,
                max_line_chars=8192,
            )
        except Exception as e:
            logger.debug(f"Failed to append history store: {e}")

    def _sync_history_from_store(self) -> None:
        history_lines = list(
            read_text_tail_lines(
                self.history_store_path,
                max_lines=220,
                max_bytes=1048576,
                max_line_chars=8192,
            )
        )
        correction_lines = list(
            read_text_tail_lines(
                self.history_correction_feedback_path,
                max_lines=220,
                max_bytes=1048576,
                max_line_chars=8192,
            )
        )
        seeded_rows = self._normalize_history_seed_rows(
            history_lines,
            correction_lines,
            session_started_at=float(self.history_session_started_at),
        )
        if not seeded_rows:
            return

        for item_like in seeded_rows:
            fingerprint = self._history_item_fingerprint(item_like)
            if fingerprint in self.history_seen_fingerprints:
                continue
            self._remember_history_fingerprint(fingerprint)

            merge_target = self._get_active_correction_target()
            if (
                merge_target
                and str(item_like.get("source_kind", "live")) == "live"
                and float(item_like.get("event_epoch", 0.0) or 0.0) >= float(self.history_session_started_at)
            ):
                self._merge_history_item(
                    merge_target,
                    str(item_like.get("full_text", "")),
                    float(item_like.get("audio_duration", 0.0)),
                    float(item_like.get("processing_time", 0.0)),
                    event_ts=str(item_like.get("ts", "")),
                    event_epoch=float(item_like.get("event_epoch", 0.0) or time.time()),
                )
                continue

            self.history_event_seq += 1
            item_like["id"] = self.history_event_seq
            item_like["segments"] = 1
            self.recent_transcriptions.append(item_like)

    def _save_history_correction(self, item: Dict[str, Any], editor: tk.Text):
        item_id = int(item.get("id", 0))
        original_text = str(item.get("full_text", "")).strip()
        corrected_text = str(editor.get("1.0", "end-1c")).strip()
        self.history_correction_drafts[item_id] = corrected_text
        if not corrected_text:
            self._show_history_feedback("Correction is empty.")
            return
        if corrected_text == original_text:
            self._show_history_feedback("No change to save.")
            return

        previous = self.history_last_saved_corrections.get(item_id)
        if previous and previous[0] == original_text and previous[1] == corrected_text:
            self._show_history_feedback("Already saved.")
            return

        payload = {
            "ts": time.time(),
            "local_ts": datetime.now().isoformat(timespec="seconds"),
            "item_id": item_id,
            "audio_duration": float(item.get("audio_duration", 0.0)),
            "processing_time": float(item.get("processing_time", 0.0)),
            "original_text": original_text,
            "corrected_text": corrected_text,
        }
        if self._append_correction_feedback(payload):
            self.history_last_saved_corrections[item_id] = (original_text, corrected_text)
            _emit_correction_feedback_learning(original_text, corrected_text, payload)
            self._show_history_feedback("Saved correction feedback.")
        else:
            self._show_history_feedback("Save failed.")

    def open_correction_review(self):
        self._queue_ui_action(self._open_correction_review_ui, (), {})

    def _open_correction_review_ui(self):
        if not self._ensure_history_panel_ui():
            return
        self.history_review_pinned = True
        if not self.dock_enabled:
            self._set_dock_enabled_ui(True)
        if not self.history_visible:
            self._toggle_history_panel()
        if not self.history_correction_mode:
            self._toggle_history_correction_mode()
        else:
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
            if not self._ensure_history_panel_ui() or not self.history_items_frame:
                return
        self._sync_history_from_store()

        if self.history_correction_btn:
            self.history_correction_btn.configure(
                text=("Review On" if self.history_correction_mode else "Review")
            )

        for child in self.history_items_frame.winfo_children():
            child.destroy()

        if not self.recent_transcriptions:
            if self.history_summary_var:
                self.history_summary_var.set(self._describe_history_rows([], self.history_active_filter))
            empty = tk.Label(
                self.history_items_frame,
                text="No transcriptions yet in this session.",
                bg=self._ui("panel_surface"),
                fg=self._ui("text_muted"),
                font=("Segoe UI", 9),
                anchor="w",
                justify=tk.LEFT,
                padx=10,
                pady=8,
            )
            empty.pack(fill=tk.X)
            return

        rows = sorted(
            list(self.recent_transcriptions),
            key=lambda entry: (
                float(entry.get("updated_epoch", 0.0) or 0.0),
                int(entry.get("id", 0) or 0),
            ),
            reverse=True,
        )
        if self.history_summary_var:
            self.history_summary_var.set(self._describe_history_rows(rows, self.history_active_filter))

        rows = self._filter_history_rows(rows, self.history_active_filter)
        if not rows:
            empty = tk.Label(
                self.history_items_frame,
                text="No items match this filter yet.",
                bg=self._ui("panel_surface"),
                fg=self._ui("text_muted"),
                font=("Segoe UI", 9),
                anchor="w",
                justify=tk.LEFT,
                padx=10,
                pady=8,
            )
            empty.pack(fill=tk.X)
            return
        if not self.history_expanded:
            rows = rows[:8]
        if self.history_correction_mode:
            rows = rows[:4]
            valid_ids = {int(entry.get("id", -1)) for entry in rows}
            if self.history_correction_target_id not in valid_ids:
                self.history_correction_target_id = int(rows[0].get("id", 0)) if rows else None

        for item in rows:
            item_id = int(item.get("id", 0))
            full_text = str(item.get("full_text", "")).strip()
            preview = str(item.get("preview", "")).strip()
            show_full = item_id in self.history_item_expanded_ids
            display_text = full_text if show_full else preview
            can_expand = len(full_text) > len(preview)
            is_correction_target = bool(
                self.history_correction_mode and self.history_correction_target_id == item_id
            )

            card = tk.Frame(
                self.history_items_frame,
                bg=self._ui("panel_surface_alt"),
                highlightthickness=1,
                highlightbackground=self._ui("panel_border"),
            )
            card.pack(fill=tk.X, padx=0, pady=3)

            header = tk.Frame(card, bg=self._ui("panel_surface_alt"))
            header.pack(fill=tk.X, padx=8, pady=(5, 2))

            meta = tk.Label(
                header,
                text="[{ts}] dur={dur:.1f}s proc={proc:.2f}s rtf={rtf:.2f}x".format(
                    ts=item["ts"],
                    dur=item["audio_duration"],
                    proc=item["processing_time"],
                    rtf=item["rtf"],
                ),
                bg=self._ui("panel_surface_alt"),
                fg=self._ui("text_muted"),
                font=("Consolas", 8, "bold"),
                anchor="w",
                justify=tk.LEFT,
                pady=0,
            )
            meta.pack(side=tk.LEFT, fill=tk.X, expand=True)

            badge_text, badge_bg, badge_fg = self._history_source_badge(item)
            source_badge = tk.Label(
                header,
                text=badge_text,
                bg=badge_bg,
                fg=badge_fg,
                font=("Segoe UI", 7, "bold"),
                padx=6,
                pady=1,
            )
            source_badge.pack(side=tk.LEFT, padx=(0, 6))

            if self.history_correction_mode:
                edit_btn = tk.Button(
                    header,
                    text=("Editing" if is_correction_target else "Correct"),
                    command=lambda i=item_id: self._select_history_correction_item(i),
                    bg=(
                        self._ui("accent_strong")
                        if is_correction_target
                        else self._ui("panel_surface_alt")
                    ),
                    fg=(
                        self._ui("accent_soft")
                        if is_correction_target
                        else self._ui("text_secondary")
                    ),
                    activebackground=(
                        _mix_color(self._ui("accent_strong"), "#FFFFFF", 0.08)
                        if is_correction_target
                        else self._ui("panel_surface")
                    ),
                    activeforeground=self._ui("text_primary"),
                    relief=tk.FLAT,
                    bd=0,
                    highlightthickness=0,
                    padx=7,
                    pady=1,
                    font=("Segoe UI", 8, "bold"),
                    cursor="hand2",
                )
                edit_btn.pack(side=tk.RIGHT, padx=(0, 6))

            copy_btn = tk.Button(
                header,
                text="Copy",
                command=lambda txt=full_text: self._copy_history_item(txt),
                bg=self._ui("panel_surface"),
                fg=self._ui("text_secondary"),
                activebackground=self._ui("panel_surface_alt"),
                activeforeground=self._ui("text_primary"),
                relief=tk.FLAT,
                bd=0,
                highlightthickness=0,
                padx=7,
                pady=1,
                font=("Segoe UI", 8, "bold"),
                cursor="hand2",
            )
            copy_btn.pack(side=tk.RIGHT)

            if is_correction_target:
                compare = tk.Frame(card, bg=self._ui("panel_surface_alt"))
                compare.pack(fill=tk.X, padx=8, pady=(0, 8))

                left_col = tk.Frame(compare, bg=self._ui("panel_surface_alt"))
                left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4))
                right_col = tk.Frame(compare, bg=self._ui("panel_surface_alt"))
                right_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0))

                left_label = tk.Label(
                    left_col,
                    text="Original",
                    bg=self._ui("panel_surface_alt"),
                    fg=self._ui("text_muted"),
                    font=("Segoe UI", 8, "bold"),
                    anchor="w",
                )
                left_label.pack(fill=tk.X, pady=(0, 2))

                original_msg = tk.Label(
                    left_col,
                    text=full_text,
                    bg=self._ui("panel_surface"),
                    fg=self._ui("text_secondary"),
                    font=("Segoe UI", 9),
                    anchor="nw",
                    justify=tk.LEFT,
                    wraplength=232,
                    padx=8,
                    pady=6,
                )
                original_msg.pack(fill=tk.BOTH, expand=True)

                right_label = tk.Label(
                    right_col,
                    text="Corrected",
                    bg=self._ui("panel_surface_alt"),
                    fg=self._ui("text_muted"),
                    font=("Segoe UI", 8, "bold"),
                    anchor="w",
                )
                right_label.pack(fill=tk.X, pady=(0, 2))

                draft_text = self.history_correction_drafts.get(item_id, full_text)
                editor_height = max(6, min(12, (len(draft_text) // 52) + 2))
                editor = tk.Text(
                    right_col,
                    height=editor_height,
                    wrap=tk.WORD,
                    bg=self._ui("panel_surface"),
                    fg=self._ui("text_primary"),
                    insertbackground=self._ui("text_primary"),
                    relief=tk.FLAT,
                    bd=1,
                    highlightthickness=1,
                    highlightbackground=self._ui("panel_border_soft"),
                    font=("Segoe UI", 9),
                    padx=6,
                    pady=6,
                )
                editor.insert("1.0", draft_text)
                editor.bind(
                    "<KeyRelease>",
                    lambda _event, i=item_id, w=editor: self._capture_history_correction_draft(i, w),
                )
                editor.pack(fill=tk.BOTH, expand=True)

                correction_actions = tk.Frame(right_col, bg=self._ui("panel_surface_alt"))
                correction_actions.pack(fill=tk.X, pady=(4, 0))

                save_btn = tk.Button(
                    correction_actions,
                    text="Save Feedback",
                    command=lambda itm=item, w=editor: self._save_history_correction(itm, w),
                    bg=self._ui("success_bg"),
                    fg=self._ui("success_fg"),
                    activebackground=_mix_color(self._ui("success_bg"), "#FFFFFF", 0.08),
                    activeforeground=self._ui("text_primary"),
                    relief=tk.FLAT,
                    bd=0,
                    highlightthickness=0,
                    padx=8,
                    pady=2,
                    font=("Segoe UI", 8, "bold"),
                    cursor="hand2",
                )
                save_btn.pack(side=tk.LEFT)

                copy_corrected_btn = tk.Button(
                    correction_actions,
                    text="Copy Corrected",
                    command=lambda w=editor: self._copy_history_text_widget(w),
                    bg=self._ui("panel_surface"),
                    fg=self._ui("text_secondary"),
                    activebackground=self._ui("panel_surface_alt"),
                    activeforeground=self._ui("text_primary"),
                    relief=tk.FLAT,
                    bd=0,
                    highlightthickness=0,
                    padx=8,
                    pady=2,
                    font=("Segoe UI", 8, "bold"),
                    cursor="hand2",
                )
                copy_corrected_btn.pack(side=tk.LEFT, padx=(6, 0))
            else:
                message = tk.Label(
                    card,
                    text=display_text,
                    bg=self._ui("panel_surface_alt"),
                    fg=self._ui("text_secondary"),
                    font=("Segoe UI", 9),
                    anchor="w",
                    justify=tk.LEFT,
                    wraplength=470,
                    padx=8,
                    pady=0,
                )
                message.pack(fill=tk.X, pady=(0, 6))

            if can_expand and not is_correction_target:
                actions = tk.Frame(card, bg=self._ui("panel_surface_alt"))
                actions.pack(fill=tk.X, padx=8, pady=(0, 6))
                expand_btn = tk.Button(
                    actions,
                    text=("Less" if show_full else "More"),
                    command=lambda i=item_id: self._toggle_history_item_details(i),
                    bg=self._ui("panel_surface_alt"),
                    fg=self._ui("accent"),
                    activebackground=self._ui("panel_surface_alt"),
                    activeforeground=self._ui("accent_soft"),
                    relief=tk.FLAT,
                    bd=0,
                    highlightthickness=0,
                    padx=0,
                    pady=2,
                    font=("Segoe UI", 8, "bold"),
                    cursor="hand2",
                )
                expand_btn.pack(side=tk.LEFT)

    def record_transcription_event(
        self,
        text: str,
        audio_duration: float,
        processing_time: float,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record summary for always-on dock/history panel."""
        safe_text = (text or "").strip()
        if not safe_text:
            return
        event_epoch = time.time()
        preview = self._history_preview_text(safe_text)
        proc = max(0.001, float(processing_time))
        rtf = float(audio_duration) / proc if audio_duration > 0 else 0.0
        event_meta: Dict[str, Any] = dict(metadata or {})
        raw_audio_duration = float(event_meta.get("raw_audio_duration", audio_duration) or audio_duration)
        compacted_audio_duration = float(
            event_meta.get("compacted_audio_duration", audio_duration) or audio_duration
        )
        compaction_reduction_pct = float(event_meta.get("compaction_reduction_pct", 0.0) or 0.0)
        self._append_history_store(
            {
                "ts": datetime.now().strftime("%H:%M:%S"),
                "event_epoch": event_epoch,
                "audio_duration": float(audio_duration),
                "raw_audio_duration": raw_audio_duration,
                "compacted_audio_duration": compacted_audio_duration,
                "compaction_reduction_pct": compaction_reduction_pct,
                "processing_time": float(processing_time),
                "rtf": float(rtf),
                "preview": preview,
                "full_text": safe_text,
                "retry_used": bool(event_meta.get("retry_used", False)),
                "transcription_path": str(event_meta.get("transcription_path", "")),
                "idle_resume_active": bool(event_meta.get("idle_resume_active", False)),
            }
        )

        event = (safe_text, float(audio_duration), float(processing_time), event_meta)
        if not self.command_queue or not self.gui_ready:
            self.pending_history_events.append(event)
            return
        try:
            while self.pending_history_events:
                pending = self.pending_history_events.popleft()
                if len(pending) >= 4:
                    pending_text, pending_audio, pending_proc, pending_meta = pending
                else:
                    pending_text, pending_audio, pending_proc = pending
                    pending_meta = {}
                self.command_queue.put(
                    (
                        self._record_transcription_event_ui,
                        (pending_text, pending_audio, pending_proc, pending_meta),
                        {},
                    )
                )
            self.command_queue.put(
                (self._record_transcription_event_ui, event, {})
            )
        except Exception as e:
            logger.debug(f"Failed to queue transcription event: {e}")

    def _flush_pending_history_events_ui(self):
        """Flush startup-race history events when history panel is opened."""
        if not self.pending_history_events:
            return
        while self.pending_history_events:
            pending = self.pending_history_events.popleft()
            if len(pending) >= 4:
                pending_text, pending_audio, pending_proc, pending_meta = pending
            else:
                pending_text, pending_audio, pending_proc = pending
                pending_meta = {}
            self._record_transcription_event_ui(pending_text, pending_audio, pending_proc, pending_meta)

    def _record_transcription_event_ui(
        self,
        text: str,
        audio_duration: float,
        processing_time: float,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        safe_text = (text or "").strip()
        if not safe_text:
            return
        event_epoch = time.time()
        preview = self._history_preview_text(safe_text)
        proc = max(0.001, float(processing_time))
        rtf = float(audio_duration) / proc if audio_duration > 0 else 0.0
        event_meta: Dict[str, Any] = dict(metadata or {})

        incoming_fingerprint = self._history_item_fingerprint(
            {
                "audio_duration": float(audio_duration),
                "processing_time": float(processing_time),
                "full_text": safe_text,
            }
        )
        merge_target = self._get_active_correction_target()
        if merge_target:
            self._remember_history_fingerprint(incoming_fingerprint)
            item = self._merge_history_item(
                merge_target,
                safe_text,
                float(audio_duration),
                float(processing_time),
                event_epoch=event_epoch,
            )
            self._refresh_dock_text(last_item=item)
            if self.history_visible:
                self._render_history_panel()
            elif self.history_review_pinned and self.history_window:
                self.history_visible = True
                if not self.history_correction_mode:
                    self.history_correction_mode = True
                if self.history_geometry_compact:
                    self.history_window.geometry(self.history_geometry_compact)
                self._render_history_panel()
                self.history_window.deiconify()
            return

        self.history_event_seq += 1
        item = {
            "id": self.history_event_seq,
            "ts": datetime.now().strftime("%H:%M:%S"),
            "event_epoch": event_epoch,
            "updated_epoch": event_epoch,
            "audio_duration": float(audio_duration),
            "processing_time": float(processing_time),
            "rtf": float(rtf),
            "preview": preview,
            "full_text": safe_text,
            "segments": 1,
            "raw_audio_duration": float(event_meta.get("raw_audio_duration", audio_duration) or audio_duration),
            "compacted_audio_duration": float(
                event_meta.get("compacted_audio_duration", audio_duration) or audio_duration
            ),
            "compaction_reduction_pct": float(event_meta.get("compaction_reduction_pct", 0.0) or 0.0),
            "retry_used": bool(event_meta.get("retry_used", False)),
            "source_kind": "live",
            "transcription_path": str(event_meta.get("transcription_path", "")),
            "idle_resume_active": bool(event_meta.get("idle_resume_active", False)),
        }
        self._remember_history_fingerprint(incoming_fingerprint)
        self.recent_transcriptions.append(item)
        valid_ids = {int(entry.get("id", -1)) for entry in self.recent_transcriptions}
        self.history_item_expanded_ids.intersection_update(valid_ids)
        self.history_correction_drafts = {
            int(k): v for k, v in self.history_correction_drafts.items() if int(k) in valid_ids
        }
        if self.history_correction_target_id not in valid_ids:
            self.history_correction_target_id = None
        self._refresh_dock_text(last_item=item)

        if self.history_visible:
            self._render_history_panel()
        elif self.history_review_pinned and self.history_window:
            # Keep correction review open across repeated start/stop transcription cycles.
            self.history_visible = True
            if not self.history_correction_mode:
                self.history_correction_mode = True
            if self.history_geometry_compact:
                self.history_window.geometry(self.history_geometry_compact)
            self._render_history_panel()
            self.history_window.deiconify()

    def _refresh_dock_text(self, status: Optional[TranscriptionStatus] = None, last_item: Optional[Dict[str, Any]] = None):
        if not self.dock_var:
            return
        if not self.dock_enabled:
            self.dock_var.set("")
            return
        status_value = (status or self.current_status).value
        status_label = "Ready" if status_value == "idle" else status_value.title()
        tail = "History"
        if last_item:
            tail = "Last {dur:.1f}s -> {proc:.2f}s".format(
                dur=last_item["audio_duration"],
                proc=last_item["processing_time"],
            )
        elif status_value in ("listening", "processing", "transcribing", "complete"):
            tail = "Live"
        self.dock_var.set(f"{status_label} | {tail}")

    @with_error_recovery(fallback_value=None)
    def show_status(self, status: TranscriptionStatus, message: str = None, duration: float = None):
        """Show status indicator with message - Thread-safe with CRITICAL GUARDRAILS

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
            self._refresh_dock_text(status=status)
            self._update_status_badge(status)
            self._set_waveform_theme(status)

            # Update progress bar and overlay visibility based on status
            pb = getattr(self, "progress_bar", None)
            if status == TranscriptionStatus.LISTENING:
                self._fade_in()
                self._init_geometric_motif(seed=(time.time_ns() & 0xFFFF))
                if pb:
                    pb.configure(mode='indeterminate')
                    pb.start(10)
                self._start_animation(status)
            elif status in (TranscriptionStatus.PROCESSING, TranscriptionStatus.TRANSCRIBING):
                # Keep overlay visible — user needs feedback that work is happening
                self._fade_in()
                if pb:
                    pb.stop()
                self._start_animation(status)
            elif status in (TranscriptionStatus.COMPLETE, TranscriptionStatus.ERROR):
                # Show briefly to confirm outcome; auto-hide timer in show_status handles dismiss
                self._fade_in()
                self._stop_animation()
                if pb:
                    pb.stop()
                self.progress_var.set(0)
                if self.preview_var:
                    self.preview_var.set("")
                self._bubble_tokens.clear()
                self._last_stream_word_count = 0
            else:
                # IDLE — fade out and hide
                self._fade_out()
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

        except Exception as e:
            print(f"[VisualIndicator] UI update error: {e}")

    def _update_status_badge(self, status: TranscriptionStatus) -> None:
        """Update the status badge label and color to reflect the current state."""
        badge_styles = {
            TranscriptionStatus.LISTENING: (
                self._ui("badge_correction_bg"), self._ui("badge_correction_fg"), "Listening"
            ),
            TranscriptionStatus.PROCESSING: (
                self._ui("badge_retry_bg"), self._ui("badge_retry_fg"), "Processing"
            ),
            TranscriptionStatus.TRANSCRIBING: (
                self._ui("badge_live_bg"), self._ui("badge_live_fg"), "Transcribing"
            ),
            TranscriptionStatus.COMPLETE: (
                self._ui("success_bg"), self._ui("success_fg"), "Done"
            ),
            TranscriptionStatus.ERROR: (
                _mix_color(self.error_color, self._ui("panel_surface"), 0.72),
                self.error_color,
                "Error",
            ),
            TranscriptionStatus.IDLE: (
                self._ui("panel_surface"), self._ui("text_muted"), ""
            ),
        }
        bg, fg, label = badge_styles.get(
            status, (self._ui("panel_surface"), self._ui("text_muted"), "")
        )
        badge_frame = getattr(self, "status_badge_frame", None)
        if badge_frame:
            try:
                badge_frame.configure(bg=bg, highlightbackground=bg)
            except Exception:
                pass
        if self.status_label:
            try:
                self.status_label.configure(bg=bg, fg=fg)
            except Exception:
                pass
        if self.status_var:
            try:
                self.status_var.set(label)
            except Exception:
                pass

    def _get_default_message(self, status: TranscriptionStatus) -> str:
        """Get default message for status (used by dock and notifications)."""
        messages = {
            TranscriptionStatus.IDLE: "VoiceFlow Ready",
            TranscriptionStatus.LISTENING: "Listening...",
            TranscriptionStatus.PROCESSING: "Processing audio...",
            TranscriptionStatus.TRANSCRIBING: "Transcribing...",
            TranscriptionStatus.COMPLETE: "Transcription complete",
            TranscriptionStatus.ERROR: "Transcription failed",
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

            # Fade the window out smoothly
            self._fade_out()

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
                    self._last_preview_words = []
                    self._preview_correction_tokens.clear()
                    return

                caption_tokens = words[-max(1, int(self.live_caption_words)) :]
                caption = " ".join(caption_tokens)
                if len(caption) > int(self.live_caption_max_chars):
                    caption = "..." + caption[-int(self.live_caption_max_chars):]
                self.preview_var.set(caption)
                self._last_preview_words = list(words)
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
            token_norm = re.sub(r"[^\w']+", "", str(token).lower()).strip()
            if token_norm and token_norm in self._preview_correction_tokens:
                txt_color = "#FCD34D"
            else:
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
            self._last_preview_words = []
            self._preview_correction_tokens.clear()
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

def record_transcription_event(
    text: str,
    audio_duration: float,
    processing_time: float,
    metadata: Optional[Dict[str, Any]] = None,
):
    """Record recent transcription item for dock/history display."""
    indicator = get_indicator()
    if indicator:
        indicator.record_transcription_event(text, audio_duration, processing_time, metadata=metadata)

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

def set_animation_preferences(quality: str = "auto", reduced_motion: bool = False, target_fps: int = 28):
    """Apply animation preferences globally and to active indicator when present."""
    _ANIMATION_PREFS["quality"] = str(quality or "auto").strip().lower()
    _ANIMATION_PREFS["reduced_motion"] = bool(reduced_motion)
    try:
        _ANIMATION_PREFS["target_fps"] = int(target_fps)
    except Exception:
        _ANIMATION_PREFS["target_fps"] = 28
    global _indicator
    if _indicator:
        _indicator.set_animation_preferences(
            quality=str(_ANIMATION_PREFS["quality"]),
            reduced_motion=bool(_ANIMATION_PREFS["reduced_motion"]),
            target_fps=int(_ANIMATION_PREFS["target_fps"]),
        )

def _append_ui_action_request(action: str) -> None:
    safe_action = str(action or "").strip().lower()
    if safe_action not in {"open_recent_history", "open_correction_review"}:
        return
    path = config_dir() / "ui_actions.jsonl"
    try:
        payload = {
            "ts": time.time(),
            "pid": int(os.getpid()),
            "action": safe_action,
        }
        append_jsonl_bounded(
            path,
            payload,
            max_file_bytes=524288,
            keep_lines=240,
            max_line_chars=1024,
        )
    except Exception:
        pass

def toggle_recent_history():
    """Toggle recent transcription history panel."""
    indicator = get_indicator()
    if indicator:
        indicator.toggle_recent_history()

def open_recent_history():
    """Open recent transcription history panel."""
    indicator = get_indicator()
    if indicator:
        indicator.open_recent_history()

def open_correction_review():
    """Open recent history in correction-review mode."""
    indicator = get_indicator()
    if indicator:
        indicator.open_correction_review()

def request_open_recent_history():
    """Broadcast and open recent history for cross-process tray reliability."""
    _append_ui_action_request("open_recent_history")
    open_recent_history()

def request_open_correction_review():
    """Broadcast and open correction review for cross-process tray reliability."""
    _append_ui_action_request("open_correction_review")
    open_correction_review()

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
