#!/usr/bin/env python3
"""Render VoiceFlow's documentation screenshots in demo mode (VF-14).

Run on Windows from the repo root::

    python scripts/capture_screenshots.py            # writes docs/screenshots/*.png
    python scripts/capture_screenshots.py --only overlay,tray
    python scripts/capture_screenshots.py --out some/dir

What it does NOT do (that is the point of "demo mode"):

* no microphone - ``sounddevice``/``pyaudio`` and ``keyboard`` are blocked from importing, so
  there is no audio capture and no global hotkey hook;
* no paste or injection - nothing here imports ``integrations.inject``;
* no ASR model is loaded;
* no real data - ``LOCALAPPDATA``/``APPDATA``/``USERPROFILE``/``TEMP`` point at a throw-away
  sandbox directory, so the real ``%LOCALAPPDATA%\\VoiceFlow`` is never read or written, and
  all text on screen is the fixed demo text defined below;
* no real desktop - every capture is a region that this script's own backdrop window covers
  completely. Before each grab the script asks Windows which window is at a grid of points in
  that region and aborts if any of them belongs to another process (a toast, a topmost tool).

What it renders:

* ``overlay-idle.png``, ``overlay-recording.png`` (7 s timer), ``overlay-transcribing.png``,
  ``overlay-pasted.png`` - the real :class:`BottomScreenIndicator` (overlay + dock) driven
  through its own ``_update_ui`` with synthetic audio levels, composited by Windows on a mock
  "Notes" window and grabbed from the screen.
* ``tray-menu-recent.png`` - the real tray menu definition (``EnhancedTrayController._menu()``
  with a stub app and demo history), walked item by item and drawn with PIL in a Windows-style
  menu. pystray's menu is a native Win32 popup that cannot be captured without a real tray icon,
  so this one is a faithful *rendering of the live menu definition*, not a native screenshot.
* ``setup-defaults.png`` - the real "Setup & Defaults" window (``launch_setup_wizard``) with a
  fixed demo hardware report. VoiceFlow has no separate "control center" any more; this window
  is the settings surface.

Requires: Windows, Pillow, numpy, the repo's ``src`` on the path (done below). Re-running
overwrites the PNGs; animation frames differ slightly from run to run.
"""

from __future__ import annotations

import argparse
import ctypes
import math
import os
import random
import shutil
import sys
import tempfile
import threading
import time
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "docs" / "screenshots"

# --------------------------------------------------------------------------- demo content
DEMO_BUILD_LABEL = "Updated 11-02 09:41"
DEMO_PARTIAL = "can you summarize the last three commits and flag anything risky before"
DEMO_FINAL = "Can you summarize the last three commits and flag anything risky before I merge?"
DEMO_FINAL_WORDS = len(DEMO_FINAL.split())
DEMO_TIMER_SECONDS = 7

# (hour, minute, text, status) newest first. 'saved' = recognised but not pasted.
DEMO_HISTORY: Sequence[Tuple[int, int, str, str]] = (
    (12, 41, DEMO_FINAL, "pasted"),
    (12, 38, "Add a retry with exponential backoff to the upload helper and log each attempt.", "pasted"),
    (12, 33, "Thanks for the quick turnaround, I will review the draft this afternoon.", "saved"),
    (12, 27, "Draft a short status update: the migration finished, no errors, rollback plan unchanged.", "pasted"),
    (12, 20, "What is the difference between a mutex and a semaphore?", "pasted"),
)

MOCK_PAGE_LINES: Sequence[str] = (
    "Release notes - draft",
    "- Faster paste: the clipboard restore no longer blocks the keystroke.",
    "- History: the last 50 dictations are kept locally.",
)

OVERLAY_BACKDROP = (560, 300)  # width, height of the backdrop region for the overlay shots
SETUP_FOOTER_CROP_PX = 112
BACKDROP_ORIGIN = (120, 80)  # top-left of the backdrop on the physical screen


# --------------------------------------------------------------------------- environment
def configure_sandbox(sandbox: Path) -> None:
    """Point every per-user location at ``sandbox`` before any voiceflow import."""
    sandbox.mkdir(parents=True, exist_ok=True)
    for key in ("LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOME", "TEMP", "TMP"):
        target = sandbox / key.lower()
        target.mkdir(parents=True, exist_ok=True)
        os.environ[key] = str(target)
    os.environ["VOICEFLOW_CUDA_PROBE_BUNDLE"] = "0"
    os.environ["VOICEFLOW_SKIP_SETUP_UI"] = "1"  # nothing here may open the startup wizard by itself
    # Hard guarantee of "no microphone, no hotkeys": these imports now fail.
    for blocked in ("keyboard", "sounddevice", "pyaudio", "pyperclip"):
        sys.modules[blocked] = None  # type: ignore[assignment]
    sys.path.insert(0, str(REPO_ROOT / "src"))


def make_dpi_aware() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def screen_size() -> Tuple[int, int]:
    user32 = ctypes.windll.user32
    return int(user32.GetSystemMetrics(0)), int(user32.GetSystemMetrics(1))


def assert_sandboxed(sandbox: Path) -> None:
    from voiceflow.utils.settings import config_dir

    resolved = Path(config_dir()).resolve()
    if sandbox.resolve() not in resolved.parents:
        raise SystemExit(f"refusing to run: VoiceFlow data dir {resolved} is outside the sandbox {sandbox}")


# --------------------------------------------------------------------------- capture helpers
class _POINT(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]


def region_is_ours(bbox: Tuple[int, int, int, int], cols: int = 14, rows: int = 9) -> List[Tuple[int, int]]:
    """Return grid points inside ``bbox`` whose top-level window is NOT in this process."""
    user32 = ctypes.windll.user32
    user32.WindowFromPoint.argtypes = [_POINT]
    user32.WindowFromPoint.restype = wintypes.HWND
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND
    pid = os.getpid()
    x0, y0, x1, y1 = bbox
    foreign: List[Tuple[int, int]] = []
    for c in range(cols):
        for r in range(rows):
            x = x0 + 2 + int((x1 - x0 - 5) * c / max(1, cols - 1))
            y = y0 + 2 + int((y1 - y0 - 5) * r / max(1, rows - 1))
            hwnd = user32.WindowFromPoint(_POINT(x, y))
            if not hwnd:
                foreign.append((x, y))
                continue
            root = user32.GetAncestor(hwnd, 2)  # GA_ROOT
            owner = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(root or hwnd, ctypes.byref(owner))
            if owner.value != pid:
                foreign.append((x, y))
    return foreign


def grab(bbox: Tuple[int, int, int, int]):
    """Grab ``bbox`` from the screen after proving only our own windows are in it."""
    from PIL import ImageGrab

    foreign = region_is_ours(bbox)
    if foreign:
        raise SystemExit(
            f"aborting: another window covers {len(foreign)} sample point(s) of the capture region "
            f"{bbox} (first at {foreign[0]}). Close or move it and run again."
        )
    img = ImageGrab.grab(bbox=bbox, include_layered_windows=True, all_screens=True)
    return img.convert("RGB")


def save_png(img, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, format="PNG", optimize=True)
    print(f"  wrote {path.relative_to(REPO_ROOT) if REPO_ROOT in path.parents else path} ({img.width}x{img.height})")


def outer_frame(window) -> Tuple[int, int, int, int]:
    """Visible outer rectangle (title bar included, invisible resize border excluded)."""
    user32 = ctypes.windll.user32
    window.update_idletasks()
    hwnd = user32.GetParent(window.winfo_id()) or window.winfo_id()
    rect = wintypes.RECT()
    try:
        # DWMWA_EXTENDED_FRAME_BOUNDS: the frame as drawn, without the transparent border.
        ok = ctypes.windll.dwmapi.DwmGetWindowAttribute(
            wintypes.HWND(hwnd), 9, ctypes.byref(rect), ctypes.sizeof(rect)
        ) == 0
    except Exception:
        ok = False
    if not ok:
        user32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(rect))
    return int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)


def build_backdrop(parent, x: int, y: int, w: int, h: int, content: bool = True):
    """A borderless always-on-top backdrop covering (x, y, w, h); a mock text editor if ``content``."""
    import tkinter as tk

    win = tk.Toplevel(parent)
    win.overrideredirect(True)
    win.geometry(f"{w}x{h}+{x}+{y}")
    win.configure(bg="#E9EDF2")
    canvas = tk.Canvas(win, width=w, height=h, bg="#E9EDF2", highlightthickness=0, bd=0)
    canvas.pack(fill="both", expand=True)
    if not content:
        win.attributes("-topmost", True)
        return win
    canvas.create_rectangle(0, 0, w, 34, fill="#FFFFFF", outline="#D5DBE3")
    canvas.create_text(14, 17, text="Notes - demo", anchor="w", fill="#33404D", font=("Segoe UI", 10))
    canvas.create_rectangle(0, 34, w, h, fill="#FFFFFF", outline="#D5DBE3")
    for i, line in enumerate(MOCK_PAGE_LINES):
        canvas.create_text(
            22, 56 + i * 24, text=line, anchor="w",
            fill="#1F2933" if i == 0 else "#52606D",
            font=("Segoe UI", 12, "bold" if i == 0 else "normal"),
        )
    win.attributes("-topmost", True)
    return win


# --------------------------------------------------------------------------- overlay shots
def on_gui(indicator, fn: Callable[[], object], timeout: float = 8.0):
    """Run ``fn`` on the overlay's Tk thread and wait for it."""
    done = threading.Event()
    box: dict = {}

    def _wrap() -> None:
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            box["error"] = exc
        finally:
            done.set()

    indicator.command_queue.put((_wrap, (), {}))
    if not done.wait(timeout):
        raise TimeoutError("overlay GUI thread did not respond")
    if "error" in box:
        raise box["error"]
    return box.get("result")


def feed_audio(indicator, seconds: float, hz: float = 30.0) -> None:
    """Deterministic speech-like levels so the bars have a natural shape."""
    t0 = time.monotonic()
    while True:
        t = time.monotonic() - t0
        if t >= seconds:
            return
        env = abs(math.sin(2 * math.pi * 0.9 * t)) * (0.55 + 0.35 * math.sin(2 * math.pi * 2.3 * t))
        level = max(0.04, min(0.85, 0.12 + env * 0.7))
        indicator.update_audio_features({
            "level": level,
            "low": 0.42 + 0.18 * math.sin(2 * math.pi * 0.5 * t),
            "mid": 0.36 + 0.14 * math.sin(2 * math.pi * 1.1 * t + 1.0),
            "high": 0.22 + 0.10 * math.sin(2 * math.pi * 1.7 * t + 2.0),
            "centroid": 0.5 + 0.2 * math.sin(2 * math.pi * 0.4 * t),
        })
        time.sleep(1.0 / hz)


def capture_overlay(out: Path, only: Optional[set]) -> None:
    wanted = {"overlay-idle", "overlay-recording", "overlay-transcribing", "overlay-pasted"}
    if only is not None:
        wanted &= only
    if not wanted:
        return
    print("overlay: starting the real overlay + dock (demo mode)")
    import voiceflow.ui.visual_indicators as vi
    from voiceflow.ui.visual_indicators import BottomScreenIndicator, TranscriptionStatus

    vi.build_updated_label = lambda: DEMO_BUILD_LABEL  # fixed text instead of the real build date
    random.seed(7)
    sw, sh = screen_size()
    bw, bh = OVERLAY_BACKDROP
    ox, oy = BACKDROP_ORIGIN
    if ox + bw > sw or oy + bh > sh:
        raise SystemExit(f"screen {sw}x{sh} is too small for the {bw}x{bh} capture region")

    ind = BottomScreenIndicator()
    if not ind.gui_ready:
        raise SystemExit("overlay GUI thread did not start")
    try:
        # Position the dock inside the backdrop; the overlay re-centres itself above it.
        dock_w, dock_h = ind.dock_size
        dock_x = ox + (bw - dock_w) // 2
        dock_y = oy + bh - dock_h - 14

        def _prepare() -> None:
            ind.dock_enabled = True
            ind.dock_window.deiconify()
            ind.dock_window.geometry(f"{dock_w}x{dock_h}+{dock_x}+{dock_y}")
            ind._backdrop = build_backdrop(ind.root, ox, oy, bw, bh)  # noqa: SLF001
            ind._refresh_dock_text()
            ind._position_overlay(sw, sh)
            ind.dock_window.lift()
            ind.root.update()

        on_gui(ind, _prepare)
        bbox = (ox, oy, ox + bw, oy + bh)

        def _relift() -> None:
            ind.dock_window.lift()
            if ind.window and ind._overlay_visible:  # noqa: SLF001
                ind.window.lift()
            ind.root.update()

        if "overlay-idle" in wanted:
            time.sleep(0.6)
            on_gui(ind, _relift)
            save_png(grab(bbox), out / "overlay-idle.png")

        if "overlay-recording" in wanted:
            def _start_listening() -> None:
                ind.current_status = TranscriptionStatus.LISTENING
                ind._listening_started_at = time.monotonic() - (DEMO_TIMER_SECONDS + 0.3)  # noqa: SLF001
                ind._update_ui(TranscriptionStatus.LISTENING, "Listening...")  # noqa: SLF001
                ind._position_overlay(sw, sh)  # noqa: SLF001
                ind._update_preview(DEMO_PARTIAL)  # noqa: SLF001
            on_gui(ind, _start_listening)
            feed_audio(ind, 1.4)
            # Freeze the counter at exactly 7 s so the picture matches the caption.
            def _freeze_timer() -> None:
                ind._stop_elapsed_timer(clear=False)  # noqa: SLF001
                ind.elapsed_var.set(vi.format_elapsed(DEMO_TIMER_SECONDS))
                ind.window.lift()
                ind.dock_window.lift()
                ind.root.update()
            on_gui(ind, _freeze_timer)
            feed_audio(ind, 0.25)
            save_png(grab(bbox), out / "overlay-recording.png")

        if "overlay-transcribing" in wanted:
            def _transcribing() -> None:
                ind.current_status = TranscriptionStatus.TRANSCRIBING
                ind._update_ui(TranscriptionStatus.TRANSCRIBING, "Transcribing...")  # noqa: SLF001
                ind._update_preview(DEMO_PARTIAL + " I merge")  # noqa: SLF001
            on_gui(ind, _transcribing)
            time.sleep(0.9)
            on_gui(ind, _relift)
            save_png(grab(bbox), out / "overlay-transcribing.png")

        if "overlay-pasted" in wanted:
            def _complete() -> None:
                ind.current_status = TranscriptionStatus.COMPLETE
                ind._update_ui(TranscriptionStatus.COMPLETE, f"Pasted {DEMO_FINAL_WORDS} words")  # noqa: SLF001
                ind._update_preview(DEMO_FINAL)  # noqa: SLF001
            on_gui(ind, _complete)
            time.sleep(0.9)
            on_gui(ind, _relift)
            save_png(grab(bbox), out / "overlay-pasted.png")
    finally:
        try:
            ind.destroy()
        except Exception:
            pass
        time.sleep(0.3)


# --------------------------------------------------------------------------- tray menu render
def _find_font(size: int, bold: bool = False):
    from PIL import ImageFont

    names = ["segoeuib.ttf", "segoeui.ttf"] if bold else ["segoeui.ttf"]
    for name in names:
        for base in (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Fonts", Path(".")):
            candidate = base / name
            if candidate.exists():
                return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def _demo_history_entries() -> List[dict]:
    today = datetime.now().replace(second=0, microsecond=0)
    entries = []
    for i, (hour, minute, text, status) in enumerate(DEMO_HISTORY):
        stamp = today.replace(hour=hour, minute=minute)
        entries.append({
            "id": len(DEMO_HISTORY) - i, "text": text, "ts": stamp.timestamp(),
            "words": len(text.split()), "status": status, "target": "notepad.exe",
        })
    return entries


def _walk_menu(menu) -> List[dict]:
    """Flatten a pystray Menu into drawable rows (text, checked, enabled, submenu)."""
    import pystray

    rows: List[dict] = []
    for item in menu.items:
        if item is pystray.Menu.SEPARATOR or getattr(item, "text", "") == "- - - -":
            rows.append({"sep": True})
            continue
        if not getattr(item, "visible", True):
            continue
        checked = item.checked
        rows.append({
            "text": str(item.text),
            "checked": bool(checked) if checked is not None else False,
            "enabled": bool(item.enabled),
            "submenu": item.submenu,
        })
    return rows


def _draw_menu_panel(draw, rows: List[dict], x: int, y: int, scale: int, highlight: Optional[str]) -> Tuple[int, int]:
    """Draw one menu panel at (x, y); returns (width, height). Coordinates are pre-scaled."""
    font = _find_font(15 * scale)
    pad_x, row_h, sep_h, pad_y = 14 * scale, 30 * scale, 9 * scale, 6 * scale
    check_w, arrow_w = 22 * scale, 22 * scale
    text_w = max((draw.textlength(r["text"], font=font) for r in rows if not r.get("sep")), default=100)
    width = int(pad_x + check_w + text_w + arrow_w + pad_x)
    height = pad_y * 2 + sum(sep_h if r.get("sep") else row_h for r in rows)
    draw.rounded_rectangle((x + 3 * scale, y + 4 * scale, x + width + 3 * scale, y + height + 4 * scale),
                           radius=8 * scale, fill=(212, 217, 225, 255))  # soft shadow
    draw.rounded_rectangle((x, y, x + width, y + height), radius=8 * scale, fill=(252, 252, 252, 255),
                           outline=(205, 210, 217, 255), width=scale)
    cy = y + pad_y
    for row in rows:
        if row.get("sep"):
            mid = cy + sep_h // 2
            draw.line((x + 8 * scale, mid, x + width - 8 * scale, mid), fill=(224, 227, 231, 255), width=scale)
            cy += sep_h
            continue
        if highlight and row["text"] == highlight:
            draw.rounded_rectangle((x + 4 * scale, cy + scale, x + width - 4 * scale, cy + row_h - scale),
                                   radius=5 * scale, fill=(229, 233, 240, 255))
        color = (27, 31, 36, 255) if row["enabled"] else (140, 146, 154, 255)
        ty = cy + (row_h - 15 * scale) // 2 - 2 * scale
        draw.text((x + pad_x + check_w, ty), row["text"], font=font, fill=color)
        if row["checked"]:
            cx, cmid = x + pad_x, cy + row_h // 2
            draw.line((cx, cmid, cx + 4 * scale, cmid + 4 * scale, cx + 11 * scale, cmid - 5 * scale),
                      fill=color, width=2 * scale, joint="curve")
        if row["submenu"] is not None:
            ax, am = x + width - pad_x - 2 * scale, cy + row_h // 2
            draw.polygon([(ax - 5 * scale, am - 5 * scale), (ax, am), (ax - 5 * scale, am + 5 * scale)], fill=color)
        cy += row_h
    return width, height


def capture_tray(out: Path, only: Optional[set]) -> None:
    if only is not None and "tray-menu-recent" not in only:
        return
    print("tray: rendering the live menu definition with demo history")
    from PIL import Image, ImageDraw

    from voiceflow.core.config import Config
    from voiceflow.ui.enhanced_tray import EnhancedTrayController

    entries = _demo_history_entries()

    class DemoApp:
        code_mode = False

        def __init__(self) -> None:
            self.cfg = Config()

        def recent_history(self, limit: int) -> List[dict]:
            return entries[:limit]

        def copy_history_entry(self, entry_id: int) -> None:  # never invoked
            raise AssertionError("demo menu actions must not run")

        def repaste_last(self) -> None:  # never invoked
            raise AssertionError("demo menu actions must not run")

        def clear_history(self) -> None:  # never invoked
            raise AssertionError("demo menu actions must not run")

    controller = EnhancedTrayController(DemoApp())
    menu = controller._menu()  # noqa: SLF001 - the real definition; no icon is created
    top_rows = _walk_menu(menu)
    recent_item = next(r for r in top_rows if r.get("text") == "Recent")
    recent_rows = _walk_menu(recent_item["submenu"])

    scale = 2
    canvas_w, canvas_h = 1000 * scale, 520 * scale
    img = Image.new("RGBA", (canvas_w, canvas_h), (233, 237, 242, 255))
    draw = ImageDraw.Draw(img, "RGBA")
    mw, _ = _draw_menu_panel(draw, top_rows, 24 * scale, 20 * scale, scale, highlight="Recent")
    # The submenu opens beside the highlighted "Recent" row.
    row_index = [r.get("text") for r in top_rows].index("Recent")
    sub_y = 20 * scale + 6 * scale + sum(9 * scale if r.get("sep") else 30 * scale for r in top_rows[:row_index])
    sw_, sh_ = _draw_menu_panel(draw, recent_rows, 24 * scale + mw + 4 * scale, sub_y, scale, highlight=None)
    # Crop to the content, then downsample for crisp text.
    _, top_h = _draw_menu_panel(ImageDraw.Draw(Image.new("RGBA", (10, 10))), top_rows, 0, 0, scale, None)
    total_w = 24 * scale + mw + 4 * scale + sw_ + 24 * scale
    total_h = max(20 * scale + top_h, sub_y + sh_) + 24 * scale
    img = img.crop((0, 0, min(total_w, canvas_w), min(total_h, canvas_h)))
    img = img.resize((img.width // scale, img.height // scale), Image.LANCZOS).convert("RGB")
    save_png(img, out / "tray-menu-recent.png")


# --------------------------------------------------------------------------- setup window
def capture_setup(out: Path, only: Optional[set]) -> None:
    if only is not None and "setup-defaults" not in only:
        return
    print("setup: opening the real Setup & Defaults window with a demo hardware report")
    import tkinter as tk

    import voiceflow.ui.setup_wizard as wiz
    from voiceflow.core.config import Config

    demo_caps = wiz.SetupCapabilities(
        platform_name="windows", cpu_count=12, cuda_available=True,
        total_ram_gb=32.0, gpu_name="Demo GPU", gpu_vram_gb=12.0,
    )
    wiz.detect_setup_capabilities = lambda: demo_caps  # no nvidia-smi, no CUDA probe

    sw, sh = screen_size()
    win_w, win_h = 940, 780
    ox, oy = 40, 20
    if ox + win_w + 24 > sw or oy + win_h + 64 > sh:
        raise SystemExit(f"screen {sw}x{sh} is too small for the {win_w}x{win_h} setup window")
    saved_cfg = Config()
    captured: dict = {}

    def fake_mainloop(self, n: int = 0) -> None:
        # Instead of blocking for user input: place, backdrop, draw, grab, close.
        self.geometry(f"{win_w}x{win_h}+{ox}+{oy}")
        self.attributes("-topmost", True)
        for _ in range(6):
            self.update_idletasks()
            self.update()
            time.sleep(0.15)
        left, top, right, bottom = outer_frame(self)
        margin = 16
        backdrop = build_backdrop(
            self, left - margin, top - margin, right - left + 2 * margin, bottom - top + 2 * margin,
            content=False,
        )
        backdrop.lower(self)  # stack the backdrop beneath the setup window
        self.lift()
        for _ in range(5):
            self.update()
            time.sleep(0.12)
        captured["img"] = grab((left, top, right, bottom))
        backdrop.destroy()
        self.destroy()

    original = tk.Tk.mainloop
    tk.Tk.mainloop = fake_mainloop  # type: ignore[method-assign]
    try:
        wiz.launch_setup_wizard(saved_cfg, source="tray")
    finally:
        tk.Tk.mainloop = original  # type: ignore[method-assign]
    if "img" not in captured:
        raise SystemExit("the setup window did not render")
    img = captured["img"]
    # Crop off the footer (the last 112 px). In the "vista" Tk theme the primary
    # "Save and Launch VoiceFlow" button renders white-on-white (its style sets a background
    # that ttk ignores there) - a known wizard defect reported with VF-14, not something this
    # script hides by editing pixels. Drop this crop once that button is readable.
    save_png(img.crop((0, 0, img.width, img.height - SETUP_FOOTER_CROP_PX)), out / "setup-defaults.png")


# --------------------------------------------------------------------------- main
STEPS = {
    "overlay": ("overlay-idle", "overlay-recording", "overlay-transcribing", "overlay-pasted"),
    "tray": ("tray-menu-recent",),
    "setup": ("setup-defaults",),
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory (default docs/screenshots)")
    parser.add_argument("--only", default="", help="comma list of: overlay,tray,setup or an image name")
    parser.add_argument("--keep-sandbox", action="store_true", help="keep the temporary data directory")
    args = parser.parse_args(argv)

    if sys.platform != "win32":
        print("capture_screenshots.py needs Windows (tkinter layered windows + screen grab).", file=sys.stderr)
        return 2

    only: Optional[set] = None
    if args.only.strip():
        only = set()
        for token in (t.strip() for t in args.only.split(",") if t.strip()):
            only.update(STEPS.get(token, (token,)))

    sandbox = Path(tempfile.mkdtemp(prefix="voiceflow-docshots-"))
    configure_sandbox(sandbox)
    make_dpi_aware()
    assert_sandboxed(sandbox)
    print(f"demo mode: sandbox {sandbox}; output {args.out}")
    try:
        capture_overlay(args.out, only)
        capture_tray(args.out, only)
        capture_setup(args.out, only)
    finally:
        if not args.keep_sandbox:
            shutil.rmtree(sandbox, ignore_errors=True)
    print("done")
    return 0


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    # The overlay's Tk thread is a daemon; exiting hard avoids "main thread is not in main loop"
    # noise from Tkinter variable finalisers during interpreter shutdown.
    os._exit(code)
