from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from PIL import Image, ImageGrab

from VoiceFlow_Control_Center import VoiceFlowControlCenter


def _prepare_window(app: VoiceFlowControlCenter) -> None:
    app.root.deiconify()
    app.root.state("normal")
    app.root.update_idletasks()
    app.root.update()
    app.root.lift()
    app.root.attributes("-topmost", True)
    app.root.focus_force()
    app.root.update_idletasks()
    app.root.update()
    time.sleep(0.45)


def _grab_window_image(app: VoiceFlowControlCenter) -> Optional[Image.Image]:
    hwnd = int(app.root.winfo_id())

    # Pillow 11+ on Windows supports direct HWND capture and avoids desktop-region race conditions.
    try:
        image = ImageGrab.grab(window=hwnd)
        if image and image.size[0] > 200 and image.size[1] > 200:
            return image
    except Exception:
        pass

    x = app.root.winfo_rootx()
    y = app.root.winfo_rooty()
    w = app.root.winfo_width()
    h = app.root.winfo_height()
    if w <= 0 or h <= 0:
        return None

    return ImageGrab.grab(
        bbox=(x, y, x + w, y + h),
        include_layered_windows=True,
        all_screens=True,
    )


def _capture_window(app: VoiceFlowControlCenter, out_path: Path) -> None:
    _prepare_window(app)
    image = _grab_window_image(app)
    if image is None:
        raise RuntimeError("Failed to capture Control Center window image.")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(out_path)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    out_dir = repo_root / "assets"
    main_out = out_dir / "control-center-polished-main.png"
    troubleshoot_out = out_dir / "control-center-polished-troubleshoot.png"

    app = VoiceFlowControlCenter()
    app.root.geometry("1180x760")
    app.update_status("Ready")
    app.log("Screenshot capture session started.")
    _capture_window(app, main_out)

    app.show_troubleshoot_panel()
    app.log("Troubleshooting panel enabled for screenshot.")
    app.update_status("Troubleshooting mode")
    _capture_window(app, troubleshoot_out)

    app.root.attributes("-topmost", False)
    app.root.destroy()
    print(f"Saved: {main_out}")
    print(f"Saved: {troubleshoot_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
