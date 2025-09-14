from __future__ import annotations

import threading
from typing import Optional

try:
    import pystray
    from PIL import Image, ImageDraw
except Exception:
    pystray = None  # type: ignore
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore


def _make_icon(size: int = 16):
    if Image is None:
        return None
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Background circle (Windows-accent-like blue)
    d.ellipse((0, 0, size - 1, size - 1), fill=(0, 120, 215, 255))
    # Simple microphone glyph in white
    pad = 3
    d.ellipse((pad, pad, size - pad - 1, size - pad - 3), fill=(255, 255, 255, 255))
    d.rectangle((size // 2 - 1, size - pad - 3, size // 2 + 1, size - 1), fill=(255, 255, 255, 255))
    return img


class TrayController:
    """System tray controller. Optional; requires pystray + Pillow.

    Provides toggles for code mode, injection behavior, and exit.
    """

    def __init__(self, app):
        self.app = app
        self._icon: Optional[pystray.Icon] = None  # type: ignore
        self._thread: Optional[threading.Thread] = None

    def _menu(self):
        if pystray is None:
            return None

        def toggle_code_mode(icon, item):  # noqa: ARG001
            self.app.code_mode = not self.app.code_mode
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
            except Exception:
                pass

        def toggle_paste(icon, item):  # noqa: ARG001
            self.app.cfg.paste_injection = not self.app.cfg.paste_injection
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
            except Exception:
                pass

        def toggle_enter(icon, item):  # noqa: ARG001
            self.app.cfg.press_enter_after_paste = not self.app.cfg.press_enter_after_paste
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
            except Exception:
                pass

        def quit_app(icon, item):  # noqa: ARG001
            try:
                if self._icon:
                    self._icon.stop()
            finally:
                # Best-effort exit; keyboard.wait() will be interrupted by Ctrl+C from user
                import os
                os._exit(0)

        # PTT presets
        def set_ptt(ctrl: bool, shift: bool, alt: bool, key: str):
            self.app.cfg.hotkey_ctrl = ctrl
            self.app.cfg.hotkey_shift = shift
            self.app.cfg.hotkey_alt = alt
            self.app.cfg.hotkey_key = key
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
            except Exception:
                pass
            self._notify("LocalFlow", f"PTT set to: {'Ctrl+' if ctrl else ''}{'Shift+' if shift else ''}{'Alt+' if alt else ''}{key.upper() if key else ''}")

        def is_ptt(ctrl: bool, shift: bool, alt: bool, key: str):
            return (
                self.app.cfg.hotkey_ctrl == ctrl
                and self.app.cfg.hotkey_shift == shift
                and self.app.cfg.hotkey_alt == alt
                and (self.app.cfg.hotkey_key or '') == (key or '')
            )

        ptt_menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: "Ctrl+Shift (default)",
                lambda icon, item: set_ptt(True, True, False, ""),
                checked=lambda item: is_ptt(True, True, False, ""),
            ),
            pystray.MenuItem(
                lambda item: "Ctrl+Shift+Space",
                lambda icon, item: set_ptt(True, True, False, "space"),
                checked=lambda item: is_ptt(True, True, False, "space"),
            ),
            pystray.MenuItem(
                lambda item: "Ctrl+Alt+Space",
                lambda icon, item: set_ptt(True, False, True, "space"),
                checked=lambda item: is_ptt(True, False, True, "space"),
            ),
            pystray.MenuItem(
                lambda item: "Ctrl+Alt (no key)",
                lambda icon, item: set_ptt(True, False, True, ""),
                checked=lambda item: is_ptt(True, False, True, ""),
            ),
            pystray.MenuItem(
                lambda item: "Ctrl+Space",
                lambda icon, item: set_ptt(True, False, False, "space"),
                checked=lambda item: is_ptt(True, False, False, "space"),
            ),
            pystray.MenuItem(
                lambda item: "Alt+Space",
                lambda icon, item: set_ptt(False, False, True, "space"),
                checked=lambda item: is_ptt(False, False, True, "space"),
            ),
        )

        def set_ctrl_alt_default(icon, item):  # noqa: ARG001
            set_ptt(True, False, True, "")

        return pystray.Menu(
            pystray.MenuItem(
                lambda item: f"Code Mode: {'ON' if self.app.code_mode else 'OFF'}",
                toggle_code_mode,
                checked=lambda item: self.app.code_mode,
            ),
            pystray.MenuItem(
                lambda item: f"Injection: {'Paste' if self.app.cfg.paste_injection else 'Type'}",
                toggle_paste,
                checked=lambda item: self.app.cfg.paste_injection,
            ),
            pystray.MenuItem(
                lambda item: f"Send Enter: {'ON' if self.app.cfg.press_enter_after_paste else 'OFF'}",
                toggle_enter,
                checked=lambda item: self.app.cfg.press_enter_after_paste,
            ),
            pystray.MenuItem("PTT Hotkey", ptt_menu),
            pystray.MenuItem("Set Ctrl+Alt as default PTT", set_ctrl_alt_default),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", quit_app),
        )

    def _notify(self, title: str, message: str):
        try:
            if self._icon and hasattr(self._icon, "notify"):
                # pystray API: notify(message, title="...")
                self._icon.notify(message, title=title)
        except Exception:
            pass

    def start(self):
        if pystray is None:
            print("Tray disabled: pystray/Pillow not installed.")
            return
        if self._icon is not None:
            return
        image = _make_icon(16)
        self._icon = pystray.Icon("LocalFlow", image, "LocalFlow", self._menu())

        def _run():
            assert self._icon is not None
            self._icon.run()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        # Brief notification after start
        def _post_start_notif():
            import time
            time.sleep(1.0)
            self._notify("LocalFlow", "Running. PTT: see tray > PTT Hotkey.")
        threading.Thread(target=_post_start_notif, daemon=True).start()

    def stop(self):
        if self._icon is not None:
            try:
                self._icon.stop()
            finally:
                self._icon = None
                self._thread = None
