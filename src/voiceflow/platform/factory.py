from __future__ import annotations

import platform
from typing import Any, Callable, Optional

from voiceflow.core.config import Config
from voiceflow.platform.mock_posix import (
    MockPosixHotkeyBackend,
    MockPosixInjectorBackend,
    MockPosixTrayBackend,
)


def runtime_platform_name() -> str:
    raw = str(platform.system() or "").strip().lower()
    if raw.startswith("win"):
        return "windows"
    if raw == "darwin":
        return "darwin"
    if raw == "linux":
        return "linux"
    return raw or "unknown"


def create_injector_backend(cfg: Config, *, platform_name: Optional[str] = None):
    plat = str(platform_name or runtime_platform_name()).lower()
    if plat == "windows":
        from voiceflow.integrations.inject import ClipboardInjector

        return ClipboardInjector(cfg)
    return MockPosixInjectorBackend(cfg)


def create_hotkey_backend(
    cfg: Config,
    on_start: Callable[[], None],
    on_stop: Callable[[], None],
    *,
    platform_name: Optional[str] = None,
):
    plat = str(platform_name or runtime_platform_name()).lower()
    if plat == "windows":
        from voiceflow.integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener

        return EnhancedPTTHotkeyListener(cfg=cfg, on_start=on_start, on_stop=on_stop)
    return MockPosixHotkeyBackend(cfg=cfg, on_start=on_start, on_stop=on_stop)


def create_tray_backend(
    app: Any,
    *,
    platform_name: Optional[str] = None,
    prefer_enhanced: bool = True,
):
    plat = str(platform_name or runtime_platform_name()).lower()
    if plat == "windows":
        if prefer_enhanced:
            from voiceflow.ui.enhanced_tray import EnhancedTrayController

            return EnhancedTrayController(app)
        from voiceflow.ui.tray import TrayController

        return TrayController(app)
    return MockPosixTrayBackend(app)

