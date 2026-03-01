from __future__ import annotations

from voiceflow.core.config import Config
from voiceflow.platform.factory import (
    create_hotkey_backend,
    create_injector_backend,
    create_tray_backend,
    runtime_platform_name,
)
from voiceflow.platform.mock_posix import (
    MockPosixHotkeyBackend,
    MockPosixInjectorBackend,
    MockPosixTrayBackend,
)


def test_runtime_platform_name_returns_non_empty():
    assert runtime_platform_name()


def test_create_injector_backend_returns_mock_for_linux():
    backend = create_injector_backend(Config(), platform_name="linux")
    assert isinstance(backend, MockPosixInjectorBackend)


def test_create_hotkey_backend_returns_mock_for_darwin():
    backend = create_hotkey_backend(
        cfg=Config(),
        on_start=lambda: None,
        on_stop=lambda: None,
        platform_name="darwin",
    )
    assert isinstance(backend, MockPosixHotkeyBackend)


def test_create_tray_backend_returns_mock_for_non_windows():
    app = object()
    backend = create_tray_backend(app, platform_name="linux")
    assert isinstance(backend, MockPosixTrayBackend)

