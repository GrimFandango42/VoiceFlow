"""Smoke tests for `voiceflow_tray`.

These tests monkey-patch *pystray* so they can run in headless CI environments
(without actually creating a system-tray icon or GUI threads).
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, List

import builtins
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Dummy replacements for pystray API – minimal surface needed for the tests
# ---------------------------------------------------------------------------


class _DummyIcon:  # noqa: D101 – simple stub
    def __init__(self, name: str, image: Any, title: str, menu: Any):
        self.name = name
        self.image = image
        self.title = title
        self.menu = menu
        self.visible = False
        self._stopped = False

    def run(self):  # noqa: D401
        """Pretend to show the tray icon and block until stop() called."""
        self.visible = True

    def stop(self):  # noqa: D401
        self._stopped = True
        self.visible = False

    def update_menu(self):  # noqa: D401 – no-op
        pass


class _DummyMenuItem(SimpleNamespace):
    pass


@pytest.fixture(autouse=True)
def _patch_pystray(monkeypatch):  # noqa: D401
    """Replace *pystray* module with stubs so import succeeds offline."""

    dummy_pystray = SimpleNamespace(Icon=_DummyIcon, MenuItem=_DummyMenuItem,
                                    Menu=lambda *items: list(items),
                                    Menu_SEP="---")

    monkeypatch.setitem(builtins.__dict__, "pystray", dummy_pystray)

    yield

    # Cleanup – nothing special; fixture scope is function so patch rolls back


def test_get_icon_returns_image():  # noqa: D103
    import voiceflow_tray as vft  # import after patching pystray

    img = vft.get_icon()
    # Pillow Image exposes size attr; use that to confirm we got an image-like obj
    assert hasattr(img, "size"), "Expected PIL.Image object from get_icon()"


def test_setup_tray_icon_creates_icon(monkeypatch):  # noqa: D103
    import voiceflow_tray as vft

    created_icons: List[_DummyIcon] = []

    def _fake_icon(name, image, title, menu):  # noqa: D401
        icon = _DummyIcon(name, image, title, menu)
        created_icons.append(icon)
        return icon

    monkeypatch.setattr(vft, "pystray", SimpleNamespace(Icon=_fake_icon,
                                                          MenuItem=_DummyMenuItem,
                                                          Menu=lambda *items: list(items)))

    # Run in a separate thread to avoid blocking; but vft.setup_tray_icon just
    # instantiates icon and calls icon.run(), which is a no-op in _fake_icon.
    vft.setup_tray_icon()

    assert created_icons, "setup_tray_icon() did not create any Icon"
    icon = created_icons[0]
    assert icon.visible, "Icon should be visible after run()"
