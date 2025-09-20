import pytest
pytestmark = pytest.mark.integration

"""Smoke tests for `voiceflow_tray`.

These tests monkey-patch *pystray* so they can run in headless CI environments
(without actually creating a system-tray icon or GUI threads).
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List
from unittest import mock

import pytest

# Add project root to path to allow importing voiceflow_tray
sys.path.insert(0, str(Path(__file__).parent.parent))

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
        self.stop = mock.Mock(side_effect=self._set_stopped)

    def run(self):  # noqa: D401
        """Pretend to show the tray icon."""
        self.visible = True

    def _set_stopped(self):
        self._stopped = True
        self.visible = False

    def update_menu(self):  # noqa: D401 – no-op
        pass


class _DummyMenuItem(SimpleNamespace):
    pass


@pytest.fixture(autouse=True)
def _patch_pystray(monkeypatch):  # noqa: D401
    """Replace *pystray* module with stubs so import succeeds offline."""
    def _dummy_menu(*items):
        menu_list = list(items)
        # Add SEPARATOR attribute to the function
        menu_list.SEPARATOR = _DummyMenuItem(text="---", action=None)
        return menu_list
    
    _dummy_menu.SEPARATOR = _DummyMenuItem(text="---", action=None)
    
    dummy_pystray = SimpleNamespace(
        Icon=_DummyIcon,
        MenuItem=lambda text, action, **kwargs: _DummyMenuItem(text=text, action=action, **kwargs),
        Menu=_dummy_menu,
        Menu_SEP="---"
    )
    monkeypatch.setitem(sys.modules, "pystray", dummy_pystray)
    yield
    monkeypatch.delitem(sys.modules, "pystray", raising=False)


@mock.patch('voiceflow_tray.os.path.exists', return_value=False)
@mock.patch('voiceflow_tray.Image.open')
def test_get_icon_returns_image(mock_image_open, mock_exists):  # noqa: D103
    import voiceflow_tray as vft  # import after patching pystray

    mock_image = mock.Mock()
    mock_image.size = (16, 16)
    mock_image_open.return_value = mock_image

    img = vft.get_icon()
    assert hasattr(img, "size"), "Expected PIL.Image object from get_icon()"
    mock_image_open.assert_called_once()


@mock.patch('voiceflow_tray.get_icon', return_value="dummy_image")
def test_setup_tray_icon_creates_icon(mock_get_icon, monkeypatch):  # noqa: D103
    import voiceflow_tray as vft

    created_icons: List[_DummyIcon] = []

    def _fake_icon(name, image, title, menu):
        icon = _DummyIcon(name, image, title, menu)
        created_icons.append(icon)
        return icon

    monkeypatch.setattr(vft.pystray, 'Icon', _fake_icon)

    vft.setup_tray_icon()

    assert created_icons, "setup_tray_icon() did not create any Icon"
    icon = created_icons[0]
    assert icon.visible, "Icon should be visible after run()"
    mock_get_icon.assert_called_once()


@mock.patch('voiceflow_tray.get_icon', return_value="dummy_image")
def test_tray_menu_and_callbacks(mock_get_icon, monkeypatch):
    """Verify tray menu items are created correctly and callbacks are wired up."""
    import voiceflow_tray as vft

    # Mock the callback functions
    monkeypatch.setattr(vft, 'start_voiceflow', mock.Mock())
    monkeypatch.setattr(vft, 'stop_voiceflow', mock.Mock())
    monkeypatch.setattr(vft, 'open_settings', mock.Mock())
    monkeypatch.setattr(vft, 'exit_action', mock.Mock())

    # Capture the created icon instance
    created_icons: List[_DummyIcon] = []
    original_icon_class = vft.pystray.Icon

    def _fake_icon(name, image, title, menu):
        icon = original_icon_class(name, image, title, menu)
        created_icons.append(icon)
        return icon

    monkeypatch.setattr(vft.pystray, 'Icon', _fake_icon)

    # Run the setup function
    vft.setup_tray_icon()

    assert created_icons, "setup_tray_icon() did not create an Icon"
    icon = created_icons[0]
    menu_items = icon.menu

    # Check menu structure and callbacks
    expected_menu = {
        "Start VoiceFlow": vft.start_voiceflow,
        "Stop VoiceFlow": vft.stop_voiceflow,
        "Settings": vft.open_settings,
        "Exit": vft.exit_action,
    }

    actual_menu = {item.text: item.action for item in menu_items if item != '---'}

    assert list(actual_menu.keys()) == list(expected_menu.keys())
    assert list(actual_menu.values()) == list(expected_menu.values())

    # Simulate a click on the exit menu to check the mock
    exit_item = menu_items[-1]
    exit_item.action(icon, exit_item)
    vft.exit_action.assert_called_once_with(icon, exit_item)

