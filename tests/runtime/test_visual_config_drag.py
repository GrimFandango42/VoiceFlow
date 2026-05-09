from __future__ import annotations

import json
from pathlib import Path

import pytest

from voiceflow.ui.visual_config import VisualConfigManager


@pytest.fixture()
def manager(tmp_path: Path) -> VisualConfigManager:
    cfg_file = tmp_path / "visual_config.json"
    return VisualConfigManager(config_file=str(cfg_file))


def test_dock_position_round_trip_persists_to_disk(manager: VisualConfigManager) -> None:
    manager.set_dock_position(120, 340)

    saved = json.loads(Path(manager.config_file).read_text(encoding="utf-8"))
    assert saved["dock_custom_x"] == 120
    assert saved["dock_custom_y"] == 340


def test_get_dock_position_returns_saved_when_within_bounds(manager: VisualConfigManager) -> None:
    manager.set_dock_position(120, 340)

    pos = manager.get_dock_position(screen_width=1920, screen_height=1080, dock_w=372, dock_h=26)

    assert pos == (120, 340)


def test_get_dock_position_clears_offscreen_value(manager: VisualConfigManager) -> None:
    # Simulate a dock saved on a now-disconnected 4K monitor.
    manager.set_dock_position(3000, 1500)

    pos = manager.get_dock_position(screen_width=1920, screen_height=1080, dock_w=372, dock_h=26)

    assert pos is None
    # The off-screen value should have been cleared on disk so next launch is clean.
    saved = json.loads(Path(manager.config_file).read_text(encoding="utf-8"))
    assert saved["dock_custom_x"] == -1
    assert saved["dock_custom_y"] == -1


def test_get_dock_position_returns_none_when_unset(manager: VisualConfigManager) -> None:
    pos = manager.get_dock_position(screen_width=1920, screen_height=1080, dock_w=372, dock_h=26)
    assert pos is None


def test_history_position_round_trip(manager: VisualConfigManager) -> None:
    manager.set_history_position(50, 500)

    pos = manager.get_history_position(screen_width=1920, screen_height=1080, panel_w=500, panel_h=208)
    assert pos == (50, 500)


def test_history_position_clears_offscreen_value(manager: VisualConfigManager) -> None:
    manager.set_history_position(-200, 500)

    pos = manager.get_history_position(screen_width=1920, screen_height=1080, panel_w=500, panel_h=208)
    assert pos is None


def test_dock_and_history_positions_are_independent(manager: VisualConfigManager) -> None:
    manager.set_dock_position(100, 200)
    manager.set_history_position(300, 400)

    assert manager.get_dock_position(1920, 1080, 372, 26) == (100, 200)
    assert manager.get_history_position(1920, 1080, 500, 208) == (300, 400)
