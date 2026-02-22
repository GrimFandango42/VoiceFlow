from __future__ import annotations

import time
from types import SimpleNamespace

from voiceflow.core.config import Config
import voiceflow.integrations.hotkeys_enhanced as hotkeys_mod


def test_short_press_release_stops_without_listener_lock_deadlock(monkeypatch):
    state = {"ctrl": False, "shift": False, "alt": False}
    stop_calls: list[float] = []

    monkeypatch.setattr(hotkeys_mod.keyboard, "KEY_DOWN", "down", raising=False)
    monkeypatch.setattr(hotkeys_mod.keyboard, "KEY_UP", "up", raising=False)
    monkeypatch.setattr(hotkeys_mod.keyboard, "is_pressed", lambda key: bool(state.get(key, False)))
    monkeypatch.setattr(hotkeys_mod.keyboard, "hook", lambda callback: object())
    monkeypatch.setattr(hotkeys_mod.keyboard, "unhook", lambda hook: None)
    monkeypatch.setattr(hotkeys_mod.keyboard, "block_key", lambda key: None)
    monkeypatch.setattr(hotkeys_mod.keyboard, "unblock_key", lambda key: None)

    cfg = Config()
    cfg.hotkey_ctrl = True
    cfg.hotkey_shift = True
    cfg.hotkey_alt = False
    cfg.hotkey_key = ""
    cfg.ptt_tail_buffer_seconds = 0.25
    cfg.ptt_tail_min_recording_seconds = 0.35

    listener = hotkeys_mod.EnhancedPTTHotkeyListener(
        cfg=cfg,
        on_start=lambda: None,
        on_stop=lambda: stop_calls.append(time.time()),
    )
    listener.start()
    try:
        state["ctrl"] = True
        listener._on_event(SimpleNamespace(name="ctrl", event_type="down"))
        state["shift"] = True
        listener._on_event(SimpleNamespace(name="shift", event_type="down"))
        time.sleep(0.06)  # keep recording shorter than tail-min threshold

        state["ctrl"] = False
        listener._on_event(SimpleNamespace(name="ctrl", event_type="up"))
        state["shift"] = False
        listener._on_event(SimpleNamespace(name="shift", event_type="up"))

        deadline = time.time() + 1.5
        while time.time() < deadline and not stop_calls:
            time.sleep(0.02)

        assert stop_calls, "Expected on_stop callback after short release"
        assert not listener._recording

        # Regression guard: lock must remain acquirable (no deadlocked listener thread).
        acquired = listener._lock.acquire(timeout=0.2)
        assert acquired
        if acquired:
            listener._lock.release()
    finally:
        listener.stop()
