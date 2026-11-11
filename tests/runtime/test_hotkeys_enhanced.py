from __future__ import annotations

import time
from types import SimpleNamespace

from voiceflow.core.config import Config
import pytest

import voiceflow.integrations.hotkeys_enhanced as hotkeys_mod


@pytest.fixture(autouse=True)
def _no_os_key_state(monkeypatch):
    """These tests drive a fake keyboard; never consult the developer's real key state."""
    monkeypatch.setattr(hotkeys_mod, "_os_key_state", lambda name: None)


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


def _make_listener(monkeypatch, state, on_start=None, on_stop=None):
    """Wire a listener to a fake keyboard whose physical state is `state`."""
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

    return hotkeys_mod.EnhancedPTTHotkeyListener(
        cfg=cfg,
        on_start=on_start or (lambda: None),
        on_stop=on_stop or (lambda: None),
    )


def test_stale_modifier_cannot_start_recording_on_single_key_tap(monkeypatch):
    """
    A lost Shift key-up must not turn a bare Ctrl tap into a recording.

    keyboard.write() synthesises Shift to type capitals, and an elevated
    window stealing focus can swallow a key-up. Either way the tracked set
    can keep 'shift' while the user is not holding it. Physical state is
    checked before the microphone opens, so the chord stays closed.
    """
    state = {"ctrl": False, "shift": False, "alt": False}
    starts: list[int] = []
    listener = _make_listener(monkeypatch, state, on_start=lambda: starts.append(1))

    # Poisoned tracked state: Shift looks held, but physically it is not.
    listener._pressed_keys = {"shift"}

    # User taps Ctrl alone.
    state["ctrl"] = True
    listener._on_event(SimpleNamespace(name="left ctrl", event_type="down"))

    time.sleep(0.1)  # on_start is dispatched asynchronously; give it the chance to (wrongly) fire
    assert not starts, "Ctrl-only tap started a recording from stale Shift state"
    assert not listener._recording
    # The bogus Shift should have been scrubbed on the way out.
    assert "shift" not in listener._pressed_keys


def test_real_chord_still_starts_recording(monkeypatch):
    """Guard the fix above against over-correcting: a genuine chord must work."""
    state = {"ctrl": False, "shift": False, "alt": False}
    starts: list[int] = []
    listener = _make_listener(monkeypatch, state, on_start=lambda: starts.append(1))

    state["ctrl"] = True
    listener._on_event(SimpleNamespace(name="left ctrl", event_type="down"))
    state["shift"] = True
    listener._on_event(SimpleNamespace(name="left shift", event_type="down"))

    # on_start runs on the ordered PTT callback thread (VF-12), not inline.
    deadline = time.time() + 2.0
    while not starts and time.time() < deadline:
        time.sleep(0.01)
    assert starts == [1]
    assert listener._recording


def test_idle_poll_scrubs_stale_tracked_keys(monkeypatch):
    """The idle watchdog pass clears tracked keys that are not physically down."""
    state = {"ctrl": False, "shift": False, "alt": False}
    listener = _make_listener(monkeypatch, state)
    listener._pressed_keys = {"shift"}

    listener.start()
    try:
        deadline = time.time() + 1.0
        while time.time() < deadline and listener._pressed_keys:
            time.sleep(0.02)
        assert not listener._pressed_keys, "Idle poll left a stale modifier in the tracked set"
    finally:
        listener.stop()


def test_injection_window_events_do_not_poison_tracked_keys(monkeypatch):
    """
    Synthetic Shift events during text injection must not be tracked.

    This is the upstream cause of the stale modifier: while the suppression
    window is open the event stream belongs to keyboard.write(), not the user.
    """
    state = {"ctrl": False, "shift": False, "alt": False}
    listener = _make_listener(monkeypatch, state)

    listener.suppress_event_side_effects(0.5)

    # keyboard.write() presses Shift to emit a capital, and its key-up is lost.
    listener._on_event(SimpleNamespace(name="shift", event_type="down"))

    assert "shift" not in listener._pressed_keys
    assert not listener._recording
