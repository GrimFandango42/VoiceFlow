"""VF-11: key release must be completed without help from the poller or from a later key event.

Field evidence (VF-10 log analysis): 3 of 57 key releases were caught only by the
polling backup. Two defects explain it:

1. The hook path recorded the first key-up and returned, then needed ANOTHER event
   after the confirm window to finish. After the last key-up there is none.
2. "Physical" state came from ``keyboard.is_pressed``, which reads the library's
   hook-fed table, not the OS. A key-up the hook never saw stays "pressed" there.
"""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

import voiceflow.integrations.hotkeys_enhanced as hk
from voiceflow.core.config import Config


@pytest.fixture()
def rig(monkeypatch):
    state = {"ctrl": False, "shift": False, "alt": False}
    monkeypatch.setattr(hk.keyboard, "KEY_DOWN", "down", raising=False)
    monkeypatch.setattr(hk.keyboard, "KEY_UP", "up", raising=False)
    monkeypatch.setattr(hk.keyboard, "is_pressed", lambda key: bool(state.get(key, False)))
    monkeypatch.setattr(hk.keyboard, "block_key", lambda key: None)
    monkeypatch.setattr(hk.keyboard, "unblock_key", lambda key: None)
    monkeypatch.setattr(hk, "_os_key_state", lambda name: None)

    cfg = Config()
    cfg.hotkey_ctrl, cfg.hotkey_shift, cfg.hotkey_alt, cfg.hotkey_key = True, True, False, ""
    cfg.ptt_tail_buffer_seconds = 0.05
    cfg.ptt_tail_min_recording_seconds = 0.2
    cfg.ptt_release_confirm_seconds = 0.08

    events: list[str] = []
    listener = hk.EnhancedPTTHotkeyListener(
        cfg=cfg,
        on_start=lambda: events.append("start"),
        on_stop=lambda: events.append("stop"),
    )

    def press(name: str, down: bool) -> None:
        state[name] = down
        listener._on_event(SimpleNamespace(name=name, event_type="down" if down else "up"))

    yield SimpleNamespace(listener=listener, state=state, events=events, press=press, monkeypatch=monkeypatch)
    listener.stop()


def _wait(predicate, timeout=2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_release_completes_from_the_hook_path_alone(rig):
    """No poll thread, no further key events: the last key-up must still stop recording."""
    assert rig.listener._poll_thread is None  # start() not called -> no poller

    rig.press("ctrl", True)
    rig.press("shift", True)
    assert _wait(lambda: "start" in rig.events)
    time.sleep(0.3)  # longer than ptt_tail_min_recording_seconds -> tail-buffer path

    rig.press("shift", False)
    rig.press("ctrl", False)  # last event; nothing follows

    assert _wait(lambda: "stop" in rig.events, timeout=2.0), "release was never completed"
    assert rig.events == ["start", "stop"]
    assert not rig.listener._recording


def test_short_press_release_stops_immediately_from_the_hook_path(rig):
    rig.press("ctrl", True)
    rig.press("shift", True)
    time.sleep(0.03)
    rig.press("shift", False)
    rig.press("ctrl", False)
    assert _wait(lambda: "stop" in rig.events, timeout=1.0)


def test_release_timer_is_cancelled_when_the_chord_is_pressed_again(rig):
    rig.press("ctrl", True)
    rig.press("shift", True)
    assert _wait(lambda: "start" in rig.events)
    time.sleep(0.3)

    rig.press("shift", False)  # chord broken ...
    rig.press("shift", True)   # ... and restored inside the confirm window
    time.sleep(0.4)

    assert "stop" not in rig.events
    assert rig.listener._recording


def test_os_key_state_beats_a_stale_library_table(rig):
    """The hook missed the key-ups: the library still says 'pressed', Windows says 'up'."""
    rig.press("ctrl", True)
    rig.press("shift", True)
    assert _wait(lambda: "start" in rig.events)
    time.sleep(0.3)

    # Keys physically released, but keyboard.is_pressed keeps answering True.
    rig.monkeypatch.setattr(hk.keyboard, "is_pressed", lambda key: True)
    rig.monkeypatch.setattr(hk, "_os_key_state", lambda name: False)
    rig.listener._on_event(SimpleNamespace(name="shift", event_type="up"))

    assert _wait(lambda: "stop" in rig.events, timeout=2.0)


def test_slow_on_stop_does_not_block_the_hook_thread(rig):
    """on_stop used to run under the listener lock on the hook thread."""
    release_stop = threading.Event()
    rig.listener.on_stop = lambda: release_stop.wait(2.0)

    rig.press("ctrl", True)
    rig.press("shift", True)
    time.sleep(0.05)
    rig.press("shift", False)
    rig.press("ctrl", False)
    time.sleep(0.3)  # stop is now running inside the (blocked) callback

    started = time.perf_counter()
    rig.listener._on_event(SimpleNamespace(name="a", event_type="down"))
    blocked_ms = (time.perf_counter() - started) * 1000.0
    release_stop.set()

    assert blocked_ms < 100, f"hook thread blocked {blocked_ms:.0f} ms behind on_stop"


def test_callbacks_run_in_order(rig):
    rig.press("ctrl", True)
    rig.press("shift", True)
    time.sleep(0.03)
    rig.press("shift", False)
    rig.press("ctrl", False)
    assert _wait(lambda: len(rig.events) == 2)
    assert rig.events == ["start", "stop"]


@pytest.mark.parametrize(
    ("name", "vk"),
    [("ctrl", 0x11), ("shift", 0x10), ("alt", 0x12), ("space", 0x20), ("a", 0x41), ("5", 0x35), ("f9", 0x78)],
)
def test_virtual_key_mapping(name, vk):
    assert hk._vk_for(name) == vk


def test_unmapped_key_falls_back_to_the_library():
    assert hk._vk_for("left windows") is None


# ---- VF-12 review finding 2: the "window at release" is sampled at release, not after the tail

def test_release_target_is_sampled_at_release_not_after_the_tail(rig):
    focus = {"hwnd": "A"}
    sampled: list = []
    rig.listener.on_release = lambda: sampled.append(focus["hwnd"])
    rig.listener.on_stop = lambda: (rig.events.append("stop"), sampled.append("stop:" + focus["hwnd"]))
    rig.listener._tail_buffer_duration = 0.25

    rig.press("ctrl", True)
    rig.press("shift", True)
    assert _wait(lambda: "start" in rig.events)
    time.sleep(0.3)

    rig.press("shift", False)
    rig.press("ctrl", False)
    assert _wait(lambda: sampled[:1] == ["A"], timeout=1.0), "release was never reported"
    focus["hwnd"] = "B"                     # user alt-tabs during the post-key-up tail
    assert _wait(lambda: "stop" in rig.events, timeout=2.0)
    assert sampled == ["A", "stop:B"], "target must be taken at release (A), before the tail"


def test_release_window_is_pinned_synchronously_even_if_the_callback_queue_is_busy(rig):
    # VF-12 review finding 1: capture at the instant of release, not when the queued callback
    # eventually runs. Block the callback worker, alt-tab A -> B right after the release, and
    # check the callback still receives A.
    focus = {"hwnd": "A"}
    gate = threading.Event()
    received: list = []
    sampled = threading.Event()

    def sampler():
        value = focus["hwnd"]
        sampled.set()                   # only after the read: the test flips focus next
        return value

    rig.listener.release_sampler = sampler
    rig.listener.on_release = lambda sample: received.append(sample)

    rig.press("ctrl", True)
    rig.press("shift", True)
    assert _wait(lambda: "start" in rig.events)
    time.sleep(0.3)
    rig.listener._dispatch("block", gate.wait)      # worker is now stuck ahead of on_release
    time.sleep(0.05)

    rig.press("shift", False)
    rig.press("ctrl", False)
    # the release is confirmed (sampler ran) once the confirm window has passed
    assert sampled.wait(1.0), "release never confirmed"
    focus["hwnd"] = "B"                            # user alt-tabs; callback has not run yet
    assert received == [], "callback must still be queued behind the blocked worker"
    gate.set()
    assert _wait(lambda: received, timeout=1.0)
    assert received == ["A"], "target must be the window focused at release"


def test_release_is_reported_once_per_release_and_again_after_a_resume(rig):
    notes: list = []
    rig.listener.on_release = lambda: notes.append(time.time())
    rig.listener._tail_buffer_duration = 0.4
    rig.press("ctrl", True)
    rig.press("shift", True)
    assert _wait(lambda: "start" in rig.events)
    time.sleep(0.3)

    rig.press("shift", False)
    rig.press("ctrl", False)
    assert _wait(lambda: len(notes) == 1, timeout=1.0)
    rig.press("ctrl", True)                 # pressed again during the tail: recording resumes
    rig.press("shift", True)
    time.sleep(0.6)
    assert "stop" not in rig.events
    rig.press("shift", False)
    rig.press("ctrl", False)
    assert _wait(lambda: "stop" in rig.events, timeout=2.0)
    assert len(notes) == 2, "the second release must re-sample the window"


def test_forced_short_stop_still_samples_the_release_window(rig):
    notes: list = []
    rig.listener.on_release = lambda: notes.append("r")
    rig.press("ctrl", True)
    rig.press("shift", True)
    time.sleep(0.03)
    rig.press("shift", False)
    rig.press("ctrl", False)
    assert _wait(lambda: "stop" in rig.events, timeout=1.0)
    assert notes == ["r"], "exactly one sample, taken before on_stop"


def test_slow_release_callback_does_not_block_the_hook_thread_and_still_precedes_stop(rig):
    order: list = []

    def slow_release():
        time.sleep(0.4)                     # e.g. GetWindowTextW on a hung window
        order.append("release")

    rig.listener.on_release = slow_release
    rig.listener.on_stop = lambda: (order.append("stop"), rig.events.append("stop"))
    rig.press("ctrl", True)
    rig.press("shift", True)
    time.sleep(0.05)
    started = time.perf_counter()
    rig.press("shift", False)
    rig.press("ctrl", False)                # confirm + dispatch happen on this thread
    time.sleep(0.2)
    rig.listener._on_event(SimpleNamespace(name="a", event_type="down"))
    blocked_ms = (time.perf_counter() - started) * 1000.0
    assert blocked_ms < 450, f"hook thread blocked {blocked_ms:.0f} ms behind the release callback"
    assert _wait(lambda: "stop" in rig.events, timeout=3.0)
    assert order == ["release", "stop"], "the release sample must precede on_stop"


def test_a_failing_release_callback_does_not_break_the_stop(rig):
    def boom():
        raise RuntimeError("focus lookup failed")

    rig.listener.on_release = boom
    rig.press("ctrl", True)
    rig.press("shift", True)
    time.sleep(0.3)
    rig.press("shift", False)
    rig.press("ctrl", False)
    assert _wait(lambda: "stop" in rig.events, timeout=2.0)
