from __future__ import annotations

import types
import time

from voiceflow.core.config import Config
from voiceflow.integrations.inject import ClipboardInjector


class DummyClipboard:
    def __init__(self):
        self.value = "BASE"
    def copy(self, s: str):
        self.value = s
    def paste(self) -> str:
        return self.value


def test_inject_paste_then_type(monkeypatch):
    cfg = Config(paste_injection=True, restore_clipboard=True)

    # Patch pyperclip
    dummy = DummyClipboard()
    monkeypatch.setattr("voiceflow.integrations.inject.pyperclip.copy", dummy.copy)
    monkeypatch.setattr("voiceflow.integrations.inject.pyperclip.paste", dummy.paste)

    # Patch keyboard
    sent = []
    def fake_send(seq: str):
        sent.append(seq)
    def fake_write(text: str, delay=0):
        sent.append(f"WRITE:{text}")
    monkeypatch.setattr("voiceflow.integrations.inject.keyboard.send", fake_send)
    monkeypatch.setattr("voiceflow.integrations.inject.keyboard.write", fake_write)

    inj = ClipboardInjector(cfg)
    assert inj.inject("hello")
    assert cfg.paste_shortcut in sent[0]

    # Flip to type-only
    cfg.paste_injection = False
    sent.clear()
    assert inj.inject("world")
    assert any(s.startswith("WRITE:") for s in sent)


def test_inject_refocuses_target_before_release_inject(monkeypatch):
    cfg = Config(
        paste_injection=False,
        restore_clipboard=False,
        min_inject_interval_ms=0,
        inject_require_target_focus=True,
        inject_refocus_on_miss=True,
        inject_refocus_attempts=2,
        inject_refocus_delay_ms=0,
    )

    sent = []
    def fake_send(seq: str):
        sent.append(seq)
    def fake_write(text: str, delay=0):
        sent.append(f"WRITE:{text}")
    monkeypatch.setattr("voiceflow.integrations.inject.keyboard.send", fake_send)
    monkeypatch.setattr("voiceflow.integrations.inject.keyboard.write", fake_write)

    inj = ClipboardInjector(cfg)
    inj._target_hwnd = 4242
    state = {"focused": False}

    monkeypatch.setattr(inj, "_foreground_window", lambda: 4242 if state["focused"] else 9999)
    monkeypatch.setattr(inj, "_focus_target_window", lambda: state.__setitem__("focused", True))

    assert inj.inject("refocus ok")
    assert any(entry.startswith("WRITE:refocus ok") for entry in sent)


def test_inject_blocks_when_focus_drift_and_refocus_disabled(monkeypatch):
    cfg = Config(
        paste_injection=False,
        restore_clipboard=False,
        min_inject_interval_ms=0,
        inject_require_target_focus=True,
        inject_refocus_on_miss=False,
    )

    sent = []
    def fake_send(seq: str):
        sent.append(seq)
    def fake_write(text: str, delay=0):
        sent.append(f"WRITE:{text}")
    monkeypatch.setattr("voiceflow.integrations.inject.keyboard.send", fake_send)
    monkeypatch.setattr("voiceflow.integrations.inject.keyboard.write", fake_write)

    inj = ClipboardInjector(cfg)
    inj._target_hwnd = 123
    monkeypatch.setattr(inj, "_foreground_window", lambda: 777)

    assert inj.inject("should not send") is False
    assert sent == []


def test_copy_text_to_clipboard_fallback(monkeypatch):
    cfg = Config()
    dummy = DummyClipboard()
    monkeypatch.setattr("voiceflow.integrations.inject.pyperclip.copy", dummy.copy)
    monkeypatch.setattr("voiceflow.integrations.inject.pyperclip.paste", dummy.paste)

    inj = ClipboardInjector(cfg)
    assert inj.copy_text_to_clipboard("manual paste backup")
    assert dummy.value == "manual paste backup"


def test_clipboard_restore_async_retry_recovers_previous_value(monkeypatch):
    cfg = Config(
        paste_injection=True,
        restore_clipboard=True,
        min_inject_interval_ms=0,
        clipboard_restore_delay_ms=0,
        clipboard_restore_retry_attempts=1,  # force immediate restore failure path
        clipboard_restore_retry_base_delay_ms=1,
        clipboard_restore_async_retry_seconds=0.3,
    )

    state = {"value": "BASE", "restore_failures": 0}

    def flaky_copy(value: str):
        # Fail the first immediate restore attempts for BASE, then succeed in async retry.
        if value == "BASE" and state["restore_failures"] < 2:
            state["restore_failures"] += 1
            raise RuntimeError("clipboard busy")
        state["value"] = value

    def fake_paste() -> str:
        return state["value"]

    sent = []

    def fake_send(seq: str):
        sent.append(seq)

    monkeypatch.setattr("voiceflow.integrations.inject.pyperclip.copy", flaky_copy)
    monkeypatch.setattr("voiceflow.integrations.inject.pyperclip.paste", fake_paste)
    monkeypatch.setattr("voiceflow.integrations.inject.keyboard.send", fake_send)

    inj = ClipboardInjector(cfg)
    assert inj.inject("hello async restore")
    assert sent  # paste shortcut sent

    # Background retry should restore original clipboard text.
    deadline = time.time() + 1.0
    while time.time() < deadline and state["value"] != "BASE":
        time.sleep(0.02)
    assert state["value"] == "BASE"

