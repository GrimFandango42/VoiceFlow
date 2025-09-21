from __future__ import annotations

import types

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

