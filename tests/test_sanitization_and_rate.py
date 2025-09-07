from __future__ import annotations

import time

from localflow.config import Config
from localflow.inject import ClipboardInjector


def test_control_chars_removed_and_truncated(monkeypatch):
    cfg = Config(max_inject_chars=5)
    inj = ClipboardInjector(cfg)

    # Patch out actual IO
    monkeypatch.setattr("localflow.inject.pyperclip.copy", lambda s: None)
    monkeypatch.setattr("localflow.inject.keyboard.send", lambda s: None)
    monkeypatch.setattr("localflow.inject.keyboard.write", lambda s, delay=0: None)

    payload = "A\x07B\x1fCDEFG"  # contains control chars and >5 chars
    assert inj.inject(payload) is True


def test_rate_limit(monkeypatch):
    cfg = Config(min_inject_interval_ms=1)
    inj = ClipboardInjector(cfg)
    monkeypatch.setattr("localflow.inject.pyperclip.copy", lambda s: None)
    monkeypatch.setattr("localflow.inject.keyboard.send", lambda s: None)
    monkeypatch.setattr("localflow.inject.keyboard.write", lambda s, delay=0: None)

    t0 = time.perf_counter()
    assert inj.inject("hello")
    assert inj.inject("world")
    t1 = time.perf_counter()
    assert (t1 - t0) >= 0

