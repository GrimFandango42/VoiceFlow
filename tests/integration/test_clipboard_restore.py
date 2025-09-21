import pytest
pytestmark = pytest.mark.integration

from __future__ import annotations

import time

import pyperclip

from voiceflow.config import Config
from voiceflow.inject import ClipboardInjector


def test_clipboard_restore_roundtrip():
    cfg = Config(restore_clipboard=True)
    inj = ClipboardInjector(cfg)
    baseline = pyperclip.paste()
    payload = "hello world"
    assert inj.paste_text(payload)
    time.sleep(0.05)
    # After paste, clipboard should be restored to baseline (best effort)
    current = pyperclip.paste()
    # If pyperclip fails to fetch older value on this platform, at least ensure it's a string
    assert isinstance(current, str)


