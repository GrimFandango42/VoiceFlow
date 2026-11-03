"""VF-11: paste returns as soon as the keystroke is sent; the clipboard restore is deferred.

The restore must still always happen, including when a second dictation starts
before the first restore has fired.
"""
from __future__ import annotations

import time
import types

import pytest

import voiceflow.integrations.inject as inj
from voiceflow.core.config import Config

CF_UNICODETEXT = 13
CF_DIB = 8


def _fake_win32(clipboard: dict, formats: list):
    def enum(prev):
        if prev == 0:
            return formats[0] if formats else 0
        idx = formats.index(prev) if prev in formats else -1
        return formats[idx + 1] if 0 <= idx + 1 < len(formats) else 0

    def set_data(fmt, data):
        clipboard[fmt] = data
        if fmt not in formats:
            formats.append(fmt)

    def empty():
        clipboard.clear()

    return types.SimpleNamespace(
        OpenClipboard=lambda hwnd=None: None,
        CloseClipboard=lambda: None,
        EmptyClipboard=empty,
        EnumClipboardFormats=enum,
        GetClipboardData=lambda fmt: clipboard[fmt],
        SetClipboardData=set_data,
    )


@pytest.fixture()
def env(monkeypatch):
    clipboard = {CF_UNICODETEXT: "ORIGINAL", CF_DIB: b"IMG"}
    formats = [CF_UNICODETEXT, CF_DIB]
    monkeypatch.setattr(inj, "_win32clipboard", _fake_win32(clipboard, formats))
    monkeypatch.setattr(inj, "_HAS_WIN32CLIPBOARD", True)

    # pyperclip.copy writes the text format of the same fake clipboard.
    def copy(text):
        clipboard.clear()
        formats[:] = [CF_UNICODETEXT]
        clipboard[CF_UNICODETEXT] = text

    monkeypatch.setattr(inj, "pyperclip", types.SimpleNamespace(copy=copy, paste=lambda: clipboard.get(CF_UNICODETEXT, "")))
    sent: list = []
    monkeypatch.setattr(
        inj,
        "keyboard",
        types.SimpleNamespace(send=sent.append, write=lambda t, delay=0: sent.append(f"WRITE:{t}")),
    )
    monkeypatch.setattr(inj, "_pending_restore", None)
    monkeypatch.setattr(inj, "_ALLOW_DEFERRED_RESTORE", True)
    yield types.SimpleNamespace(clipboard=clipboard, sent=sent)
    inj.flush_pending_clipboard_restore()


def _injector(delay_ms: int, **kw) -> inj.ClipboardInjector:
    cfg = Config(
        paste_injection=True,
        restore_clipboard=True,
        clipboard_restore_delay_ms=delay_ms,
        min_inject_interval_ms=0,
        **kw,
    )
    return inj.ClipboardInjector(cfg)


def _wait_for(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_paste_returns_before_restore_delay_and_still_restores(env):
    injector = _injector(delay_ms=400)

    started = time.perf_counter()
    assert injector.paste_text("hello world") is True
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    # 30 ms settle + keystroke. The 400 ms restore wait must not be on this path.
    assert elapsed_ms < 250, f"paste_text blocked for {elapsed_ms:.0f} ms"
    assert env.clipboard.get(CF_UNICODETEXT) == "hello world"  # restore has not fired yet

    assert _wait_for(lambda: env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL")
    assert env.clipboard.get(CF_DIB) == b"IMG", "non-text formats must come back too"


def test_second_paste_before_restore_keeps_the_users_original_clipboard(env):
    injector = _injector(delay_ms=300)

    assert injector.paste_text("first dictation") is True
    # Second dictation arrives while the first restore is still pending: it must
    # not snapshot "first dictation" as if that were the user's clipboard.
    assert injector.paste_text("second dictation") is True
    assert env.clipboard.get(CF_UNICODETEXT) == "second dictation"

    assert _wait_for(lambda: env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL", timeout=3.0)
    assert env.clipboard.get(CF_DIB) == b"IMG"
    assert env.sent.count("ctrl+v") == 2
    # Exactly one restore ran: nothing is left pending.
    assert inj._pending_restore is None


def test_flush_runs_a_pending_restore_immediately(env):
    injector = _injector(delay_ms=5000)
    assert injector.paste_text("dictation") is True
    assert env.clipboard.get(CF_UNICODETEXT) == "dictation"

    started = time.perf_counter()
    inj.flush_pending_clipboard_restore()
    assert time.perf_counter() - started < 1.0
    assert env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL"


def test_zero_delay_restores_before_returning(env):
    injector = _injector(delay_ms=0)
    assert injector.paste_text("dictation") is True
    assert env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL"


def test_press_enter_keeps_the_inline_wait_and_restores_synchronously(env):
    injector = _injector(delay_ms=120, press_enter_after_paste=True)
    started = time.perf_counter()
    assert injector.paste_text("dictation") is True
    assert (time.perf_counter() - started) >= 0.12
    assert env.sent[-1] == "enter"
    assert env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL"
