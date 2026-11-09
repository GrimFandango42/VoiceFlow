"""TDD tests for multi-format clipboard preservation (images, files, text)."""
from __future__ import annotations

import types

import voiceflow.integrations.inject as inj_module
from voiceflow.core.config import Config
from voiceflow.integrations.inject import (
    ClipboardInjector,
    _preserve_clipboard,
    _restore_clipboard_all_formats,
    _snapshot_clipboard_all_formats,
)

CF_UNICODETEXT = 13
CF_DIB = 8
CF_DIBV5 = 17
CF_HDROP = 15


def _make_fake_win32(clipboard: dict, formats_list: list):
    """Build a fake win32clipboard module backed by a dict."""

    def fake_enum(prev_fmt):
        if prev_fmt == 0:
            return formats_list[0] if formats_list else 0
        try:
            idx = formats_list.index(prev_fmt)
            return formats_list[idx + 1] if idx + 1 < len(formats_list) else 0
        except ValueError:
            return 0

    restored = {}

    def fake_set(fmt, data):
        clipboard[fmt] = data
        restored[fmt] = data

    fake_win32 = types.SimpleNamespace(
        OpenClipboard=lambda hwnd=None: None,
        CloseClipboard=lambda: None,
        EmptyClipboard=clipboard.clear,
        EnumClipboardFormats=fake_enum,
        GetClipboardData=lambda fmt: clipboard[fmt],
        SetClipboardData=fake_set,
    )
    return fake_win32, restored


# ---------------------------------------------------------------------------
# RED tests — these fail before implementation
# ---------------------------------------------------------------------------


def test_snapshot_captures_image_format(monkeypatch):
    """_snapshot_clipboard_all_formats should capture CF_DIB bytes."""
    clipboard = {CF_UNICODETEXT: "original text", CF_DIB: b"FAKEIMGDATA"}
    fake_win32, _ = _make_fake_win32(clipboard, [CF_UNICODETEXT, CF_DIB])

    monkeypatch.setattr(inj_module, "_win32clipboard", fake_win32)
    monkeypatch.setattr(inj_module, "_HAS_WIN32CLIPBOARD", True)

    snapshot = _snapshot_clipboard_all_formats()

    assert snapshot is not None, "snapshot should not be None when win32clipboard is available"
    assert CF_DIB in snapshot, "image format CF_DIB must be in snapshot"
    assert snapshot[CF_DIB] == b"FAKEIMGDATA"
    assert snapshot.get(CF_UNICODETEXT) == "original text"


def test_snapshot_returns_none_without_win32clipboard(monkeypatch):
    """_snapshot_clipboard_all_formats should return None when win32clipboard unavailable."""
    monkeypatch.setattr(inj_module, "_HAS_WIN32CLIPBOARD", False)

    snapshot = _snapshot_clipboard_all_formats()

    assert snapshot is None


def test_restore_writes_all_formats(monkeypatch):
    """_restore_clipboard_all_formats should EmptyClipboard then SetClipboardData for each format."""
    clipboard = {}
    fake_win32, restored = _make_fake_win32(clipboard, [])

    monkeypatch.setattr(inj_module, "_win32clipboard", fake_win32)
    monkeypatch.setattr(inj_module, "_HAS_WIN32CLIPBOARD", True)

    snapshot = {CF_DIB: b"IMGDATA", CF_UNICODETEXT: "original"}
    _restore_clipboard_all_formats(snapshot)

    assert restored.get(CF_DIB) == b"IMGDATA"
    assert restored.get(CF_UNICODETEXT) == "original"


def test_restore_skips_handle_based_formats(monkeypatch):
    """_restore_clipboard_all_formats should silently skip formats that raise on SetClipboardData."""
    CF_BITMAP = 2  # handle-based, unsupported

    errors = []

    def bad_set(fmt, data):
        if fmt == CF_BITMAP:
            errors.append(fmt)
            raise OSError("cannot set handle-based format")
        # other formats succeed silently

    fake_win32 = types.SimpleNamespace(
        OpenClipboard=lambda hwnd=None: None,
        CloseClipboard=lambda: None,
        EmptyClipboard=lambda: None,
        SetClipboardData=bad_set,
    )
    monkeypatch.setattr(inj_module, "_win32clipboard", fake_win32)
    monkeypatch.setattr(inj_module, "_HAS_WIN32CLIPBOARD", True)

    # Should not raise even though CF_BITMAP fails
    _restore_clipboard_all_formats({CF_BITMAP: b"junk", CF_UNICODETEXT: "ok"})
    assert CF_BITMAP in errors  # confirmed it was attempted


def test_preserve_clipboard_restores_image_after_paste(monkeypatch):
    """_preserve_clipboard must restore CF_DIB image data after a paste operation."""
    original_img = b"\x28\x00\x00\x00FAKEIMGPIXELS"
    clipboard = {CF_UNICODETEXT: "original text", CF_DIB: original_img}
    fake_win32, _ = _make_fake_win32(clipboard, [CF_UNICODETEXT, CF_DIB])

    monkeypatch.setattr(inj_module, "_win32clipboard", fake_win32)
    monkeypatch.setattr(inj_module, "_HAS_WIN32CLIPBOARD", True)

    with _preserve_clipboard(True):
        # Simulate paste overwriting clipboard with transcription
        clipboard.clear()
        clipboard[CF_UNICODETEXT] = "transcribed speech"

    assert clipboard.get(CF_DIB) == original_img, "image should be restored after paste"
    assert clipboard.get(CF_UNICODETEXT) == "original text", "text should be restored after paste"


def test_preserve_clipboard_restores_file_drop(monkeypatch):
    """_preserve_clipboard must restore CF_HDROP (file list) after paste."""
    file_data = b"FILEDROPSERIALIZED"
    clipboard = {CF_HDROP: file_data, CF_UNICODETEXT: "some text"}
    fake_win32, _ = _make_fake_win32(clipboard, [CF_HDROP, CF_UNICODETEXT])

    monkeypatch.setattr(inj_module, "_win32clipboard", fake_win32)
    monkeypatch.setattr(inj_module, "_HAS_WIN32CLIPBOARD", True)

    with _preserve_clipboard(True):
        clipboard.clear()
        clipboard[CF_UNICODETEXT] = "transcribed"

    assert clipboard.get(CF_HDROP) == file_data, "file drop should be restored after paste"


def test_preserve_clipboard_falls_back_to_pyperclip_when_no_win32(monkeypatch):
    """When win32clipboard is unavailable, text is still preserved via pyperclip."""
    monkeypatch.setattr(inj_module, "_HAS_WIN32CLIPBOARD", False)

    state = {"value": "original text"}
    monkeypatch.setattr(inj_module, "pyperclip", types.SimpleNamespace(
        copy=lambda s: state.__setitem__("value", s),
        paste=lambda: state["value"],
    ))

    with _preserve_clipboard(True):
        state["value"] = "transcribed"

    assert state["value"] == "original text"


def test_full_paste_text_preserves_image(monkeypatch):
    """ClipboardInjector.paste_text should restore image clipboard after injection."""
    original_img = b"IMGBYTES"
    clipboard = {CF_UNICODETEXT: "was here", CF_DIB: original_img}
    fake_win32, _ = _make_fake_win32(clipboard, [CF_UNICODETEXT, CF_DIB])

    monkeypatch.setattr(inj_module, "_win32clipboard", fake_win32)
    monkeypatch.setattr(inj_module, "_HAS_WIN32CLIPBOARD", True)

    # Keep pyperclip on the same fake clipboard: the real one must never be touched by
    # a test (it would overwrite the user's clipboard, and fails without desktop access).
    copied = []

    def fake_copy(text):
        copied.append(text)
        clipboard.clear()  # like a real copy, the paste text replaces every format
        clipboard[CF_UNICODETEXT] = text

    monkeypatch.setattr(inj_module, "pyperclip", types.SimpleNamespace(
        copy=fake_copy,
        paste=lambda: clipboard.get(CF_UNICODETEXT, ""),
    ))

    sent = []
    monkeypatch.setattr(inj_module, "keyboard", types.SimpleNamespace(
        send=sent.append,
        write=lambda t, delay=0: sent.append(f"WRITE:{t}"),
    ))

    cfg = Config(
        paste_injection=True,
        restore_clipboard=True,
        clipboard_restore_delay_ms=0,
        min_inject_interval_ms=0,
    )
    inj = ClipboardInjector(cfg)
    result = inj.paste_text("hello world")

    assert result is True
    assert copied == ["hello world"]
    assert clipboard.get(CF_DIB) == original_img, "image must survive a paste injection"
    assert clipboard.get(CF_UNICODETEXT) == "was here"
