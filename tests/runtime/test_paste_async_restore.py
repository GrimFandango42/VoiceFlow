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


# --- VF-11 review finding 1: a failed restore keeps its retry inside the pending lifecycle ---


@pytest.fixture()
def flaky(env, monkeypatch):
    """Make the multi-format restore fail while ``state.fail`` is set."""
    real = inj._restore_clipboard_all_formats
    state = types.SimpleNamespace(fail=True, failures=0)

    def restore(snapshot):
        if state.fail:
            state.failures += 1
            raise OSError("clipboard locked")
        real(snapshot)

    monkeypatch.setattr(inj, "_restore_clipboard_all_formats", restore)
    monkeypatch.setattr(inj, "_RETRY_BACKOFF_S", 0.03)
    return state


def test_immediate_restore_failure_then_second_paste_keeps_original(env, flaky):
    injector = _injector(delay_ms=0)

    assert injector.paste_text("FIRST_DICTATION") is True
    assert flaky.failures >= 1
    assert env.clipboard.get(CF_UNICODETEXT) == "FIRST_DICTATION"
    # The failed restore is still owed: it must stay registered, not be forgotten.
    assert inj._pending_restore is not None

    # Second dictation arrives before the retry has succeeded.
    assert injector.paste_text("SECOND_DICTATION") is True
    flaky.fail = False

    assert _wait_for(lambda: env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL")
    assert env.clipboard.get(CF_DIB) == b"IMG"
    assert _wait_for(lambda: inj._pending_restore is None)


def test_deferred_restore_failure_then_second_paste_keeps_original(env, flaky):
    injector = _injector(delay_ms=40)

    assert injector.paste_text("FIRST_DICTATION") is True
    assert _wait_for(lambda: flaky.failures >= 1), "deferred restore never attempted"
    pending = inj._pending_restore
    assert pending is not None and not pending.done

    assert injector.paste_text("SECOND_DICTATION") is True
    flaky.fail = False

    assert _wait_for(lambda: env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL", timeout=3.0)
    assert env.clipboard.get(CF_DIB) == b"IMG"
    assert pending.finished.wait(timeout=2.0)
    assert _wait_for(lambda: inj._pending_restore is None)


def test_claimed_retry_never_overwrites_the_next_paste(env, flaky):
    injector = _injector(delay_ms=0)
    assert injector.paste_text("FIRST_DICTATION") is True
    pending = inj._pending_restore
    assert pending is not None

    claimed = inj._claim_pending_restore()
    assert claimed is pending and pending.claimed

    # The next paste is now in flight and has put its text on the clipboard. Even with
    # the clipboard free again, the abandoned retry must not write the original over it.
    env.clipboard.clear()
    env.clipboard[CF_UNICODETEXT] = "SECOND_DICTATION"
    flaky.fail = False
    assert pending.finished.wait(timeout=2.0)
    time.sleep(0.15)
    assert env.clipboard.get(CF_UNICODETEXT) == "SECOND_DICTATION"
    assert inj._pending_restore is None


def test_restore_that_definitively_fails_does_not_wedge_later_pastes(env, flaky):
    injector = _injector(delay_ms=0, clipboard_restore_async_retry_seconds=0.5)
    assert injector.paste_text("FIRST_DICTATION") is True
    pending = inj._pending_restore
    assert pending is not None
    # Window is 0.5 s; after it the pending gives up and is released.
    assert pending.finished.wait(timeout=3.0)
    assert inj._pending_restore is None

    flaky.fail = False
    started = time.perf_counter()
    assert injector.paste_text("SECOND_DICTATION") is True
    assert time.perf_counter() - started < 1.5


# --- VF-11b review finding 1: a restore write that outlasts the old 2 s claim timeout ---


def test_second_paste_waits_for_a_slow_restore_and_keeps_original(env, monkeypatch, caplog):
    """The second paste must wait out a restore write longer than 2 s, never snapshot."""
    import threading

    real = inj._restore_clipboard_all_formats
    started = threading.Event()

    def slow_restore(snapshot):
        if not started.is_set():
            started.set()
            time.sleep(2.25)  # hold the restore write beyond the old 2 s claim timeout
        real(snapshot)

    monkeypatch.setattr(inj, "_restore_clipboard_all_formats", slow_restore)
    # First restore runs on the timer thread (40 ms) so the second paste overlaps it;
    # the second paste's own restore (400 ms) lands after the slow write has finished.
    first = _injector(delay_ms=40)
    second = _injector(delay_ms=400)

    assert first.paste_text("FIRST_DICTATION") is True
    assert started.wait(timeout=2.0), "deferred restore never started"

    with caplog.at_level("WARNING", logger="voiceflow"):
        t0 = time.perf_counter()
        assert second.paste_text("SECOND_DICTATION") is True
        blocked = time.perf_counter() - t0

        # It was serialized behind the in-flight restore rather than giving up at 2 s.
        assert blocked >= 2.0, f"second paste only waited {blocked:.2f} s"
        assert env.sent.count("ctrl+v") == 2

        # Let every restore settle, then check the final clipboard.
        assert _wait_for(lambda: inj._pending_restore is None, timeout=4.0)
        time.sleep(0.6)

    # Both the original text and the image survive, not FIRST_DICTATION.
    assert env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL", (
        f"clipboard ended as {env.clipboard.get(CF_UNICODETEXT)!r}"
    )
    assert env.clipboard.get(CF_DIB) == b"IMG", "image format must survive"
    assert "clipboard_restore_claim_timeout" not in caplog.text


# --- VF-11b review (26ec09f) finding 1: shutdown flush must finish every owed restore ---


def test_flush_waits_out_an_in_flight_restore_longer_than_two_seconds(env, monkeypatch):
    """The reviewer's repro: a 2.25 s restore write already running when shutdown flushes."""
    import threading

    real = inj._restore_clipboard_all_formats
    started = threading.Event()

    def slow_restore(snapshot):
        started.set()
        time.sleep(2.25)
        real(snapshot)

    monkeypatch.setattr(inj, "_restore_clipboard_all_formats", slow_restore)
    injector = _injector(delay_ms=40)
    assert injector.paste_text("DICTATION") is True
    assert started.wait(timeout=2.0), "deferred restore never started"
    assert env.clipboard.get(CF_UNICODETEXT) == "DICTATION"

    t0 = time.perf_counter()
    flushed = inj.flush_pending_clipboard_restore()
    elapsed = time.perf_counter() - t0
    clip_at_return = env.clipboard.get(CF_UNICODETEXT)

    # Checked synchronously at flush return: a process exit here must find the original.
    assert clip_at_return == "ORIGINAL", f"clipboard held {clip_at_return!r} when flush returned"
    assert elapsed >= 2.0, f"flush returned after {elapsed:.2f} s, before the write finished"
    assert env.clipboard.get(CF_DIB) == b"IMG"
    assert flushed is True
    assert inj._pending_restore is None


def test_flush_waits_for_background_retry_after_immediate_failure(env, flaky):
    """Immediate mode (pending.run is None) retries on a thread; flush must wait for it."""
    import threading

    injector = _injector(delay_ms=0)
    assert injector.paste_text("DICTATION") is True
    assert flaky.failures >= 1
    pending = inj._pending_restore
    assert pending is not None and pending.run is None and not pending.done

    result: list = []
    flusher = threading.Thread(target=lambda: result.append(inj.flush_pending_clipboard_restore()))
    flusher.start()
    time.sleep(0.15)
    # The retry is still failing: flush must not return with the dictation on the clipboard.
    assert flusher.is_alive(), "flush returned while the restore was still owed"
    assert env.clipboard.get(CF_UNICODETEXT) == "DICTATION"

    flaky.fail = False
    flusher.join(timeout=5.0)
    assert not flusher.is_alive()
    assert result == [True]
    assert env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL"
    assert env.clipboard.get(CF_DIB) == b"IMG"
    assert inj._pending_restore is None


def test_flush_waits_for_a_paste_that_holds_the_inherited_original(env, monkeypatch):
    """A paste mid-flight has claimed the original but not yet re-registered it."""
    import threading

    first = _injector(delay_ms=5000)
    assert first.paste_text("FIRST_DICTATION") is True
    assert inj._pending_restore is not None

    in_send = threading.Event()
    release = threading.Event()

    def blocking_send(seq):
        in_send.set()
        assert release.wait(timeout=5.0)

    monkeypatch.setattr(
        inj, "keyboard", types.SimpleNamespace(send=blocking_send, write=lambda t, delay=0: None)
    )
    second = _injector(delay_ms=5000)
    paster = threading.Thread(target=second.paste_text, args=("SECOND_DICTATION",))
    paster.start()
    assert in_send.wait(timeout=2.0)
    assert inj._pending_restore is None  # claimed: only the in-flight paste holds the original

    result: list = []
    flusher = threading.Thread(target=lambda: result.append(inj.flush_pending_clipboard_restore()))
    flusher.start()
    time.sleep(0.15)
    assert flusher.is_alive(), "flush returned while a paste still held the user's original"

    release.set()
    paster.join(timeout=5.0)
    flusher.join(timeout=5.0)
    assert not flusher.is_alive()
    assert result == [True]
    assert env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL"
    assert env.clipboard.get(CF_DIB) == b"IMG"
    assert inj._pending_restore is None


def test_flush_with_finite_timeout_reports_an_unfinished_restore(env, flaky):
    injector = _injector(delay_ms=0)
    assert injector.paste_text("DICTATION") is True
    t0 = time.perf_counter()
    assert inj.flush_pending_clipboard_restore(timeout=0.2) is False
    assert time.perf_counter() - t0 < 1.0
    flaky.fail = False
    assert inj.flush_pending_clipboard_restore() is True
    assert env.clipboard.get(CF_UNICODETEXT) == "ORIGINAL"


def test_flush_with_nothing_pending_returns_immediately(env):
    t0 = time.perf_counter()
    assert inj.flush_pending_clipboard_restore() is True
    assert time.perf_counter() - t0 < 0.1
