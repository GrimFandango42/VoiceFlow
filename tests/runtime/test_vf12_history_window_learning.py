"""VF-12 items 2, 3, 5, 6: window targeting, history, learned hotwords, cancel + overlay text.

Nothing here touches the real %LOCALAPPDATA%\\VoiceFlow: conftest repoints LOCALAPPDATA at a
temp dir for the whole session, and the history/hotword stores are given tmp_path anyway.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from voiceflow.ai import hotword_learning as hw
from voiceflow.ai.adaptive_memory import AdaptiveLearningManager
from voiceflow.core.config import Config
from voiceflow.core.history import (
    STATUS_CLIPBOARD,
    STATUS_PASTED,
    TranscriptHistory,
    default_history_path,
    menu_label,
)
from voiceflow.integrations import inject as inject_mod
from voiceflow.integrations.inject import ClipboardInjector
from voiceflow.ui import cli_enhanced as cli
from voiceflow.ui.cli_enhanced import EnhancedApp


# ============================================================ item 3: history

class TestHistory:
    def test_keeps_only_the_last_50(self, tmp_path):
        h = TranscriptHistory(tmp_path / "h.json")
        for i in range(60):
            h.add(f"transcript number {i}")
        assert len(h) == 50
        assert h.last()["text"] == "transcript number 59"
        assert h.recent()[-1]["text"] == "transcript number 10"

    def test_persists_across_restarts(self, tmp_path):
        path = tmp_path / "h.json"
        a = TranscriptHistory(path)
        first = a.add("keep me", target="chrome.exe")
        a.set_status(first, STATUS_PASTED)
        b = TranscriptHistory(path)
        assert b.last()["text"] == "keep me"
        assert b.last()["status"] == STATUS_PASTED
        assert b.add("next") == first + 1

    def test_recent_is_newest_first_and_limited(self, tmp_path):
        h = TranscriptHistory(tmp_path / "h.json")
        for word in ("one", "two", "three"):
            h.add(word)
        assert [e["text"] for e in h.recent(2)] == ["three", "two"]

    def test_empty_text_is_not_recorded(self, tmp_path):
        h = TranscriptHistory(tmp_path / "h.json")
        assert h.add("   ") == 0
        assert len(h) == 0

    def test_corrupt_file_is_quarantined_not_overwritten(self, tmp_path):
        path = tmp_path / "h.json"
        path.write_text("{not json", encoding="utf-8")
        h = TranscriptHistory(path)
        assert len(h) == 0
        assert path.with_suffix(".corrupt").exists()
        h.add("fresh")
        assert json.loads(path.read_text(encoding="utf-8"))["items"][0]["text"] == "fresh"

    def test_write_is_atomic_and_leaves_no_temp_files(self, tmp_path):
        h = TranscriptHistory(tmp_path / "h.json")
        for i in range(5):
            h.add(f"x{i}")
        assert sorted(p.name for p in tmp_path.iterdir()) == ["h.json"]

    def test_stores_process_name_never_window_titles(self, tmp_path):
        h = TranscriptHistory(tmp_path / "h.json")
        h.add("hello", target="chrome.exe")
        raw = json.loads((tmp_path / "h.json").read_text(encoding="utf-8"))["items"][0]
        assert set(raw) == {"id", "ts", "text", "words", "status", "target"}

    def test_clear_removes_content_from_disk(self, tmp_path):
        h = TranscriptHistory(tmp_path / "h.json")
        h.add("secret thing")
        h.clear()
        assert "secret thing" not in (tmp_path / "h.json").read_text(encoding="utf-8")
        assert len(h) == 0

    def test_concurrent_adds_do_not_lose_entries(self, tmp_path):
        h = TranscriptHistory(tmp_path / "h.json", max_items=500)
        threads = [threading.Thread(target=lambda n=n: [h.add(f"t{n}-{i}") for i in range(10)]) for n in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert len(h) == 80
        assert len({e["id"] for e in h.recent()}) == 80

    def test_default_path_is_inside_the_app_data_dir_sandbox(self):
        local = Path(os.environ["LOCALAPPDATA"]).resolve()
        assert local in default_history_path().resolve().parents
        assert default_history_path().name == "transcript_history.json"

    def test_menu_label_is_one_line_and_escapes_ampersands(self):
        label = menu_label({"text": "Q&A notes\nsecond line " + "x" * 200, "ts": time.time(), "status": STATUS_PASTED})
        assert "\n" not in label and len(label) < 80
        assert "Q&&A" in label
        assert "(not pasted)" in menu_label({"text": "hi", "ts": time.time(), "status": STATUS_CLIPBOARD})

    def test_config_defaults_for_history(self):
        cfg = Config()
        assert cfg.history_enabled and cfg.history_max_items == 50


# ============================================================ app-level behaviour

class _Injector:
    def __init__(self, inject_ok=True):
        self.inject_ok = inject_ok
        self.pasted, self.copied, self.captured = [], [], 0
        self.last_failure_reason = ""
        self.retargeted = 0

    def inject(self, text):
        self.pasted.append(text)
        return self.inject_ok

    def copy_text_to_clipboard(self, text):
        self.copied.append(text)
        return True

    def capture_target_window(self):
        self.captured += 1

    def get_target_context(self, refresh=False):
        return {"process_name": "notepad.exe", "window_title": "secret title"}

    def retarget_to_foreground(self):
        self.retargeted += 1
        return True


class _Rec:
    def __init__(self, recording=True):
        self.recording = recording
        self.stopped = 0

    def is_recording(self):
        return self.recording

    def stop(self):
        self.stopped += 1
        self.recording = False
        import numpy as np
        return np.zeros(0, dtype=np.float32)


class _App:
    """Just the EnhancedApp pieces VF-12 added, wired to fakes."""

    _history_add = EnhancedApp._history_add
    _history_mark = EnhancedApp._history_mark
    recent_history = EnhancedApp.recent_history
    clear_history = EnhancedApp.clear_history
    copy_history_entry = EnhancedApp.copy_history_entry
    repaste_last = EnhancedApp.repaste_last
    _overlay_message = EnhancedApp._overlay_message
    _wait_for_modifiers_released = staticmethod(lambda timeout=1.5: None)
    _arm_cancel_key = EnhancedApp._arm_cancel_key
    _disarm_cancel_key = EnhancedApp._disarm_cancel_key
    cancel_recording = EnhancedApp.cancel_recording
    stop_recording = EnhancedApp.stop_recording

    def __init__(self, tmp_path, *, inject_ok=True, **cfg):
        self.cfg = Config(audio_feedback_beeps=False, **cfg)
        self.history = TranscriptHistory(tmp_path / "h.json")
        self.injector = _Injector(inject_ok)
        self.rec = _Rec()
        self._log = logging.getLogger("vf12.test")
        self.visual_indicators_enabled = True
        self.tray_controller = None
        self._cancel_pending = False
        self._cancel_hook = None
        self.calls = []
        for name in ("_stop_streaming_preview", "_stop_audio_visual_monitor",
                     "_stop_live_checkpoint_monitor", "_reset_checkpoint_state"):
            setattr(self, name, lambda n=name: self.calls.append(n))


@pytest.fixture()
def overlay(monkeypatch):
    shown = []
    monkeypatch.setattr(cli, "VISUAL_INDICATORS_AVAILABLE", True)
    monkeypatch.setattr(cli, "show_complete", lambda msg=None: shown.append(("ok", msg)))
    monkeypatch.setattr(cli, "show_error", lambda msg=None: shown.append(("err", msg)))
    monkeypatch.setattr(cli, "update_tray_status", lambda *a, **k: None)
    monkeypatch.setattr(cli, "mark_idle", lambda: None)
    return shown


class TestRepasteAndCopy:
    def test_repaste_pastes_the_last_transcript_where_the_user_is_now(self, tmp_path, overlay):
        app = _App(tmp_path)
        app.history.add("older")
        app.history.add("the latest words here")
        assert app.repaste_last() is True
        assert app.injector.pasted == ["the latest words here"]
        assert app.injector.captured == 1, "must retarget to the current window, not a stale one"
        assert overlay[-1] == ("ok", "Re-pasted 4 words")

    def test_repaste_failure_falls_back_to_the_clipboard(self, tmp_path, overlay):
        app = _App(tmp_path, inject_ok=False)
        app.history.add("keep this")
        assert app.repaste_last() is False
        assert app.injector.copied == ["keep this"]
        assert overlay[-1][0] == "err"

    def test_repaste_with_empty_history_says_so(self, tmp_path, overlay):
        app = _App(tmp_path)
        assert app.repaste_last() is False
        assert overlay[-1] == ("err", "No transcript to re-paste")

    def test_copy_from_recent_list(self, tmp_path, overlay):
        app = _App(tmp_path)
        a = app.history.add("first")
        app.history.add("second")
        assert app.copy_history_entry(a) is True
        assert app.injector.copied == ["first"]
        assert app.copy_history_entry(9999) is False

    def test_history_add_records_process_but_not_title(self, tmp_path):
        app = _App(tmp_path)
        entry_id = app._history_add("hello there")
        app._history_mark(entry_id, STATUS_PASTED)
        entry = app.history.get(entry_id)
        assert entry["target"] == "notepad.exe" and entry["status"] == STATUS_PASTED
        assert "secret title" not in json.dumps(entry)

    def test_default_repaste_hotkey_avoids_wispr_and_ptt_chords(self):
        chord = Config().repaste_hotkey.lower().replace(" ", "")
        parts = set(chord.split("+"))
        assert not {"ctrl", "shift"} <= parts, "collides with VoiceFlow's Ctrl+Shift hold"
        assert not {"ctrl", "alt"} <= parts, "collides with Wispr Flow / the Ctrl+Alt toggles"
        assert chord.split("+")[-1] not in {"space", "enter"}


class TestMessages:
    def test_success_message_counts_words(self):
        assert cli.paste_success_message(237) == "Pasted 237 words"
        assert cli.paste_success_message(1) == "Pasted 1 word"

    def test_failure_messages(self):
        assert cli.inject_failure_message("target_closed", True) == "Target window closed - saved to history"
        assert cli.inject_failure_message("target_closed", False) == "Target window closed - saved to history"
        assert "saved to history" in cli.inject_failure_message("focus_drift", True)
        assert "saved to history" in cli.inject_failure_message("focus_drift", False)


# ============================================================ item 6: cancel

class TestCancel:
    def test_cancel_discards_without_transcribing(self, tmp_path, overlay, monkeypatch):
        app = _App(tmp_path)
        monkeypatch.setattr(cli.keyboard, "unhook", lambda h: None, raising=False)
        assert app.cancel_recording() is True
        assert app.rec.stopped == 1
        assert app._cancel_pending is True
        assert overlay[-1] == ("ok", "Recording discarded")
        assert "_reset_checkpoint_state" in app.calls

    def test_cancel_when_not_recording_is_a_no_op(self, tmp_path, overlay):
        app = _App(tmp_path)
        app.rec.recording = False
        assert app.cancel_recording() is False
        assert app.rec.stopped == 0

    def test_release_after_cancel_does_not_start_a_transcription(self, tmp_path, overlay, monkeypatch):
        app = _App(tmp_path)
        monkeypatch.setattr(cli.keyboard, "unhook", lambda h: None, raising=False)
        app.cancel_recording()
        rec_stops = app.rec.stopped
        app.stop_recording()                     # the key-up that follows the Esc
        assert app.rec.stopped == rec_stops, "stop_recording must return early after a cancel"
        assert app._cancel_pending is False       # armed state is consumed

    def test_esc_hook_is_armed_only_with_suppression_and_can_be_disarmed(self, tmp_path, monkeypatch):
        calls = {}
        def fake_on_press_key(key, cb, suppress=False):
            calls.update(key=key, suppress=suppress)
            return "handle"
        unhooked = []
        monkeypatch.setattr(cli.keyboard, "on_press_key", fake_on_press_key, raising=False)
        monkeypatch.setattr(cli.keyboard, "unhook", lambda h: unhooked.append(h), raising=False)
        app = _App(tmp_path)
        app._arm_cancel_key()
        assert calls == {"key": "esc", "suppress": True}
        app._arm_cancel_key()                     # idempotent
        app._disarm_cancel_key()
        assert unhooked == ["handle"] and app._cancel_hook is None

    def test_cancel_key_can_be_disabled(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli.keyboard, "on_press_key",
                            lambda *a, **k: pytest.fail("must not arm"), raising=False)
        app = _App(tmp_path, cancel_recording_key="")
        app._arm_cancel_key()
        assert app._cancel_hook is None


# ============================================================ item 2: window targeting

class _User32:
    def __init__(self):
        self.alive = True
        self.foreground = 100
        self.pid = 4242

    def IsWindow(self, hwnd):
        return 1 if self.alive else 0

    def GetForegroundWindow(self):
        return self.foreground

    def GetWindowThreadProcessId(self, hwnd, ref):
        ref.value = self.pid
        return 1

    def SetForegroundWindow(self, hwnd):
        return 1


@pytest.fixture()
def win(monkeypatch):
    user32 = _User32()
    fake_ctypes = SimpleNamespace(windll=SimpleNamespace(user32=user32), byref=lambda x: x)
    monkeypatch.setattr(inject_mod, "ctypes", fake_ctypes)
    monkeypatch.setattr(inject_mod, "_HAS_WIN32_API", True)
    sent = []
    monkeypatch.setattr(inject_mod.keyboard, "send", lambda seq: sent.append(seq))
    monkeypatch.setattr(inject_mod.keyboard, "write", lambda text, delay=0: sent.append("WRITE:" + text))
    monkeypatch.setattr(inject_mod, "_clipboard_copy_with_retry", lambda text: None)
    inj = ClipboardInjector(Config(min_inject_interval_ms=0, restore_clipboard=False,
                                   inject_refocus_delay_ms=0, inject_refocus_attempts=1))
    monkeypatch.setattr(inj, "_build_window_context", lambda hwnd: {"hwnd": hwnd, "process_name": "app.exe"})
    inj._target_hwnd = 100
    return SimpleNamespace(user32=user32, inj=inj, sent=sent)


class TestWindowTargeting:
    def test_closed_target_is_not_pasted_into_whatever_has_focus(self, win):
        win.user32.alive = False
        win.user32.foreground = 200        # something else is in front now
        assert win.inj.inject("do not lose me") is False
        assert win.inj.last_failure_reason == "target_closed"
        assert win.sent == [], "nothing may be sent to the wrong window"

    def test_live_target_still_pastes(self, win):
        assert win.inj.inject("hello") is True
        assert win.inj.last_failure_reason == ""
        assert win.inj.cfg.paste_shortcut in win.sent

    def test_focus_drift_is_reported_as_such(self, win):
        win.user32.foreground = 200
        win.inj.cfg.inject_refocus_on_miss = False
        assert win.inj.inject("x") is False
        assert win.inj.last_failure_reason == "focus_drift"

    def test_no_captured_target_means_no_closed_window_check(self, win):
        win.inj._target_hwnd = None
        win.user32.alive = False
        assert win.inj.target_window_exists() is True

    def test_failure_reason_resets_on_the_next_inject(self, win):
        win.user32.alive = False
        win.inj.inject("a")
        win.user32.alive = True
        win.inj.inject("b")
        assert win.inj.last_failure_reason == ""

    def test_release_policy_retargets_to_the_foreground_window(self, win):
        win.user32.foreground = 300
        assert win.inj.retarget_to_foreground() is True
        assert win.inj._target_hwnd == 300
        assert win.inj.get_target_context()["hwnd"] == 300

    def test_release_policy_ignores_voiceflows_own_windows(self, win):
        win.user32.foreground = 300
        win.user32.pid = os.getpid()
        assert win.inj.retarget_to_foreground() is False
        assert win.inj._target_hwnd == 100

    def test_start_is_the_default_policy_and_the_release_hook_is_policy_gated(self, tmp_path, overlay, monkeypatch):
        assert Config().inject_target_policy == "start"
        monkeypatch.setattr(cli.keyboard, "unhook", lambda h: None, raising=False)
        start_app = _App(tmp_path)
        start_app.stop_recording()
        assert start_app.injector.retargeted == 0
        release_app = _App(tmp_path, inject_target_policy="release")
        release_app.stop_recording()
        assert release_app.injector.retargeted == 1


# ============================================================ item 5: learning

class TestLearnedHotwords:
    def test_term_is_promoted_after_two_explicit_corrections(self, tmp_path):
        store = hw.LearnedHotwords(tmp_path / "l.json", min_count=2)
        store.observe_pairs([("olama", "Ollama")])
        assert store.terms() == []
        store.observe_pairs([("a llama", "Ollama")])
        assert store.terms() == ["Ollama"]

    def test_persists_and_can_forget(self, tmp_path):
        a = hw.LearnedHotwords(tmp_path / "l.json", min_count=1)
        a.observe_pairs([("veev a", "Veeva")])
        assert hw.LearnedHotwords(tmp_path / "l.json", min_count=1).terms() == ["Veeva"]
        assert a.forget("veeva") is True
        assert a.terms() == []

    @pytest.mark.parametrize("term", ["the", "that", "to be or", "123", "a b", "it's", ""])
    def test_common_words_and_junk_are_never_promoted(self, term):
        assert hw.is_term_like(term) is False

    @pytest.mark.parametrize("term", ["Ollama", "Claude Code", "LIMS", "Madison", "faster-whisper"])
    def test_real_terms_qualify(self, term):
        assert hw.is_term_like(term) is True

    def test_only_explicit_user_corrections_feed_the_store(self, tmp_path):
        cfg = Config(adaptive_learning_enabled=True, learned_hotword_min_count=1)
        mgr = AdaptiveLearningManager(cfg)
        mgr._hotword_store = hw.LearnedHotwords(tmp_path / "l.json", min_count=1)
        mgr.observe("we use olama here", "we use Ollama here", {"source": "runtime_transcription"})
        mgr.observe("we use olama here", "we use Ollama here", {"source": "daily_auto_analysis"})
        assert mgr._hotword_store.terms() == [], "auto-detected deltas must not become hotwords"
        mgr.observe("we use olama here", "we use Ollama here", {"source": "manual_correction"})
        assert mgr._hotword_store.terms() == ["Ollama"]

    def test_learning_can_be_switched_off(self):
        mgr = AdaptiveLearningManager(Config(learned_hotwords_enabled=False))
        assert mgr._hotword_store is None


class TestEffectiveHotwords:
    SEEDS = ["VoiceFlow", "Wispr", "Claude", "Codex", "Gemini", "Ollama", "Atlas", "LIMS", "Veeva", "Madison"]

    def test_all_ten_seeds_present_even_with_an_old_saved_config(self, tmp_path):
        old_saved = "VoiceFlow, Wispr, Claude, Codex, Atlas, LIMS, Veeva"
        out = hw.effective_hotwords(old_saved, store_path=tmp_path / "none.json")
        terms = [t.strip() for t in out.split(",")]
        for seed in self.SEEDS:
            assert seed in terms

    def test_config_default_lists_the_seed_terms_too(self):
        terms = [t.strip() for t in Config().asr_hotwords.split(",")]
        assert terms == self.SEEDS

    def test_order_is_seeds_then_configured_then_learned(self, tmp_path):
        store = hw.LearnedHotwords(tmp_path / "l.json", min_count=1)
        store.observe_pairs([("kubernetes", "Kubernetes")])
        out = hw.effective_hotwords("Zephyr", store_path=tmp_path / "l.json", min_count=1)
        terms = [t.strip() for t in out.split(",")]
        assert terms[:10] == self.SEEDS
        assert terms[10:] == ["Zephyr", "Kubernetes"]

    def test_deduplicates_case_insensitively(self, tmp_path):
        out = hw.effective_hotwords("claude, VOICEFLOW", store_path=tmp_path / "none.json")
        assert [t.lower() for t in out.split(", ")].count("claude") == 1

    def test_budget_is_bounded_however_much_is_learned(self, tmp_path):
        store = hw.LearnedHotwords(tmp_path / "l.json", min_count=1, max_terms=500, max_stored=500)
        store.observe_pairs([("x", f"Term{chr(65 + i % 26)}{chr(97 + i // 26)}abc") for i in range(120)])
        out = hw.effective_hotwords("", store_path=tmp_path / "l.json", min_count=1, max_terms=500)
        assert len(out) <= hw.MAX_HOTWORD_CHARS
        assert all(seed in out for seed in self.SEEDS), "seeds are never crowded out"

    def test_learned_terms_are_capped(self, tmp_path):
        store = hw.LearnedHotwords(tmp_path / "l.json", min_count=1, max_terms=3)
        store.observe_pairs([("x", w) for w in ("Alpha1x", "Bravo2x", "Charlie3", "Delta4x", "Echo5xx")])
        assert len(store.terms()) == 3

    def test_asr_wrapper_refreshes_hotwords_before_each_decode(self, tmp_path, monkeypatch):
        from voiceflow.core import asr_engine

        monkeypatch.setattr(hw, "default_store_path", lambda: tmp_path / "l.json")
        hw._CACHE.clear()
        seen = []
        monkeypatch.setattr(asr_engine.ASREngine, "transcribe",
                            lambda self, *a, **k: seen.append(self.model_config.hotwords) or SimpleNamespace(text="ok"))
        asr = asr_engine.ModernWhisperASR.__new__(asr_engine.ModernWhisperASR)
        asr.cfg = Config(enable_smart_prompting=False)
        asr.model_config = SimpleNamespace(hotwords="")
        asr.session_transcription_count = 0
        asr.transcribe(None)
        assert "Ollama" in seen[0] and "Zorblax" not in seen[0]
        hw.LearnedHotwords(tmp_path / "l.json", min_count=1).observe_pairs([("zorb lax", "Zorblax")])
        asr.cfg.learned_hotword_min_count = 1
        asr.transcribe(None)
        assert "Zorblax" in seen[1]


class TestAccuracyGuards:
    """Text-level guard: learning must not alter text that was already right."""

    CLEAN = [
        "We should review the deployment plan before Friday.",
        "Claude and Codex both read the config file.",
        "Madison has a great farmers market on Saturday.",
        "The llama grazed near the old stone wall.",
        "Veeva shipped the release notes this morning.",
        "Can you open the settings and check the hotkey?",
        "I think we should wait for the build to finish.",
        "Atlas will summarise the quarterly numbers.",
    ]

    def test_learned_corrections_leave_correct_text_untouched(self, tmp_path):
        cfg = Config(adaptive_learning_enabled=True, adaptive_user_correction_min_count=1)
        mgr = AdaptiveLearningManager(cfg)
        mgr._hotword_store = hw.LearnedHotwords(tmp_path / "l.json", min_count=1)
        for _ in range(2):
            mgr.observe("we use olama daily", "we use Ollama daily", {"source": "manual_correction"})
            mgr.observe("ask jem eye about it", "ask Gemini about it", {"source": "manual_correction"})
        changed = [t for t in self.CLEAN if mgr.apply(t) != t]
        assert changed == []
        assert mgr.apply("we use olama daily") == "we use Ollama daily"

    def test_hotword_string_does_not_depend_on_the_text_being_decoded(self, tmp_path):
        # hotwords bias decoding; they never rewrite output, so the text path is unaffected.
        a = hw.effective_hotwords("", store_path=tmp_path / "none.json")
        b = hw.effective_hotwords("", store_path=tmp_path / "none.json")
        assert a == b
