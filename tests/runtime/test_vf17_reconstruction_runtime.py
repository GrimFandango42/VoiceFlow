"""VF-17 item 5: no speed regression - sync only when it fits the budget, otherwise async.

Plus the "replace last paste" safety rules, which are what make the async path
usable without ever deleting the wrong text.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from types import SimpleNamespace

import pytest

from voiceflow.ai.reconstruction import ReconstructionOutcome
from voiceflow.ai.reconstruction_runtime import (
    AUTO_MIN_SAMPLES,
    LatencyTracker,
    ReconstructionCoordinator,
)
from voiceflow.ai.tuning_log import TuningLog
from voiceflow.core.config import Config

PRE = "so i think we need twelve licenses and maya should send the budget to the team"
GOOD = "So I think we need twelve licenses, and maya should send the budget to the team."


class _FakeReconstructor:
    """Stands in for the Ollama-backed Reconstructor with a controllable delay."""

    def __init__(self, delay_s: float = 0.0, outcome: ReconstructionOutcome | None = None) -> None:
        self.delay_s = delay_s
        self.outcome = outcome
        self.calls = 0
        self.gate: threading.Event | None = None

    def should_run(self, pre_text, *, code_mode=False, destination_profile=""):
        if code_mode:
            return False, "destination_excluded"
        return True, ""

    def reconstruct(self, pre_text, raw_text="", *, context=(), timeout_s=None):
        self.calls += 1
        if self.gate is not None:
            self.gate.wait(5)
        time.sleep(self.delay_s)
        if self.outcome is not None:
            return self.outcome
        return ReconstructionOutcome("accepted", text=GOOD, latency_ms=self.delay_s * 1000.0)


def _coord(**cfg_overrides) -> tuple[ReconstructionCoordinator, _FakeReconstructor]:
    cfg = Config()
    for k, v in cfg_overrides.items():
        setattr(cfg, k, v)
    fake = _FakeReconstructor()
    return ReconstructionCoordinator(cfg, fake), fake  # type: ignore[arg-type]


def test_auto_mode_starts_async_so_the_paste_is_never_delayed() -> None:
    coord, fake = _coord(reconstruction_mode="auto")
    assert coord.sync_wait_s() == 0.0

    fake.delay_s = 0.3  # slow model
    t0 = time.perf_counter()
    job = coord.begin(PRE)
    assert job is not None
    assert job.wait(coord.sync_wait_s()) is None  # not waited for
    assert (time.perf_counter() - t0) < 0.1, "begin()+wait(0) must not block on the model"


def test_auto_mode_goes_sync_only_after_p95_fits_budget_and_reverts_when_it_stops() -> None:
    coord, _ = _coord(reconstruction_mode="auto", reconstruction_budget_ms=800)
    for _ in range(AUTO_MIN_SAMPLES):
        coord.latency.record(250.0)
    assert coord.sync_wait_s() == pytest.approx(0.8)

    for _ in range(10):
        coord.latency.record(8000.0)  # the real llama3.1:8b-on-CPU case
    assert coord.sync_wait_s() == 0.0


def test_fixed_modes() -> None:
    assert _coord(reconstruction_mode="async")[0].sync_wait_s() == 0.0
    assert _coord(reconstruction_mode="sync", reconstruction_budget_ms=500)[0].sync_wait_s() == pytest.approx(0.5)
    assert _coord(reconstruction_mode="off")[0].sync_wait_s() == 0.0
    assert _coord(reconstruction_enabled=False)[0].mode == "off"


def test_sync_path_returns_the_accepted_text_within_budget() -> None:
    coord, fake = _coord(reconstruction_mode="sync", reconstruction_budget_ms=800)
    fake.delay_s = 0.05
    job = coord.begin(PRE)
    outcome = job.wait(coord.sync_wait_s())
    assert outcome is not None and outcome.accepted and outcome.text == GOOD


def test_sync_path_over_budget_falls_back_to_async() -> None:
    coord, fake = _coord(reconstruction_mode="sync", reconstruction_budget_ms=100)
    fake.delay_s = 0.4
    job = coord.begin(PRE)
    assert job.wait(coord.sync_wait_s()) is None  # missed the budget -> caller pastes the fast text
    published = threading.Event()
    coord.attach_async(job, utterance_id="u1", pasted_text=PRE, on_done=lambda o, usable: published.set())
    assert published.wait(3)
    assert coord.take_pending() is not None and coord.take_pending().improved_text == GOOD


def test_async_result_becomes_pending_only_if_accepted_and_different() -> None:
    for outcome, expect_pending in (
        (ReconstructionOutcome("rejected", text="x", reason="number_changed"), False),
        (ReconstructionOutcome("failed", reason="llm_error"), False),
        (ReconstructionOutcome("timeout", reason="llm_error"), False),
        (ReconstructionOutcome("unchanged", text=PRE), False),
        (ReconstructionOutcome("accepted", text=PRE), False),  # accepted but identical: nothing to swap
        (ReconstructionOutcome("accepted", text=GOOD), True),
    ):
        coord, fake = _coord(reconstruction_mode="async")
        fake.outcome = outcome
        job = coord.begin(PRE)
        done = threading.Event()
        coord.attach_async(job, utterance_id="u", pasted_text=PRE, on_done=lambda o, u: done.set())
        assert done.wait(3)
        assert (coord.take_pending() is not None) is expect_pending, outcome.status


def test_stale_result_for_an_older_paste_is_dropped() -> None:
    coord, fake = _coord(reconstruction_mode="async")
    fake.gate = threading.Event()
    first = coord.begin(PRE)
    second = coord.begin(PRE + " again")  # a newer dictation supersedes the first
    done = threading.Event()
    coord.attach_async(first, utterance_id="old", pasted_text=PRE, on_done=lambda o, u: done.set())
    fake.gate.set()
    assert done.wait(3)
    assert coord.take_pending() is None
    assert second is not None


def test_pending_expires() -> None:
    coord, fake = _coord(reconstruction_mode="async")
    job = coord.begin(PRE)
    done = threading.Event()
    coord.attach_async(job, utterance_id="u", pasted_text=PRE, on_done=lambda o, u: done.set())
    assert done.wait(3)
    assert coord.has_pending(120.0)
    coord.pending.created_at -= 500  # type: ignore[union-attr]
    assert not coord.has_pending(120.0)


def test_policy_skip_returns_no_job() -> None:
    coord, fake = _coord()
    assert coord.begin(PRE, code_mode=True) is None
    assert fake.calls == 0


def test_latency_tracker_percentiles() -> None:
    t = LatencyTracker()
    for v in range(1, 51):  # window is the last 50 samples
        t.record(float(v))
    assert t.p50() == pytest.approx(25.5)
    assert t.p95() == pytest.approx(47.55)
    for _ in range(50):
        t.record(1000.0)  # old samples age out of the window
    assert t.p50() == 1000.0


# ---------------------------------------------------------------------------
# replace-last-paste: the injector must refuse whenever deleting could hit the wrong text
# ---------------------------------------------------------------------------

@pytest.fixture
def injector(monkeypatch):
    from voiceflow.integrations import inject as inject_mod

    sent: list[str] = []
    pasted: list[str] = []
    clipboard: list[str] = []
    monkeypatch.setattr(inject_mod.keyboard, "send", lambda seq: sent.append(seq), raising=False)
    monkeypatch.setattr(inject_mod.keyboard, "is_pressed", lambda k: False, raising=False)
    monkeypatch.setattr(inject_mod.pyperclip, "copy", lambda s: clipboard.append(s))
    monkeypatch.setattr(inject_mod.pyperclip, "paste", lambda: "")

    cfg = Config(paste_injection=True, restore_clipboard=False, press_enter_after_paste=False, min_inject_interval_ms=0)
    inj = inject_mod.ClipboardInjector(cfg)
    inj._key_counter_live = True
    inj._foreground_window = lambda: 4242  # type: ignore[method-assign]
    inj._target_hwnd = None
    monkeypatch.setattr(inj, "paste_text", lambda text: (pasted.append(text) or True))
    inj._last_paste = {"text": PRE, "hwnd": 4242, "ts": time.time(), "keys": 0}
    inj.sent, inj.pasted, inj.clipboard = sent, pasted, clipboard
    return inj


def test_replace_swaps_text_with_exact_backspace_count(injector) -> None:
    assert injector.replace_last_paste(PRE, GOOD) == "replaced"
    assert injector.sent.count("backspace") == len(PRE)
    assert injector.pasted == [GOOD]
    assert injector.last_paste_text() == GOOD


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda i: i._last_paste.update(keys=-1), "typed_since_paste"),
        (lambda i: i._last_paste.update(hwnd=999), "window_changed"),
        (lambda i: i._last_paste.update(ts=time.time() - 1000), "too_old"),
        (lambda i: setattr(i, "_last_paste", None), "no_recent_paste"),
        (lambda i: setattr(i, "_key_counter_live", False), "keystroke_tracking_unavailable"),
        (lambda i: setattr(i.cfg, "press_enter_after_paste", True), "enter_was_sent"),
        (lambda i: i._last_paste.update(text="something else"), "text_mismatch"),
    ],
)
def test_replace_refuses_and_falls_back_to_clipboard(injector, mutate, reason) -> None:
    mutate(injector)
    result = injector.replace_last_paste(PRE, GOOD)
    assert result == f"clipboard:{reason}"
    assert "backspace" not in injector.sent  # nothing was deleted
    assert injector.pasted == []
    assert GOOD in injector.clipboard[-1]  # but the improved text is on the clipboard


def test_replace_refuses_multiline(injector) -> None:
    multi = "first line\nsecond line"
    injector._last_paste["text"] = multi
    assert injector.replace_last_paste(multi, GOOD).startswith("clipboard:multiline")
    assert "backspace" not in injector.sent


def test_replace_waits_for_hotkey_modifiers_then_refuses_if_stuck(injector, monkeypatch) -> None:
    from voiceflow.integrations import inject as inject_mod

    monkeypatch.setattr(inject_mod.keyboard, "is_pressed", lambda k: k == "ctrl", raising=False)
    monkeypatch.setattr(type(injector), "_wait_for_hotkey_release", staticmethod(lambda timeout_s=1.5: False))
    assert injector.replace_last_paste(PRE, GOOD) == "clipboard:modifiers_held"
    assert "backspace" not in injector.sent


def test_typing_after_the_paste_is_counted_but_our_own_events_and_hotkeys_are_not(injector) -> None:
    injector._last_paste["keys"] = injector._keys_typed
    ev = lambda name, t: SimpleNamespace(name=name, time=t)  # noqa: E731
    injector._ignore_until = 100.0
    injector._on_key_event(ev("a", 50.0))      # our own paste's event, delivered late
    assert injector._keys_typed == 0
    injector._on_key_event(ev("ctrl", 200.0))  # modifier
    assert injector._keys_typed == 0
    injector._on_key_event(ev("x", 200.0))     # the user typing
    assert injector._keys_typed == 1
    assert injector.replace_last_paste(PRE, GOOD) == "clipboard:typed_since_paste"


# ---------------------------------------------------------------------------
# app-level glue
# ---------------------------------------------------------------------------

def _app(tmp_path, injector_result="replaced"):
    import logging

    from voiceflow.ui.cli_enhanced import EnhancedApp

    coord, fake = _coord(reconstruction_mode="async")
    coord.pending = None
    calls = {}

    class _Inj:
        def replace_last_paste(self, old, new, max_age_s=120.0):
            calls["args"] = (old, new)
            return injector_result

        def copy_text_to_clipboard(self, t):
            calls["clip"] = t
            return True

    app = SimpleNamespace(
        reconstruction=coord,
        injector=_Inj(),
        cfg=Config(),
        tuning_log=TuningLog(tmp_path / "t.jsonl"),
        ptt_listener=None,
        visual_indicators_enabled=False,
        _log=logging.getLogger("t"),
    )
    app.replace_last_paste = lambda: EnhancedApp.replace_last_paste(app)
    app.has_pending_improvement = lambda: EnhancedApp.has_pending_improvement(app)
    return app, coord, calls


def test_app_replace_last_paste_happy_path(tmp_path) -> None:
    from voiceflow.ai.reconstruction_runtime import PendingImprovement

    app, coord, calls = _app(tmp_path)
    assert app.replace_last_paste() == "none"  # nothing pending
    assert not app.has_pending_improvement()

    app.tuning_log.append_utterance(raw_text="r", final_text=PRE, utterance_id="u9")
    coord.pending = PendingImprovement("u9", PRE, GOOD, time.time())
    assert app.has_pending_improvement()
    assert app.replace_last_paste() == "replaced"
    assert calls["args"] == (PRE, GOOD)
    assert coord.pending is None
    (rec,) = app.tuning_log.load_utterances()
    assert rec["reconstruction"]["applied"] == "replaced"


def test_app_replace_refusal_keeps_pending_so_the_user_can_retry(tmp_path) -> None:
    from voiceflow.ai.reconstruction_runtime import PendingImprovement

    app, coord, calls = _app(tmp_path, injector_result="clipboard:typed_since_paste")
    coord.pending = PendingImprovement("u9", PRE, GOOD, time.time())
    assert app.replace_last_paste() == "clipboard:typed_since_paste"
    assert coord.pending is not None
