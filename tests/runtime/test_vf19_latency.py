"""VF-19: the slow tail - process scheduling, trigger/stop/paste timing, per-minute latency.

1. The app raises its own CPU priority (and memory priority, and opts out of power
   throttling) instead of trusting the launcher: Task Scheduler starts it BelowNormal.
2. New log fields: the trigger's callback-queue wait, the stop path and the wait
   behind a previous dictation (both missing from the health metric), and where the
   paste step's time goes.
3. scripts/dev/log_latency.py: latency per minute of audio, and a per-day cause table.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
import threading
import time
import types
from pathlib import Path

import pytest

import voiceflow.integrations.inject as inj
from voiceflow.core.config import Config
from voiceflow.integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener
from voiceflow.utils import process_priority as pp

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("vf19_log_latency", REPO / "scripts" / "dev" / "log_latency.py")
ll = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
sys.modules["vf19_log_latency"] = ll
_spec.loader.exec_module(ll)


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@pytest.fixture()
def vf_log():
    logger = logging.getLogger("voiceflow")
    handler = _Capture()
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield handler
    logger.removeHandler(handler)
    logger.setLevel(old_level)


# --------------------------------------------------------------------------- 1. scheduling


class FakeApi:
    def __init__(self, priority="below_normal", memory=2, throttling_ok=True, available=True, set_ok=True):
        self.available = available
        self.priority = pp.PRIORITY_CLASSES[priority]
        self.memory = memory
        self.throttling_ok = throttling_ok
        self.set_ok = set_ok
        self.set_calls: list[int] = []

    def get_priority_class(self):
        return self.priority

    def set_priority_class(self, value):
        self.set_calls.append(value)
        if self.set_ok:
            self.priority = value
        return self.set_ok

    def get_memory_priority(self):
        return self.memory

    def set_memory_priority(self, value):
        self.memory = value
        return True

    def disable_execution_speed_throttling(self):
        return self.throttling_ok


def test_below_normal_launch_is_raised_to_normal_and_logged(vf_log):
    api = FakeApi("below_normal", memory=2)
    result = pp.ensure_interactive_scheduling("normal", api=api, log=logging.getLogger("voiceflow"))
    assert result["before"] == "below_normal"
    assert result["after"] == "normal"
    assert result["raised"] is True
    assert (result["memory_before"], result["memory_after"]) == (2, pp.MEMORY_PRIORITY_NORMAL)
    assert result["power_throttling"] == "off"
    line = next(m for m in vf_log.messages if m.startswith("process_priority "))
    assert "before=below_normal after=normal raised=True" in line
    assert "memory_priority_before=2 memory_priority_after=5" in line


def test_idle_class_is_raised_too():
    api = FakeApi("idle")
    assert pp.ensure_interactive_scheduling("normal", api=api)["after"] == "normal"


@pytest.mark.parametrize("start", ["normal", "above_normal", "high"])
def test_never_lowers_a_priority(start):
    api = FakeApi(start, memory=5)
    result = pp.ensure_interactive_scheduling("normal", api=api)
    assert api.set_calls == []
    assert result["after"] == start
    assert result["raised"] is False
    assert result["memory_after"] == 5


def test_target_is_capped_at_above_normal():
    api = FakeApi("below_normal")
    pp.ensure_interactive_scheduling("realtime", api=api)
    assert api.set_calls == [pp.PRIORITY_CLASSES["above_normal"]]


def test_unknown_target_means_normal():
    api = FakeApi("below_normal")
    pp.ensure_interactive_scheduling("turbo", api=api)
    assert api.set_calls == [pp.PRIORITY_CLASSES["normal"]]


def test_failed_set_is_reported_not_claimed():
    api = FakeApi("below_normal", set_ok=False)
    result = pp.ensure_interactive_scheduling("normal", api=api)
    assert result["raised"] is False
    assert result["after"] == "below_normal"


def test_unavailable_api_is_a_logged_no_op(vf_log):
    result = pp.ensure_interactive_scheduling(api=FakeApi(available=False), log=logging.getLogger("voiceflow"))
    assert result["available"] is False
    assert "process_priority available=False" in vf_log.messages


def test_unsupported_power_throttling_is_reported():
    result = pp.ensure_interactive_scheduling(api=FakeApi("normal", throttling_ok=False))
    assert result["power_throttling"] == "unsupported"


def test_real_api_never_raises():
    # On Windows this reads (and may raise to Normal) the test process's own priority;
    # elsewhere it reports unavailable. Either way it must not throw or lower anything.
    result = pp.ensure_interactive_scheduling("normal")
    assert result["after"] in {"unknown", "normal", "above_normal", "high", "realtime"}


def test_app_startup_hook_honours_off_and_never_raises(monkeypatch, vf_log):
    from voiceflow.ui import cli_enhanced as ce

    log = logging.getLogger("voiceflow")
    assert ce._apply_process_priority(types.SimpleNamespace(process_priority_minimum="off"), log) == {}
    assert "process_priority skipped=config" in vf_log.messages

    def boom(*_a, **_k):
        raise RuntimeError("no kernel32")

    monkeypatch.setattr(pp, "ensure_interactive_scheduling", boom)
    assert ce._apply_process_priority(types.SimpleNamespace(process_priority_minimum="normal"), log) == {}
    assert any(m.startswith("process_priority_failed") for m in vf_log.messages)


def test_config_default_is_normal():
    assert Config().process_priority_minimum == "normal"


# --------------------------------------------------------------------------- 2. timing fields


def test_listener_measures_how_long_a_start_waited_behind_a_stop():
    listener = EnhancedPTTHotkeyListener(Config(), on_start=lambda: None, on_stop=lambda: None)
    release = threading.Event()
    ran = threading.Event()
    listener._dispatch("on_stop", lambda: release.wait(2.0))   # a slow stop path
    listener._dispatch("on_start", ran.set)
    time.sleep(0.12)
    release.set()
    assert ran.wait(2.0)
    assert listener.callback_wait_ms["on_start"] >= 100.0
    assert listener.callback_wait_ms["on_stop"] < 100.0


def test_listener_wait_ms_reads_the_listener_and_tolerates_its_absence():
    from voiceflow.ui.cli_enhanced import listener_wait_ms

    app = types.SimpleNamespace(ptt_listener=types.SimpleNamespace(callback_wait_ms={"on_start": 42.5}))
    assert listener_wait_ms(app, "on_start") == 42.5
    assert listener_wait_ms(app, "on_stop") == 0.0
    assert listener_wait_ms(types.SimpleNamespace(), "on_start") == 0.0   # test doubles, other backends


def test_pre_job_timing_splits_stop_queue_and_total():
    from voiceflow.ui.cli_enhanced import pre_job_timing

    t = {"stop_started_at": 100.0, "submitted_at": 100.05, "stop_wait_ms": 7.0}
    out = pre_job_timing(t, entered_at=106.05, now=106.55)
    assert out["stop_ms"] == pytest.approx(50.0)
    assert out["queue_ms"] == pytest.approx(6000.0)      # the 2026-11-10 21:35:14 case
    assert out["stop_wait_ms"] == 7.0
    assert out["stop_to_text_ms"] == pytest.approx(7.0 + 6550.0)


def test_pre_job_timing_without_stamps_is_zero_not_an_error():
    from voiceflow.ui.cli_enhanced import pre_job_timing

    assert pre_job_timing(None, 1.0, 2.0) == {"stop_wait_ms": 0.0, "stop_ms": 0.0, "queue_ms": 0.0, "stop_to_text_ms": 0.0}
    assert pre_job_timing({"submitted_at": "x"}, 1.0, 2.0)["queue_ms"] == 0.0
    # clock oddities never produce negative times
    assert pre_job_timing({"stop_started_at": 5.0, "submitted_at": 4.0}, 3.0, 2.0)["stop_ms"] == 0.0


@pytest.fixture()
def paste_env(monkeypatch):
    clip: dict = {13: "ORIGINAL"}
    monkeypatch.setattr(inj, "_HAS_WIN32CLIPBOARD", False)
    monkeypatch.setattr(
        inj,
        "pyperclip",
        types.SimpleNamespace(copy=lambda t: clip.__setitem__(13, t), paste=lambda: clip.get(13, "")),
    )
    sent: list = []
    monkeypatch.setattr(inj, "keyboard", types.SimpleNamespace(send=sent.append, write=lambda t, delay=0: sent.append(t)))
    monkeypatch.setattr(inj, "_pending_restore", None)
    monkeypatch.setattr(inj, "_ALLOW_DEFERRED_RESTORE", False)
    yield sent
    inj.flush_pending_clipboard_restore()


def _injector(**kw) -> inj.ClipboardInjector:
    cfg = Config(paste_injection=True, restore_clipboard=True, min_inject_interval_ms=0, type_if_len_le=0, **kw)
    injector = inj.ClipboardInjector(cfg)
    injector.target_window_exists = lambda: True
    injector._ensure_target_focus_for_release = lambda: True
    return injector


def test_paste_logs_where_its_time_went(paste_env, vf_log):
    injector = _injector()
    assert injector.inject("hello world") is True
    timing = injector.last_inject_timing
    assert timing["method"] == "paste"
    assert timing["settle_ms"] >= 25.0          # the fixed 30 ms clipboard settle
    parts = timing["throttle_ms"] + timing["target_ms"] + timing["snapshot_ms"] + timing["copy_ms"] + timing["settle_ms"] + timing["send_ms"]
    assert parts <= timing["total_ms"] + 1.0
    line = next(m for m in vf_log.messages if m.startswith("inject_timing "))
    assert "method=paste" in line and "settle_ms=" in line and "snapshot_ms=" in line
    assert "hello" not in line                  # numbers only, never the text


def test_refused_paste_still_logs_its_timing(paste_env, vf_log):
    injector = _injector()
    injector.target_window_exists = lambda: False
    assert injector.inject("hello world") is False
    assert injector.last_inject_timing["method"] == "none"
    assert injector.last_inject_timing["target_ms"] is not None
    assert any(m.startswith("inject_timing method=none") for m in vf_log.messages)


# --------------------------------------------------------------------------- 3. log analysis


def test_latency_per_audio_minute_with_short_clip_floor():
    assert ll.latency_per_audio_minute(1.0, 60.0) == pytest.approx(1.0)
    assert ll.latency_per_audio_minute(1.4, 84.0) == pytest.approx(1.0)
    # a 1 s clip counts as 10 s: 0.2 s of latency is 1.2 s/min, not 12
    assert ll.latency_per_audio_minute(0.2, 1.0) == pytest.approx(1.2)


def _fin(ts: str, dur: float, sec: float) -> str:
    return f"2026-11-10 {ts} INFO [T] transcription_finished duration={dur:.2f} seconds={sec:.3f} chars=10 words=2\n"


def _timing(ts: str, total: float, device: str = "cuda", idle: bool = False, warmup: float = 0.0, extra: str = "") -> str:
    return (
        f"2026-11-10 {ts} INFO [T] transcription_timing total_ms={total:.1f} path=primary model_id=m "
        f"device={device} compute=x retry_used=False compaction_ms=0.0 guard_ms=0.0 asr_ms={total:.1f} "
        f"retry_ms=0.0 post_ms=1.0 safe2_ms=0.0 heavy2_ms=0.0 second_pass=safe delta_chars=0 inject_ms=50.0 "
        f"raw_dur=5.00 compacted_dur=5.00 reduction=0.0 retry_strategy=none retry_chunks=0 "
        f"idle_resume={idle} idle_resume_force_primary=False warmup_ms={warmup:.1f}{extra}\n"
    )


def _day() -> list[str]:
    return [
        "2026-11-10 05:30:08 INFO [MainThread] single_instance_ok pid=1\n",
        "2026-11-10 05:30:38 INFO [ModelPreloader] Model preloading complete - load: 23.48s, warmup: 6.35s\n",
        # 1. CPU fallback
        "2026-11-10 09:46:14 INFO [P] recording_stopped duration=60.93 samples=1\n",
        "2026-11-10 09:46:14 INFO [T] transcription_started duration=44.70\n",
        _fin("09:46:25", 44.70, 11.63), _timing("09:46:26", 11629.7, device="cpu"),
        # 2. first after idle (on CPU too)
        "2026-11-10 10:09:58 INFO [P] recording_stopped duration=17.47 samples=1\n",
        "2026-11-10 10:10:04 INFO [T] transcription_started duration=14.58\n",
        _fin("10:10:09", 14.58, 11.196), _timing("10:10:09", 11196.2, device="cpu", idle=True, warmup=6044.6),
        # 3. long dictation: slow in wall time, normal per minute
        "2026-11-10 21:06:25 INFO [P] recording_stopped duration=88.06 samples=1\n",
        "2026-11-10 21:06:25 INFO [T] transcription_started duration=88.06\n",
        _fin("21:06:27", 88.06, 1.429), _timing("21:06:27", 1428.7),
        # 4. contention: nothing in VoiceFlow explains it
        "2026-11-10 21:34:58 INFO [P] recording_stopped duration=5.82 samples=1\n",
        "2026-11-10 21:34:58 INFO [T] transcription_started duration=5.82\n",
        "2026-11-10 21:35:14 INFO [P] recording_stopped duration=5.76 samples=1\n",
        _fin("21:35:19", 5.82, 21.559), _timing("21:35:20", 21559.0),
        # 5. queued 6 s behind #4, while a reconstruction runs
        "2026-11-10 21:35:20 INFO [T] transcription_started duration=5.76\n",
        _fin("21:35:24", 5.76, 3.908), _timing("21:35:24", 3907.8),
        "2026-11-10 21:35:32 INFO [vf-reconstruct_0] reconstruction_async status=rejected reason=word_ratio latency_ms=13010 usable=False\n",
        # 6. a normal one
        "2026-11-10 21:36:19 INFO [P] recording_stopped duration=10.18 samples=1\n",
        "2026-11-10 21:36:19 INFO [T] transcription_started duration=10.18\n",
        _fin("21:36:19", 10.18, 0.364), _timing("21:36:19", 364.1),
        # a line with dictated text must never matter
        "2026-11-10 21:36:20 INFO [T] something seconds=99999 duration=1 transcription_finished? no\n",
    ]


def test_cause_table_matches_the_2026_11_10_evidence():
    report = ll.day_report(_day(), "2026-11-10")
    assert report["recordings"] == 6
    causes = {s["time"]: s["causes"] for s in report["slow"]}
    assert causes["09:46:25"] == ["cpu_fallback"]
    assert causes["10:10:09"] == ["cpu_fallback", "first_after_idle"]   # warm-up not counted as queue
    assert causes["21:06:27"] == ["long_dictation"]
    assert causes["21:35:19"] == ["contention_unexplained"]
    assert causes["21:35:24"] == ["queued_behind_previous", "reconstruction_running"]
    assert "21:36:19" not in causes
    assert report["app_starts"] == 1


def test_model_loading_after_restart_is_its_own_cause():
    lines = [
        "2026-11-10 21:46:56 INFO [MainThread] single_instance_ok pid=2\n",
        _fin("21:47:30", 5.0, 30.0), _timing("21:47:30", 30000.0),
        "2026-11-10 21:49:35 INFO [ModelPreloader] Model preloading complete - load: 157.18s, warmup: 1.99s\n",
    ]
    assert ll.day_report(lines, "2026-11-10")["slow"][0]["causes"] == ["model_loading_after_restart"]


def test_logged_queue_ms_wins_over_timestamps():
    lines = [_fin("12:00:05", 5.0, 3.0), _timing("12:00:05", 3000.0, extra=" stop_wait_ms=0.0 stop_ms=20.0 queue_ms=2500.0 stop_to_text_ms=5600.0")]
    slow = ll.day_report(lines, "2026-11-10")["slow"][0]
    assert slow["queue_s"] == 2.5
    assert "queued_behind_previous" in slow["causes"]


def test_long_dictations_alone_do_not_make_a_per_minute_regression():
    lines = []
    for i in range(10):
        lines += [_fin(f"21:0{i}:00", 88.0, 1.4), _timing(f"21:0{i}:00", 1400.0)]
    report = ll.day_report(lines, "2026-11-10")
    assert report["release_to_text_p90_s"] > ll.WALL_LIMIT_S
    assert report["regression_wall_only"] is True
    assert report["regression_wall_and_per_minute"] is False


def test_real_slowness_is_still_a_regression():
    report = ll.day_report(_day(), "2026-11-10")
    assert report["regression_wall_and_per_minute"] is True


def test_summary_adds_queue_and_per_minute_on_new_logs():
    line = _timing("12:00:00", 400.0, extra=" stop_wait_ms=0.0 stop_ms=20.0 queue_ms=500.0 stop_to_text_ms=970.0")
    s = ll.summarize(ll.parse([line]))
    assert s["release_through_injection_ms"]["median"] == 970.0   # 400 + 50 inject + 20 + 500
    assert s["latency_per_audio_minute_s"]["median"] == pytest.approx(5.8, abs=0.1)  # 0.97 s per 10 s floor


def test_causes_cli(tmp_path, capsys):
    log = tmp_path / "voiceflow.log"
    log.write_text("".join(_day()), encoding="utf-8")
    assert ll.main([str(log), "--causes", "--date", "2026-11-10"]) == 0
    out = capsys.readouterr().out
    assert "cpu_fallback" in out and "contention_unexplained" in out
