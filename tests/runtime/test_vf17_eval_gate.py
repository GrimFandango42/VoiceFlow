"""VF-17 review finding 2: the evaluator must fail (non-zero exit) when acceptance is not met."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "vf_eval.py"


@pytest.fixture(scope="module")
def ev():
    spec = importlib.util.spec_from_file_location("vf_eval_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _row(**kw):
    base = dict(wer_before=0.05, wer_after_audio=0.05, tail_before=True, tail_after_audio=True,
                legible_before=1.0, legible_after_audio=1.0)
    base.update(kw)
    return base


def _result(key, *rows):
    return {"key": key, "title": key, "n": len(rows), "rows": list(rows)}


def test_clean_results_pass(ev) -> None:
    results = [_result("technical", _row(), _row(wer_after_audio=0.0)),
               _result("tail", _row(tail_before=False), _row())]
    assert ev.acceptance_failures(results, have_llm=False) == []


def test_a_wer_regression_on_one_fixture_fails_even_if_the_mean_improves(ev) -> None:
    results = [_result("technical", _row(wer_before=0.0, wer_after_audio=0.1), _row(wer_before=0.4, wer_after_audio=0.0))]
    failures = ev.acceptance_failures(results, have_llm=False)
    assert any("technical[0]: WER regressed" in f for f in failures), failures


def test_tail_retention_below_100_percent_fails(ev) -> None:
    results = [_result("tail", _row(), _row(tail_before=False, tail_after_audio=False))]
    failures = ev.acceptance_failures(results, have_llm=False)
    assert any("retention" in f for f in failures), failures


def test_losing_a_tail_word_the_base_kept_fails(ev) -> None:
    failures = ev.acceptance_failures([_result("fast", _row(tail_after_audio=False))], have_llm=False)
    assert any("tail word lost" in f for f in failures), failures


def test_legibility_regression_fails_but_not_for_the_tail_scenario(ev) -> None:
    worse = _row(legible_after_audio=0.5)
    assert any("legibility" in f for f in ev.acceptance_failures([_result("pauses", worse)], have_llm=False))
    assert not any("legibility" in f for f in ev.acceptance_failures([_result("tail", worse)], have_llm=False))


def test_full_pipeline_columns_are_used_when_the_llm_ran(ev) -> None:
    row = _row(wer_after=0.2, tail_after=True, legible_after=1.0)  # audio side fine, reconstruction made it worse
    failures = ev.acceptance_failures([_result("technical", row)], have_llm=True)
    assert any("WER regressed" in f for f in failures), failures


GOOD_WINDOW = {"text_preserved": True, "replace_refused_after_switch": True, "verdict": "clipboard:window_changed"}


def _run_main(ev, monkeypatch, tmp_path, scenario, window, flag=()):
    class _Dummy:
        def __init__(self, *a, **k) -> None:
            pass

    monkeypatch.setenv("VOICEFLOW_VOCABULARY_PATH", "")  # main() points it at an empty file; undo on teardown
    monkeypatch.setattr(ev, "Tts", _Dummy)
    monkeypatch.setattr(ev, "Asr", _Dummy)
    monkeypatch.setattr(ev, "run_scenario", lambda *a, **k: scenario)
    if isinstance(window, Exception):
        def _boom():
            raise window
        monkeypatch.setattr(ev, "run_window_switch", _boom)
    else:
        monkeypatch.setattr(ev, "run_window_switch", lambda: window)
    return ev.main(["--no-llm", "--no-corpus", "--scenarios", "technical", "--cache-dir", str(tmp_path), *flag])


def _clean_scenario():
    clean = _result("technical", _row())
    clean.update(wer_before=0.05, wer_after_audio=0.05, wer_after=None, tail_before=1.0, tail_after_audio=1.0,
                 tail_after=None, legible_before=1.0, legible_after_audio=1.0, legible_after=None)
    return clean


@pytest.mark.parametrize("flag,expected", [([], 1), (["--no-gate"], 0)])
def test_main_exit_code_follows_the_gate(ev, monkeypatch, tmp_path, flag, expected) -> None:
    regressed = _result("technical", _row(wer_before=0.0, wer_after_audio=0.1))
    regressed.update(wer_before=0.0, wer_after_audio=0.1, wer_after=None, tail_before=1.0, tail_after_audio=1.0,
                     tail_after=None, legible_before=1.0, legible_after_audio=1.0, legible_after=None)
    assert _run_main(ev, monkeypatch, tmp_path, regressed, GOOD_WINDOW, flag) == expected


# --- review round 3, finding 3: the window-switch scenario is part of the gate -------------------------------

def test_a_clean_run_with_good_window_safeguards_passes(ev, monkeypatch, tmp_path) -> None:
    assert _run_main(ev, monkeypatch, tmp_path, _clean_scenario(), GOOD_WINDOW) == 0


@pytest.mark.parametrize("broken", ["text_preserved", "replace_refused_after_switch"])
def test_a_false_window_switch_result_fails_the_gate(ev, monkeypatch, tmp_path, capsys, broken) -> None:
    window = dict(GOOD_WINDOW, **{broken: False})
    assert _run_main(ev, monkeypatch, tmp_path, _clean_scenario(), window) == 1
    out = capsys.readouterr().out
    assert "ACCEPTANCE: FAIL" in out and broken in out
    assert _run_main(ev, monkeypatch, tmp_path, _clean_scenario(), window, ["--no-gate"]) == 0


def test_a_missing_or_crashed_window_switch_result_fails_the_gate(ev, monkeypatch, tmp_path) -> None:
    assert _run_main(ev, monkeypatch, tmp_path, _clean_scenario(), {}) == 1
    assert _run_main(ev, monkeypatch, tmp_path, _clean_scenario(), RuntimeError("boom")) == 1


def test_window_failures_unit(ev) -> None:
    assert ev.window_failures(GOOD_WINDOW) == []
    assert len(ev.window_failures({"text_preserved": False, "replace_refused_after_switch": False})) == 2
    assert ev.acceptance_failures([], have_llm=False, window={"text_preserved": True}, check_window=True)
    assert ev.acceptance_failures([], have_llm=False) == []  # window not checked unless asked
