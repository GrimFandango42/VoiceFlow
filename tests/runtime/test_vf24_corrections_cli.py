"""VF-24 item 2: one command records "heard X, meant Y" where the nightly learner reads it.

Everything runs against tmp_path (``--data-dir``); the suite's conftest also sandboxes
%LOCALAPPDATA%, so the live data folder is unreachable.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from voiceflow.ai import corrections
from voiceflow.ai.daily_learning import DailyLearningJob
from voiceflow.core.config import Config

ROOT = Path(__file__).resolve().parents[2]


def _rows(data_dir: Path) -> list[dict]:
    path = data_dir / corrections.CORRECTIONS_FILENAME
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_add_then_list_shows_the_entry(tmp_path, capsys) -> None:
    assert corrections.main(["add", "--heard", "x", "--meant", "y", "--data-dir", str(tmp_path)]) == 0
    assert corrections.main(["list", "--data-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "x -> y" in out
    row = _rows(tmp_path)[0]
    assert row["original_text"] == "x" and row["corrected_text"] == "y"
    assert row["source"] == "manual_correction"
    assert row["local_ts"] and row["ts"] > 0


def test_list_is_newest_first_and_read_only(tmp_path, capsys) -> None:
    for heard, meant in (("Jamelan", "Gemini"), ("OpenRoder", "OpenRouter")):
        corrections.main(["add", "--heard", heard, "--meant", meant, "--data-dir", str(tmp_path)])
    before = (tmp_path / corrections.CORRECTIONS_FILENAME).read_bytes()
    capsys.readouterr()
    corrections.main(["list", "--data-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert out.index("OpenRoder -> OpenRouter") < out.index("Jamelan -> Gemini")
    assert (tmp_path / corrections.CORRECTIONS_FILENAME).read_bytes() == before


def test_list_on_an_empty_folder(tmp_path, capsys) -> None:
    assert corrections.main(["list", "--data-dir", str(tmp_path)]) == 0
    assert "No corrections recorded" in capsys.readouterr().out


@pytest.mark.parametrize(("heard", "meant"), [("", "y"), ("x", "  "), ("Gemini", "gemini")])
def test_empty_or_no_op_pairs_are_refused(tmp_path, heard, meant) -> None:
    assert corrections.main(["add", "--heard", heard, "--meant", meant, "--data-dir", str(tmp_path)]) == 2
    assert not (tmp_path / corrections.CORRECTIONS_FILENAME).exists()


def test_ordinary_english_is_recorded_with_a_warning(tmp_path, capsys) -> None:
    # The measured "do it" for Duet: the evidence is kept (it can promote a hotword),
    # but it never becomes a global rewrite (see test_vf24_cloud_rules).
    assert corrections.main(["add", "--heard", "do it", "--meant", "Duet", "--data-dir", str(tmp_path)]) == 0
    assert "ordinary English" in capsys.readouterr().out
    assert _rows(tmp_path)[0]["original_text"] == "do it"


def test_module_runs_as_a_command(tmp_path) -> None:
    """The documented form: python -m voiceflow.ai.corrections add/list."""
    env_cmd = [sys.executable, "-m", "voiceflow.ai.corrections"]
    kw = dict(cwd=str(ROOT / "src"), capture_output=True, text=True, timeout=60,
              env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")})
    added = subprocess.run([*env_cmd, "add", "--heard", "x", "--meant", "y", "--data-dir", str(tmp_path)], **kw)
    assert added.returncode == 0, added.stderr
    listed = subprocess.run([*env_cmd, "list", "--data-dir", str(tmp_path)], **kw)
    assert listed.returncode == 0, listed.stderr
    assert "x -> y" in listed.stdout


def _write_dated(data_dir: Path, heard: str, meant: str, when: datetime, n: int) -> None:
    path = data_dir / corrections.CORRECTIONS_FILENAME
    with path.open("a", encoding="utf-8") as fh:
        for _ in range(n):
            fh.write(json.dumps({"ts": when.timestamp(), "local_ts": when.isoformat(timespec="seconds"),
                                 "original_text": heard, "corrected_text": meant,
                                 "source": "manual_correction", "entry_point": "cli"}) + "\n")


def _job(tmp_path: Path) -> DailyLearningJob:
    cfg = Config(adaptive_learning_enabled=True, adaptive_user_correction_min_count=2,
                 adaptive_ai_analysis_enabled=False)
    job = DailyLearningJob(cfg, base_dir=tmp_path)
    from voiceflow.ai.hotword_learning import LearnedHotwords

    job.manager._hotword_store = LearnedHotwords(tmp_path / "learned_hotwords.json", min_count=2)
    return job


def test_two_logged_corrections_become_an_active_rule_overnight(tmp_path) -> None:
    yesterday = datetime.now() - timedelta(days=1)
    corrections.add_correction("Jamelan", "Gemini", data_dir=tmp_path)  # today: not yet processed
    _write_dated(tmp_path, "Jamelan", "Gemini", yesterday, 2)
    job = _job(tmp_path)
    report = job.run(days_back=1)
    assert report["stats"]["correction_items_total"] == 2
    assert report["stats"]["correction_items_used"] == 2
    assert job.manager.apply("Jamelan said hi") == "Gemini said hi"
    assert "Gemini" in job.manager._hotword_store.terms()


def test_one_logged_correction_is_not_yet_a_rule(tmp_path) -> None:
    _write_dated(tmp_path, "Jamelan", "Gemini", datetime.now() - timedelta(days=1), 1)
    job = _job(tmp_path)
    job.run(days_back=1)
    assert job.manager.apply("Jamelan said hi") == "Jamelan said hi"


def test_logged_do_it_never_rewrites_ordinary_speech(tmp_path) -> None:
    _write_dated(tmp_path, "do it", "Duet", datetime.now() - timedelta(days=1), 3)
    job = _job(tmp_path)
    job.run(days_back=1)
    assert job.manager.apply("please do it now") == "please do it now"
    assert "Duet" in job.manager._hotword_store.terms()
