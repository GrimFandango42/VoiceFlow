"""VF-12 review finding 5: the real-Whisper harness must use the production audio routing.

Production (EnhancedApp.stop_recording): a recording that ``should_segment`` hands the decoder RAW,
because the segmenter replaces pause compaction; shorter recordings are pause-compacted first. The
harness used to compact unconditionally, so its long-paused numbers did not describe the app.
No model is loaded: the engines and decode entry point are fakes.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from voiceflow.core.config import Config
from voiceflow.core.segmenter import should_segment

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "vf12_real_whisper_eval.py"
SR = 16000


@pytest.fixture(scope="module")
def harness():
    spec = importlib.util.spec_from_file_location("vf12_real_whisper_eval", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pipeline(harness, *, segmentable: bool):
    p = object.__new__(harness.Pipeline)
    p.cfg = Config()
    p.primary, p.tiny = "PRIMARY", "TINY"
    seen = SimpleNamespace(compacted=0, decoded=[])

    class _Compactor:
        def _compact_pauses(self, audio):
            seen.compacted += 1
            return audio[: len(audio) // 2]          # visibly different from the raw buffer

    def _decode(engine, audio, cfg):
        seen.decoded.append((engine, len(audio)))
        return "text"

    p._compactor = _Compactor()
    p.decode_for_duration = _decode
    p.should_segment = should_segment if segmentable else None
    return p, seen


def test_long_recording_reaches_the_decoder_raw_and_uncompacted(harness):
    p, seen = _pipeline(harness, segmentable=True)
    audio = np.zeros(60 * SR, dtype=np.float32)
    text, path = p.run(audio)
    assert seen.compacted == 0, "segmentable recordings must bypass pause compaction, as in the app"
    assert seen.decoded == [("PRIMARY", len(audio))]
    assert path == "primary+segmented" and text == "text"


def test_short_recording_is_still_compacted_first(harness):
    p, seen = _pipeline(harness, segmentable=True)
    audio = np.zeros(8 * SR, dtype=np.float32)
    p.run(audio)
    assert seen.compacted == 1
    assert seen.decoded == [("PRIMARY", len(audio) // 2)]


def test_tiny_routing_is_by_raw_duration_and_unchanged(harness):
    p, seen = _pipeline(harness, segmentable=True)
    p.run(np.zeros(int(0.8 * SR), dtype=np.float32))
    assert seen.decoded[0][0] == "TINY"


def test_baseline_tree_without_a_segmenter_always_compacts(harness):
    p, seen = _pipeline(harness, segmentable=False)
    audio = np.zeros(60 * SR, dtype=np.float32)
    p.run(audio)
    assert seen.compacted == 1 and seen.decoded == [("PRIMARY", len(audio) // 2)]


def test_threshold_matches_the_app_config(harness):
    # The harness must not hard-code its own cut-off: it asks the same should_segment the app uses.
    cfg = Config()
    assert should_segment(cfg.segmented_min_audio_seconds, cfg)
    assert not should_segment(cfg.segmented_min_audio_seconds - 0.5, cfg)
