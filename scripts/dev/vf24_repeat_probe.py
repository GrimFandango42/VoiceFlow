#!/usr/bin/env python
"""VF-24: how often does a short dictation come out more than once? (offline probe)

    python scripts/dev/vf24_repeat_probe.py                       # distil-large-v3 on CPU int8
    python scripts/dev/vf24_repeat_probe.py --model small.en --voices 0 --settings base,guards
    python scripts/dev/vf24_repeat_probe.py --json out.json

Nothing here launches the app, touches a microphone, the GPU or the real data
folder: the app's data directory is pointed at an empty temp folder, CPU is
forced and the Hugging Face hub is offline. Speech is Windows SAPI TTS; the model
comes from the local faster-whisper cache.

The audio takes the app's own final-decode route: AudioPreprocessor, pause
compaction, then ``segmenter.decode_audio`` (0.4 s of room tone appended) into a
real ``ModernWhisperASR`` (tail lift, vocabulary prompt, hotwords, the decode
settings and, from VF-24 on, the short-clip repetition guards).

A clip "repeats" when the normalised reference sentence occurs two or more times
in the normalised decode. The table is the share of clips that repeat.

``--settings base`` switches the VF-24 engine behaviour off (the pre-VF-24 decode);
``--settings guards`` leaves it on (the shipped defaults).
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
import time
import zlib
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

SR = 16000

PHRASES: List[str] = [
    "Here's an example.",
    "Thank you.",
    "Sounds good.",
    "Let me check.",
    "I'll send it today.",
    "Can you open the file?",
    "That works for me.",
    "Yes.",
    "Okay, let's go.",
    "Please call me back.",
    "This is a test.",
    "Add it to the list.",
]

#: Engine switches that VF-24 adds. ``base`` turns them off to get the pre-VF-24 decode.
VF24_SWITCHES = (
    "asr_short_clip_guards",
    "asr_tail_lift_skip_short",
    "repeat_collapse_enabled",
)


def norm(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9' ]+", " ", text.lower()).split())


def repeats_of(reference: str, decoded: str) -> int:
    ref, out = norm(reference), norm(decoded)
    if not ref or not out:
        return 0
    return len(re.findall(r"(?<![a-z0-9'])" + re.escape(ref) + r"(?![a-z0-9'])", out))


class VoiceTts:
    """vf_eval's SAPI helper with a selectable voice and a per-voice cache."""

    def __init__(self, cache: Path, voice_index: int) -> None:
        import vf_eval

        folder = cache / f"voice{voice_index}"
        folder.mkdir(parents=True, exist_ok=True)
        self.inner = vf_eval.Tts(folder)
        self.inner._sapi()
        voices = self.inner._voice.GetVoices()
        self.inner._voice.Voice = voices.Item(voice_index)
        self.name = voices.Item(voice_index).GetDescription()

    def say(self, text: str, rate: int = 0) -> np.ndarray:
        return self.inner.say(text, rate)


def build_clip(speech: np.ndarray, cut_after_ms: int, seed: int) -> np.ndarray:
    """0.4 s lead-in, the speech, then ``cut_after_ms`` of room-noise floor (the key release)."""
    rng = np.random.default_rng(seed)
    floor = 0.0004
    lead = (rng.standard_normal(int(0.4 * SR)) * floor).astype(np.float32)
    body = speech + (rng.standard_normal(len(speech)) * floor).astype(np.float32)
    tail = (rng.standard_normal(int(cut_after_ms / 1000 * SR)) * floor).astype(np.float32)
    return np.concatenate([lead, body, tail]).astype(np.float32)


def add_room_noise(clip: np.ndarray, snr_db: float, seed: int) -> np.ndarray:
    """Pink-ish room noise ``snr_db`` under the speech level (0 = none), as vf_eval does."""
    if snr_db <= 0:
        return clip
    import vf_eval

    rng = np.random.default_rng(seed)
    voiced = clip[np.abs(clip) > 0.01]
    speech_rms = float(np.sqrt(np.mean(voiced ** 2))) if voiced.size else 0.05
    sigma = speech_rms / (10 ** (snr_db / 20.0))
    return np.clip(clip + sigma * vf_eval._pinkish(len(clip), rng), -1.0, 1.0).astype(np.float32)


def fade_tail(speech: np.ndarray, db: float, ms: int = 350) -> np.ndarray:
    """Let the last word fade: ramp the final ``ms`` of speech down by ``db`` (a speaker dropping their voice)."""
    if db <= 0:
        return speech
    n = min(len(speech), int(ms / 1000 * SR))
    ramp = np.linspace(1.0, 10 ** (-db / 20.0), n).astype(np.float32)
    out = speech.copy()
    out[-n:] *= ramp
    return out


def ints(text: str) -> List[int]:
    return [int(x) for x in text.split(",")]


def floats(text: str) -> List[float]:
    return [float(x) for x in text.split(",")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="distil-large-v3")
    ap.add_argument("--voices", default="0,1", help="SAPI voice indexes, comma separated")
    ap.add_argument("--rates", default="0", help="SAPI rate values, comma separated")
    ap.add_argument("--cuts", default="0,25,50", help="ms of floor noise after the last word")
    ap.add_argument("--fades", default="0,10", help="dB the last 350 ms of speech fades by (0 = none)")
    ap.add_argument("--trunc", default="0", help="ms cut off the END of the speech (key released mid-word)")
    ap.add_argument("--snr", default="0", help="room-noise SNR in dB (0 = none)")
    ap.add_argument("--lifts", default="0,9", help="asr_tail_lift_db values")
    ap.add_argument("--settings", default="base", help="comma list of: base, guards (the VF-24 engine behaviour)")
    ap.add_argument("--json", default="")
    ap.add_argument("--cache", default="")
    args = ap.parse_args()

    import os
    import tempfile
    import types

    # Never read the real dictation folder: an empty temp folder, CPU only, offline.
    scratch = tempfile.mkdtemp(prefix="vf24_probe_")
    os.environ["LOCALAPPDATA"] = scratch
    os.environ["APPDATA"] = scratch
    os.environ["VOICEFLOW_FORCE_CPU"] = "1"
    os.environ["HF_HUB_OFFLINE"] = "1"

    from voiceflow.core import segmenter
    from voiceflow.core.asr_engine import ModernWhisperASR
    from voiceflow.core.audio_preprocessing import AudioPreprocessor
    from voiceflow.core.config import Config
    from voiceflow.ui.cli_enhanced import EnhancedApp

    cache = Path(args.cache) if args.cache else Path(tempfile.gettempdir()) / "vf24_probe_cache"
    cache.mkdir(parents=True, exist_ok=True)

    voices, rates, cuts = ints(args.voices), ints(args.rates), ints(args.cuts)
    fades, truncs, snrs = floats(args.fades), ints(args.trunc), floats(args.snr)
    lifts = floats(args.lifts)
    settings = args.settings.split(",")

    def make_engine(lift: float, setting: str):
        cfg = Config()
        cfg.model_name = args.model
        cfg.model_tier = None
        cfg.device = "cpu"
        cfg.compute_type = "int8"
        cfg.asr_tail_lift_db = lift
        if setting == "base":
            for name in VF24_SWITCHES:
                if hasattr(cfg, name):
                    setattr(cfg, name, False)
        return cfg, ModernWhisperASR(cfg)

    rows: List[Dict[str, Any]] = []
    started = time.time()
    for setting in settings:
        for lift in lifts:
            cfg, engine = make_engine(lift, setting)
            engine.load()
            for vi in voices:
                tts = VoiceTts(cache, vi)
                for rate, phrase in itertools.product(rates, PHRASES):
                    speech0 = tts.say(phrase, rate)
                    for fade, trunc, cut, snr in itertools.product(fades, truncs, cuts, snrs):
                        speech = fade_tail(speech0, fade)
                        if trunc > 0:
                            speech = speech[: max(1, len(speech) - int(trunc / 1000 * SR))]
                        seed = zlib.crc32(f"{vi}|{rate}|{phrase}|{cut}".encode())
                        clip = add_room_noise(build_clip(speech, cut, seed), snr, seed)
                        processed = AudioPreprocessor(cfg).process(clip)
                        audio = EnhancedApp._compact_pauses(types.SimpleNamespace(cfg=cfg), processed)
                        text = segmenter.decode_audio(engine, audio, cfg)
                        rows.append({
                            "setting": setting, "lift_db": lift, "voice": vi, "rate": rate,
                            "phrase": phrase, "fade_db": fade, "trunc_ms": trunc, "snr_db": snr,
                            "cut_ms": cut, "seconds": round(len(audio) / SR, 2), "text": text,
                            "repeats": repeats_of(phrase, text),
                        })
            engine.cleanup()
            print(f"setting={setting} lift={lift} done, {time.time() - started:.0f}s elapsed", flush=True)

    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1), encoding="utf-8")

    print()
    print(f"model={args.model} cpu int8, {len(rows)} decodes (real ModernWhisperASR + decode_audio path)")
    head = f"{'setting':8} {'lift_db':>7} {'fade_db':>7} {'trunc':>5} {'snr':>4} {'cut_ms':>6}"
    print(f"{head} {'clips':>6} {'repeat':>7} {'share':>6}  worst")
    for setting, lift, fade, trunc, snr, cut in itertools.product(settings, lifts, fades, truncs, snrs, cuts):
        sel = [r for r in rows if (r["setting"], r["lift_db"], r["fade_db"], r["trunc_ms"], r["snr_db"], r["cut_ms"])
               == (setting, lift, fade, trunc, snr, cut)]
        bad = [r for r in sel if r["repeats"] >= 2]
        worst = max((r["repeats"] for r in sel), default=0)
        share = 100 * len(bad) / max(1, len(sel))
        print(f"{setting:8} {lift:7.1f} {fade:7.1f} {trunc:5d} {snr:4.0f} {cut:6d} {len(sel):6d} {len(bad):7d} {share:5.1f}%  x{worst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
