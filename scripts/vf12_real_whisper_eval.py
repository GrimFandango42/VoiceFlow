"""VF-12 real-Whisper evaluation: one code tree per run, then ``--compare``.

    python scripts/vf12_make_tts_clips.py                       # once: SAPI speech clips
    python scripts/vf12_real_whisper_eval.py --src build/vf12-real/old/src --label old
    python scripts/vf12_real_whisper_eval.py --src src --label new
    python scripts/vf12_real_whisper_eval.py --compare old new

``--src`` is the ``src`` directory of the tree under test (``old`` = ``git archive 15be897 src``
extracted under build/vf12-real/old). Everything runs offline against locally cached Whisper
models; LOCALAPPDATA is redirected to a scratch directory so no user data is read or written.

What is measured, for each tree, with the REAL model and each tree's own audio path
(pause compaction + decode entry point + short-clip model routing):

* long   : a 4+ minute dictation, 5-20 s pauses between sentences (WER, deleted words,
           inserted words = hallucinations)
* ending : 25 short utterances (questions, short final words) at several post-key-up
           tails (whole-utterance WER, last-word error)
* general: 12 ordinary sentences at a normal tail (WER)
* silence: silence / room-tone / speech-then-long-silence recordings (any output on pure
           silence is a hallucination)

Limits (state them in any report): speech is Windows SAPI TTS, not a human voice; the
microphone tail after key-up (recorder + hotkey listener) is not exercised, only the audio
the decoder is handed, so tail length is a parameter here.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import wave
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WORK = ROOT / "build" / "vf12-real"
SR = 16000
NOISE_STD = 0.002


# ------------------------------------------------------------------ text scoring

_NUM = {"50": "fifty", "3": "three", "1": "one", "2": "two", "5": "five"}


def norm(text: str) -> list[str]:
    text = text.lower().replace("let's", "let us").replace("-", " ")
    toks = re.findall(r"[a-z0-9']+", text)
    return [_NUM.get(t, t) for t in toks]


def edit_ops(ref: list[str], hyp: list[str]) -> tuple[int, int, int]:
    """(substitutions, deletions, insertions) of a minimal word alignment."""
    n, m = len(ref), len(hyp)
    d = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        d[i][0] = i
    for j in range(m + 1):
        d[0][j] = j
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (ref[i - 1] != hyp[j - 1]))
    i, j, s, dele, ins = n, m, 0, 0, 0
    while i or j:
        if i and j and d[i][j] == d[i - 1][j - 1] + (ref[i - 1] != hyp[j - 1]):
            s += ref[i - 1] != hyp[j - 1]
            i, j = i - 1, j - 1
        elif i and d[i][j] == d[i - 1][j] + 1:
            dele += 1
            i -= 1
        else:
            ins += 1
            j -= 1
    return s, dele, ins


# ------------------------------------------------------------------ audio fixtures

def load_clip(clip_id: str) -> np.ndarray:
    with wave.open(str(WORK / "clips" / f"{clip_id}.wav"), "rb") as w:
        rate = w.getframerate()
        assert w.getnchannels() == 1 and w.getsampwidth() == 2
        raw = w.readframes(w.getnframes())
    x = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
    if rate != SR:                                  # SAPI voices write their native 22.05 kHz
        # Linear interpolation is adequate for speech going 22.05 -> 16 kHz (no scipy needed).
        n_out = int(round(len(x) * SR / rate))
        x = np.interp(np.arange(n_out) * (rate / SR), np.arange(len(x)), x).astype(np.float32)
    return x


def tone(seconds: float, seed: int, std: float = NOISE_STD) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return (rng.standard_normal(int(seconds * SR)) * std).astype(np.float32)


def sentences() -> dict[str, str]:
    out = {}
    for ln in (HERE / "vf12_eval_sentences.txt").read_text(encoding="utf-8").splitlines():
        if ln.strip() and not ln.startswith("#"):
            k, v = ln.split("|", 1)
            out[k] = v
    return out


def utterance(clip_id: str, tail_s: float, seed: int = 0, lead_s: float = 0.4,
              noise_std: float = NOISE_STD) -> np.ndarray:
    """lead + speech + tail with constant background noise over the whole recording."""
    clip = load_clip(clip_id)
    n = int((lead_s + tail_s) * SR) + len(clip)
    audio = np.zeros(n, dtype=np.float32)
    audio[int(lead_s * SR):int(lead_s * SR) + len(clip)] = clip
    return audio + tone(n / SR, seed + 1, std=noise_std)[:n]


# ------------------------------------------------------------------ pipelines of the tree under test

class Pipeline:
    def __init__(self, src: str):
        sys.path.insert(0, src)
        os.environ["LOCALAPPDATA"] = str(WORK / "appdata")
        os.environ["APPDATA"] = str(WORK / "appdata")
        (WORK / "appdata").mkdir(parents=True, exist_ok=True)
        from voiceflow.core.config import Config
        from voiceflow.core.asr_engine import ModernWhisperASR
        from voiceflow.ui.cli_enhanced import EnhancedApp

        self.cfg = Config()
        self.cfg.audio_feedback_beeps = False
        self.primary = ModernWhisperASR(self.cfg)
        tiny_cfg = Config()
        tiny_cfg.model_tier = "tiny"
        self.tiny = ModernWhisperASR(tiny_cfg)
        try:
            from voiceflow.core.segmenter import decode_for_duration, should_segment
        except ImportError:                       # the old tree has no segmenter: always compacts
            decode_for_duration = should_segment = None
        self.decode_for_duration = decode_for_duration
        self.should_segment = should_segment

        cfg = self.cfg

        class _Compactor:
            _compact_pauses = EnhancedApp._compact_pauses

            def __init__(self):
                self.cfg = cfg

        self._compactor = _Compactor()
        self.primary_name = getattr(getattr(self.primary, "model_config", None), "name", "?")
        self.tiny_name = getattr(getattr(self.tiny, "model_config", None), "name", "?")

    def run(self, audio: np.ndarray) -> tuple[str, str]:
        """Same routing and buffer as EnhancedApp.stop_recording (cli_enhanced.py, "if should_segment").

        Route by raw duration. A segmentable recording (>= segmented_min_audio_seconds) goes to
        the decoder RAW because the segmenter replaces pause compaction; anything else is
        pause-compacted first. A tree without a segmenter (the old baseline) always compacts and
        does one transcribe call, which is what that tree did.
        """
        duration = len(audio) / SR
        threshold = min(
            float(getattr(self.cfg, "latency_boost_max_audio_seconds", 12.0)),
            float(getattr(self.cfg, "latency_boost_tiny_max_audio_seconds", 3.0)),
        )
        engine, path = (self.tiny, "fast") if 0.0 < duration <= threshold else (self.primary, "primary")
        if self.should_segment is not None and self.should_segment(duration, self.cfg):
            decode_in = audio
            path += "+segmented"
        else:
            decode_in = self._compactor._compact_pauses(audio)
        if self.decode_for_duration is not None:
            text = self.decode_for_duration(engine, decode_in, self.cfg)
        else:
            text = engine.transcribe(decode_in)
            text = getattr(text, "text", text)
        return str(text or "").strip(), path


# ------------------------------------------------------------------ scenarios

def scenario_long(p: Pipeline, texts: dict[str, str]) -> list[dict]:
    ids = [f"l{i:02d}" for i in range(1, 11)] + [f"g{i:02d}" for i in range(1, 7)]
    gaps = [5, 12, 8, 20, 6, 15, 9, 18, 7, 11, 14, 5, 19, 10, 16]     # seconds, 5-20 s
    parts = [tone(0.5, 11)]
    for k, cid in enumerate(ids):
        parts.append(load_clip(cid))
        if k < len(ids) - 1:
            parts.append(tone(gaps[k], 100 + k))
    parts.append(tone(0.7, 12))
    audio = np.concatenate(parts)
    ref = norm(" ".join(texts[c] for c in ids))
    t0 = time.time()
    text, path = p.run(audio)
    hyp = norm(text)
    s, d, i = edit_ops(ref, hyp)
    return [{"name": "long_paused_dictation", "seconds": round(len(audio) / SR, 1), "ref_words": len(ref),
             "sub": s, "del": d, "ins": i, "wer": round((s + d + i) / len(ref), 4), "decode_s": round(time.time() - t0, 1),
             "path": path, "text_tail": text[-160:]}]


def scenario_ending(p: Pipeline, texts: dict[str, str], conditions) -> list[dict]:
    rows = []
    for tail, noise_std in conditions:
        errs = last_err = words = 0
        fast = 0
        detail = []
        for n, cid in enumerate(sorted(c for c in texts if c.startswith("e"))):
            ref = norm(texts[cid])
            text, path = p.run(utterance(cid, tail, seed=n * 7, noise_std=noise_std))
            hyp = norm(text)
            s, d, i = edit_ops(ref, hyp)
            errs += s + d + i
            words += len(ref)
            last_bad = int(not hyp or hyp[-1] != ref[-1])
            last_err += last_bad
            fast += path.startswith("fast")
            if s + d + i:
                detail.append(f"{cid}: '{text}'")
        rows.append({"name": f"ending_tail_{tail:.2f}s_noise_{noise_std}", "utterances": 25, "ref_words": words, "word_errors": errs,
                     "wer": round(errs / words, 4), "last_word_errors": last_err, "routed_to_tiny": fast,
                     "misses": detail})
    return rows


def scenario_general(p: Pipeline, texts: dict[str, str]) -> list[dict]:
    errs = words = 0
    detail = []
    for n, cid in enumerate(sorted(c for c in texts if c.startswith("g"))):
        ref = norm(texts[cid])
        text, _ = p.run(utterance(cid, 0.7, seed=500 + n))
        s, d, i = edit_ops(ref, norm(text))
        errs += s + d + i
        words += len(ref)
        if s + d + i:
            detail.append(f"{cid}: '{text}'")
    return [{"name": "general_sentences", "utterances": 12, "ref_words": words, "word_errors": errs,
             "wer": round(errs / words, 4), "misses": detail}]


def scenario_silence(p: Pipeline, texts: dict[str, str]) -> list[dict]:
    cases = {
        "digital_silence_30s": np.zeros(30 * SR, dtype=np.float32),
        "room_tone_30s": tone(30.0, 21),
        "fan_noise_30s": tone(30.0, 22, std=0.01),
        "speech_then_20s_silence": np.concatenate([tone(0.4, 31), load_clip("e03"), tone(20.0, 32)]),
        # A genuinely spoken "Thank you." inside 30 s of noise must be KEPT (not scored as a hallucination).
        "spoken_thank_you_in_30s_noise": np.concatenate(
            [tone(12.0, 70, std=0.01), load_clip("t01") + tone(len(load_clip("t01")) / SR, 71, std=0.01),
             tone(16.0, 72, std=0.01)]),
        "speech_then_5x_pauses": np.concatenate(
            [tone(0.4, 41)] + [x for k in range(4) for x in (load_clip(f"e0{k + 1}"), tone(12.0, 50 + k))]
            + [load_clip("e05"), tone(0.7, 60)]),
    }
    refs = {"speech_then_20s_silence": texts["e03"],
            "spoken_thank_you_in_30s_noise": texts["t01"],
            "speech_then_5x_pauses": " ".join(texts[f"e0{k}"] for k in range(1, 6))}
    rows = []
    for name, audio in cases.items():
        text, path = p.run(audio)
        row = {"name": f"silence:{name}", "seconds": round(len(audio) / SR, 1), "output": text}
        if name in refs:
            ref = norm(refs[name])
            s, d, i = edit_ops(ref, norm(text))
            row.update({"ref_words": len(ref), "sub": s, "del": d, "ins": i, "wer": round((s + d + i) / len(ref), 4)})
        else:
            row["hallucinated_words"] = len(norm(text))
        rows.append(row)
    return rows


# ------------------------------------------------------------------ driver

SCENARIOS = ("ending", "general", "silence", "long")


def run_tree(src: str, label: str, only: tuple[str, ...] = SCENARIOS) -> None:
    texts = sentences()
    p = Pipeline(str(Path(src).resolve()))
    # warm the models so the first scenario is not charged for load time
    p.run(utterance("e01", 0.7))
    rows: list[dict] = []
    fns = {"ending": lambda: scenario_ending(p, texts, [(t, n) for n in (0.002, 0.03, 0.06) for t in (0.0, 0.2, 0.7)]),
           "general": lambda: scenario_general(p, texts),
           "silence": lambda: scenario_silence(p, texts),
           "long": lambda: scenario_long(p, texts)}
    for fn in (fns[k] for k in SCENARIOS if k in only):
        rows.extend(fn())
        print(f"[{label}] done {rows[-1]['name']}", flush=True)
    out = {"label": label, "src": src, "primary_model": p.primary_name, "tiny_model": p.tiny_name,
           "tiny_cap_s": getattr(p.cfg, "latency_boost_tiny_max_audio_seconds", None),
           "segmented": p.decode_for_duration is not None, "rows": rows}
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / f"results-{label}.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"wrote {WORK / f'results-{label}.json'}")


def compare(a: str, b: str) -> None:
    ra = json.loads((WORK / f"results-{a}.json").read_text(encoding="utf-8"))
    rb = json.loads((WORK / f"results-{b}.json").read_text(encoding="utf-8"))
    print(f"models: primary={ra['primary_model']} tiny={ra['tiny_model']}; "
          f"tiny cap {a}={ra['tiny_cap_s']}s {b}={rb['tiny_cap_s']}s\n")
    print(f"| scenario | metric | {a} | {b} |\n|---|---|---|---|")
    by_b = {r["name"]: r for r in rb["rows"]}
    for x in ra["rows"]:
        if x["name"] not in by_b:
            continue
        y = by_b[x["name"]]
        keys = [k for k in ("wer", "word_errors", "last_word_errors", "routed_to_tiny", "sub", "del", "ins",
                            "hallucinated_words", "decode_s") if k in x]
        for k in keys:
            print(f"| {x['name']} | {k} | {x[k]} | {y.get(k)} |")
        if "output" in x:
            print(f"| {x['name']} | output | {x['output']!r} | {y['output']!r} |")
    for label, r in ((a, ra), (b, rb)):
        for row in r["rows"]:
            for m in row.get("misses", []):
                print(f"[{label}] {row['name']} miss {m}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--src")
    ap.add_argument("--label")
    ap.add_argument("--only", default=",".join(SCENARIOS), help="comma list of: " + ",".join(SCENARIOS))
    ap.add_argument("--compare", nargs=2)
    a = ap.parse_args()
    if a.compare:
        compare(*a.compare)
    else:
        run_tree(a.src, a.label, tuple(x for x in a.only.split(",") if x))
