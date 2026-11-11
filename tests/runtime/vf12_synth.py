"""Synthetic dictation fixtures for VF-12.

No real speech and no Whisper model here (neither is available to the test run),
so a "word" is a tone burst whose frequency is its id, and the "decoder" is an
oracle that reports a burst as ``w<id>`` only if the audio it was handed contains
the WHOLE burst. A burst that was clipped (key released early, compaction trimmed
it, a segment boundary cut it) decodes as ``?``.

That makes these fixtures a measurement of what the audio path gives the decoder
-- tail cut, segment boundaries, silence handed to the model -- and says nothing
about acoustic word-error rate. Reports must say so.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

import numpy as np

SR = 16000
WORD_S = 0.35          # nominal duration of one synthetic word
WORD_GAP_S = 0.12      # gap between words inside a phrase
NOISE = 0.002          # room noise amplitude (std)
AMP = 0.25


def word_id_freq(word_id: int) -> float:
    return 300.0 + 40.0 * word_id


def _burst(word_id: int) -> np.ndarray:
    n = int(WORD_S * SR)
    t = np.arange(n) / SR
    env = np.ones(n)
    ramp = int(0.02 * SR)
    env[:ramp] = np.linspace(0, 1, ramp)
    env[-ramp:] = np.linspace(1, 0, ramp)
    return (AMP * env * np.sin(2 * np.pi * word_id_freq(word_id) * t)).astype(np.float32)


def noise(seconds: float, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return (rng.standard_normal(int(seconds * SR)) * NOISE).astype(np.float32)


@dataclass
class Built:
    audio: np.ndarray
    words: List[int]                    # expected ids in order
    gaps_before: List[float]            # silence before each phrase (seconds)
    word_spans: List[Tuple[int, int]]   # (start, end) sample of every word


def build(phrases: Sequence[Sequence[int]], gaps: Sequence[float], *, lead_s: float = 0.4,
          tail_s: float = 0.0, seed: int = 1) -> Built:
    """Phrases of word ids separated by ``gaps`` seconds of room noise.

    ``tail_s`` is silence after the last word (0 = the recording ends with the word,
    i.e. what is left if the key is released as the word finishes).
    """
    parts: List[np.ndarray] = [noise(lead_s, seed)]
    cursor = int(lead_s * SR)
    spans: List[Tuple[int, int]] = []
    words: List[int] = []
    for pi, phrase in enumerate(phrases):
        if pi > 0:
            g = noise(gaps[pi - 1], seed + pi)
            parts.append(g)
            cursor += len(g)
        for wi, wid in enumerate(phrase):
            if wi > 0:
                g = noise(WORD_GAP_S, seed + 100 + pi * 31 + wi)
                parts.append(g)
                cursor += len(g)
            b = _burst(wid)
            parts.append(b + noise(WORD_S, seed + 7 + wid + wi)[: len(b)])
            spans.append((cursor, cursor + len(b)))
            cursor += len(b)
            words.append(wid)
    if tail_s > 0:
        parts.append(noise(tail_s, seed + 999))
    return Built(np.concatenate(parts), words, list(gaps), spans)


# ---------------------------------------------------------------- oracle decoder

def _regions(audio: np.ndarray, thr: float = 0.03, frame: int = 160, gap_frames: int = 12):
    n = len(audio) // frame
    if n == 0:
        return []
    rms = np.sqrt(np.mean(audio[: n * frame].astype(np.float64).reshape(n, frame) ** 2, axis=1))
    on = rms >= thr
    out: List[List[int]] = []
    i = 0
    while i < n:
        if on[i]:
            j = i
            while j < n and on[j]:
                j += 1
            if out and i - out[-1][1] <= gap_frames:
                out[-1][1] = j
            else:
                out.append([i, j])
            i = j
        else:
            i += 1
    return [(a * frame, b * frame) for a, b in out]


def oracle_words(audio: np.ndarray) -> List[str]:
    """One token per burst: ``w<id>`` if intact, ``?`` if clipped. Words inside a phrase
    are separated by 120 ms, so split regions on dips as well."""
    toks: List[str] = []
    frame = 160
    n = len(audio) // frame
    if n == 0:
        return toks
    rms = np.sqrt(np.mean(audio[: n * frame].astype(np.float64).reshape(n, frame) ** 2, axis=1))
    on = rms >= 0.03
    i = 0
    while i < n:
        if on[i]:
            j = i
            while j < n and on[j]:
                j += 1
            seg = audio[i * frame: j * frame]
            dur = len(seg) / SR
            spec = np.abs(np.fft.rfft(seg * np.hanning(len(seg))))
            freq = float(np.argmax(spec)) * SR / len(seg)
            wid = int(round((freq - 300.0) / 40.0))
            toks.append(f"w{wid}" if dur >= 0.9 * WORD_S else "?")
            i = j
        else:
            i += 1
    return toks


class OracleEngine:
    """Stands in for the ASR engine. Silence-only audio gets a hallucinated "Thank you."."""

    def __init__(self) -> None:
        self.calls: List[Tuple[float, float]] = []   # (duration_s, voiced_fraction)
        self.last_no_speech_prob = 0.0

    def transcribe(self, audio: np.ndarray) -> str:
        n = len(audio) // 160
        rms = np.sqrt(np.mean(audio[: n * 160].astype(np.float64).reshape(n, 160) ** 2, axis=1)) if n else np.zeros(0)
        voiced = float(np.mean(rms >= 0.03)) if n else 0.0
        self.calls.append((len(audio) / SR, voiced))
        toks = oracle_words(audio)
        if not toks:
            self.last_no_speech_prob = 0.95
            return "Thank you."
        self.last_no_speech_prob = 0.05
        return " ".join(toks)
