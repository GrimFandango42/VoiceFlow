"""The live caption pipeline, end to end, with a fake engine.

Speech is faked as a level per word: word N is 0.4 s of constant amplitude
N/1000, words are separated by 0.1 s of silence. The fake engine reads the
levels back as "wN". A word cut in two by a bad commit therefore shows up
twice, and a dropped stretch of audio shows up as a missing word, which is
exactly what the real caption must not do.
"""

from __future__ import annotations

import threading
import time

import numpy as np
import pytest

from voiceflow.core.live_caption import LiveCaptionSession, find_pause_cut

SR = 16000
WORD = int(0.4 * SR)
GAP = int(0.1 * SR)


def speech(first: int, last: int) -> np.ndarray:
    parts = []
    for n in range(first, last + 1):
        parts.append(np.full(WORD, n / 1000.0, dtype=np.float32))
        parts.append(np.zeros(GAP, dtype=np.float32))
    return np.concatenate(parts)


def fake_transcribe(audio: np.ndarray, prompt=None) -> str:
    words, last = [], 0
    for level in np.round(audio[::160] * 1000).astype(int):
        if level and level != last:
            words.append(f"w{level}")
        last = level
    return " ".join(words)


class Mic:
    """Stands in for the recorder's ring buffer."""

    def __init__(self, audio: np.ndarray):
        self.audio = audio
        self.available = 0

    def advance(self, seconds: float) -> None:
        self.available = min(len(self.audio), self.available + int(seconds * SR))

    def fetch(self, cursor: int):
        return self.audio[cursor : self.available], self.available


def run_dictation(audio, **kwargs):
    mic = Mic(audio)
    shown, calls = [], []

    def transcribe(chunk, prompt=None):
        calls.append(len(chunk) / SR)
        return fake_transcribe(chunk, prompt)

    session = LiveCaptionSession(transcribe, mic.fetch, shown.append, sample_rate=SR, **kwargs)
    while mic.available < len(audio):
        mic.advance(0.5)
        session.step()
    return session, shown, calls


def test_caption_is_the_whole_dictation_not_a_sliding_window():
    session, shown, _ = run_dictation(speech(1, 80))  # 40 seconds
    expected = " ".join(f"w{n}" for n in range(1, 81))
    assert shown[-1] == expected
    assert session.summary()["commits"] >= 3


def test_every_decode_is_bounded_however_long_the_dictation():
    _, _, calls = run_dictation(speech(1, 120), window_seconds=8.0)  # 60 seconds
    assert max(calls) <= 8.0 + 0.5 + 0.01


def test_caption_only_ever_grows_at_the_end():
    _, shown, _ = run_dictation(speech(1, 60))
    for before, after in zip(shown, shown[1:]):
        kept = before.split()[:-1]  # the last word may still be forming
        assert after.split()[: len(kept)] == kept


def test_first_words_appear_within_about_a_second_of_speech():
    session, shown, _ = run_dictation(speech(1, 4))
    assert shown and shown[0].startswith("w1")
    assert session.summary()["outcome"] == "ok"


def test_nothing_is_published_after_stop_even_from_a_decode_in_flight():
    mic = Mic(speech(1, 6))
    mic.advance(3.0)
    shown = []
    entered, release = threading.Event(), threading.Event()

    def slow(chunk, prompt=None):
        entered.set()
        release.wait(5)
        return fake_transcribe(chunk)

    session = LiveCaptionSession(slow, mic.fetch, shown.append, sample_rate=SR, interval_seconds=0.05)
    session.start()
    assert entered.wait(5)
    started = time.monotonic()
    summary = session.stop()
    assert time.monotonic() - started < 0.5, "stop() must not wait for the decode"
    release.set()
    session._thread.join(5)
    assert shown == []
    assert session.summary()["dropped_after_stop"] == 1
    assert summary["outcome"] != "ok"


def test_a_failing_engine_says_so_once_and_stops_trying():
    mic = Mic(speech(1, 40))
    shown, said, attempts = [], [], []

    def broken(chunk, prompt=None):
        attempts.append(1)
        raise RuntimeError("cublas64_12.dll not found")

    session = LiveCaptionSession(broken, mic.fetch, shown.append, on_status=said.append, sample_rate=SR)
    for _ in range(20):
        mic.advance(0.5)
        session.step()
    assert len(attempts) == 3
    assert shown == []
    assert len(said) == 1 and "cublas64_12.dll" in said[0]
    summary = session.summary()
    assert summary["outcome"] == "failed" and "cublas64_12.dll" in summary["last_error"]


def test_one_failed_decode_does_not_end_the_caption():
    mic = Mic(speech(1, 10))
    shown, n = [], [0]

    def flaky(chunk, prompt=None):
        n[0] += 1
        if n[0] == 2:
            raise RuntimeError("transient")
        return fake_transcribe(chunk)

    session = LiveCaptionSession(flaky, mic.fetch, shown.append, sample_rate=SR)
    for _ in range(10):
        mic.advance(0.5)
        session.step()
    assert shown[-1].split()[-1] == "w10"
    assert session.summary()["errors"] == 1


def test_silence_is_never_sent_to_the_engine():
    mic = Mic(np.zeros(SR * 6, dtype=np.float32))
    calls = []
    session = LiveCaptionSession(lambda a, p=None: calls.append(1) or "Thank you.", mic.fetch, lambda t: None, sample_rate=SR)
    for _ in range(12):
        mic.advance(0.5)
        session.step()
    assert calls == []
    assert session.summary()["outcome"] == "no_text"


def test_hallucinated_filler_is_filtered_out_of_the_caption():
    mic = Mic(speech(1, 4))
    shown = []
    session = LiveCaptionSession(
        lambda a, p=None: "Thank you.", mic.fetch, shown.append, sample_rate=SR,
        text_filter=lambda text: text == "Thank you.",
    )
    for _ in range(4):
        mic.advance(0.5)
        session.step()
    assert shown == []
    assert session.summary()["filtered"] >= 1


def test_committed_text_is_the_prompt_for_what_follows_never_the_same_audio():
    mic = Mic(speech(1, 40))
    prompts = []

    def transcribe(chunk, prompt=None):
        prompts.append((prompt, fake_transcribe(chunk)))
        return fake_transcribe(chunk)

    session = LiveCaptionSession(transcribe, mic.fetch, lambda t: None, sample_rate=SR)
    while mic.available < len(mic.audio):
        mic.advance(0.5)
        session.step()
    assert prompts[0][0] is None
    for prompt, heard in prompts:
        if prompt:
            assert not set(prompt.split()) & set(heard.split()), "prompt overlaps the audio being decoded"


def test_pause_cut_lands_in_the_gap_between_words():
    audio = speech(1, 20)
    cut = find_pause_cut(audio, SR, earliest_seconds=3.0, latest_seconds=9.0)
    assert audio[cut] == 0.0
    assert 3.0 * SR <= cut <= 9.0 * SR


def test_works_against_the_recorders_real_ring_buffer():
    audio_enhanced = pytest.importorskip("voiceflow.core.audio_enhanced")
    ring = audio_enhanced.BoundedRingBuffer(max_duration_seconds=300.0, sample_rate=SR)
    shown = []
    session = LiveCaptionSession(fake_transcribe, ring.get_samples_since, shown.append, sample_rate=SR)
    audio = speech(1, 30)
    for start in range(0, len(audio), SR // 2):
        ring.append(audio[start : start + SR // 2])
        session.step()
    assert shown[-1] == " ".join(f"w{n}" for n in range(1, 31))
