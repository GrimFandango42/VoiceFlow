"""VF-24 item 1: what the decoder is actually handed, on every path the app uses.

Main pass, long-recording pieces (segmenter calls ``transcribe(audio)``) and the live
caption (``transcribe(audio, initial_prompt=<running text>, beam_size_override=1,
vad_filter_override=False)``) all go through ``ModernWhisperASR.transcribe`` ->
``ASREngine.transcribe`` -> ``FasterWhisperBackend.transcribe`` -> the model. Only the
model is faked here; it records its keyword arguments.

Finding: hotwords (shipped seeds + ``asr_hotwords`` + learned terms) already reached
every call. The vocabulary prompt did not reach the caption once its running text was
non-empty: the caller's context replaced it. That is fixed by ``vocab.compose_prompt``.
"""

from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

from voiceflow.ai import hotword_learning as hw
from voiceflow.core import asr_engine, vocab
from voiceflow.core.asr_engine import FasterWhisperBackend
from voiceflow.core.config import Config

AUDIO = np.full(16000, 0.05, dtype=np.float32)


class _RecordingModel:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def transcribe(self, audio, *, language=None, beam_size=1, best_of=1, temperature=0.0,
                   condition_on_previous_text=False, without_timestamps=False, vad_filter=False,
                   vad_parameters=None, initial_prompt=None, hotwords=None):
        self.calls.append(dict(initial_prompt=initial_prompt, hotwords=hotwords, beam_size=beam_size))
        seg = SimpleNamespace(text="a sentence about something else", start=0.0, end=1.0,
                              avg_logprob=-0.2, no_speech_prob=0.01)
        return iter([seg]), SimpleNamespace(language="en")


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    """A real ModernWhisperASR with a fake model, user files under tmp_path."""
    vocab_file = tmp_path / "custom_vocabulary.txt"
    vocab_file.write_text("# mine\nzorbo flux -> ZorboFlux\n", encoding="utf-8")
    monkeypatch.setattr(vocab, "_user_vocab_path", lambda: vocab_file)
    vocab.invalidate_cache()
    store = tmp_path / "learned_hotwords.json"
    hw.LearnedHotwords(store, min_count=1).observe_pairs([("kwerty", "Qwertyx")])
    monkeypatch.setattr(hw, "default_store_path", lambda: store)
    hw._CACHE.clear()

    cfg = Config(device="cpu", model_name="tiny.en", asr_hotwords="Zephyrine",
                 learned_hotword_min_count=1, enable_smart_prompting=True)
    asr = asr_engine.ModernWhisperASR(cfg)
    model = _RecordingModel()
    backend = FasterWhisperBackend(asr.model_config)
    backend._model = model
    asr._backend = backend
    yield SimpleNamespace(asr=asr, model=model, vocab_file=vocab_file,
                          vocab_bytes=vocab_file.read_bytes())
    vocab.invalidate_cache()
    hw._CACHE.clear()


def _hotword_terms(call: dict) -> list[str]:
    return [t.strip() for t in str(call["hotwords"] or "").split(",") if t.strip()]


def _assert_full_hotwords(call: dict) -> None:
    terms = _hotword_terms(call)
    for name in vocab.NAME_SEED_TERMS:
        assert name in terms, f"seed {name!r} missing from the decoder's hotwords"
    assert "Zephyrine" in terms, "configured asr_hotwords term missing"
    assert "Qwertyx" in terms, "learned hotword missing"


def test_main_pass_gets_seeds_config_learned_and_vocabulary(engine) -> None:
    engine.asr.transcribe(AUDIO)
    call = engine.model.calls[-1]
    _assert_full_hotwords(call)
    prompt = call["initial_prompt"] or ""
    assert "ZorboFlux" in prompt, "custom_vocabulary.txt canonical missing from the prompt"
    for name in vocab.NAME_SEED_TERMS:
        assert name in prompt, f"seed {name!r} missing from the vocabulary prompt"


def test_segmented_pieces_take_the_main_path(engine) -> None:
    # The segmenter decodes each piece with transcribe(chunk): no caller prompt.
    for _ in range(3):
        engine.asr.transcribe(AUDIO)
    for call in engine.model.calls:
        _assert_full_hotwords(call)
        assert "ZorboFlux" in (call["initial_prompt"] or "")


def test_live_caption_first_decode_gets_vocabulary_and_hotwords(engine) -> None:
    engine.asr.transcribe(AUDIO, initial_prompt=None, beam_size_override=1, vad_filter_override=False)
    call = engine.model.calls[-1]
    _assert_full_hotwords(call)
    assert "ZorboFlux" in (call["initial_prompt"] or "")
    assert call["beam_size"] == 1


def test_live_caption_with_running_text_keeps_both_context_and_vocabulary(engine) -> None:
    """The VF-24 fix: before, the running text replaced the vocabulary prompt."""
    running = "so I was telling Jen about the new dock"
    engine.asr.transcribe(AUDIO, initial_prompt=running, beam_size_override=1, vad_filter_override=False)
    call = engine.model.calls[-1]
    _assert_full_hotwords(call)
    prompt = call["initial_prompt"] or ""
    assert prompt.endswith(running), "the running text must stay last (Whisper keeps the end)"
    assert "ZorboFlux" in prompt and "Claude" in prompt
    assert len(prompt) <= vocab.INITIAL_PROMPT_MAX_CHARS


def test_composed_prompt_never_exceeds_the_budget() -> None:
    vocab.invalidate_cache()
    for ctx_len in (0, 10, 300, 690, 699, 700, 2000):
        ctx = ("word " * 500)[:ctx_len]
        assert len(vocab.compose_prompt(ctx)) <= vocab.INITIAL_PROMPT_MAX_CHARS


def test_smart_prompting_off_passes_the_caller_prompt_through(engine) -> None:
    engine.asr.cfg.enable_smart_prompting = False
    engine.asr.transcribe(AUDIO, initial_prompt="ctx only")
    assert engine.model.calls[-1]["initial_prompt"] == "ctx only"


def test_user_vocabulary_file_is_never_rewritten(engine) -> None:
    for prompt in (None, "running text"):
        engine.asr.transcribe(AUDIO, initial_prompt=prompt)
    assert engine.vocab_file.read_bytes() == engine.vocab_bytes


def test_seed_list_fits_the_measured_term_ceiling() -> None:
    assert set(vocab.NAME_SEED_TERMS) <= set(hw.SEED_HOTWORDS)
    assert list(hw.SEED_HOTWORDS[: len(vocab.NAME_SEED_TERMS)]) == list(vocab.NAME_SEED_TERMS)
    # Room is left for configured and learned terms (at least a quarter of the ceiling).
    assert len(hw.SEED_HOTWORDS) <= int(hw.MAX_HOTWORD_TERMS * 0.75)
    assert len(", ".join(hw.SEED_HOTWORDS)) <= hw.MAX_HOTWORD_CHARS


def test_learned_terms_keep_room_under_the_default_config(tmp_path) -> None:
    """Seeds + the default asr_hotwords alone reach the ceiling; corrections must still fit."""
    store = tmp_path / "l.json"
    hw.LearnedHotwords(store, min_count=1).observe_pairs(
        [("x", t) for t in ("Zorblax", "Quuxly", "Frobnic", "Wibblex", "Plughx", "Xyzzyq", "Thudly")]
    )
    hw._CACHE.clear()
    out = hw.effective_hotwords(Config().asr_hotwords, store_path=store, min_count=1)
    terms = [t.strip() for t in out.split(",")]
    assert len(terms) == hw.MAX_HOTWORD_TERMS
    learned_in = [t for t in terms if t in {"Zorblax", "Quuxly", "Frobnic", "Wibblex", "Plughx", "Xyzzyq", "Thudly"}]
    assert len(learned_in) == hw.LEARNED_RESERVED_TERMS
    assert terms[: len(hw.SEED_HOTWORDS)] == list(hw.SEED_HOTWORDS)
    # Without learned terms the configured list gets the whole remainder.
    hw._CACHE.clear()
    full = hw.effective_hotwords(Config().asr_hotwords, store_path=tmp_path / "none.json")
    for term in ("Wispr", "Atlas", "LIMS", "Veeva", "Madison"):
        assert term in full


def test_term_ceiling_is_enforced_however_much_is_configured(tmp_path) -> None:
    many = ", ".join(f"Termx{i}" for i in range(80))
    out = hw.effective_hotwords(many, store_path=tmp_path / "none.json", max_chars=10_000)
    terms = [t.strip() for t in out.split(",")]
    assert len(terms) == hw.MAX_HOTWORD_TERMS
    assert terms[: len(hw.SEED_HOTWORDS)] == list(hw.SEED_HOTWORDS)
