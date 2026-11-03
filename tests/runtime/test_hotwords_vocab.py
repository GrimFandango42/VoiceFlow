"""VF-11: the app name came out as "voice flona". Bias the decoder and repair the leftovers,
without rewriting ordinary speech.

faster-whisper drops ``initial_prompt`` after the first 30 s window when it is not
conditioning on previous text, but re-applies ``hotwords`` to every window; Nithin's
failing dictation was 118 s, i.e. four windows. Hence hotwords, not a longer prompt.
"""
from __future__ import annotations

import logging
from types import SimpleNamespace

import numpy as np
import pytest

from voiceflow.core import asr_engine, textproc, vocab
from voiceflow.core.asr_engine import (
    FasterWhisperBackend,
    ModelConfig,
    _is_hotword_echo,
    _model_accepts_hotwords,
)
from voiceflow.core.config import Config

HOTWORDS = "VoiceFlow, Wispr, Claude, Codex, Atlas, LIMS, Veeva"


class _ModelWithHotwords:
    def __init__(self, text: str = "hello there") -> None:
        self.calls: list[dict] = []
        self.text = text

    def transcribe(self, audio, *, language=None, beam_size=1, best_of=1, temperature=0.0,
                   condition_on_previous_text=False, without_timestamps=False, vad_filter=False,
                   vad_parameters=None, initial_prompt=None, hotwords=None):
        self.calls.append(dict(initial_prompt=initial_prompt, hotwords=hotwords, beam_size=beam_size))
        seg = SimpleNamespace(text=self.text, start=0.0, end=1.0, avg_logprob=-0.2, no_speech_prob=0.01)
        return iter([seg]), SimpleNamespace(language="en")


class _ModelWithoutHotwords(_ModelWithHotwords):
    def transcribe(self, audio, *, language=None, beam_size=1, best_of=1, temperature=0.0,
                   condition_on_previous_text=False, without_timestamps=False, vad_filter=False,
                   vad_parameters=None, initial_prompt=None):
        self.calls.append(dict(initial_prompt=initial_prompt, hotwords="<unsupported>", beam_size=beam_size))
        seg = SimpleNamespace(text=self.text, start=0.0, end=1.0, avg_logprob=-0.2, no_speech_prob=0.01)
        return iter([seg]), SimpleNamespace(language="en")


def _backend(model, hotwords: str = HOTWORDS) -> FasterWhisperBackend:
    cfg = ModelConfig(name="t", model_id="t", backend="faster-whisper", hotwords=hotwords)
    backend = FasterWhisperBackend(cfg)
    backend._model = model
    return backend


AUDIO = np.full(16000, 0.05, dtype=np.float32)


# --- decoder gets the hotwords -------------------------------------------------------

def test_hotwords_reach_the_decoder_on_final_and_preview_passes() -> None:
    model = _ModelWithHotwords()
    backend = _backend(model)

    backend.transcribe(AUDIO, initial_prompt="Claude, MCP")                       # final pass
    backend.transcribe(AUDIO, beam_size_override=2, vad_filter_override=False)    # streaming preview

    assert [c["hotwords"] for c in model.calls] == [HOTWORDS, HOTWORDS]
    # initial_prompt is untouched: hotwords are an addition, not a replacement.
    assert model.calls[0]["initial_prompt"] == "Claude, MCP"


def test_empty_hotwords_are_not_sent() -> None:
    model = _ModelWithHotwords()
    _backend(model, hotwords="").transcribe(AUDIO)
    assert model.calls[0]["hotwords"] is None


def test_older_faster_whisper_without_hotwords_does_not_crash() -> None:
    model = _ModelWithoutHotwords()
    result = _backend(model).transcribe(AUDIO)
    assert result.text == "hello there"
    assert model.calls[0]["hotwords"] == "<unsupported>"
    assert _model_accepts_hotwords(model) is False
    assert _model_accepts_hotwords(_ModelWithHotwords()) is True


def test_installed_faster_whisper_accepts_hotwords() -> None:
    """The version the app is built against must support the parameter we rely on."""
    from faster_whisper import WhisperModel

    assert _model_accepts_hotwords(SimpleNamespace(transcribe=WhisperModel.transcribe)) is True


def test_config_default_and_guardrail() -> None:
    cfg = Config()
    for term in ("VoiceFlow", "Wispr", "Claude", "Codex", "Atlas", "LIMS", "Veeva"):
        assert term in cfg.asr_hotwords
    assert len(cfg.asr_hotwords) < 80  # short on purpose: long lists bias ordinary speech


def test_guardrail_keeps_the_default_and_trims_an_overlong_list() -> None:
    from voiceflow.utils.guardrails import validate_config

    untouched = validate_config(Config())
    assert untouched.asr_hotwords == Config().asr_hotwords

    cfg = Config()
    cfg.asr_hotwords = ", ".join(f"Term{i}" for i in range(80))
    trimmed = validate_config(cfg).asr_hotwords
    assert 0 < len(trimmed) <= 160
    assert not trimmed.endswith(",")  # trimmed on a term boundary

    cfg = Config()
    cfg.asr_hotwords = ["not", "a", "string"]  # type: ignore[assignment]
    assert validate_config(cfg).asr_hotwords == ""


def test_hotword_list_read_back_on_silence_is_discarded() -> None:
    assert _is_hotword_echo("VoiceFlow, Wispr Claude Codex", HOTWORDS) is True
    # Real dictation that merely mentions some of the terms is kept.
    assert _is_hotword_echo("Claude", HOTWORDS) is False
    assert _is_hotword_echo("open Claude and ask Codex about Atlas", HOTWORDS) is False
    assert _is_hotword_echo("anything at all", "") is False


def test_engine_blanks_a_hotword_echo_but_keeps_real_speech(monkeypatch) -> None:
    model = _ModelWithHotwords(text="VoiceFlow Wispr Claude Codex Atlas")
    engine = asr_engine.ASREngine(model_name="tiny.en", device="cpu", hotwords=HOTWORDS)
    engine._backend = _backend(model)
    engine.model_config.hotwords = HOTWORDS
    assert engine.transcribe(AUDIO).text == ""

    model.text = "send the Atlas report to Veeva"
    assert engine.transcribe(AUDIO).text == "send the Atlas report to Veeva"


# --- prompt vocabulary ----------------------------------------------------------------

def test_new_terms_fit_the_default_initial_prompt(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vocab, "_user_vocab_path", lambda: tmp_path / "custom_vocabulary.txt")
    vocab.invalidate_cache()
    prompt = vocab.initial_prompt()
    for term in ("Wispr", "Codex", "Atlas", "LIMS", "Veeva", "VoiceFlow", "Claude"):
        assert term in prompt


# --- rewrite repair, and general text must not change ---------------------------------

@pytest.fixture()
def no_user_vocab(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VOICEFLOW_VOCABULARY_PATH", str(tmp_path / "none.txt"))
    monkeypatch.setenv("VOICEFLOW_TERMS_PATH", str(tmp_path / "none.json"))


@pytest.mark.parametrize(
    "heard",
    ["voice flona", "Voice Flona", "voice flow", "voiceflow", "voice-flow", "voice flo", "voice flowna"],
)
def test_app_name_misheard_variants_are_repaired(heard: str, no_user_vocab) -> None:
    fixed = textproc._apply_technical_term_dictionary(f"I opened {heard} today", False)
    assert fixed == "I opened VoiceFlow today"


def test_app_name_repair_works_without_the_seeded_vocabulary_file(no_user_vocab) -> None:
    """Existing installs keep their old custom_vocabulary.txt; the rule must not live only there."""
    out = textproc._apply_technical_term_dictionary("voice flona is great", False)
    assert out == "VoiceFlow is great"


GENERAL_SENTENCES = [
    "The voice of the crowd flows through the old city.",
    "She atlas-mapped the route and asked for the lime juice.",
    "Please review the limits for the claude cloth and the codex of laws.",
    "We booked a flight to Florida and a voice lesson in Madison.",
    "An atlas of the world sat next to a dictionary on the shelf.",
    "The workflow needs a voicemail flow and a clean handoff.",
    "Veeva is a company; wispr is not a word; limbs and lemons are.",
    "I would like two coffees, a bagel, and the weather forecast for tomorrow.",
]


@pytest.mark.parametrize("sentence", GENERAL_SENTENCES)
def test_ordinary_sentences_are_not_rewritten(sentence: str, no_user_vocab) -> None:
    """The added rule must not change speech that is not the app's name."""
    assert textproc._apply_technical_term_dictionary(sentence, False) == sentence
