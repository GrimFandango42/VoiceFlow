import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

import pytest

from voiceflow.core.asr_buffer_safe import BufferSafeWhisperASR
from voiceflow.core.config import Config


class DummyModel:
    def __init__(self, label):
        self.label = label
        self.closed = False

    def close(self):
        self.closed = True

    def transcribe(self, audio, **kwargs):
        return [], {"text": self.label}


@pytest.fixture()
def asr_instance():
    cfg = Config()
    return BufferSafeWhisperASR(cfg)


def test_reload_preserves_existing_model_on_failure(monkeypatch, asr_instance):
    old_model = DummyModel("old")
    asr_instance._model = old_model
    asr_instance._transcriptions_since_reload = 5

    monkeypatch.setattr(asr_instance, "_create_fresh_model", lambda: None)

    result = asr_instance._reload_model_fresh()

    assert result is False
    assert asr_instance._model is old_model
    assert asr_instance._transcriptions_since_reload == 5


def test_reload_swaps_model_when_creation_succeeds(monkeypatch, asr_instance):
    old_model = DummyModel("old")
    new_model = DummyModel("new")
    asr_instance._model = old_model
    asr_instance._transcriptions_since_reload = 12

    monkeypatch.setattr(asr_instance, "_create_fresh_model", lambda: new_model)
    monkeypatch.setattr(asr_instance, "_cleanup_model", lambda model: setattr(model, 'closed', True))

    result = asr_instance._reload_model_fresh()

    assert result is True
    assert asr_instance._model is new_model
    assert asr_instance._transcriptions_since_reload == 0
    assert asr_instance._consecutive_errors == 0


def test_ensure_model_available_returns_null_on_load_failure(monkeypatch, asr_instance):
    def failing_load():
        raise RuntimeError("load failure")

    monkeypatch.setattr(asr_instance, "load", failing_load)
    asr_instance._model = None

    model = asr_instance._ensure_model_available()

    assert model is asr_instance._null_model
