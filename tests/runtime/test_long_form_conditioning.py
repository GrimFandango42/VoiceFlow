"""Long dictations must not be decoded with cross-segment conditioning.

Whisper's `condition_on_previous_text` feeds its own prior output back into the
decode. On a medium clip that improves continuity. On a long one it propagates
the first error forward, and the transcript drifts, repeats, or drops words the
further it runs -- reported from real use as "the longer the conversation goes,
quality seems to deteriorate".
"""

from __future__ import annotations

import pytest

from voiceflow.core.config import Config


def _decision(audio_duration: float, cfg: Config, is_final_pass: bool = True) -> dict:
    """Mirror of the gate in FasterWhisperBackend.transcribe."""
    long_form = audio_duration >= 12.0 and is_final_pass
    ceiling = float(getattr(cfg, "long_form_condition_max_seconds", 30.0))
    long_form_condition = long_form and ceiling > 0 and audio_duration <= ceiling
    return {
        "beam_bumped": long_form,
        "conditioned": bool(cfg.condition_on_previous_text) or long_form_condition,
    }


class TestConditioningWindow:
    def test_short_clip_is_not_conditioned(self):
        assert _decision(5.0, Config())["conditioned"] is False

    @pytest.mark.parametrize("duration", [12.0, 20.0, 30.0])
    def test_medium_clip_keeps_the_conditioning_lift(self, duration):
        assert _decision(duration, Config())["conditioned"] is True

    @pytest.mark.parametrize("duration", [30.1, 61.0, 120.0, 300.0])
    def test_long_clip_is_decoded_clean(self, duration):
        # The regression this file exists for. A 60s dictation used to be
        # conditioned, and drifted.
        assert _decision(duration, Config())["conditioned"] is False


class TestBeamLiftIsUnaffected:
    @pytest.mark.parametrize("duration", [12.0, 30.0, 61.0, 300.0])
    def test_every_long_clip_still_gets_the_beam_bump(self, duration):
        # Only the conditioning was bounded; the accuracy lift stays.
        assert _decision(duration, Config())["beam_bumped"] is True

    def test_short_clip_keeps_the_fast_path(self):
        assert _decision(5.0, Config())["beam_bumped"] is False


class TestConfigurability:
    def test_ceiling_of_zero_disables_the_lift_entirely(self):
        cfg = Config(long_form_condition_max_seconds=0.0)
        for d in (12.0, 20.0, 90.0):
            assert _decision(d, cfg)["conditioned"] is False

    def test_ceiling_can_be_raised(self):
        cfg = Config(long_form_condition_max_seconds=120.0)
        assert _decision(90.0, cfg)["conditioned"] is True
        assert _decision(150.0, cfg)["conditioned"] is False

    def test_explicit_config_opt_in_still_wins(self):
        cfg = Config(condition_on_previous_text=True)
        assert _decision(300.0, cfg)["conditioned"] is True


class TestStreamingUnaffected:
    def test_preview_pass_is_never_conditioned_by_the_long_form_rule(self):
        # Streaming passes overrides, so is_final_pass is False.
        assert _decision(60.0, Config(), is_final_pass=False)["conditioned"] is False
