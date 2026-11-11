"""Pieces split at a breath pause must read as one sentence, without changing a word."""

from voiceflow.core.segmenter import join_across_pause


def joined(a, b):
    left, right = join_across_pause(a, b)
    return f"{left} {right}"


def test_piece_cut_on_a_word_no_sentence_ends_on_is_rejoined():
    assert joined("So overall seems to.", "Work well, the animations are smoother.") == (
        "So overall seems to work well, the animations are smoother."
    )


def test_lowercase_continuation_turns_the_full_stop_into_a_comma():
    assert joined("accuracy, and overall use of model efficiency.", "and also automation.") == (
        "accuracy, and overall use of model efficiency, and also automation."
    )


def test_real_sentence_boundaries_are_left_alone():
    assert joined("That is awesome.", "The timer is great.") == "That is awesome. The timer is great."
    assert joined("Is it working?", "Yes it is.") == "Is it working? Yes it is."


def test_names_acronyms_and_i_keep_their_capitals():
    assert joined("Send this to.", "VoiceFlow for testing.") == "Send this to VoiceFlow for testing."
    assert joined("I went because.", "I wanted to.") == "I went because I wanted to."
    assert joined("It is the.", "GPU that matters.") == "It is the GPU that matters."


def test_no_words_are_added_or_removed():
    a, b = "We should look at the.", "History panel next."
    assert joined(a, b).lower().replace(",", "").replace(".", "").split() == (
        (a + " " + b).lower().replace(".", "").split()
    )


def test_words_that_do_end_sentences_are_not_joined():
    assert joined("I'll send it to you.", "Get back to me.") == "I'll send it to you. Get back to me."
    assert joined("Tell me what it is.", "Then we decide.") == "Tell me what it is. Then we decide."


def test_short_silent_recording_is_not_decoded(monkeypatch):
    import numpy as np
    from voiceflow.core import segmenter

    class Engine:
        calls = 0

        def transcribe(self, audio, **kw):
            Engine.calls += 1
            return "End."

    audio = np.zeros(16000 * 3, dtype=np.float32)
    monkeypatch.setattr(segmenter, "vad_speech_regions", lambda a, sr, cfg=None: [])
    assert segmenter.decode_for_duration(Engine(), audio, None) == ""
    assert Engine.calls == 0
    # VAD unavailable (None) must not block real speech: decode as before.
    monkeypatch.setattr(segmenter, "vad_speech_regions", lambda a, sr, cfg=None: None)
    assert segmenter.decode_for_duration(Engine(), audio, None) == "End."
    # Speech present: decoded.
    monkeypatch.setattr(segmenter, "vad_speech_regions", lambda a, sr, cfg=None: [(0, 16000)])
    assert segmenter.decode_for_duration(Engine(), audio, None) == "End."
