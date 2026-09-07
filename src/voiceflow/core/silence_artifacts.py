"""Suppress Whisper's silence hallucinations so blank audio yields blank text.

Whisper emits confident, well-formed phrases when handed silence or near-silence
— "Thank you." and "you" most often, plus a family of end-of-video sign-offs
learned from subtitle training data. It also loops short tokens when the audio
runs out mid-decode.

Two different problems, two different tests:

* **Repeat loops** are never legitimate dictation. A user does not say
  "okay okay okay" into a push-to-talk hotkey. Suppress on sight.
* **Single artifacts** ARE legitimate dictation sometimes. Someone really can
  dictate "Thank you." So these are only suppressed when the decoder itself
  reports it did not hear speech — `no_speech_prob` from faster-whisper — or
  when a separate non-speech guard already flagged the clip.

That second rule is the whole design. Suppressing "thank you" unconditionally
trades one annoying bug for a worse one: silently eating words the user said.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Loops. Space-joined so they match what a decoder actually emits.
#
# Historical note worth keeping: these were previously written as `'okay' * 3`,
# which Python evaluates to "okayokayokay" — no spaces. No decoder ever emits
# that, so every one of these filters silently matched nothing.
REPEAT_HALLUCINATIONS: tuple[str, ...] = (
    " ".join(["okay"] * 3),
    " ".join(["thank you"] * 2),
    " ".join(["you"] * 4),
    " ".join(["thanks for watching"] * 2),
    " ".join(["bye"] * 3),
)

# Single phrases Whisper produces from silence. Compared against the ENTIRE
# output after normalization, never as a substring — "thank you for the report"
# must survive.
SILENCE_ARTIFACTS: frozenset[str] = frozenset(
    {
        "thank you",
        "thanks",
        "thanks for watching",
        "thank you for watching",
        "thank you very much",
        "you",
        "bye",
        "bye bye",
        "so",
        "oh",
        "hmm",
        "please subscribe",
        "subscribe",
    }
)

#: Above this, faster-whisper is saying the segment is probably not speech.
DEFAULT_NO_SPEECH_THRESHOLD = 0.60

_PUNCT_EDGES = re.compile(r"^[\s\.\,\!\?\-—…\"'`]+|[\s\.\,\!\?\-—…\"'`]+$")
_WHITESPACE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Lowercase, collapse whitespace, strip edge punctuation."""
    if not text:
        return ""
    lowered = _WHITESPACE.sub(" ", str(text)).strip().lower()
    return _PUNCT_EDGES.sub("", lowered).strip()


def is_repeat_hallucination(
    text: str,
    patterns: Iterable[str] = REPEAT_HALLUCINATIONS,
) -> bool:
    """True when the text contains a known decoder loop."""
    haystack = normalize(text)
    if not haystack:
        return False
    return any(p in haystack for p in patterns)


def is_silence_artifact(
    text: str,
    artifacts: frozenset[str] = SILENCE_ARTIFACTS,
) -> bool:
    """True when the ENTIRE output is one known silence phrase."""
    return normalize(text) in artifacts


def classify(
    text: str,
    *,
    no_speech_prob: float = 0.0,
    non_speech_suspected: bool = False,
    no_speech_threshold: float = DEFAULT_NO_SPEECH_THRESHOLD,
) -> tuple[bool, str]:
    """Decide whether to suppress a transcription.

    Returns ``(suppress, reason)``. ``reason`` is stable and log-safe.

    ``no_speech_prob`` is the decoder's own confidence that the audio held no
    speech. ``non_speech_suspected`` is the app's separate burst/noise guard.
    Either one is enough to turn a lone "thank you" into silence; neither one
    present means the phrase is treated as something the user actually said.
    """
    if not text or not text.strip():
        return True, "empty"

    if is_repeat_hallucination(text):
        return True, "repeat_hallucination"

    if is_silence_artifact(text):
        if non_speech_suspected:
            return True, "silence_artifact_non_speech_guard"
        if float(no_speech_prob or 0.0) >= float(no_speech_threshold):
            return True, "silence_artifact_no_speech_prob"
        return False, "silence_artifact_but_speech_detected"

    return False, ""
