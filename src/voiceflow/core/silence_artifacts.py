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

# Phrase loops. Space-joined so they match what a decoder actually emits.
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

#: Short words Whisper loops or emits alone when it is handed silence. Observed
#: in this user's own history at 0.9-2.6s of audio: "Okay.", "So.", "Thank you."
FILLER_TOKENS: frozenset[str] = frozenset(
    {
        "okay", "ok", "kay", "mkay",
        "you", "so", "oh", "ah", "um", "uh", "hmm", "mhm", "mm",
        "yeah", "bye", "thanks", "thank",
    }
)

#: A known filler repeated this many times in a row is a decoder loop --
#: but only when the run is essentially the whole output. "No no no, use the
#: other branch" is a person talking, not a loop.
FILLER_REPEAT_RUN = 3
#: Any token repeated this many times in a row is a loop, provided the run
#: dominates the output.
GENERIC_REPEAT_RUN = 4
#: Fraction of the output a generic run must cover to count as a loop.
GENERIC_REPEAT_DOMINANCE = 0.6

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
        "okay",
        "ok",
        "bye",
        "bye bye",
        "so",
        "oh",
        "hmm",
        "yeah",
        "please subscribe",
        "subscribe",
    }
)

#: Above this, faster-whisper is saying the segment is probably not speech.
DEFAULT_NO_SPEECH_THRESHOLD = 0.60

_PUNCT_EDGES = re.compile(r"^[\s\.\,\!\?\-—…\"'`]+|[\s\.\,\!\?\-—…\"'`]+$")
_WHITESPACE = re.compile(r"\s+")
_WORD = re.compile(r"[a-z0-9']+")


def normalize(text: str) -> str:
    """Lowercase, collapse whitespace, strip edge punctuation."""
    if not text:
        return ""
    lowered = _WHITESPACE.sub(" ", str(text)).strip().lower()
    return _PUNCT_EDGES.sub("", lowered).strip()


def tokenize(text: str) -> list[str]:
    """Lowercased words with ALL punctuation dropped.

    Interior punctuation is why a naive substring test misses the real thing:
    Whisper writes its loops as "Okay. Okay. Okay." far more often than
    "okay okay okay", and "okay okay okay" is not a substring of the former.
    """
    if not text:
        return []
    return _WORD.findall(str(text).lower())


def longest_run(tokens: list[str]) -> tuple[str, int]:
    """Return the most-repeated consecutive token and the length of its run."""
    if not tokens:
        return "", 0
    best_tok, best = tokens[0], 1
    cur_tok, cur = tokens[0], 1
    for tok in tokens[1:]:
        if tok == cur_tok:
            cur += 1
        else:
            cur_tok, cur = tok, 1
        if cur > best:
            best_tok, best = cur_tok, cur
    return best_tok, best


def is_repeat_hallucination(
    text: str,
    patterns: Iterable[str] = REPEAT_HALLUCINATIONS,
) -> bool:
    """True when the text is a decoder loop rather than dictation."""
    haystack = normalize(text)
    if not haystack:
        return False

    tokens = tokenize(text)
    if not tokens:
        return False

    # Known phrase loops -- but they too must dominate. "Thank you thank you"
    # alone is a loop; "thank you thank you so much for everything" is a person.
    for phrase in patterns:
        if phrase in haystack:
            phrase_len = len(tokenize(phrase))
            if phrase_len >= GENERIC_REPEAT_DOMINANCE * len(tokens):
                return True

    token, run = longest_run(tokens)
    # A loop is repetition that DOMINATES the output. Repetition surrounded by
    # real words is a person speaking emphatically.
    if run >= GENERIC_REPEAT_RUN and run >= GENERIC_REPEAT_DOMINANCE * len(tokens):
        return True
    if token in FILLER_TOKENS and run >= FILLER_REPEAT_RUN and run >= len(tokens) - 1:
        return True

    # "Okay. Okay." -- the whole output is one filler word, said twice or more.
    # Nobody dictates that on purpose.
    if len(tokens) >= 2 and len(set(tokens)) == 1 and tokens[0] in FILLER_TOKENS:
        return True

    return False


def is_silence_artifact(
    text: str,
    artifacts: frozenset[str] = SILENCE_ARTIFACTS,
) -> bool:
    """True when the ENTIRE output is one known silence phrase."""
    if normalize(text) in artifacts:
        return True
    # Also catch all-filler output that is not one of the fixed phrases,
    # e.g. "Okay, so." -- still needs silence evidence to be suppressed.
    tokens = tokenize(text)
    return bool(tokens) and len(tokens) <= 3 and all(t in FILLER_TOKENS for t in tokens)


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
