"""VF-24: collapse a short dictation that the decoder said more than once.

Whisper-family decoders sometimes loop on a short clip: "Here's an example." said
once comes out as "Here's an example. Here's an example. Here's an example."
Nobody dictates a clip of a few seconds by saying the same multi-word sentence
back-to-back, so for a clip under ``max_audio_seconds`` a sentence that repeats
immediately (the same after case and punctuation are normalised) is reduced to one.

What it deliberately does NOT do:

* touch a clip of ``max_audio_seconds`` or longer, or one whose length is unknown
  (a long dictation can say the same line twice on purpose);
* touch a repeat that is not back-to-back ("A. B. A." stays);
* touch a one-word sentence ("No. No." is emphasis, and the decoder's single-word
  loops are ``silence_artifacts``' business);
* reword anything: what survives is the first copy, verbatim.

``collapse_adjacent_repeats`` returns ``(text, removed)``; ``removed`` is the number
of duplicate copies dropped (0 = untouched), which is the ``n`` in the
``repeat_collapsed n=<k>`` log line.
"""

from __future__ import annotations

import re
from typing import List, Tuple

#: Clips at or above this length are never touched.
DEFAULT_MAX_AUDIO_SECONDS = 8.0

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_WORD = re.compile(r"[a-z0-9]+(?:'[a-z0-9]+)*")
_TERMINAL = ".!?"


def _words(text: str) -> Tuple[str, ...]:
    return tuple(_WORD.findall(text.lower().replace("’", "'")))


def _split_sentences(text: str) -> List[str]:
    return [part for part in _SENTENCE_END.split(text.strip()) if part.strip()]


def _collapse_sentences(sentences: List[str]) -> Tuple[List[str], int]:
    """Drop a sentence that equals the one right before it (after normalisation)."""
    kept: List[str] = []
    kept_words: List[Tuple[str, ...]] = []
    removed = 0
    for sentence in sentences:
        words = _words(sentence)
        if not words:
            kept.append(sentence)
            kept_words.append(words)
            continue
        if kept_words and words == kept_words[-1] and len(words) >= 2:
            removed += 1
            continue
        kept.append(sentence)
        kept_words.append(words)
    return kept, removed


def _drop_trailing_partial(sentences: List[str], removed: int) -> Tuple[List[str], int]:
    """After a loop was found, a final fragment that is only the start of the kept sentence is the loop's cut-off tail."""
    if removed < 1 or len(sentences) < 2:
        return sentences, removed
    last, before = _words(sentences[-1]), _words(sentences[-2])
    if last and len(last) < len(before) and before[: len(last)] == last:
        return sentences[:-1], removed + 1
    return sentences, removed


def _collapse_unpunctuated(text: str) -> Tuple[str, int]:
    """One run of words that is the same phrase over and over, with no sentence marks between the copies."""
    tokens = text.split()
    if len(tokens) < 4:
        return text, 0
    keys = [" ".join(_words(tok)) for tok in tokens]
    if not all(keys):
        return text, 0
    n = len(tokens)
    for period in range(2, n // 2 + 1):
        if len(set(keys[:period])) < 2:
            continue  # "ha ha ha ha" is one word said four times, not a phrase looped
        if all(keys[i] == keys[i % period] for i in range(n)):
            first = tokens[:period]
            if first[-1][-1] not in _TERMINAL and tokens[-1][-1] in _TERMINAL:
                first[-1] = first[-1].rstrip(",;:") + tokens[-1][-1]
            copies = n // period + (1 if n % period else 0)
            return " ".join(first), copies - 1
    return text, 0


def collapse_adjacent_repeats(
    text: str,
    audio_seconds: float,
    max_audio_seconds: float = DEFAULT_MAX_AUDIO_SECONDS,
) -> Tuple[str, int]:
    """Collapse back-to-back repeats of a sentence in the text of a short clip.

    Returns ``(text, removed)``. ``removed`` is 0 and ``text`` is returned unchanged for
    a long or unknown-length clip, for text with nothing repeated, and for a repeat that
    is a single word or is not adjacent.
    """
    if not text or not text.strip():
        return text, 0
    try:
        seconds = float(audio_seconds)
    except (TypeError, ValueError):
        return text, 0
    if not (0.0 < seconds < float(max_audio_seconds)):
        return text, 0

    sentences = _split_sentences(text)
    kept, removed = _collapse_sentences(sentences)
    kept, removed = _drop_trailing_partial(kept, removed)
    result = " ".join(kept) if removed else text.strip()
    if len(kept) == 1:
        result, extra = _collapse_unpunctuated(result)
        removed += extra
    if not removed:
        return text, 0
    return result, removed


__all__ = ["DEFAULT_MAX_AUDIO_SECONDS", "collapse_adjacent_repeats"]
