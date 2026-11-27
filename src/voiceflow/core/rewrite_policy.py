"""Words that must never become a global find-and-replace rule (VF-24).

Some mis-hearings are also ordinary English: Whisper writes "cloud" for "Claude" and
"do it" for "Duet", but "in the cloud" and "please do it now" are real speech. A
learned or configured rule ``cloud -> Claude`` would rewrite every genuine cloud, so
these sources are refused at every route that creates or applies a whole-word rule:

* adaptive rules learned from corrections (``ai/adaptive_memory.py``), new and on disk;
* ``custom_vocabulary.txt`` lines (``core/textproc.py``);
* review-queue approvals (``ai/review.py``) and VF-17 promotions (``core/vocab.py``).

The corrected term itself is still useful: an explicit ``do it -> Duet`` correction
still counts toward the durable hotword store, which biases the decoder toward "Duet"
without rewriting anything. Phrase rules that contain such a word ("cloud code",
"cloud max") are fine, because the phrase cannot mean a real cloud.

No imports beyond the standard library, so any layer can use it.
"""

from __future__ import annotations

import re
from typing import FrozenSet

#: Lower-cased, whitespace-collapsed sources that are never rewritten on their own.
NEVER_GLOBAL_SOURCES: FrozenSet[str] = frozenset(
    {
        "cloud",
        "clouds",
        "cloud's",
        "clouds'",
        "do it",
    }
)

_WS = re.compile(r"\s+")


def _normalize(source: str) -> str:
    text = _WS.sub(" ", str(source or "").strip().lower())
    return text.replace("’", "'")


def is_unsafe_global_source(source: str) -> bool:
    """True when ``source`` must not be the left-hand side of a whole-word rewrite rule."""
    return _normalize(source) in NEVER_GLOBAL_SOURCES


__all__ = ("NEVER_GLOBAL_SOURCES", "is_unsafe_global_source")
