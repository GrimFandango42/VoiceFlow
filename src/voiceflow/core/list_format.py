"""Spoken lists become real lists, and nothing else does.

Two shapes are recognised, both of them things people say when they mean a
list:

* **Markers**: "point one ... point two ...", "number one ...", "step one ...",
  "item one ...", or "bullet ... bullet ...". Numbered markers must count up
  from one, so "my number one priority" stays prose.
* **Ordinals**: sentences that open with "First, ... Second, ... (Third, ...)
  (Finally, ...)", in that order, starting at "first". "Second thought, ...
  First, though, ..." is out of order and stays prose.

Rules that keep it safe, each covered by ``tests/runtime/test_list_format.py``:

1. Every item must have words of its own. "followed by point one, point two
   and then point three" names placeholders, not items, and is left exactly as
   spoken. (The formatter this replaces turned it into "followed by • And then.
   •", deleting the words.)
2. The marker words are the only words removed. Everything else is kept in
   order; items get a capital letter and lose a trailing comma.
3. Text before the list ends with a colon; text after it starts a new
   paragraph.

Output uses "1." for numbered markers and ordinals and "- " for bullets,
one item per line, which a chat box, an editor and Markdown all read as a list.
Pure string work: well under a millisecond for a minute of dictation.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

_NUM = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}

_MARKER = re.compile(
    r"(?<![\w'])(?:(?P<kind>point|number|item|step)\s+(?P<n>one|two|three|four|five|six|seven|eight|nine|ten|\d{1,2})"
    r"|(?P<bullet>bullet)(?:\s+point)?)(?![\w'])[ \t]*[,:.\-]?[ \t]*",
    re.IGNORECASE,
)

# Words that join items in speech and carry nothing of the item itself.
_CONNECTOR_TAIL = re.compile(r"(?:[\s,;]+(?:and then|and also|and|then|also|plus|or))+[\s,;]*$", re.IGNORECASE)
_CONNECTOR_HEAD = re.compile(r"^[\s,;:.\-]*(?:(?:and then|and|then|also)\b[\s,]*)?", re.IGNORECASE)
_INTRO_TAIL = re.compile(r"(?:[\s,;:]+(?:followed by|which are|namely|and they are|they are))?[\s,;:.]*$",
                         re.IGNORECASE)

_ORDINALS = ["first", "second", "third", "fourth", "fifth", "sixth"]
_ORDINAL_OPEN = re.compile(
    r"^(?P<w>first(?:ly)?(?:\s+of\s+all)?|second(?:ly)?|third(?:ly)?|fourth(?:ly)?|fifth(?:ly)?|sixth(?:ly)?"
    r"|finally|lastly)\b\s*[,:\-]\s*",
    re.IGNORECASE,
)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def _number(token: str) -> Optional[int]:
    token = token.lower()
    if token.isdigit():
        return int(token)
    return _NUM.get(token)


def _clean_item(text: str) -> str:
    item = _CONNECTOR_HEAD.sub("", text or "")
    item = _CONNECTOR_TAIL.sub("", item).strip()
    item = re.sub(r"[\s,;:]+$", "", item)
    if item and item[0].islower():
        item = item[0].upper() + item[1:]
    return item


def _has_words(item: str) -> bool:
    return bool(re.search(r"[A-Za-z0-9]{2,}", item or ""))


def _intro(text: str) -> str:
    intro = (text or "").rstrip()
    if not intro:
        return ""
    intro = _INTRO_TAIL.sub("", intro).rstrip()
    if not intro:
        return ""
    if intro[-1] in "?!":
        return intro
    return intro.rstrip(".") + ":"


def _assemble(intro: str, items: List[str], outro: str, numbered: bool) -> str:
    lines = [f"{i}. {item}" if numbered else f"- {item}" for i, item in enumerate(items, 1)]
    out = ((_intro(intro) + "\n") if intro.strip() else "") + "\n".join(lines)
    outro = (outro or "").strip()
    if outro:
        if outro[0].islower():
            outro = outro[0].upper() + outro[1:]
        out += "\n\n" + outro
    return out


# A marker opens an item only at the start of a clause: "is my number one priority"
# and "is number two on the list" are prose.
_CLAUSE_START = re.compile(r"(?:^|[.!?,;:]\s*|\b(?:and|then|also|plus|by|with)\s+)$", re.IGNORECASE)


def _marker_list(text: str) -> Optional[str]:
    marks = [m for m in _MARKER.finditer(text) if _CLAUSE_START.search(text[: m.start()])]
    if len(marks) < 2:
        return None
    # Take the first run that is either all bullets or counts 1, 2, 3...
    run: List[re.Match] = []
    for m in marks:
        if m.group("bullet"):
            if run and not run[0].group("bullet"):
                break
            run.append(m)
            continue
        n = _number(m.group("n"))
        if not run:
            if n == 1:
                run.append(m)
            continue
        if run[0].group("bullet") or n != _number(run[-1].group("n")) + 1:
            break
        run.append(m)
    if len(run) < 2:
        return None

    items: List[str] = []
    for i, m in enumerate(run):
        if i + 1 < len(run):
            body = text[m.end(): run[i + 1].start()]
            rest = ""
        else:
            tail = text[m.end():]
            # The last item runs to the end of its sentence.
            cut = re.search(r"[.!?](?=\s|$)", tail)
            body, rest = (tail[: cut.end()], tail[cut.end():]) if cut else (tail, "")
        item = _clean_item(body)
        if not _has_words(item):
            return None
        items.append(item)
    numbered = not run[0].group("bullet")
    return _assemble(text[: run[0].start()], items, rest, numbered)


def _ordinal_list(text: str) -> Optional[str]:
    sentences = [s for s in _SENTENCE_END.split(text.strip()) if s]
    starts: List[Tuple[int, str]] = []
    for idx, sentence in enumerate(sentences):
        m = _ORDINAL_OPEN.match(sentence)
        if m:
            starts.append((idx, m.group("w").lower()))

    # A run: "first", then "second", "third"... in order, optionally closed by "finally"/"lastly".
    best: List[int] = []
    for k, (idx, word) in enumerate(starts):
        if not word.startswith("first"):
            continue
        run, expect = [idx], 1
        for idx2, word2 in starts[k + 1:]:
            if expect < len(_ORDINALS) and word2.startswith(_ORDINALS[expect]):
                run.append(idx2)
                expect += 1
            elif word2 in ("finally", "lastly") and len(run) >= 2:
                run.append(idx2)
                break
            else:
                break
        if len(run) >= 2:
            best = run
            break
    if not best:
        return None

    items: List[str] = []
    for j, idx in enumerate(best):
        end = best[j + 1] if j + 1 < len(best) else idx + 1
        body = " ".join(sentences[idx:end])
        body = _ORDINAL_OPEN.sub("", body, count=1)
        item = _clean_item(body)
        if not _has_words(item):
            return None
        items.append(item)
    intro = " ".join(sentences[: best[0]])
    outro = " ".join(sentences[best[-1] + 1:])
    return _assemble(intro, items, outro, numbered=True)


def _format_block(block: str) -> str:
    if not block.strip() or re.search(r"(?m)^\s*(?:[-•]|\d+\.)\s", block):
        return block  # already structured (spoken "bullet" commands, an earlier pass)
    for build in (_marker_list, _ordinal_list):
        try:
            shaped = build(block)
        except Exception:
            shaped = None
        if shaped:
            return shaped
    return block


def format_lists(text: str) -> str:
    """Turn spoken lists into one-item-per-line lists. Anything else is returned unchanged."""
    if not text or not text.strip():
        return text
    parts = re.split(r"(\n\s*\n)", text)
    return "".join(part if not part.strip() or part.startswith("\n") else _format_block(part) for part in parts)


__all__ = ["format_lists"]
