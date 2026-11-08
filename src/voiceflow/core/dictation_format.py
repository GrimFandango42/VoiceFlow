"""Conservative dictation cleanup and spoken formatting commands (VF-12 item 4).

Goal: text that is ready to hand to an AI assistant, without ever rewriting what the
user meant. Every rule here removes only things that are almost never content:

* ``um`` / ``uh`` / ``erm`` fillers;
* immediate stutters of function words ("the, the thing" -> "the thing") and
  verbatim repeated 2-3 word restarts ("I think I think we" -> "I think we");
* the discourse marker "I mean," when it opens a sentence, and "you know," when it is
  set off by commas on both sides;
* "scratch that" (drops the sentence/clause it retracts) and "no wait, <restart>".

It deliberately does NOT touch: "that that", "had had", "very very", "no no no",
"I guess", mid-sentence "I mean", or anything inside a code-ish token (file names,
paths, CamelCase, snake_case, flags). The old rule-based corrector deleted everything
before any "I mean" and collapsed any repeated word; ``tests/runtime/test_vf12_cleanup``
measures the difference.

Spoken commands -- "new line", "new paragraph", "bullet <text>" -- are recognised only
when set off as their own phrase (punctuation or the text edge on both sides), so
"I need a new line of products" stays literal.
"""

from __future__ import annotations

import re
from typing import List, Tuple

# ----------------------------------------------------------------------------- code-ish

# Known extensions only: "hello.world" is two sentences with a missing space, not a file.
_EXTENSIONS = (
    "py|pyw|pyi|js|jsx|ts|tsx|mjs|json|jsonl|yaml|yml|toml|ini|cfg|conf|env|md|txt|csv|tsv|"
    "html|htm|css|scss|xml|sh|bat|cmd|ps1|psm1|exe|dll|msi|log|pdf|docx?|xlsx?|pptx?|png|"
    "jpe?g|gif|svg|zip|tar|gz|whl|lock|sql|db|sqlite|ipynb|go|rs|java|kt|cs|cpp|hpp|c|h|rb|"
    "php|com|org|net|io|dev|ai|app|edu|gov|co"
)

_CODEISH = re.compile(
    r"""
    \S*[\\/_]\S*                      # paths, snake_case, and/or
    | (?<![\w-])--?[A-Za-z][\w-]*     # flags (not the hyphen in well-known)
    | \b[\w-]+\.(?:EXT)\b             # file.ext / domain.com
    | \b[A-Za-z]*[a-z][A-Z]\w*        # CamelCase / camelCase
    """.replace("EXT", _EXTENSIONS),
    re.VERBOSE,
)
_OPEN, _CLOSE = "⟦", "⟧"
_PLACEHOLDER = re.compile(re.escape(_OPEN) + r"(\d+)" + re.escape(_CLOSE))


def protect_codeish(text: str) -> Tuple[str, List[str]]:
    """Swap code-ish tokens for placeholders so no rule can edit them."""
    saved: List[str] = []

    def _stash(match: re.Match) -> str:
        saved.append(match.group(0))
        return f"{_OPEN}{len(saved) - 1}{_CLOSE}"

    return _CODEISH.sub(_stash, text), saved


def restore_codeish(text: str, saved: List[str]) -> str:
    return _PLACEHOLDER.sub(lambda m: saved[int(m.group(1))], text)


# ----------------------------------------------------------------------------- tokens

_FILLERS = frozenset({"um", "umm", "ummm", "uh", "uhh", "uhhh", "uhm", "erm", "ermm"})
_STUTTER_WORDS = frozenset(
    "the a an to of in on at for with and but or i we you they he she it is was are "
    "my our your this".split()
)
_EDGE = ".,;:!?…\"'()[]"


def _core(token: str) -> str:
    return token.strip(_EDGE).lower()


def _ends_sentence(token: str) -> bool:
    return token.rstrip("\"')]").endswith((".", "!", "?", "…"))


def _capitalize_first_alpha(token: str) -> str:
    for i, ch in enumerate(token):
        if ch.isalpha():
            return token[:i] + ch.upper() + token[i + 1:]
        if ch in (_OPEN,):
            return token
    return token


def _sentence_initial(tokens: List[str], i: int) -> bool:
    return i == 0 or _ends_sentence(tokens[i - 1])


def strip_fillers(line: str) -> str:
    tokens = line.split(" ")
    out: List[str] = []
    capitalize_next = False
    for idx, tok in enumerate(tokens):
        if tok and _core(tok) in _FILLERS:
            if _sentence_initial(out, len(out)) or _ends_sentence(tok):
                # "Um, so ..." / "... end. Um. Next" -> the next word opens the sentence.
                capitalize_next = _sentence_initial(out, len(out))
            if _ends_sentence(tok) and out and not _ends_sentence(out[-1]):
                out[-1] = out[-1].rstrip(",;:") + tok[len(tok.rstrip(".!?…")):]
            elif tok.endswith(",") and out and out[-1].endswith(","):
                out[-1] = out[-1][:-1]   # "should, uh, open" -> "should open"
            continue
        if capitalize_next and tok:
            tok = _capitalize_first_alpha(tok)
            capitalize_next = False
        out.append(tok)
    return " ".join(out)


def collapse_stutters(line: str) -> str:
    tokens = line.split(" ")
    i = 0
    out: List[str] = []
    while i < len(tokens):
        tok = tokens[i]
        # n-gram restarts first (3, then 2 words): "I think I think we" -> "I think we"
        dropped = False
        for n in (3, 2):
            if i + 2 * n <= len(tokens):
                first = [_core(t) for t in tokens[i:i + n]]
                second = [_core(t) for t in tokens[i + n:i + 2 * n]]
                interior_stop = any(_ends_sentence(t) for t in tokens[i:i + n])
                if first == second and all(first) and not interior_stop and len(set(first)) > 1:
                    keep_cap = tok[:1].isupper()
                    i += n  # drop the first copy, keep the second
                    if keep_cap and i < len(tokens):
                        tokens[i] = _capitalize_first_alpha(tokens[i])
                    dropped = True
                    break
        if dropped:
            continue
        if (
            i + 1 < len(tokens)
            and _core(tok) in _STUTTER_WORDS
            and _core(tok) == _core(tokens[i + 1])
            and not _ends_sentence(tok)
        ):
            if tok[:1].isupper():
                tokens[i + 1] = _capitalize_first_alpha(tokens[i + 1])
            i += 1
            continue
        out.append(tok)
        i += 1
    return " ".join(out)


# ----------------------------------------------------------------------------- false starts

_I_MEAN_OPENER = re.compile(r"(^|(?<=[.!?]\s))\s*I mean,\s+", re.IGNORECASE)
_YOU_KNOW_ASIDE = re.compile(r",\s*you know,\s*", re.IGNORECASE)
_SCRATCH_THAT = re.compile(r"\bscratch that(?=\s*(?:[,.!?]|$))[,.!?]?\s*", re.IGNORECASE)
_NO_WAIT = re.compile(r"[,]?\s*\b(?:no|nope),?\s+wait(?=\s*[,.!?])[,.!?]?\s*", re.IGNORECASE)


def _drop_scratched(text: str) -> str:
    """"A. B scratch that. C" -> "A. C": remove the clause the cue retracts."""
    while True:
        m = _SCRATCH_THAT.search(text)
        if not m:
            return text
        before = text[: m.start()].rstrip()
        after = text[m.end():].lstrip()
        # Retract back to the previous sentence boundary (or text start).
        cut = max(before.rfind(". "), before.rfind("! "), before.rfind("? "), before.rfind("\n"))
        kept = before[: cut + 1].rstrip() if cut >= 0 else ""
        text = (kept + " " + after).strip() if kept else after
        if after and not kept:
            text = _capitalize_first_alpha(text)


def _resolve_no_wait(text: str) -> str:
    """"send it to John, no wait, send it to Jane" -> "send it to Jane" -- only when the
    words after the cue restart the clause (same first word); otherwise leave it alone."""
    m = _NO_WAIT.search(text)
    if not m:
        return text
    before = text[: m.start()].rstrip()
    after = text[m.end():].lstrip()
    cut = max(before.rfind(". "), before.rfind("! "), before.rfind("? "), before.rfind("\n"))
    clause = before[cut + 1:].strip() if cut >= 0 else before.strip()
    prefix = before[: cut + 1].rstrip() if cut >= 0 else ""
    first_clause = _core(clause.split(" ")[0]) if clause else ""
    first_after = _core(after.split(" ")[0]) if after else ""
    if clause and after and first_clause and first_clause == first_after:
        merged = (prefix + " " + after).strip() if prefix else after
        return _capitalize_first_alpha(merged) if not prefix else merged
    return text


def drop_false_starts(text: str) -> str:
    text = _I_MEAN_OPENER.sub(lambda m: m.group(1) or "", text)
    text = _YOU_KNOW_ASIDE.sub(", ", text)
    text = _drop_scratched(text)
    text = _resolve_no_wait(text)
    return text


# ----------------------------------------------------------------------------- commands

_B = r"(?:(?<=^)|(?<=[.!?,;:]\s)|(?<=[.!?,;:]))"           # boundary before
_A = r"(?=\s*(?:$|[.!?,;:]))"                              # boundary after
_NEW_LINE = re.compile(rf"\s*{_B}\s*\bnew line\b{_A}[.!?,;:]?\s*", re.IGNORECASE)
_NEW_PARA = re.compile(rf"\s*{_B}\s*\bnew paragraph\b{_A}[.!?,;:]?\s*", re.IGNORECASE)
# "bullet" is a command only in the unambiguous form "bullet, <text>" / "bullet: <text>"
# (Whisper punctuates a deliberately paused command that way). Without the comma/colon it
# is an ordinary word: "bullet train", "bullet wound", "bullet points are useful".
_BULLET = re.compile(
    rf"\s*{_B}\s*\b(?:next )?bullet(?: point)?\b\s*[,:]\s*(?=\S)", re.IGNORECASE
)


def _join_break(match_text_before: str, br: str) -> str:
    return match_text_before.rstrip(" ,;:") + br


def apply_spoken_commands(text: str) -> str:
    """"new line" -> newline, "new paragraph" -> blank line, "bullet x" -> "- x"."""
    if not text:
        return text

    def _swap(pattern: re.Pattern, br: str, src: str) -> str:
        out, last = [], 0
        for m in pattern.finditer(src):
            out.append(src[last:m.start()].rstrip(" ,;") if src[last:m.start()].strip() else src[last:m.start()])
            out.append(br)
            last = m.end()
        out.append(src[last:])
        return "".join(out)

    text = _swap(_NEW_PARA, "\n\n", text)
    text = _swap(_NEW_LINE, "\n", text)

    # Bullets: only the explicit "bullet, <text>" form (see _BULLET).
    out, last = [], 0
    for m in _BULLET.finditer(text):
        raw = m.group(0)
        head = text[last:m.start()]
        out.append(head.rstrip(" ,;") if head.strip() else head)
        # A break the user already asked for ("new paragraph") stays: don't shrink it.
        lead = re.match(r"\s*", raw).group(0)
        at_start = not "".join(out).strip()
        out.append(("" if at_start else ("\n" * min(2, lead.count("\n")) or "\n")) + "- ")
        last = m.end()
    if last:
        out.append(text[last:])
        text = "".join(out)

    # Sentence case after an inserted break.
    text = re.sub(
        r"(\n+(?:- )?)([a-z])",
        lambda m: m.group(1) + m.group(2).upper(),
        text,
    )
    text = re.sub(r"^(- )([a-z])", lambda m: m.group(1) + m.group(2).upper(), text)
    return text.strip(" ")


# ----------------------------------------------------------------------------- entry points

def clean_dictation(
    text: str,
    *,
    fillers: bool = True,
    false_starts: bool = True,
    stutters: bool = True,
) -> str:
    """Conservative cleanup of one transcript (no spoken commands)."""
    if not text or not text.strip():
        return text
    masked, saved = protect_codeish(text)
    lines = masked.split("\n")
    cleaned: List[str] = []
    for line in lines:
        if not line.strip():
            cleaned.append(line)
            continue
        if false_starts:
            line = drop_false_starts(line)
        if fillers:
            line = strip_fillers(line)
        if stutters:
            line = collapse_stutters(line)
        line = re.sub(r"[ \t]{2,}", " ", line)
        line = re.sub(r"\s+([,.!?;:])", r"\1", line).strip()
        line = re.sub(r"^[,;:]\s*", "", line)
        if line and line[0].islower():
            line = _capitalize_first_alpha(line)
        cleaned.append(line)
    return restore_codeish("\n".join(cleaned), saved)


def prepare_prompt_text(
    text: str,
    *,
    spoken_commands: bool = True,
    cleanup: bool = True,
) -> str:
    """Spoken commands first (they introduce line breaks), then conservative cleanup."""
    if not text or not text.strip():
        return text
    masked, saved = protect_codeish(text)
    if spoken_commands:
        masked = apply_spoken_commands(masked)
    out = restore_codeish(masked, saved)
    if cleanup:
        out = clean_dictation(out)
    return out
