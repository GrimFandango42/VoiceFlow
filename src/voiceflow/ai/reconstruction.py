"""Reconstruction pass (VF-17 items 3 and 4).

Whisper transcribes what it *heard*. This stage proposes the most plausible
*legible* rendering of what was *said*: sentence casing and punctuation,
run-ons and broken conjunctions, dropped function words, and words that are
phonetically close to a known vocabulary term or a name/identifier used earlier in
the same dictation.

    VF-12 item 4 said "never rewrite meaning". This stage relaxes that to
    "never CHANGE meaning, but DO repair form". The two orders do not
    contradict: form repair is allowed, meaning change is still forbidden, and
    the second half is enforced in code (below), not asked of the model.

The model is untrusted. Everything it returns goes through ``check_candidate``
before it can be used, and *any* failure (guard, timeout, Ollama down, empty or
chatty output) means the caller pastes the pre-reconstruction text unchanged.
The pass can therefore never make output worse than it was before this stage
existed; at worst it costs CPU in the background.

Guards (all deterministic, none depend on the prompt):

    numbers         every digit-number and spelled number word (except "one")
                    in the pre-text appears the same number of times, and no
                    new one appears
    protected       every URL, e-mail, file path, file name with extension,
                    snake_case / camelCase / CamelCase / ALLCAPS / dotted token
                    present in the pre-text is still present, verbatim
    proper nouns    every capitalised mid-sentence word in the pre-text is still
                    present, verbatim
    word ratio      0.8x <= words <= 1.4x of the pre-text
    new entities    no capitalised word appears that is not in the pre-text,
                    the raw ASR text, or the vocabulary (sentence-initial words
                    must additionally be known function words)
    novel content   words that are in neither text nor the vocabulary and are
                    not a plausible phonetic/spelling repair of a word that was
                    removed are capped at ~0-2 per dictation (this is what
                    stops an invented clause that adds no number or name)
"""

from __future__ import annotations

import difflib
import logging
import math
import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Lexical helpers
# --------------------------------------------------------------------------- #

FUNCTION_WORDS: frozenset[str] = frozenset("""
a an the this that these those there here it its it's he she they we you i me him her them us my your his
their our mine yours theirs myself yourself himself herself itself ourselves themselves one ones
am is are was were be been being do does did done doing have has had having will would shall should can could
may might must ought let lets let's
and or but nor so yet for because since although though while whereas if unless until till whether than
as like then also too either neither both each every any some no not none all more most less least much many
very really quite just only even still already again ever never always often sometimes usually
of in on at by with from to into onto over under about above below between among through during before after
up down out off across against around without within toward towards per via
what which who whom whose when where why how whatever whoever whenever wherever
yes yeah yep okay ok well now anyway however therefore thus otherwise instead meanwhile besides moreover
maybe perhaps probably actually basically honestly sure right
i'm i've i'll i'd you're you've you'll you'd we're we've we'll we'd they're they've they'll they'd
he's she's that's there's here's what's who's isn't aren't wasn't weren't don't doesn't didn't won't wouldn't
can't couldn't shouldn't haven't hasn't hadn't
get got go going gone make made take took come came see saw say said know think thought want need
""".split())

NUMBER_WORDS: frozenset[str] = frozenset("""
zero two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen
eighteen nineteen twenty thirty forty fifty sixty seventy eighty ninety hundred thousand million billion trillion
first second third fourth fifth sixth seventh eighth ninth tenth half quarter dozen
""".split())

_FILE_EXT = (
    "py|js|ts|tsx|jsx|json|md|txt|exe|bat|ps1|html|htm|css|yml|yaml|toml|ini|cfg|csv|pdf|docx|xlsx|pptx|zip|log|sql|"
    "sh|cpp|java|go|rs|rb|png|jpg|jpeg|gif|svg|dll|msi|lock|env|ipynb"
)

_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_WIN_PATH = re.compile(r"\b[A-Za-z]:\\[^\s<>\"']+")
_NIX_PATH = re.compile(r"(?<![\w/])(?:~|\.{1,2})?(?:/[\w.\-]+){2,}/?")
_FILE_NAME = re.compile(rf"\b[\w\-]+(?:\.[\w\-]+)*\.(?:{_FILE_EXT})\b", re.I)
_SNAKE = re.compile(r"\b[A-Za-z0-9]+(?:_[A-Za-z0-9]+)+\b")
_CAMEL = re.compile(r"\b(?:[a-z]+(?:[A-Z][a-z0-9]*)+|[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+)\b")
_ALLCAPS = re.compile(r"\b[A-Z]{2,}[A-Z0-9]*\b")
_DOTTED = re.compile(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\b")
_ALNUM_CODE = re.compile(r"\b(?=[A-Za-z\-]*\d)(?=[\d\-]*[A-Za-z])[A-Za-z0-9]+(?:[-.][A-Za-z0-9]+)*\b")
_DIGIT_NUMBER = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?%?")
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9'’]*")
_SENT_END = re.compile(r"[.!?]+[\"')\]]*\s+$|\n\s*$")

_TRAILING_PUNCT = ".,;:!?)]}\"'"


def _strip_trailing(token: str) -> str:
    return token.rstrip(_TRAILING_PUNCT)


def words(text: str) -> List[str]:
    """Words as the guards count them (apostrophes kept, hyphen splits)."""
    return _WORD.findall(text.replace("-", " ").replace("’", "'"))


def _norm(word: str) -> str:
    return word.lower().replace("'", "").replace("’", "")


#: FUNCTION_WORDS with apostrophes stripped, because every comparison in the guards is on _norm() forms.
FUNCTION_NORMS: frozenset[str] = frozenset(_norm(w) for w in FUNCTION_WORDS)


def protected_tokens(text: str) -> Counter:
    """Code-ish / identifier-ish tokens that must survive verbatim."""
    found: Counter = Counter()
    consumed: List[tuple[int, int]] = []

    def _add(match: re.Match, *, strip: bool = True) -> None:
        for lo, hi in consumed:
            if match.start() >= lo and match.end() <= hi:
                return  # already counted as part of a longer token (URL, path)
        token = _strip_trailing(match.group(0)) if strip else match.group(0)
        if not token:
            return
        found[token] += 1
        consumed.append((match.start(), match.start() + len(token)))

    for pattern in (_URL, _EMAIL, _WIN_PATH, _NIX_PATH, _FILE_NAME, _DOTTED, _SNAKE, _CAMEL, _ALNUM_CODE, _ALLCAPS):
        for match in pattern.finditer(text):
            # Plain decimals ("3.5") are numbers, handled by the number guard.
            if pattern is _DOTTED and re.fullmatch(r"[\d.]+", match.group(0)):
                continue
            _add(match)
    return found


def number_tokens(text: str) -> Counter:
    """Digit-numbers and spelled number words, as a multiset.

    "one" is excluded: in dictation it is overwhelmingly a pronoun ("the one
    that...", "no one"), and treating it as a number would reject harmless
    repairs. Digit tokens that belong to a protected token (``v3.2.1``) are
    covered by the protected guard instead.
    """
    shield = protected_tokens(text)
    shielded_spans: List[tuple[int, int]] = []
    for token in shield:
        for m in re.finditer(re.escape(token), text):
            shielded_spans.append((m.start(), m.end()))

    def _shielded(lo: int, hi: int) -> bool:
        return any(lo >= a and hi <= b for a, b in shielded_spans)

    nums: Counter = Counter()
    for m in _DIGIT_NUMBER.finditer(text):
        if not _shielded(m.start(), m.end()):
            nums[m.group(0).rstrip(",")] += 1
    for m in _WORD.finditer(text):
        w = m.group(0).lower()
        if w in NUMBER_WORDS and not _shielded(m.start(), m.end()):
            nums[w] += 1
    return nums


def _sentence_initial_flags(text: str) -> List[tuple[str, bool]]:
    """[(word, is_sentence_initial)] using the raw casing."""
    out: List[tuple[str, bool]] = []
    initial = True
    pos = 0
    for m in _WORD.finditer(text):
        gap = text[pos:m.start()]
        if gap and re.search(r"[.!?]\s*$|\n", gap):
            initial = True
        out.append((m.group(0), initial))
        initial = False
        pos = m.end()
    return out


def _is_capitalised_word(word: str) -> bool:
    return len(word) >= 2 and word[0].isupper() and not word.isupper() and not re.match(r"I'", word)


def proper_nouns(text: str) -> Counter:
    """Capitalised words that are not merely sentence-initial (and not "I")."""
    found: Counter = Counter()
    for word, initial in _sentence_initial_flags(text):
        if initial or word == "I":
            continue
        if _is_capitalised_word(word):
            found[word] += 1
    return found


def _consonant_skeleton(word: str) -> str:
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return ""
    skeleton = w[0] + re.sub(r"[aeiouyhw]", "", w[1:])
    return re.sub(r"(.)\1+", r"\1", skeleton)


def plausible_repair(candidate: str, originals: Iterable[str]) -> bool:
    """True when ``candidate`` is a believable spelling/phonetic repair of any original word."""
    c = _norm(candidate)
    for original in originals:
        o = _norm(original)
        if not o or not c:
            continue
        if c == o:
            return True
        if len(c) >= 3 and len(o) >= 3:
            if difflib.SequenceMatcher(None, c, o).ratio() >= 0.6:
                return True
            if len(c) >= 4 and len(o) >= 4 and _consonant_skeleton(c) == _consonant_skeleton(o):
                return True
            if len(c) >= 4 and len(o) >= 4 and c[:4] == o[:4]:  # inflection: send/sending
                return True
        elif len(c) <= 2 and len(o) <= 2 and c[0] == o[0]:
            return True
    return False


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #

@dataclass
class GuardResult:
    ok: bool
    reason: str = ""
    detail: str = ""


FILLERS: frozenset[str] = frozenset("um uh uhm er erm ah hmm mm".split())

_INFLECTION_SUFFIXES = frozenset({"s", "es", "ed", "d", "ing", "ly", "er", "ers", "est", "ies", "ied", "n", "en"})


def _is_inflection_variant(a: str, b: str) -> bool:
    """True for pairs like note/notes, that/thats, send/sending: a different word, not a respelling."""
    if a == b:
        return False
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    if not long_.startswith(short):
        # city/cities style
        if short.endswith("y") and long_.startswith(short[:-1]) and long_[len(short) - 1:] in _INFLECTION_SUFFIXES:
            return True
        return False
    return long_[len(short):] in _INFLECTION_SUFFIXES


def _spelling_close(a: str, b: str) -> bool:
    """Same letters, respelled: that is -> thats, pie installer -> pyinstaller."""
    if not a or not b or min(len(a), len(b)) / float(max(len(a), len(b))) < 0.5:
        return False
    return difflib.SequenceMatcher(None, a, b).ratio() >= 0.6 or (
        len(a) >= 4 and len(b) >= 4 and _consonant_skeleton(a) == _consonant_skeleton(b)
    )


def _droppable(word: str, pre_n: Sequence[str], idx: int) -> bool:
    """Words a form-repair may delete: filler sounds and immediate stutters ("should should", "the the").

    A real function word is NOT deletable: "thanks everyone and see you there" -> "thanks everyone, see you there"
    reads fine and is still not what was said (the evaluator scored it as a WER regression). Splitting a run-on is
    done with punctuation and casing, which the word-level diff does not see.
    """
    if word in FILLERS:
        return True
    return (idx > 0 and pre_n[idx - 1] == word) or (idx + 1 < len(pre_n) and pre_n[idx + 1] == word)


#: The only words a repair may INSERT. Each is a bare connector that carries no polarity, certainty, frequency, causality or
#: modality of its own: "we tested it we shipped it" -> "... and we shipped it", "we need go" -> "we need to go", "a lot of". Every
#: other function word ("not", "maybe", "always", "because", "should", "never", ...) changes what the speaker said, so it can
#: never be added, whatever the model claims. "but"/"so" are excluded too: they assert a contrast or a consequence.
INSERTABLE: frozenset[str] = frozenset({"and", "to", "of"})

#: Determiners are the one kind of "dropped function word" the speaker's choice cannot be recovered for:
#: "over WebSocket" -> "over a WebSocket" is grammatical and still not what was said. Never inserted.
DETERMINERS: frozenset[str] = frozenset({"a", "an", "the"})


def _special_norms(pre: str, vocab_norms: Set[str]) -> Set[str]:
    """Normalised words that make up a protected token, proper noun, number or vocabulary term in ``pre``.

    A small word wedged next to one of these changes what was said about it, so no word may be inserted beside them.
    """
    special: Set[str] = set(vocab_norms)
    for token in protected_tokens(pre):
        special.update(_norm(w) for w in words(token))
    for noun in proper_nouns(pre):
        special.add(_norm(noun))
    for number in number_tokens(pre):
        special.add(_norm(number))
    return special


def _term_norms(*texts: str) -> Set[str]:
    """Normalised words of the names and identifiers the speaker used: protected tokens and mid-sentence proper nouns.

    These are the only utterance words a content word may be respelled to. Ordinary words are deliberately absent, and
    so are sentence-initial words: "Car is ready." is capitalised for position, and a capital it earns that way must not
    license "The cat is red." -> "The car is red." (sentence-initial names are still protected from LOSS by
    ``_names_lost``; they just are not a replacement source).
    """
    out: Set[str] = set()
    for text in texts:
        for token in protected_tokens(text):
            out.update(_norm(w) for w in words(token))
        out.update(_norm(n) for n in proper_nouns(text))
    out.discard("")
    return out


#: Contraction tails: "that is" <-> "thats". The only function-word swap that is a respelling rather than a new word.
_CONTRACTION_TAILS: dict = {"is": "s", "are": "re", "will": "ll", "would": "d", "had": "d", "have": "ve", "am": "m", "not": "nt"}

#: Homophone sets whose members are the same spoken word (their/there/they're).
_HOMOPHONES = (frozenset({"their", "there", "theyre"}), frozenset({"your", "youre"}), frozenset({"whose", "whos"}))


def _function_respelling(removed: Sequence[str], added: Sequence[str]) -> bool:
    """True only for contraction/expansion (that is <-> thats) and homophone respellings (there -> their).

    Anything else between two small words ("he" -> "she", "can" -> "cant", "is" -> "are") is a different word the speaker
    did not say, however close the letters are.
    """
    if len(removed) == 1 and len(added) == 1:
        return any(removed[0] in group and added[0] in group for group in _HOMOPHONES)
    for long_, short in ((removed, added), (added, removed)):
        if len(long_) == 2 and len(short) == 1 and long_[1] in _CONTRACTION_TAILS:
            if short[0] == long_[0] + _CONTRACTION_TAILS[long_[1]]:
                return True
    return False


def _structural_diff(
    pre_words: Sequence[str], cand_words: Sequence[str], *, vocab_norms: Set[str], special_norms: Optional[Set[str]] = None,
    utterance_norms: Optional[Set[str]] = None,
) -> GuardResult:
    """Word-level diff of candidate against the pre-text, whitelisting only repairs of FORM.

    Allowed: insert (not determiners, not beside a protected term) a small function word, delete a filler or a stutter, swap one
    function word for another, respell a word/phrase into a close spelling or
    phonetic neighbour (a vocabulary repair). Everything else - deleting a content
    word, inserting one, reordering, swapping a content word for a different one,
    or changing a word only by an inflection (note/notes) - is a rewrite.
    The last word must survive (unless it was a filler, or was respelled to a
    vocabulary term): losing the tail is the defect this order exists to fix.
    """
    pre_n = [_norm(w) for w in pre_words]
    cand_n = [_norm(w) for w in cand_words]
    matcher = difflib.SequenceMatcher(None, pre_n, cand_n, autojunk=False)
    inserted_fn = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        removed, added = pre_n[i1:i2], cand_n[j1:j2]
        if tag == "insert":
            determiners = [w for w in added if w in DETERMINERS]
            if determiners:
                return GuardResult(False, "determiner_inserted", ",".join(determiners))
            # A vocabulary entry never licenses a meaning-bearing function word ("not" in a vocabulary list is still "not").
            unsafe = [w for w in added if w in FUNCTION_NORMS and w not in INSERTABLE and w not in DETERMINERS]
            if unsafe:
                return GuardResult(False, "meaning_word_inserted", ",".join(unsafe[:5]))
            # A vocabulary term is never inserted on its own: it may only REPLACE a word that was actually transcribed
            # and sounds/spells like it ("we will send it today" must not grow "to Claude").
            vocab_added = [w for w in added if w in vocab_norms and w not in INSERTABLE]
            if vocab_added:
                return GuardResult(False, "vocab_inserted", ",".join(vocab_added[:5]))
            bad = [w for w in added if w not in INSERTABLE]
            if bad:
                return GuardResult(False, "novel_content", ",".join(bad[:5]))
            neighbours = [pre_n[k] for k in (i1 - 1, i1) if 0 <= k < len(pre_n)]
            if special_norms and any(n in special_norms for n in neighbours):
                return GuardResult(False, "inserted_beside_protected", " ".join(added) + " near " + " ".join(neighbours))
            inserted_fn += len(added)
        elif tag == "delete":
            bad = [w for k, w in enumerate(removed) if not _droppable(w, pre_n, i1 + k)]
            if bad:
                return GuardResult(False, "content_deleted", ",".join(bad[:5]))
        else:  # replace
            if all(w in FILLERS for w in removed) and all(w in INSERTABLE for w in added):
                # a filler sound stood where a connector belongs ("um" -> "not" is a new meaning, not a repair)
                inserted_fn += len(added)
                continue
            if all(w in FUNCTION_NORMS or w in FILLERS for w in removed + added):
                # "is good" -> "they're good" or "he" -> "she" swaps one word the speaker chose for another; only a
                # respelling of the same words (that is -> that's, there -> their) is a form repair.
                if _function_respelling(removed, added):
                    inserted_fn += max(0, len(added) - len(removed))
                    continue
                return GuardResult(False, "rewritten", f"{' '.join(removed)}->{' '.join(added)}")
            if len(removed) == 1 and len(added) == 1 and _is_inflection_variant(removed[0], added[0]):
                return GuardResult(False, "inflection_changed", f"{removed[0]}->{added[0]}")
            a, b = "".join(removed), "".join(added)
            if not _spelling_close(a, b):
                return GuardResult(False, "rewritten", f"{' '.join(removed)}->{' '.join(added)}")
            # A replacement may merge words ("pie installer" -> "PyInstaller") but never grow: an extra word riding along
            # with a respelling is an insertion in disguise ("cloud" -> "to Claude").
            if len(added) > len(removed):
                return GuardResult(False, "vocab_inserted" if any(w in vocab_norms for w in added) else "novel_content",
                                   f"{' '.join(removed)}->{' '.join(added)}")
            # Close spelling is necessary, not sufficient: cat -> car is two letters apart and a different thing. A content
            # word may only become a genuine vocabulary term, or a name/identifier the speaker already used in this
            # utterance (protected token, mid-sentence proper noun) - never an ordinary word that merely occurs
            # elsewhere ("The cat and car are here. The cat is red." must not become "... The car is red."), and never a
            # word that is capitalised only because it opens a sentence ("Car is ready. The cat is red.").
            sources = vocab_norms | (utterance_norms or set())
            unsourced = [w for w in added if w not in sources]
            if unsourced:
                return GuardResult(False, "unsourced_replacement", f"{' '.join(removed)}->{' '.join(added)}")
    if inserted_fn > max(2, int(round(0.15 * len(pre_words)))):
        return GuardResult(False, "too_many_insertions", str(inserted_fn))

    if pre_n and cand_n and pre_n[-1] != cand_n[-1] and pre_n[-1] not in FILLERS:
        if cand_n[-1] not in vocab_norms:
            return GuardResult(False, "tail_changed", f"{pre_n[-1]}->{cand_n[-1]}")
    return GuardResult(True)


_NUM_TOKEN = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?%?|[A-Za-z][A-Za-z']*")

_UNIT_VALUES = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9}
_TEEN_VALUES = {"ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
                "seventeen": 17, "eighteen": 18, "nineteen": 19}
_TENS_VALUES = {"twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90}
_SCALE_VALUES = {"thousand": 1000, "million": 1000000, "billion": 1000000000, "trillion": 1000000000000}
_SPOKEN = frozenset(_UNIT_VALUES) | frozenset(_TEEN_VALUES) | frozenset(_TENS_VALUES) | frozenset(_SCALE_VALUES) | {"hundred"}
#: number words that stay words ("first", "half"): compared as the word itself
_WORD_NUMBERS = frozenset(NUMBER_WORDS) - _SPOKEN


def _mask_protected(text: str) -> str:
    """``text`` with every protected token blanked out, so digits inside v3.2.1 or a file name are not counted as numbers."""
    for token in sorted(protected_tokens(text), key=len, reverse=True):
        text = re.sub(re.escape(token), lambda m: " " * len(m.group(0)), text)
    return text


def numeric_values(text: str) -> Counter:
    """Every number in ``text`` as a multiset of canonical values, whether it was typed or spoken.

    "42", "forty two" and "forty-two" all count as "42"; "two thousand twenty six" and "2026" both count as "2026". This is
    what lets the raw ASR text ("nine") be compared with processed text ("9") without a spelled number ever being able to
    vanish unnoticed. A lone "one" is not a number (pronoun: "the one that", "no one").
    """
    out: Counter = Counter()
    tokens = [m.group(0) for m in _NUM_TOKEN.finditer(_mask_protected(text).replace("-", " "))]
    state = {"total": 0, "cur": 0, "n": 0, "last": "", "scale": 10 ** 15}

    def flush() -> None:
        if state["n"] and not (state["n"] == 1 and state["last"] == "one"):
            out[str(state["total"] + state["cur"])] += 1
        state.update(total=0, cur=0, n=0, last="", scale=10 ** 15)

    def accepts(word: str) -> bool:
        cur = state["cur"]
        if word in _UNIT_VALUES:
            return cur % 100 == 0 or (20 <= cur % 100 <= 90 and cur % 10 == 0)
        if word in _TEEN_VALUES or word in _TENS_VALUES:
            return cur % 100 == 0
        if word == "hundred":
            return 0 <= cur < 100
        return _SCALE_VALUES[word] < state["scale"] and (cur > 0 or state["n"] == 0)

    def add(word: str) -> None:
        if word in _UNIT_VALUES:
            state["cur"] += _UNIT_VALUES[word]
        elif word in _TEEN_VALUES:
            state["cur"] += _TEEN_VALUES[word]
        elif word in _TENS_VALUES:
            state["cur"] += _TENS_VALUES[word]
        elif word == "hundred":
            state["cur"] = (state["cur"] or 1) * 100
        else:
            state["total"] += (state["cur"] or 1) * _SCALE_VALUES[word]
            state["cur"] = 0
            state["scale"] = _SCALE_VALUES[word]
        state["n"] += 1
        state["last"] = word

    for i, tok in enumerate(tokens):
        if tok[0].isdigit():
            flush()
            out[tok.replace(",", "").rstrip("%")] += 1
            continue
        word = tok.lower().replace("'", "")
        if word in _SPOKEN:
            if state["n"] and not accepts(word):
                flush()
            add(word)
        elif word == "and" and state["last"] in ("hundred", *_SCALE_VALUES) \
                and i + 1 < len(tokens) and tokens[i + 1].lower() in _SPOKEN:
            continue  # "one hundred and five"
        else:
            flush()
            if word in _WORD_NUMBERS:
                out[word] += 1
    flush()
    return out


def initial_names(text: str) -> Counter:
    """Sentence-initial capitalised words that are not function words: names and content words that open a sentence.

    ``proper_nouns`` ignores them because "The" and "Send" are capitalised for position only; here a word that is
    neither a function word nor a filler is treated as a name, because it is cheaper to refuse a repair that touches
    one than to let "Alice sent ..." become "Alicia sent ...".
    """
    found: Counter = Counter()
    for word, initial in _sentence_initial_flags(text):
        norm = _norm(word)
        if initial and _is_capitalised_word(word) and norm not in FUNCTION_NORMS and norm not in FILLERS and norm not in NUMBER_WORDS:
            found[norm] += 1
    return found


def _names_lost(source: str, candidate: str, vocab_terms: Sequence[str] = ()) -> List[str]:
    """Names (mid-sentence and sentence-initial) in ``source`` that the candidate no longer has, with multiplicity.

    A name is excused only when it was folded into a vocabulary term the candidate introduces
    ("Pie installer is slow" -> "PyInstaller is slow").
    """
    cand_norm = [_norm(w) for w in words(candidate)]
    cand_counts = Counter(cand_norm)
    src_norm = [_norm(w) for w in words(source)]
    display: dict = {}
    for w in words(source):
        display.setdefault(_norm(w), w)
    wanted: Counter = Counter({_norm(n): c for n, c in proper_nouns(source).items()})
    wanted.update(initial_names(source))
    new_terms = {_norm("".join(words(t))) for t in vocab_terms if t} - {"".join(src_norm)}
    new_terms = {t for t in new_terms if t and t in cand_norm}
    lost: List[str] = []
    for name, count in wanted.items():
        if count - cand_counts.get(name, 0) <= 0:
            continue
        if name in src_norm and new_terms:
            i = src_norm.index(name)
            joined, run = [], ""
            for k in range(i, min(i + 3, len(src_norm))):
                run += src_norm[k]
                joined.append(run)
            if any(_spelling_close(j, t) for j in joined for t in new_terms):
                continue
        lost.append(display.get(name, name))
    return lost


def _raw_tokens_lost(raw: str, candidate: str, vocab_terms: Sequence[str] = ()) -> List[str]:
    """Numbers, protected tokens and names in the raw ASR text that the candidate no longer contains.

    Everything is compared as a multiset ("7 ... 7" cannot become "7"), spelled numbers are normalised to the same
    canonical value as digits (nine == 9), and sentence-initial names are protected like mid-sentence ones.
    """
    if not raw.strip():
        return []
    shown = {t.lower(): t for t in protected_tokens(raw)}
    raw_prot = Counter(t.lower() for t in protected_tokens(raw).elements())
    cand_prot = Counter(t.lower() for t in protected_tokens(candidate).elements())
    lost: List[str] = [shown[t] for t in sorted((raw_prot - cand_prot).elements())]
    lost.extend(sorted((numeric_values(raw) - numeric_values(candidate)).elements()))
    lost.extend(_names_lost(raw, candidate, vocab_terms))
    return lost


def check_candidate(
    pre_text: str,
    candidate: str,
    *,
    raw_text: str = "",
    vocab_terms: Sequence[str] = (),
    min_ratio: float = 0.8,
    max_ratio: float = 1.4,
) -> GuardResult:
    """Decide whether ``candidate`` may replace ``pre_text``. Order = cheapest first."""
    pre = (pre_text or "").strip()
    cand = (candidate or "").strip()
    if not pre:
        return GuardResult(False, "empty_input")
    if not cand:
        return GuardResult(False, "empty_output")

    pre_words = words(pre)
    cand_words = words(cand)
    if not pre_words:
        return GuardResult(False, "empty_input")
    if not cand_words:
        return GuardResult(False, "empty_output")

    ratio = len(cand_words) / float(len(pre_words))
    if ratio < min_ratio or ratio > max_ratio:
        return GuardResult(False, "word_ratio", f"{len(pre_words)}->{len(cand_words)} ({ratio:.2f}x)")

    # --- numbers: must be identical as a multiset
    pre_nums, cand_nums = number_tokens(pre), number_tokens(cand)
    if pre_nums != cand_nums:
        missing = sorted((pre_nums - cand_nums).elements())
        added = sorted((cand_nums - pre_nums).elements())
        return GuardResult(False, "number_changed", f"missing={missing} added={added}")

    # --- protected tokens: none lost, none invented
    pre_prot, cand_prot = protected_tokens(pre), protected_tokens(cand)
    lost = sorted((pre_prot - cand_prot).elements())
    if lost:
        return GuardResult(False, "protected_token_lost", ",".join(lost[:5]))
    invented = sorted((cand_prot - pre_prot).elements())
    # A repair may legitimately produce a vocabulary term in canonical casing
    # ("faster whisper" -> "faster-whisper"), so vocabulary terms are exempt.
    vocab_lower = {t.lower() for t in vocab_terms}
    invented = [t for t in invented if t.lower() not in vocab_lower and t.lower() not in pre.lower()]
    if invented:
        return GuardResult(False, "protected_token_invented", ",".join(invented[:5]))

    # --- the RAW ASR text is the reference for what was actually said. The pre-text may already have lost a token
    # (a text-processing bug must not let the model "agree" with it), so digits, protected tokens and proper nouns
    # that were in the raw have to be in the candidate too.
    raw_lost = _raw_tokens_lost(raw_text or "", cand, vocab_terms)
    if raw_lost:
        return GuardResult(False, "raw_token_lost", ",".join(raw_lost[:5]))

    # --- proper nouns: none dropped or respelled
    lost_nouns = sorted((proper_nouns(pre) - proper_nouns(cand)).elements())
    if lost_nouns:
        return GuardResult(False, "proper_noun_lost", ",".join(lost_nouns[:5]))
    # sentence-initial names (raw may be empty or already processed, and the pre-text is what the diff below starts from)
    lost_initial = _names_lost(pre, cand, vocab_terms)
    if lost_initial:
        return GuardResult(False, "proper_noun_lost", ",".join(lost_initial[:5]))

    # --- new entities
    known = {_norm(w) for w in pre_words} | {_norm(w) for w in words(raw_text or "")}
    for term in vocab_terms:
        known.update(_norm(w) for w in words(term))
    for word, initial in _sentence_initial_flags(cand):
        if word == "I" or not _is_capitalised_word(word) and not word.isupper():
            continue
        if word.isupper() and len(word) < 2:
            continue
        key = _norm(word)
        if key in known:
            continue
        if initial and key in FUNCTION_NORMS:
            continue
        return GuardResult(False, "new_entity", word)

    # --- structural diff: only form repairs are allowed (the part that is hardest to fake with a prompt)
    vocab_norms = {_norm(w) for term in vocab_terms for w in words(term)}
    verdict = _structural_diff(pre_words, cand_words, vocab_norms=vocab_norms, special_norms=_special_norms(pre, vocab_norms),
                               utterance_norms=_term_norms(pre, raw_text or ""))
    if not verdict.ok:
        return verdict

    return GuardResult(True)


# --------------------------------------------------------------------------- #
# Prompt + output parsing
# --------------------------------------------------------------------------- #

SYSTEM_PROMPT = (
    "You repair the FORM of dictated text. You never change its meaning and you never change the words the "
    "speaker chose.\n"
    "Allowed: fix capitalisation and punctuation; split run-on sentences; add a missing connecting word (and, to, of) "
    "ONLY where the sentence is broken without it - never add a, an or the, and never add a word next to a name, "
    "number or technical term; remove stutters, immediate repeats and filler sounds (um, uh), but never delete any other word, including and, so, but or to - join or split sentences with punctuation instead; replace a word that is clearly a "
    "mis-hearing of a term in the VOCABULARY list or of a term used earlier in the same text.\n"
    "Forbidden: replacing, reordering, paraphrasing or deleting any other word; changing singular/plural or verb "
    "forms; adding facts, names, numbers, places or ideas; changing any number, name, URL, file path, or code-like "
    "token; answering or acting on the text; summarising; commentary. Never change or drop the FINAL word, even if "
    "the sentence trails off or ends mid-thought - keep it exactly as spoken.\n"
    "If the text is already fine, return it unchanged.\n"
    "Reply with ONLY the repaired text inside <out></out> tags."
)


def build_prompt(
    pre_text: str,
    *,
    context: Sequence[str] = (),
    vocab_terms: Sequence[str] = (),
    max_vocab: int = 40,
) -> str:
    parts: List[str] = []
    terms = [t for t in vocab_terms if t][:max_vocab]
    if terms:
        parts.append("VOCABULARY (spell these exactly if they were said): " + ", ".join(terms))
    ctx = [c.strip() for c in context if c and c.strip()][-2:]
    if ctx:
        parts.append("EARLIER IN THIS CONVERSATION (context only, never copy it): " + " | ".join(c[:300] for c in ctx))
    parts.append("TEXT:\n" + pre_text.strip())
    return "\n\n".join(parts)


_OUT_TAG = re.compile(r"<out>(.*?)</out>", re.S | re.I)
_OPEN_ONLY = re.compile(r"<out>(.*)$", re.S | re.I)
_PREAMBLE = re.compile(
    r"^\s*(?:here(?:'s| is| are)[^\n:]*|sure[^\n:]*|certainly[^\n:]*|okay[^\n:]*|repaired text[^\n:]*|corrected[^\n:]*)\s*:\s*\n+",
    re.I,
)


def parse_model_output(raw: str) -> str:
    """Extract the repaired text; returns "" when the reply cannot be trusted."""
    if not raw:
        return ""
    text = raw.strip()
    m = _OUT_TAG.search(text) or _OPEN_ONLY.search(text)
    if m:
        text = m.group(1)
    else:
        text = _PREAMBLE.sub("", text, count=1)
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'`":
        text = text[1:-1].strip()
    text = re.sub(r"</?out>", "", text, flags=re.I).strip()
    # A reply that explains itself is not a repair.
    if re.search(r"(?i)\b(as an ai|i cannot|i can't|i'm sorry|note:|explanation:)\b", text):
        return ""
    return text


# --------------------------------------------------------------------------- #
# Model selection + the reconstructor itself
# --------------------------------------------------------------------------- #

#: Small instruct models first. "coder", "base", embeddings and thinking models
#: (qwen3 / deepseek-r1 emit <think> blocks and are slow on CPU) are skipped.
_PREFERRED = ("llama3.2:3b", "llama3.2:1b", "qwen2.5:3b", "qwen2.5:7b", "phi3", "llama3.1:8b", "gemma3", "gemma2")
_AVOID = ("embed", "coder", "base", "deepseek-r1", "qwen3", "gpt-oss", "vision")


def pick_reconstruction_model(available: Sequence[str], configured: str = "") -> str:
    models = [m for m in available if m and not any(bad in m.lower() for bad in _AVOID)]
    if configured:
        exact = next((m for m in available if m == configured), None)
        if exact:
            return exact
        partial = next((m for m in models if configured in m), None)
        if partial:
            return partial
    for pref in _PREFERRED:
        hit = next((m for m in models if m.startswith(pref) or pref in m), None)
        if hit:
            return hit
    return models[0] if models else ""


@dataclass
class ReconstructionOutcome:
    status: str  # accepted | rejected | failed | timeout | skipped | unchanged
    text: str = ""  # candidate (only meaningful for accepted / rejected)
    reason: str = ""
    detail: str = ""
    latency_ms: float = 0.0
    model: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    def as_log(self) -> dict:
        out = {
            "status": self.status,
            "reason": self.reason,
            "detail": self.detail[:200],
            "latency_ms": round(self.latency_ms, 1),
            "model": self.model,
        }
        out.update(self.extra)
        return out


class Reconstructor:
    """Runs one reconstruction attempt against the local model, then the guards."""

    def __init__(
        self,
        cfg: Any = None,
        *,
        client_factory: Optional[Callable[[], Any]] = None,
        vocab_provider: Optional[Callable[[], Sequence[str]]] = None,
    ) -> None:
        self.cfg = cfg
        self._client_factory = client_factory
        self._vocab_provider = vocab_provider
        self._client: Any = None

    # -- configuration -----------------------------------------------------
    def _opt(self, name: str, default: Any) -> Any:
        return getattr(self.cfg, name, default) if self.cfg is not None else default

    def vocab_terms(self) -> List[str]:
        try:
            if self._vocab_provider is not None:
                return list(self._vocab_provider())
        except Exception as exc:  # vocabulary is best-effort
            logger.debug("reconstruction vocab provider failed: %s", exc)
        return []

    def _get_client(self) -> Any:
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                from voiceflow.ai.llm_client import OllamaClient

                base = OllamaClient()
                model = pick_reconstruction_model(base.list_models(), str(self._opt("reconstruction_model", "") or ""))
                if not model:
                    raise RuntimeError("no suitable Ollama model installed")
                base.model = model
                self._client = base
        return self._client

    # -- policy ------------------------------------------------------------
    def should_run(self, pre_text: str, *, code_mode: bool = False, destination_profile: str = "") -> tuple[bool, str]:
        if not bool(self._opt("reconstruction_enabled", True)) or str(self._opt("reconstruction_mode", "auto")) == "off":
            return False, "disabled"
        if code_mode or destination_profile in {"terminal", "editor"}:
            return False, "destination_excluded"
        n = len(words(pre_text or ""))
        if n < int(self._opt("reconstruction_min_words", 4)):
            return False, "too_short"
        if len(pre_text) > int(self._opt("reconstruction_max_chars", 2000)):
            return False, "too_long"
        return True, ""

    # -- the attempt -------------------------------------------------------
    def propose(
        self,
        pre_text: str,
        *,
        context: Sequence[str] = (),
        timeout_s: Optional[float] = None,
    ) -> "Proposal":
        """Ask the model. No guards here: the reply is untrusted until ``judge`` has seen it."""
        started = time.perf_counter()
        timeout = float(timeout_s if timeout_s is not None else self._opt("reconstruction_timeout_s", 45.0))
        vocab = self.vocab_terms()
        try:
            client = self._get_client()
            prompt = build_prompt(pre_text, context=context, vocab_terms=vocab)
            n_words = len(words(pre_text))
            options = {"num_gpu": 0}  # the GPU belongs to Reachy (OPS-07): CPU only
            threads = int(self._opt("reconstruction_num_threads", 0) or 0)
            if threads <= 0:
                # Be a good citizen: leave half the cores for the foreground app and
                # the audio/ASR threads. Decode is memory-bound, so this costs little.
                threads = max(2, (os.cpu_count() or 4) // 2)
            options["num_thread"] = threads
            response = client.generate(
                prompt,
                system=SYSTEM_PROMPT,
                temperature=0.0,
                max_tokens=min(900, max(64, int(n_words * 2.4) + 40)),
                timeout=timeout,
                extra_options=options,
                keep_alive="30m",
            )
        except Exception as exc:
            return Proposal("failed", error=str(exc), latency_ms=(time.perf_counter() - started) * 1000.0)

        latency = (time.perf_counter() - started) * 1000.0
        model = str(getattr(response, "model", "") or getattr(getattr(self, "_client", None), "model", "") or "")
        if not getattr(response, "success", False):
            err = str(getattr(response, "error", "") or "")
            status = "timeout" if "timed out" in err.lower() or "timeout" in err.lower() else "failed"
            return Proposal(status, error=err, latency_ms=latency, model=model)
        return Proposal("ok", candidate=parse_model_output(getattr(response, "text", "")), latency_ms=latency, model=model)

    def judge(self, pre_text: str, raw_text: str, proposal: "Proposal") -> ReconstructionOutcome:
        """Apply the guards to a proposal. Deterministic; the only gate between the model and the paste."""
        base = dict(latency_ms=proposal.latency_ms, model=proposal.model)
        if proposal.status != "ok":
            return ReconstructionOutcome(proposal.status, reason="llm_error" if proposal.status != "failed" or proposal.error else "exception", detail=proposal.error, **base)
        candidate = proposal.candidate
        if not candidate:
            return ReconstructionOutcome("rejected", reason="unparseable_output", **base)
        if candidate.strip() == pre_text.strip():
            return ReconstructionOutcome("unchanged", text=candidate, **base)
        verdict = check_candidate(pre_text, candidate, raw_text=raw_text, vocab_terms=self.vocab_terms())
        if not verdict.ok:
            return ReconstructionOutcome("rejected", text=candidate, reason=verdict.reason, detail=verdict.detail, **base)
        return ReconstructionOutcome("accepted", text=candidate, **base)

    def reconstruct(
        self,
        pre_text: str,
        raw_text: str = "",
        *,
        context: Sequence[str] = (),
        timeout_s: Optional[float] = None,
    ) -> ReconstructionOutcome:
        return self.judge(pre_text, raw_text, self.propose(pre_text, context=context, timeout_s=timeout_s))


@dataclass
class Proposal:
    """What the model said, before the guards have looked at it."""

    status: str  # ok | failed | timeout
    candidate: str = ""
    error: str = ""
    latency_ms: float = 0.0
    model: str = ""


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * q
    lo, hi = int(math.floor(k)), int(math.ceil(k))
    if lo == hi:
        return float(ordered[lo])
    return float(ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo))
