"""Promote repeated phonetic misses to hotwords (VF-17 item 6).

The learner (``adaptive_memory`` / ``daily_learning``) already knew how to turn
raw -> final deltas into replacement pairs. In real use it learned nothing:
``adaptive_audit.jsonl`` shows ``raw_hash != final_hash`` on 16 of 36 recent
rows and ``learned_pairs == []`` on all of them, because the only differences
were casing and punctuation (``extract_learning_pairs`` compares lower-cased
tokens and only learns word *replacements*) and no pipeline stage proposed a
different word. The reconstruction pass is the first stage that does, so this
module gives that signal somewhere to go.

Input is the tuning log: raw -> (pasted) -> reconstructed -> user-edited.

A pair ``src -> dst`` is promoted to ``custom_vocabulary.txt`` (which feeds both
the post-ASR rewrite rules and Whisper's ``initial_prompt``) only if ALL hold:

    * it came from an accepted reconstruction or an explicit user edit
      (user edits are trusted more: they count even without a reconstruction),
    * ``dst`` looks like a term (in the vocabulary, CamelCase/ACRONYM, contains a
      digit/hyphen, or is a capitalised word) and neither side is a function word,
    * ``src`` is a plausible phonetic/spelling miss of ``dst``,
    * it was seen in at least ``min_count`` DIFFERENT utterances,
    * ``src`` is not also left alone in the output often (ambiguity <= 10%), so a
      real word like "fields" is never turned into something else everywhere.

Zero promotions is a legitimate answer; the report says so and why.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from voiceflow.ai.adaptive_memory import STOP_WORDS
from voiceflow.ai.reconstruction import FUNCTION_WORDS, _consonant_skeleton

logger = logging.getLogger(__name__)

_COMMON = frozenset(STOP_WORDS) | FUNCTION_WORDS


def _letters(text: str) -> str:
    return re.sub(r"[^a-z]", "", text.lower())


_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9']*")


def replacement_pairs(before: str, after: str, max_span: int = 3) -> List[Tuple[str, str]]:
    """Word-replacement pairs between two texts.

    Unlike ``adaptive_memory.extract_learning_pairs`` this keeps pairs that differ
    only in spacing ("voice flow" -> "VoiceFlow"): for a vocabulary term that is
    exactly the miss worth learning.
    """
    a, b = _TOKEN.findall(before), _TOKEN.findall(after)
    if not a or not b:
        return []
    out: List[Tuple[str, str]] = []
    matcher = SequenceMatcher(a=[t.lower() for t in a], b=[t.lower() for t in b])
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag != "replace" or (a1 - a0) > max_span or (b1 - b0) > max_span:
            continue
        pair = (" ".join(a[a0:a1]), " ".join(b[b0:b1]))
        if pair[0].lower() != pair[1].lower() and pair not in out:
            out.append(pair)
    return out


def is_term_like(dst: str, vocab_lower: Set[str]) -> bool:
    dst = dst.strip()
    if not dst or len(dst.split()) > 3:
        return False
    if dst.lower() in vocab_lower:
        return True
    if any(ch.isupper() for ch in dst[1:]):  # CamelCase / ACRONYM / PyInstaller
        return True
    if re.search(r"[\d_\-.]", dst):
        return True
    return dst[0].isupper()


def is_phonetic_miss(src: str, dst: str) -> bool:
    if src.strip().lower() == dst.strip().lower():
        return False  # case-only change: not a miss
    s, d = _letters(src), _letters(dst)
    if not s or not d:
        return False
    if min(len(s), len(d)) / float(max(len(s), len(d))) < 0.6:
        return False  # one side is mostly extra material, i.e. an insertion rather than a mis-hearing
    if s == d:
        return True  # same letters, different spacing: "voice flow" -> "VoiceFlow"
    if SequenceMatcher(None, s, d).ratio() >= 0.6:
        return True
    return len(s) >= 4 and len(d) >= 4 and _consonant_skeleton(s) == _consonant_skeleton(d)


def is_hotword_candidate(src: str, dst: str, vocab_lower: Optional[Set[str]] = None) -> bool:
    vocab_lower = vocab_lower or set()
    src_words = [w.lower() for w in re.findall(r"[A-Za-z0-9']+", src)]
    dst_words = [w.lower() for w in re.findall(r"[A-Za-z0-9']+", dst)]
    if not src_words or not dst_words:
        return False
    if all(w in _COMMON for w in src_words) or all(w in _COMMON for w in dst_words):
        return False
    if len(src_words) == 1 and len(src_words[0]) < 5:
        return False  # short single words are too ambiguous to rewrite globally
    return is_term_like(dst, vocab_lower) and is_phonetic_miss(src, dst)


@dataclass
class Candidate:
    src: str
    dst: str
    utterances: Set[str] = field(default_factory=set)
    from_user_edit: int = 0
    counter_evidence: int = 0

    @property
    def count(self) -> int:
        return len(self.utterances)


@dataclass
class PromotionReport:
    utterances: int = 0
    with_reconstruction: int = 0
    accepted_reconstructions: int = 0
    with_user_edit: int = 0
    raw_pairs: int = 0            # replacement pairs of any kind seen
    hotword_candidates: int = 0   # pairs that look like phonetic misses of a term
    below_threshold: int = 0
    ambiguous: int = 0
    promoted: List[Tuple[str, str]] = field(default_factory=list)
    explanation: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "utterances": self.utterances,
            "with_reconstruction": self.with_reconstruction,
            "accepted_reconstructions": self.accepted_reconstructions,
            "with_user_edit": self.with_user_edit,
            "raw_pairs": self.raw_pairs,
            "hotword_candidates": self.hotword_candidates,
            "below_threshold": self.below_threshold,
            "ambiguous": self.ambiguous,
            "promoted_count": len(self.promoted),
            "promoted": [list(p) for p in self.promoted],
            "explanation": self.explanation,
        }


def _contains_phrase(text: str, phrase: str) -> bool:
    return bool(re.search(rf"\b{re.escape(phrase)}\b", text, re.IGNORECASE))


def analyse(
    utterances: Sequence[Dict[str, Any]],
    *,
    vocab_terms: Iterable[str] = (),
    min_count: int = 3,
    max_ambiguity: float = 0.10,
) -> Tuple[PromotionReport, List[Candidate]]:
    """Pure analysis over tuning-log utterances; writes nothing."""
    vocab_lower = {t.lower() for t in vocab_terms}
    report = PromotionReport(utterances=len(utterances))
    candidates: Dict[Tuple[str, str], Candidate] = {}
    outputs: List[str] = []  # the text each utterance ended up as, for ambiguity counting

    for utt in utterances:
        uid = str(utt.get("id", ""))
        raw = str(utt.get("raw_text", "") or "")
        pasted = str(utt.get("final_text", "") or "")
        recon = utt.get("reconstructed_text")
        recon_status = str((utt.get("reconstruction") or {}).get("status", ""))
        edited = utt.get("edited_text")
        if utt.get("reconstruction"):
            report.with_reconstruction += 1
        outcome_text = str(edited or (recon if recon_status == "accepted" and recon else pasted) or "")
        outputs.append(outcome_text)

        sources: List[Tuple[str, str, bool]] = []
        if recon_status == "accepted" and recon:
            report.accepted_reconstructions += 1
            sources.append((raw, str(recon), False))
        if edited:
            report.with_user_edit += 1
            sources.append((pasted or raw, str(edited), True))

        seen_here: Set[Tuple[str, str]] = set()
        for before, after, is_user in sources:
            for src, dst in replacement_pairs(before, after):
                report.raw_pairs += 1
                if not is_hotword_candidate(src, dst, vocab_lower):
                    continue
                key = (src.lower(), dst)
                if key in seen_here:
                    continue
                seen_here.add(key)
                cand = candidates.setdefault(key, Candidate(src=src, dst=dst))
                cand.utterances.add(uid)
                if is_user:
                    cand.from_user_edit += 1

    report.hotword_candidates = len(candidates)
    promotable: List[Candidate] = []
    for cand in candidates.values():
        cand.counter_evidence = sum(1 for out in outputs if _contains_phrase(out, cand.src))
        if cand.count < min_count and cand.from_user_edit < 2:
            report.below_threshold += 1
            continue
        total = cand.count + cand.counter_evidence
        if total and cand.counter_evidence / float(total) > max_ambiguity:
            report.ambiguous += 1
            continue
        promotable.append(cand)
    promotable.sort(key=lambda c: (-c.count, c.src))
    report.promoted = [(c.src, c.dst) for c in promotable]

    if not report.promoted:
        if report.utterances == 0:
            report.explanation = "no utterances in the tuning log yet"
        elif report.accepted_reconstructions == 0 and report.with_user_edit == 0:
            report.explanation = (
                "no utterance has an accepted reconstruction or a user edit, so nothing proposes a different word; "
                "casing/punctuation-only differences are not learnable pairs"
            )
        elif report.hotword_candidates == 0:
            report.explanation = (
                f"{report.raw_pairs} replacement pair(s) seen but none is a phonetic miss of a term "
                "(grammar/word-choice edits are deliberately not promoted)"
            )
        else:
            report.explanation = (
                f"{report.hotword_candidates} candidate(s), but {report.below_threshold} seen in fewer than "
                f"{min_count} utterances and {report.ambiguous} too ambiguous"
            )
    return report, promotable


def promote(
    utterances: Sequence[Dict[str, Any]],
    *,
    min_count: int = 3,
    write: bool = True,
) -> PromotionReport:
    from voiceflow.core import vocab

    report, promotable = analyse(utterances, vocab_terms=vocab.known_terms(500), min_count=min_count)
    if write and promotable:
        written = vocab.append_promoted_terms([(c.src, c.dst) for c in promotable])
        report.promoted = written
        if not written:
            report.explanation = "all promotable terms were already in the vocabulary file"
    return report
