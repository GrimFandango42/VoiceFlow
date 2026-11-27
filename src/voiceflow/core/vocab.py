"""Vocabulary helper for Whisper biasing and post-processing.

Two surfaces:

- ``initial_prompt(max_chars)`` returns a string of comma-joined canonical
  terms for ``faster_whisper.transcribe(initial_prompt=...)``. Whisper's
  decoder uses this as soft conditioning, biasing recognition toward those
  tokens — useful for product names and acronyms it doesn't know well.

- ``seed_default_vocabulary()`` copies the bundled default vocabulary file
  into the user's config directory if no vocabulary file exists yet. The
  text post-processor (``textproc._load_custom_vocabulary``) reads from that
  same file and applies the rewrite rules after transcription.

The two paths share the same underlying data: the right-hand side of each
``wrong -> correct`` line in ``custom_vocabulary.txt`` is added to the
prompt, and a small list of canonical-only terms (with no known
mistranscription) is appended.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# Canonical terms that bias Whisper but don't have known mistranscriptions in
# the user's history. Order matters — earlier entries are more likely to fit
# inside the prompt-character budget.
#: Whisper accepts about 224 prompt tokens; this stays comfortably inside that
#: while leaving room for a real vocabulary rather than a token sample of one.
INITIAL_PROMPT_MAX_CHARS = 700

#: VF-24: names Nithin says every day and Whisper mis-hears ("cloud" for Claude,
#: "Jamelan" for Gemini, "OpenRoder" for OpenRouter, "Doet" for Duet). The one source
#: for the shipped seed: they lead the built-in prompt terms here and the hotword string
#: in ``ai/hotword_learning.py``. Merged in code at decode time, so the user's
#: ``custom_vocabulary.txt`` is never rewritten and existing installs get them too.
NAME_SEED_TERMS: Tuple[str, ...] = (
    "Claude",
    "Claude Code",
    "Claude Max",
    "Anthropic",
    "Gemini",
    "OpenRouter",
    "Duet",
    "Codex",
    "Antigravity",
    "Reachy",
    "GLaDOS",
    "Hetzner",
    "Ollama",
)

INITIAL_PROMPT_TERMS: Tuple[str, ...] = (
    *NAME_SEED_TERMS,
    "Claude Desktop",
    "MCP",
    "subagent",
    "OpenClaw",
    "Cowork",
    "OpenAI",
    "ChatGPT",
    "GitHub",
    "VS Code",
    "Cursor",
    "PowerShell",
    "Tailscale",
    "TypeScript",
    "VoiceFlow",
    "HomeVision",
    "Local Events Madison",
    "API",
    "CLI",
    "SDK",
    "LLM",
    "ASR",
    "VPS",
    "Whisper",
    "faster-whisper",
    "Sonnet",
    "Opus",
    "Haiku",
    "Wispr",
    "Atlas",
    "LIMS",
    "Veeva",
    "Madison",
)

_PROMPT_CACHE_KEY: Optional[Tuple[str, float, float]] = None
_PROMPT_CACHE_VALUE: List[str] = []


def _bundled_default_path() -> Path:
    """Return the package-shipped default vocabulary file."""
    return Path(__file__).resolve().parent.parent / "data" / "vocab_default.txt"


def _user_vocab_path() -> Path:
    """Return the user's editable vocabulary file path under config_dir()."""
    from voiceflow.utils.settings import config_dir

    return config_dir() / "custom_vocabulary.txt"


def seed_default_vocabulary(force: bool = False) -> Optional[Path]:
    """Copy the bundled default vocab to the user's config dir on first run.

    Returns the destination path if a copy was made, ``None`` otherwise. Never
    overwrites an existing file unless ``force`` is True. Failures (missing
    bundled file, read-only target dir) are logged and swallowed — vocab
    seeding is best-effort and never crashes startup.
    """
    try:
        target = _user_vocab_path()
        if target.exists() and not force:
            return None
        source = _bundled_default_path()
        if not source.exists():
            logger.debug("Default vocab file missing at %s; skipping seed", source)
            return None
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        logger.info("Seeded default vocabulary at %s", target)
        return target
    except Exception as exc:
        logger.warning("Failed to seed default vocabulary: %s", exc)
        return None


def _priority_vocab_path() -> Path:
    """Terms that must reach Whisper even when the budget is tight.

    Same `wrong -> correct` format as the main file. Seeded first, so a term
    here is never crowded out by an older line further up custom_vocabulary.txt.
    This is the "starred words" idea: the prompt budget is small enough that
    *which* terms get in matters more than how many, and the user is a better
    judge of that than file order is.
    """
    return _user_vocab_path().with_name("priority_vocabulary.txt")


def _read_corrections(path: Path) -> List[str]:
    """Return the right-hand side (canonical) of each ``wrong -> correct`` line."""
    canonicals: List[str] = []
    if not path.exists():
        return canonicals
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "->" not in line:
                continue
            _, _, dst = line.partition("->")
            dst = dst.strip()
            if dst:
                canonicals.append(dst)
    except Exception as exc:
        logger.debug("Vocab read failed at %s: %s", path, exc)
    return canonicals


def initial_prompt(max_chars: int = INITIAL_PROMPT_MAX_CHARS) -> str:
    """Build a Whisper ``initial_prompt`` string from canonical seed + user vocab.

    Caches by (path, mtime) for cheap repeated calls during a transcription
    burst. The prompt is comma-joined, deduplicated (case-insensitive),
    and truncated at the character budget on a term boundary.

    **Budget.** Whisper accepts roughly 224 prompt tokens. The old 200-character
    cap spent that allowance on about sixteen terms, so an installation with a
    hundred curated rules had all but the first sixteen silently discarded, and
    which sixteen depended on nothing but their line order in the file. The cap
    is now ``INITIAL_PROMPT_MAX_CHARS``, which stays inside Whisper's limit.

    **User terms come first.** The 200-character budget is small -- roughly 25
    terms -- and INITIAL_PROMPT_TERMS alone fills it. With the built-ins ordered
    first, every term a user added to custom_vocabulary.txt fell outside the
    budget and reached Whisper never, silently, however many they curated. The
    file's own header promises the opposite. A term someone bothered to write
    down beats a generic built-in like "API", so theirs are seeded first and the
    built-ins fill whatever budget is left.
    """
    global _PROMPT_CACHE_KEY, _PROMPT_CACHE_VALUE

    path = _user_vocab_path()
    priority_path = _priority_vocab_path()

    def _mtime(target: Path) -> float:
        try:
            return float(target.stat().st_mtime) if target.exists() else 0.0
        except Exception:
            return 0.0

    mtime = _mtime(path)
    # The cache holds the ordered term list; the string is cut per call because the live
    # caption asks for a shorter prompt (VF-24 compose_prompt) than the final pass.
    cache_key = (str(path), mtime, _mtime(priority_path))
    if _PROMPT_CACHE_KEY == cache_key and _PROMPT_CACHE_VALUE:
        ordered = _PROMPT_CACHE_VALUE
    else:
        priority_terms = _read_corrections(_priority_vocab_path())
        user_terms = _read_corrections(path)
        # Priority is the user's, but spelling is canonical: someone writing
        # "claude" in their vocab file should not downgrade the built-in "Claude".
        canonical = {t.strip().lower(): t.strip() for t in INITIAL_PROMPT_TERMS}
        seen: set[str] = set()
        ordered = []
        for term in (*priority_terms, *user_terms, *INITIAL_PROMPT_TERMS):
            normalized = term.strip()
            if not normalized:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(canonical.get(key, normalized))
        _PROMPT_CACHE_KEY = cache_key
        _PROMPT_CACHE_VALUE = ordered

    prompt = ""
    for term in ordered:
        candidate = f"{prompt}, {term}" if prompt else term
        if len(candidate) > max_chars:
            # Skip, don't stop: one long term should not discard every shorter
            # term behind it.
            continue
        prompt = candidate
    return prompt


def compose_prompt(context: str, max_chars: int = INITIAL_PROMPT_MAX_CHARS) -> str:
    """Vocabulary conditioning plus a caller's rolling context, inside one budget (VF-24).

    The live caption passes its own running text as ``initial_prompt``. Before VF-24
    that replaced the vocabulary prompt, so only the caption's first decode (empty
    context) was biased toward the user's terms. Now the vocabulary comes first and the
    context last: faster-whisper keeps the *end* of an over-long prompt, and the end is
    the text the next words continue. The total never exceeds ``max_chars``, the same
    budget as the final pass, so a caption decode costs no more than its first one did.
    """
    ctx = " ".join(str(context or "").split())
    if not ctx:
        return initial_prompt(max_chars)
    if len(ctx) >= max_chars:
        return ctx[-max_chars:]
    vocab_part = initial_prompt(max(0, max_chars - len(ctx) - 2))
    return f"{vocab_part}. {ctx}" if vocab_part else ctx


def known_terms(max_terms: int = 60) -> List[str]:
    """Canonical vocabulary terms (user priority first), for the reconstruction pass.

    Same sources and precedence as ``initial_prompt`` but returned as a list so
    callers can compare against it rather than parse a prompt string.
    """
    priority_terms = _read_corrections(_priority_vocab_path())
    user_terms = _read_corrections(_user_vocab_path())
    canonical = {t.strip().lower(): t.strip() for t in INITIAL_PROMPT_TERMS}
    seen: set[str] = set()
    ordered: List[str] = []
    for term in (*priority_terms, *user_terms, *INITIAL_PROMPT_TERMS):
        normalized = term.strip()
        key = normalized.lower()
        if not normalized or key in seen:
            continue
        seen.add(key)
        ordered.append(canonical.get(key, normalized))
    return ordered[: max(1, int(max_terms))]


def append_promoted_terms(pairs: List[Tuple[str, str]], *, header: str = "# VF-17 promoted from repeated misses") -> List[Tuple[str, str]]:
    """Append ``wrong -> correct`` rules to the user vocabulary file.

    Skips pairs whose rule (or canonical term, for a case-insensitive repeat)
    is already present. Returns the pairs actually written. Never raises.
    """
    written: List[Tuple[str, str]] = []
    try:
        path = _user_vocab_path()
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        existing_rules = {
            line.strip().lower()
            for line in existing.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        new_lines: List[str] = []
        from voiceflow.core.rewrite_policy import is_unsafe_global_source

        for wrong, right in pairs:
            wrong, right = wrong.strip(), right.strip()
            rule = f"{wrong} -> {right}"
            if not wrong or not right or rule.lower() in existing_rules:
                continue
            if is_unsafe_global_source(wrong):
                continue  # VF-24: "cloud -> Claude" would rewrite every real cloud
            new_lines.append(rule)
            existing_rules.add(rule.lower())
            written.append((wrong, right))
        if new_lines:
            path.parent.mkdir(parents=True, exist_ok=True)
            block = ("" if existing.endswith("\n") or not existing else "\n") + header + "\n" + "\n".join(new_lines) + "\n"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(block)
            invalidate_cache()
    except Exception as exc:
        logger.warning("append_promoted_terms failed: %s", exc)
    return written


def invalidate_cache() -> None:
    """Force the next ``initial_prompt`` call to re-read from disk.

    Useful after the daily learning batch appends new terms to the vocab file.
    """
    global _PROMPT_CACHE_KEY, _PROMPT_CACHE_VALUE
    _PROMPT_CACHE_KEY = None
    _PROMPT_CACHE_VALUE = []
