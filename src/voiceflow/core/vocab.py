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
INITIAL_PROMPT_TERMS: Tuple[str, ...] = (
    "Claude",
    "Claude Code",
    "Claude Desktop",
    "Anthropic",
    "MCP",
    "subagent",
    "OpenClaw",
    "Cowork",
    "OpenAI",
    "ChatGPT",
    "Gemini",
    "GitHub",
    "VS Code",
    "Cursor",
    "PowerShell",
    "Tailscale",
    "Hetzner",
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
)

_PROMPT_CACHE_KEY: Optional[Tuple[str, float]] = None
_PROMPT_CACHE_VALUE: str = ""


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


def initial_prompt(max_chars: int = 200) -> str:
    """Build a Whisper ``initial_prompt`` string from canonical seed + user vocab.

    Caches by (path, mtime) for cheap repeated calls during a transcription
    burst. The prompt is comma-joined, deduplicated (case-insensitive),
    and truncated at the character budget on a term boundary.
    """
    global _PROMPT_CACHE_KEY, _PROMPT_CACHE_VALUE

    path = _user_vocab_path()
    try:
        mtime = float(path.stat().st_mtime) if path.exists() else 0.0
    except Exception:
        mtime = 0.0

    cache_key = (str(path), mtime)
    if _PROMPT_CACHE_KEY == cache_key and _PROMPT_CACHE_VALUE:
        return _PROMPT_CACHE_VALUE

    user_terms = _read_corrections(path)
    seen: set[str] = set()
    ordered: List[str] = []
    for term in (*INITIAL_PROMPT_TERMS, *user_terms):
        normalized = term.strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(normalized)

    prompt = ""
    for term in ordered:
        candidate = f"{prompt}, {term}" if prompt else term
        if len(candidate) > max_chars:
            break
        prompt = candidate

    _PROMPT_CACHE_KEY = cache_key
    _PROMPT_CACHE_VALUE = prompt
    return prompt


def invalidate_cache() -> None:
    """Force the next ``initial_prompt`` call to re-read from disk.

    Useful after the daily learning batch appends new terms to the vocab file.
    """
    global _PROMPT_CACHE_KEY, _PROMPT_CACHE_VALUE
    _PROMPT_CACHE_KEY = None
    _PROMPT_CACHE_VALUE = ""
