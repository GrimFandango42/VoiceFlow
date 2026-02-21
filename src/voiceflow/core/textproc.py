from __future__ import annotations

import json
import os
import re
import textwrap
from pathlib import Path
from typing import Dict, Any, Mapping, Optional


SYMBOL_MAP: Dict[str, str] = {
    # Brackets
    "open bracket": "[",
    "close bracket": "]",
    "open square": "[",
    "close square": "]",
    "open paren": "(",
    "close paren": ")",
    "open parenthesis": "(",
    "close parenthesis": ")",
    "open brace": "{",
    "close brace": "}",
    "open curly": "{",
    "close curly": "}",
    # Quotes
    "quote": "\"",
    "double quote": "\"",
    "single quote": "'",
    # Punctuation
    "comma": ",",
    "period": ".",
    "dot": ".",
    "colon": ":",
    "semicolon": ";",
    "exclamation": "!",
    "question": "?",
    # Operators and symbols
    "slash": "/",
    "backslash": "\\",
    "star": "*",
    "asterisk": "*",
    "plus": "+",
    "minus": "-",
    "dash": "-",
    "underscore": "_",
    "equals": "=",
    "equal": "=",
    "double equals": "==",
    "triple equals": "===",
    "arrow": "->",
    "fat arrow": "=>",
    "pipe": "|",
    "ampersand": "&",
    "and sign": "&",
    "caret": "^",
    "tilde": "~",
    "at sign": "@",
    "hash": "#",
    "percent": "%",
    "dollar": "$",
    # Whitespace/controls (as characters)
    "new line": "\n",
    "new lines": "\n",
    "tab": "\t",
}


_TECH_CONTEXT_HINTS = (
    "api",
    "asr",
    "auth",
    "authentication",
    "authorization",
    "aws",
    "azure",
    "bash",
    "backlog",
    "bug",
    "bugfix",
    "canary",
    "ci",
    "cli",
    "cloud",
    "code",
    "docker",
    "endpoint",
    "fastapi",
    "gcp",
    "git",
    "github",
    "gitlab",
    "incident",
    "issue",
    "jira",
    "kanban",
    "kpi",
    "google cloud",
    "grpc",
    "helm",
    "http",
    "https",
    "infra",
    "jwt",
    "kafka",
    "kubernetes",
    "llm",
    "model",
    "mqtt",
    "mr",
    "observability",
    "oauth",
    "oidc",
    "oncall",
    "on-call",
    "pipeline",
    "postgres",
    "postmortem",
    "pull request",
    "powershell",
    "python",
    "pr",
    "redis",
    "release",
    "repo",
    "retrospective",
    "retro",
    "rfc",
    "rollout",
    "runbook",
    "sdk",
    "sli",
    "slo",
    "sla",
    "sql",
    "sprint",
    "standup",
    "ssh",
    "sso",
    "terraform",
    "terminal",
    "ticket",
    "token",
    "throughput",
    "latency",
    "typescript",
    "vpc",
    "vs code",
    "vscode",
    "yaml",
)

_GLOBAL_TECH_TERM_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bapi\b", re.IGNORECASE), "API"),
    (re.compile(r"\bcli\b", re.IGNORECASE), "CLI"),
    (re.compile(r"\bsdk\b", re.IGNORECASE), "SDK"),
    (re.compile(r"\bjson\b", re.IGNORECASE), "JSON"),
    (re.compile(r"\byaml\b", re.IGNORECASE), "YAML"),
    (re.compile(r"\bhttp\b", re.IGNORECASE), "HTTP"),
    (re.compile(r"\bhttps\b", re.IGNORECASE), "HTTPS"),
    (re.compile(r"\bgrpc\b", re.IGNORECASE), "gRPC"),
    (re.compile(r"\bllm\b", re.IGNORECASE), "LLM"),
    (re.compile(r"\basr\b", re.IGNORECASE), "ASR"),
    (re.compile(r"\bsql\b", re.IGNORECASE), "SQL"),
    (re.compile(r"\bcpu\b", re.IGNORECASE), "CPU"),
    (re.compile(r"\bgpu\b", re.IGNORECASE), "GPU"),
    (re.compile(r"\baws\b", re.IGNORECASE), "AWS"),
    (re.compile(r"\bgcp\b", re.IGNORECASE), "GCP"),
    (re.compile(r"\bmqtt\b", re.IGNORECASE), "MQTT"),
)

_CONTEXTUAL_TECH_TERM_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bo[\s-]*auth(?:\s*(?:2|two))?\b", re.IGNORECASE), "OAuth"),
    (re.compile(r"\boath(?:\s*(?:2|two))?\b", re.IGNORECASE), "OAuth"),
    (re.compile(r"\boat(?=\s+(?:flow|token|client|login|provider|callback|redirect|scope|grant|authorization|auth|oidc|sso|jwt))", re.IGNORECASE), "OAuth"),
    (re.compile(r"\bsee[\s-]*el[\s-]*eye\b", re.IGNORECASE), "CLI"),
    (re.compile(r"\bc[\s-]*l[\s-]*i\b", re.IGNORECASE), "CLI"),
    (re.compile(r"\bci[\s-]*cd\b", re.IGNORECASE), "CI/CD"),
)

_TECH_TERM_CACHE_KEY: tuple[str, float] | None = None
_TECH_TERM_CACHE_ALWAYS: tuple[tuple[re.Pattern[str], str], ...] = ()
_TECH_TERM_CACHE_CONTEXTUAL: tuple[tuple[re.Pattern[str], str], ...] = ()


_TERMINAL_PROCESS_HINTS = (
    "windowsterminal",
    "wt",
    "cmd",
    "powershell",
    "pwsh",
    "conhost",
    "bash",
    "wsl",
    "mintty",
)

_EDITOR_PROCESS_HINTS = (
    "code",
    "cursor",
    "devenv",
    "pycharm",
    "idea64",
    "webstorm",
    "rider64",
    "sublime_text",
    "notepad++",
)

_CHAT_PROCESS_HINTS = (
    "slack",
    "teams",
    "discord",
    "telegram",
    "whatsapp",
    "signal",
)

_DOCUMENT_PROCESS_HINTS = (
    "winword",
    "wordpad",
    "notepad",
    "onenote",
    "outlook",
)

_CHAT_TITLE_HINTS = (
    "chat",
    "message",
    "gmail",
    "inbox",
    "compose",
    "teams",
    "slack",
    "discord",
)


def _apply_regex_rules(text: str, rules: tuple[tuple[re.Pattern[str], str], ...]) -> str:
    updated = text
    for pattern, replacement in rules:
        updated = pattern.sub(replacement, updated)
    return updated


def _is_technical_sentence(sentence_lower: str) -> bool:
    return any(token in sentence_lower for token in _TECH_CONTEXT_HINTS)


def _resolve_technical_terms_path() -> Path:
    for env_name in ("VOICEFLOW_TERMS_PATH", "VOICEFLOW_TECHNICAL_TERMS_PATH"):
        override = str(os.environ.get(env_name, "")).strip()
        if override:
            return Path(override).expanduser()
    try:
        from voiceflow.utils.settings import config_dir

        base = config_dir()
        preferred = base / "engineering_terms.json"
        legacy = base / "technical_terms.json"
        if preferred.exists() or not legacy.exists():
            return preferred
        return legacy
    except Exception:
        if Path("engineering_terms.json").exists():
            return Path("engineering_terms.json")
        return Path("technical_terms.json")


def _compile_exact_term_rules(mapping: dict[str, str]) -> tuple[tuple[re.Pattern[str], str], ...]:
    compiled: list[tuple[re.Pattern[str], str]] = []
    for source, target in mapping.items():
        src = str(source or "").strip()
        dst = str(target or "").strip()
        if not src or not dst:
            continue
        compiled.append((re.compile(rf"\b{re.escape(src)}\b", re.IGNORECASE), dst))
    return tuple(compiled)


def _compile_regex_term_rules(entries: list[dict[str, str]]) -> tuple[tuple[re.Pattern[str], str], ...]:
    compiled: list[tuple[re.Pattern[str], str]] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        pattern = str(item.get("pattern", "")).strip()
        replacement = str(item.get("replacement", "")).strip()
        if not pattern or not replacement:
            continue
        try:
            compiled.append((re.compile(pattern, re.IGNORECASE), replacement))
        except re.error:
            continue
    return tuple(compiled)


def _load_custom_technical_term_rules() -> tuple[tuple[tuple[re.Pattern[str], str], ...], tuple[tuple[re.Pattern[str], str], ...]]:
    global _TECH_TERM_CACHE_KEY
    global _TECH_TERM_CACHE_ALWAYS
    global _TECH_TERM_CACHE_CONTEXTUAL

    path = _resolve_technical_terms_path()
    try:
        resolved = str(path.resolve())
    except Exception:
        resolved = str(path)

    mtime = -1.0
    if path.exists():
        try:
            mtime = float(path.stat().st_mtime)
        except Exception:
            mtime = -1.0

    key = (resolved, mtime)
    if _TECH_TERM_CACHE_KEY == key:
        return _TECH_TERM_CACHE_ALWAYS, _TECH_TERM_CACHE_CONTEXTUAL

    always_rules: tuple[tuple[re.Pattern[str], str], ...] = ()
    contextual_rules: tuple[tuple[re.Pattern[str], str], ...] = ()

    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            exact_map: dict[str, str] = {}
            regex_entries: list[dict[str, str]] = []
            technical_exact_map: dict[str, str] = {}
            technical_regex_entries: list[dict[str, str]] = []

            if isinstance(payload, dict):
                recognized_blocks = {
                    "exact",
                    "regex",
                    "technical_exact",
                    "technical_regex",
                    "engineering_exact",
                    "engineering_regex",
                }
                if recognized_blocks.intersection(set(payload.keys())):
                    if isinstance(payload.get("exact"), dict):
                        exact_map = {str(k): str(v) for k, v in payload["exact"].items()}
                    if isinstance(payload.get("regex"), list):
                        regex_entries = [item for item in payload["regex"] if isinstance(item, dict)]
                    if isinstance(payload.get("technical_exact"), dict):
                        technical_exact_map = {str(k): str(v) for k, v in payload["technical_exact"].items()}
                    if isinstance(payload.get("technical_regex"), list):
                        technical_regex_entries = [item for item in payload["technical_regex"] if isinstance(item, dict)]
                    if isinstance(payload.get("engineering_exact"), dict):
                        technical_exact_map.update({str(k): str(v) for k, v in payload["engineering_exact"].items()})
                    if isinstance(payload.get("engineering_regex"), list):
                        technical_regex_entries.extend(
                            [item for item in payload["engineering_regex"] if isinstance(item, dict)]
                        )
                elif all(isinstance(k, str) and isinstance(v, str) for k, v in payload.items()):
                    exact_map = {str(k): str(v) for k, v in payload.items()}

            always_rules = _compile_exact_term_rules(exact_map) + _compile_regex_term_rules(regex_entries)
            contextual_rules = _compile_exact_term_rules(technical_exact_map) + _compile_regex_term_rules(technical_regex_entries)
        except Exception:
            always_rules = ()
            contextual_rules = ()

    _TECH_TERM_CACHE_KEY = key
    _TECH_TERM_CACHE_ALWAYS = always_rules
    _TECH_TERM_CACHE_CONTEXTUAL = contextual_rules
    return _TECH_TERM_CACHE_ALWAYS, _TECH_TERM_CACHE_CONTEXTUAL


def _apply_technical_term_dictionary(text: str, technical_context: bool) -> str:
    updated = _apply_regex_rules(text, _GLOBAL_TECH_TERM_RULES)
    if technical_context:
        updated = _apply_regex_rules(updated, _CONTEXTUAL_TECH_TERM_RULES)
    custom_always, custom_contextual = _load_custom_technical_term_rules()
    updated = _apply_regex_rules(updated, custom_always)
    if technical_context:
        updated = _apply_regex_rules(updated, custom_contextual)
    return updated


def apply_code_mode(text: str, lowercase: bool = True) -> str:
    s = text.strip()
    if lowercase:
        s = s.lower()
    # Replace longest phrases first to avoid partial overlaps
    phrases = sorted(SYMBOL_MAP.keys(), key=len, reverse=True)
    for phrase in phrases:
        pattern = r"\b" + re.escape(phrase) + r"\b"
        repl = SYMBOL_MAP[phrase]
        # Use a function replacement so backslashes in replacements (e.g., "\\", "\n", "\t")
        # are not interpreted as regex group escapes.
        s = re.sub(pattern, lambda _m, r=repl: r, s)
    # Collapse extra spaces around brackets, punctuation, and control chars
    s = re.sub(r"\s+([\]\)\}\,\.;:!\?])", r"\1", s)
    s = re.sub(r"([\[\(\{])\s+", r"\1", s)
    # Also trim spaces adjacent to newlines and tabs introduced by replacements
    s = re.sub(r" +\n", "\n", s)      # spaces before newline
    s = re.sub(r"\n +", "\n", s)      # spaces after newline
    s = re.sub(r" +\t", "\t", s)      # spaces before tab
    s = re.sub(r"\t +", "\t", s)      # spaces after tab
    # Minor tidy
    s = s.replace("\u00a0", " ")
    return s


def format_transcript_text(text: str) -> str:
    """
    Improve transcript formatting for better readability.

    Addresses common speech-to-text formatting issues:
    - Sentence capitalization
    - Proper punctuation spacing
    - Bullet point formatting
    - Number enumeration
    - Run-on sentence breaks
    """
    if not text.strip():
        return text

    # Start with basic cleanup
    text = text.strip()

    # Context-aware correction for common dictation substitutions.
    text = _apply_context_corrections(text)

    # Fix common speech patterns
    text = _fix_sentence_capitalization(text)
    text = _format_bullet_points(text)
    text = _format_enumerations(text)
    text = _improve_punctuation(text)
    text = _fix_sentence_breaks(text)
    text = _normalize_numbered_list_layout(text)

    return text


def infer_destination_profile(destination: Optional[Mapping[str, Any]]) -> str:
    """
    Infer output profile based on destination window metadata.

    Profiles:
    - terminal: shells and command prompts
    - chat: chat-like composition inputs
    - editor: IDE/editor surfaces
    - document: document/note style inputs
    - generic: fallback profile
    """
    if not destination:
        return "generic"

    process_name = str(destination.get("process_name", "") or "").strip().lower()
    window_title = str(destination.get("window_title", "") or "").strip().lower()
    window_class = str(destination.get("window_class", "") or "").strip().lower()

    if any(hint in process_name for hint in _TERMINAL_PROCESS_HINTS):
        return "terminal"
    if "consolewindowclass" in window_class or "cascadia_hosting_window_class" in window_class:
        return "terminal"
    if any(hint in process_name for hint in _CHAT_PROCESS_HINTS):
        return "chat"
    if any(hint in process_name for hint in _EDITOR_PROCESS_HINTS):
        return "editor"
    if any(hint in process_name for hint in _DOCUMENT_PROCESS_HINTS):
        return "document"
    if any(hint in window_title for hint in _CHAT_TITLE_HINTS):
        return "chat"
    return "generic"


def format_transcript_for_destination(
    text: str,
    destination: Optional[Mapping[str, Any]] = None,
    audio_duration: float = 0.0,
) -> str:
    """
    Format transcript for readability with lightweight destination-aware rules.
    """
    formatted = format_transcript_text(text)
    if not formatted.strip():
        return formatted

    if destination and not bool(destination.get("destination_aware_formatting", True)):
        return formatted

    profile = infer_destination_profile(destination)
    long_form = len(formatted) >= 220 or float(audio_duration) >= 7.0
    if long_form and profile != "terminal":
        formatted = _insert_light_paragraph_breaks(formatted)

    if destination and not bool(destination.get("destination_wrap_enabled", True)):
        return formatted

    wrap_width = _estimate_wrap_width(destination, profile)
    if wrap_width <= 0:
        return formatted
    return _wrap_transcript_blocks(formatted, wrap_width, profile)


def normalize_context_terms(text: str) -> str:
    """Apply context-aware term normalization without full formatting."""
    return _apply_context_corrections(text or "")


def _estimate_wrap_width(destination: Optional[Mapping[str, Any]], profile: str) -> int:
    width_px = 0
    cfg_default = 78
    cfg_terminal = 96
    cfg_chat = 64
    cfg_editor = 88
    if destination:
        try:
            width_px = int(destination.get("window_width", 0) or 0)
        except Exception:
            width_px = 0
        try:
            cfg_default = int(destination.get("destination_default_chars", cfg_default) or cfg_default)
            cfg_terminal = int(destination.get("destination_terminal_chars", cfg_terminal) or cfg_terminal)
            cfg_chat = int(destination.get("destination_chat_chars", cfg_chat) or cfg_chat)
            cfg_editor = int(destination.get("destination_editor_chars", cfg_editor) or cfg_editor)
        except Exception:
            cfg_default, cfg_terminal, cfg_chat, cfg_editor = 78, 96, 64, 88

    if profile == "terminal":
        base = cfg_terminal
    elif profile == "chat":
        base = cfg_chat
    elif profile in ("editor", "document"):
        base = cfg_editor
    else:
        base = cfg_default

    if width_px <= 0:
        return base

    # Rough conversion for common Windows UI fonts.
    estimated_chars = max(32, min(180, int(width_px / 8.8)))
    if profile == "chat":
        return max(44, min(80, estimated_chars - 4))
    if profile == "terminal":
        return max(64, min(140, estimated_chars))
    if profile in ("editor", "document"):
        return max(56, min(120, estimated_chars - 2))
    return max(52, min(104, estimated_chars - 2))


def _insert_light_paragraph_breaks(text: str) -> str:
    updated = text
    updated = re.sub(
        r"([.!?])\s+(also|however|anyway|next|so|that said|in addition|on the other hand|meanwhile)\b",
        lambda m: f"{m.group(1)}\n\n{m.group(2).capitalize()}",
        updated,
        flags=re.IGNORECASE,
    )
    updated = re.sub(r"\bnew paragraph\b[:\s-]*", "\n\n", updated, flags=re.IGNORECASE)
    updated = re.sub(r"\n{3,}", "\n\n", updated)
    return updated.strip()


def _wrap_transcript_blocks(text: str, width: int, profile: str) -> str:
    blocks = re.split(r"\n\s*\n", text.strip())
    wrapped_blocks: list[str] = []
    list_prefix_re = re.compile(r"^\s*(?:[-•]|\d+\.)\s+")

    for block in blocks:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        if not lines:
            continue

        wrapped_lines: list[str] = []
        for line in lines:
            # Preserve command-like lines in terminal profile.
            if profile == "terminal" and re.search(r"(?:\\|/|--|==|::|`|\$>|^\w+:\s)", line):
                wrapped_lines.append(line)
                continue

            if list_prefix_re.match(line):
                prefix_match = list_prefix_re.match(line)
                assert prefix_match is not None
                prefix = prefix_match.group(0)
                remainder = line[len(prefix):].strip()
                wrapped = textwrap.fill(
                    remainder,
                    width=max(24, width - len(prefix)),
                    initial_indent=prefix,
                    subsequent_indent=" " * len(prefix),
                    break_long_words=False,
                    break_on_hyphens=False,
                )
                wrapped_lines.append(wrapped)
            else:
                wrapped_lines.append(
                    textwrap.fill(
                        line,
                        width=width,
                        break_long_words=False,
                        break_on_hyphens=False,
                    )
                )

        wrapped_blocks.append("\n".join(wrapped_lines))

    return "\n\n".join(wrapped_blocks)


def _apply_context_corrections(text: str) -> str:
    """Apply lightweight context-based corrections for high-frequency confusions."""
    if not text:
        return text

    # Common substitution in current test flow: "long returns" -> "long utterances"
    text = re.sub(r"\blong returns?\b", "long utterances", text, flags=re.IGNORECASE)
    text = re.sub(r"\blong the turns?\b", "long utterances", text, flags=re.IGNORECASE)
    text = re.sub(r"\blong turrets?\b", "long utterances", text, flags=re.IGNORECASE)
    text = re.sub(r"\blong utterance\b", "long utterances", text, flags=re.IGNORECASE)
    text = re.sub(r"\blong returns?\s+is still slowed down\b", "long utterances still slow down", text, flags=re.IGNORECASE)
    text = re.sub(r"\blong returns?\s+is still slow down\b", "long utterances still slow down", text, flags=re.IGNORECASE)
    text = re.sub(r"\blong utterances?\s+is still slowed down\b", "long utterances still slow down", text, flags=re.IGNORECASE)
    text = re.sub(r"\blong utterances?\s+is still slow down\b", "long utterances still slow down", text, flags=re.IGNORECASE)
    text = re.sub(r"\bis still slow down\b", "still slows down", text, flags=re.IGNORECASE)
    text = re.sub(r"\butterances still slows down\b", "utterances still slow down", text, flags=re.IGNORECASE)
    text = re.sub(r"\bwhether today is\b", "weather today is", text, flags=re.IGNORECASE)
    text = re.sub(r"\bwhether today'?s\b", "weather today's", text, flags=re.IGNORECASE)
    # Technical vocabulary normalization (accent-sensitive coding/QC terms)
    text = re.sub(r"\bpidentic\b", "Pydantic", text, flags=re.IGNORECASE)
    text = re.sub(r"\bbidanetic\b", "Pydantic", text, flags=re.IGNORECASE)
    text = re.sub(r"\bbidanticb2\b", "Pydantic v2", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(bidan[\s-]*tec|pydan[\s-]*tic)\s*v[\s-]*2\b", "Pydantic v2", text, flags=re.IGNORECASE)
    text = re.sub(r"\bpython[\s-]*async[\.\s-]*i\.?o\.?\b", "Python asyncio", text, flags=re.IGNORECASE)
    text = re.sub(r"\bsqo[\s-]*alchemy\b", "SQLAlchemy", text, flags=re.IGNORECASE)
    text = re.sub(r"\bsql[\s-]*alchemy\b", "SQLAlchemy", text, flags=re.IGNORECASE)
    text = re.sub(r"\bsql[\s-]*halchemy\b", "SQLAlchemy", text, flags=re.IGNORECASE)
    text = re.sub(r"\balambic\b", "Alembic", text, flags=re.IGNORECASE)
    text = re.sub(r"\baimbic\b", "Alembic", text, flags=re.IGNORECASE)
    text = re.sub(r"\bpost[\s-]*gra[\s-]*sql\b", "PostgreSQL", text, flags=re.IGNORECASE)
    text = re.sub(r"\bpostgres[\s-]*sql\b", "PostgreSQL", text, flags=re.IGNORECASE)
    text = re.sub(r"\bpostgres,\s*sql\b", "PostgreSQL", text, flags=re.IGNORECASE)
    text = re.sub(r"\bPostgreSQL[\s-]*16\b", "PostgreSQL 16", text, flags=re.IGNORECASE)
    text = re.sub(r"\bpostgres,\s*sql[\s-]*16\b", "PostgreSQL 16", text, flags=re.IGNORECASE)
    text = re.sub(r"\bfast[\s-]*api\b", "FastAPI", text, flags=re.IGNORECASE)
    text = re.sub(r"\breddit\b", "Redis", text, flags=re.IGNORECASE)
    text = re.sub(r"\bwebsite[\s,.-]*amity\b", "WebSocket telemetry", text, flags=re.IGNORECASE)
    text = re.sub(r"\bfarma[\s-]*qc\b", "pharma QC", text, flags=re.IGNORECASE)
    text = re.sub(r"\bkappa\b", "CAPA", text, flags=re.IGNORECASE)
    text = re.sub(r"\bkapaos\b", "CAPA, OOS", text, flags=re.IGNORECASE)
    text = re.sub(r"\bCAPA\s+oos\b", "CAPA, OOS", text, flags=re.IGNORECASE)
    text = re.sub(r"\bCAPA\s+and\s+os events\b", "CAPA and OOS events", text, flags=re.IGNORECASE)
    text = re.sub(r"\bpart of when compliant\b", "Part 11 compliant", text, flags=re.IGNORECASE)
    text = re.sub(r"\bpart 11 compliant\b", "Part 11 compliant", text, flags=re.IGNORECASE)
    text = re.sub(r"\bkloa\b", "ALCOA", text, flags=re.IGNORECASE)
    text = re.sub(r"\b121[\s,.-]*cfrr?[\s-]*11\b", "21 CFR Part 11", text, flags=re.IGNORECASE)
    text = re.sub(r"\bcfrr?[\s-]*11\b", "CFR Part 11", text, flags=re.IGNORECASE)
    text = re.sub(r"\bmqtt+t*\b", "MQTT", text, flags=re.IGNORECASE)
    text = re.sub(r"\bmqtd\b", "MQTT", text, flags=re.IGNORECASE)
    text = re.sub(r"\bbeige and\b", "Bayesian", text, flags=re.IGNORECASE)
    text = re.sub(r"\bevents[-\s]*versing\b", "event-sourcing", text, flags=re.IGNORECASE)
    text = re.sub(r"\bewma elements\b", "EWMA limits", text, flags=re.IGNORECASE)
    text = re.sub(r"\bwwma\b", "EWMA", text, flags=re.IGNORECASE)
    text = re.sub(r"\bprocess drifts\b", "process drift", text, flags=re.IGNORECASE)
    text = re.sub(r"\broll-based\b", "role-based", text, flags=re.IGNORECASE)
    text = re.sub(r"\bruling z score\b", "rolling z-score", text, flags=re.IGNORECASE)
    text = re.sub(r"\brolling c score\b", "rolling z-score", text, flags=re.IGNORECASE)
    text = re.sub(r"\binvasion change\b", "Bayesian change-point", text, flags=re.IGNORECASE)
    text = re.sub(r"\bpublished retained\b", "publish retained", text, flags=re.IGNORECASE)
    text = re.sub(r"\ball indicates\b", "all indicate", text, flags=re.IGNORECASE)
    # AI ecosystem naming corrections: "cloud" is frequently a mis-hear for "Claude".
    # Keep this context-aware to avoid breaking real cloud-provider references.
    text = re.sub(r"\bcloud[\s-]*code\b", "Claude Code", text, flags=re.IGNORECASE)
    text = re.sub(r"\bclaude[\s-]*code\b", "Claude Code", text, flags=re.IGNORECASE)
    text = re.sub(r"\banthropics?\s+cloud\b", "Anthropic's Claude", text, flags=re.IGNORECASE)
    text = re.sub(r"\ban[\s-]*traffic\s+cloud\b", "Anthropic Claude", text, flags=re.IGNORECASE)
    text = re.sub(r"\banth[\s-]*traffic\s+cloud\b", "Anthropic Claude", text, flags=re.IGNORECASE)
    text = re.sub(r"\ban[\s-]*traffic\b", "Anthropic", text, flags=re.IGNORECASE)
    text = re.sub(
        r"\bdeployed?\s+a\s+google\s+cloud\s+and\s+aws\b",
        "deploy to Google Cloud and AWS",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\bdeployed?\s+to\s+a\s+google\s+cloud\s+and\s+aws\b",
        "deploy to Google Cloud and AWS",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\bagent\s+decoding\s+where\s+close\b",
        "agentic coding workflows",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\bagent\s+decoding\b",
        "agentic coding",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\bwordflows\b", "workflows", text, flags=re.IGNORECASE)
    text = re.sub(
        r"\bi\s+declare\s+the\s+google\s+cloud\s+and\s+aws\b",
        "I deploy to Google Cloud and AWS",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\bi\s+declare\s+google\s+cloud\s+and\s+aws\b",
        "I deploy to Google Cloud and AWS",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\beach\s+end\s+encoding\s+workflows\b",
        "agentic coding workflows",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\bdeployed?\s+a\s+google\s+cloud\b",
        "deploy to Google Cloud",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\bdeploy(?:ed)?\s+the\s+google\s+cloud\b",
        "deploy to Google Cloud",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\bapply\s+to\s+google\s+cloud\s+and\s+aws\b",
        "deploy to Google Cloud and AWS",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\bterraforce\b", "Terraform", text, flags=re.IGNORECASE)
    text = re.sub(r"\bews\b", "AWS", text, flags=re.IGNORECASE)
    text = re.sub(r"\bwinter\s+reform\b", "Terraform", text, flags=re.IGNORECASE)
    text = re.sub(r"\bagendic\b", "agentic", text, flags=re.IGNORECASE)
    text = re.sub(r"\bfastapi\s+injection\s+pipeline\b", "FastAPI ingestion pipeline", text, flags=re.IGNORECASE)
    text = re.sub(r"\bqtt[\s-]*related\b", "MQTT retained", text, flags=re.IGNORECASE)

    # Sentence-level whether/weather disambiguation.
    parts = re.split(r"([.!?\n])", text)
    rebuilt: list[str] = []
    for i in range(0, len(parts), 2):
        sentence = parts[i]
        sep = parts[i + 1] if i + 1 < len(parts) else ""
        lower = sentence.lower()

        technical_context = _is_technical_sentence(lower)
        sentence = _apply_technical_term_dictionary(sentence, technical_context=technical_context)
        lower = sentence.lower()

        weather_context = any(word in lower for word in ["today", "sunny", "rain", "forecast", "temperature"])
        whether_context = any(phrase in lower for phrase in ["check ", " if ", "slow down", "still slow"])

        if weather_context and not whether_context:
            sentence = re.sub(r"\bwhether\b", "weather", sentence, flags=re.IGNORECASE)
        elif whether_context and not weather_context:
            sentence = re.sub(r"\bweather\b", "whether", sentence, flags=re.IGNORECASE)

        # Claude vs cloud disambiguation for coding-assistant context.
        claude_context = any(
            phrase in lower
            for phrase in [
                "anthropic",
                "claude",
                "claude code",
                "coding assistant",
                "llm",
                "prompt",
                "agent",
                "cursor",
                "gemini",
                "chatgpt",
                "copilot",
                "vs code",
            ]
        )
        infra_cloud_context = any(
            phrase in lower
            for phrase in [
                "aws",
                "azure",
                "gcp",
                "google cloud",
                "icloud",
                "cloud provider",
                "cloud storage",
                "kubernetes",
                "terraform",
                "vpc",
                "rds",
                "eks",
            ]
        )
        if claude_context and not infra_cloud_context:
            sentence = re.sub(r"\bcloud\b", "Claude", sentence, flags=re.IGNORECASE)
            sentence = re.sub(r"\bcloud's\b", "Claude's", sentence, flags=re.IGNORECASE)

        rebuilt.append(sentence + sep)

    return "".join(rebuilt)


def _fix_sentence_capitalization(text: str) -> str:
    """Ensure sentences start with capital letters."""
    # Capitalize first word
    if text:
        text = text[0].upper() + text[1:]

    # Capitalize after sentence endings
    text = re.sub(r'([.!?]\s+)([a-z])', lambda m: m.group(1) + m.group(2).upper(), text)

    return text


def _format_bullet_points(text: str) -> str:
    """Improve bullet point formatting."""
    number_words = {
        "one": "1",
        "two": "2",
        "three": "3",
        "four": "4",
        "five": "5",
        "six": "6",
        "seven": "7",
        "eight": "8",
        "nine": "9",
        "ten": "10",
    }

    def _spoken_point_to_numbered(match: re.Match) -> str:
        marker = (match.group(1) or "").lower()
        value = number_words.get(marker, marker if marker.isdigit() else "")
        prefix = "\n" if match.start() > 0 else ""
        if value:
            return f"{prefix}{value}. "
        return f"{prefix}- "

    # Convert "point one", "bullet 2", "point three:" into numbered/bullet list markers.
    text, spoken_count = re.subn(
        r"\b(?:point|bullet)\s*(one|two|three|four|five|six|seven|eight|nine|ten|\d{1,2})\s*[,:\-]?\s*",
        _spoken_point_to_numbered,
        text,
        flags=re.IGNORECASE,
    )

    # Convert " ... . 3, item ..." into a new numbered item.
    text = re.sub(r"([.!?])\s+(\d{1,2})\s*[,:\-]\s*", r"\1\n\2. ", text)
    # Convert misheard spoken list markers like "0.1"/"0.2" into "1."/ "2."
    text = re.sub(r"(?:^|\s)0\.(\d{1,2})\s*", lambda m: f"\n{int(m.group(1))}. ", text)

    # If we already detected spoken list context, also convert trailing
    # standalone markers like "three, ..." into numbered lines.
    if spoken_count > 0:
        text = re.sub(
            r"([.!?])\s+(one|two|three|four|five|six|seven|eight|nine|ten)\s*[,:\-]\s*",
            lambda m: f"{m.group(1)}\n{number_words.get(m.group(2).lower(), m.group(2))}. ",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(
            r"([.!?])\s+(\d{1,2})\s*[,:\-]\s*",
            r"\1\n\2. ",
            text,
            flags=re.IGNORECASE,
        )

    # Handle ordinal words at sentence starts.
    text = re.sub(
        r"(?:(?<=^)|(?<=\n)|(?<=[.!?]\s))(first|second|third|fourth|fifth)\s*[,:\-]?\s*",
        lambda m: _number_to_bullet(m.group(1)) + " ",
        text,
        flags=re.IGNORECASE,
    )

    # Normalize line starts.
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"(?:^|\n)\s*([\-•]|\d+\.)\s*([a-z])", lambda m: f"\n{m.group(1)} {m.group(2).upper()}", text)

    return text.strip()


def _number_to_bullet(word: str) -> str:
    """Convert number words to bullet format."""
    mapping = {
        'first': '• First,',
        'second': '• Second,',
        'third': '• Third,',
        'fourth': '• Fourth,',
        'fifth': '• Fifth,',
    }
    return mapping.get(word.lower(), f'• {word.capitalize()},')


def _format_enumerations(text: str) -> str:
    """Improve number and enumeration formatting."""
    # Handle "three points should be three points" type patterns
    text = re.sub(r'\b(\w+)\s+points?\s+should\s+be\s+\w+\s+points?\b',
                  r'following \1 points:', text, flags=re.IGNORECASE)

    # Format number sequences
    text = re.sub(r'\bthree\s+points\b', 'three points:', text, flags=re.IGNORECASE)

    return text


def _improve_punctuation(text: str) -> str:
    """Improve punctuation spacing and placement."""
    # Fix spacing around punctuation
    text = re.sub(r'\s+([,.!?;:])', r'\1', text)  # Remove space before punctuation
    text = re.sub(r'([,.!?;:])[ \t]*([a-zA-Z])', r'\1 \2', text)  # Keep newlines, fix horizontal spacing

    # Handle double periods at end of sentences
    text = re.sub(r'\.{2,}$', '.', text)
    text = text.replace(",.", ".")

    # Add periods to end sentences that need them
    if text and not text.endswith(('.', '!', '?', ':')):
        text += '.'

    return text


def _fix_sentence_breaks(text: str) -> str:
    """Break up run-on sentences for better readability."""
    # First fix missing spaces after periods
    text = re.sub(r'\.([a-zA-Z])', r'. \1', text)

    # Add breaks at natural pause points
    break_patterns = [
        (r'\.\s*(it\s+seems\s+to)', r'. It seems to'),
        (r'\.\s*(but\s+overall)', r'. But overall'),
        (r'\.\s*(and\s+then)', r'. And then'),
        (r'\.\s*(so\s+)', r'. So '),
        (r'\.\s*(let\'?s\s+see)', r'. Let\'s see'),
        (r'\.\s*(the\s+seems\s+to)', r'. This seems to'),
        # Handle repeated punctuation
        (r'\.{2,}', '.'),
    ]

    for pattern, replacement in break_patterns:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    return text


def _normalize_numbered_list_layout(text: str) -> str:
    """Keep numbered lists consistently multiline and punctuated."""
    if len(re.findall(r"\b\d+\.\s+", text)) < 2:
        return text

    # Put each numbered item on a separate line if they arrived inline.
    # Only split when the marker appears at logical list boundaries.
    text = re.sub(r"(?:(?<=^)|(?<=[\n.!?]))\s*(\d+\.\s+)", r"\n\1", text)

    lines = text.splitlines()
    normalized: list[str] = []
    for line in lines:
        stripped = line.strip()
        if re.match(r"^\d+\.(?:\s+|,)", stripped):
            stripped = re.sub(r"^(\d+)\.,\s*", r"\1. ", stripped)
            if stripped.endswith(","):
                stripped = stripped[:-1] + "."
            elif not stripped.endswith((".", "!", "?", ":")):
                stripped += "."
        normalized.append(stripped)

    return "\n".join([ln for ln in normalized if ln])


def format_example_transcript(text: str) -> str:
    """
    Format the example transcript you provided to show improvements.
    This demonstrates the enhanced formatting capability.
    """
    # Your original text (cleaned up version)
    formatted = format_transcript_text(text)
    return formatted
