from __future__ import annotations

import re
from typing import Dict


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
