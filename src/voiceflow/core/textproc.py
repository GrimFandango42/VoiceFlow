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

    # Fix common speech patterns
    text = _fix_sentence_capitalization(text)
    text = _format_bullet_points(text)
    text = _format_enumerations(text)
    text = _improve_punctuation(text)
    text = _fix_sentence_breaks(text)

    return text


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
    # Handle spoken bullet points
    patterns = [
        (r'\b(bullet|point)\s+', '• '),
        (r'\b(first|second|third|fourth|fifth)\s*,?\s*', lambda m: f"{_number_to_bullet(m.group(1))} "),
        # Handle explicit bullet formatting
        (r'(?:^|\n)\s*•\s*([a-z])', lambda m: f'• {m.group(1).upper()}'),
    ]

    for pattern, replacement in patterns:
        if callable(replacement):
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        else:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    return text


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
    text = re.sub(r'([,.!?;:])\s*([a-zA-Z])', r'\1 \2', text)  # Add space after punctuation

    # Handle double periods at end of sentences
    text = re.sub(r'\.{2,}$', '.', text)

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


def format_example_transcript(text: str) -> str:
    """
    Format the example transcript you provided to show improvements.
    This demonstrates the enhanced formatting capability.
    """
    # Your original text (cleaned up version)
    formatted = format_transcript_text(text)
    return formatted
