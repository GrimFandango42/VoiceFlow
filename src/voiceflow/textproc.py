"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.core.textproc
"""

from .core.textproc import apply_code_mode, format_transcript_text, normalize_context_terms

__all__ = [
    "apply_code_mode",
    "format_transcript_text",
    "normalize_context_terms",
]
