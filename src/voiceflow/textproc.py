"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.core.textproc
"""

from .core.textproc import (
    apply_code_mode,
    apply_second_pass_cleanup,
    format_transcript_text,
    format_transcript_for_destination,
    infer_destination_profile,
    normalize_context_terms,
)

__all__ = [
    "apply_code_mode",
    "apply_second_pass_cleanup",
    "format_transcript_text",
    "format_transcript_for_destination",
    "infer_destination_profile",
    "normalize_context_terms",
]
