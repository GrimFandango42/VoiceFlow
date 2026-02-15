"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.integrations.inject
"""

from .integrations.inject import ClipboardInjector

__all__ = ["ClipboardInjector"]
