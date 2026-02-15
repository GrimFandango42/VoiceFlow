"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.core.config
"""

from .core.config import Config

__all__ = ["Config"]
