"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.ui.cli_enhanced
"""

from .ui.cli_enhanced import EnhancedApp, main

__all__ = ["EnhancedApp", "main"]
