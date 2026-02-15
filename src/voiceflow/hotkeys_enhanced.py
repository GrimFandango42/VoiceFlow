"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.integrations.hotkeys_enhanced
"""

from .integrations.hotkeys_enhanced import EnhancedPTTHotkeyListener, PTTHotkeyListener

__all__ = ["EnhancedPTTHotkeyListener", "PTTHotkeyListener"]
