"""External integrations and system interfaces.

This module handles integration with external systems including
hotkey management, text injection, and system services.
"""

from .inject import ClipboardInjector
from .hotkeys_enhanced import EnhancedPTTHotkeyListener

__all__ = [
    "ClipboardInjector",
    "EnhancedPTTHotkeyListener",
]