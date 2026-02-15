"""Compatibility shim for legacy imports.

Prefer importing from:
    voiceflow.ui.enhanced_tray
"""

from .ui.enhanced_tray import EnhancedTrayController, update_tray_status

__all__ = ["EnhancedTrayController", "update_tray_status"]
