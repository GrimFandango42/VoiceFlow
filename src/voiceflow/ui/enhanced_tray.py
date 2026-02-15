#!/usr/bin/env python3
"""
Enhanced Tray Controller with Visual Indicators and ITrayManager Implementation
==============================================================================
Improved system tray with dynamic status icons, visual feedback integration,
and constitutional compliance monitoring.
"""

from __future__ import annotations

import threading
import time
from typing import Optional, List, Callable, Dict, Any
from datetime import datetime

# Import our models and interfaces
try:
    from src.voiceflow.models.tray_state import TrayState, TrayStatus, TrayMenuItem, Notification
    from src.voiceflow.models.system_performance import SystemPerformance
except ImportError:
    # Fallback for existing code compatibility
    TrayState = None
    TrayStatus = None
    TrayMenuItem = None
    Notification = None
    SystemPerformance = None

# Import contract interfaces
try:
    import sys
    from pathlib import Path
    spec_contracts_path = Path(__file__).parent.parent.parent.parent / "specs" / "clean-tray-tests-installer-enh" / "contracts"
    if spec_contracts_path.exists():
        sys.path.insert(0, str(spec_contracts_path))
        from tray_interface import ITrayManager, ITrayStatusProvider
        CONTRACT_INTERFACES_AVAILABLE = True
    else:
        ITrayManager = object
        ITrayStatusProvider = object
        CONTRACT_INTERFACES_AVAILABLE = False
except ImportError:
    ITrayManager = object
    ITrayStatusProvider = object
    CONTRACT_INTERFACES_AVAILABLE = False

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except Exception:
    pystray = None
    Image = None
    ImageDraw = None
    TRAY_AVAILABLE = False

try:
    from voiceflow.ui.visual_indicators import (
        show_listening, show_processing, show_transcribing,
        show_complete, show_error, hide_status,
        TranscriptionStatus, show_transcription_status,
        set_dock_enabled, toggle_recent_history
    )
    VISUAL_INDICATORS_AVAILABLE = True
except ImportError:
    VISUAL_INDICATORS_AVAILABLE = False
    def set_dock_enabled(_enabled: bool):
        return None
    def toggle_recent_history():
        return None

def _make_status_icon(size: int = 16, status: str = "idle", recording: bool = False):
    """Create dynamic status icons based on VoiceFlow state"""
    if Image is None:
        return None
    
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    
    # Status-based colors
    if status == "idle":
        bg_color = (0, 120, 215, 255)  # Blue - ready
        mic_color = (255, 255, 255, 255)  # White
    elif status == "listening":
        bg_color = (255, 165, 0, 255)  # Orange - listening
        mic_color = (255, 255, 255, 255)  # White
    elif status == "processing":
        bg_color = (50, 205, 50, 255)  # Green - processing
        mic_color = (255, 255, 255, 255)  # White
    elif status == "error":
        bg_color = (220, 20, 60, 255)  # Red - error
        mic_color = (255, 255, 255, 255)  # White
    else:
        bg_color = (128, 128, 128, 255)  # Gray - unknown
        mic_color = (255, 255, 255, 255)  # White
    
    # Background circle
    d.ellipse((0, 0, size - 1, size - 1), fill=bg_color)
    
    # Microphone glyph
    pad = 3
    if recording:
        # Larger microphone when recording
        d.ellipse((pad-1, pad-1, size - pad, size - pad - 2), fill=mic_color)
        d.rectangle((size // 2 - 2, size - pad - 2, size // 2 + 2, size - 1), fill=mic_color)
    else:
        # Normal microphone
        d.ellipse((pad, pad, size - pad - 1, size - pad - 3), fill=mic_color)
        d.rectangle((size // 2 - 1, size - pad - 3, size // 2 + 1, size - 1), fill=mic_color)
    
    # Recording indicator (red dot)
    if recording:
        d.ellipse((size - 6, 1, size - 1, 6), fill=(255, 0, 0, 255))
    
    return img

class EnhancedTrayController(ITrayManager):
    """Enhanced system tray controller implementing ITrayManager interface with visual status indicators"""
    
    def __init__(self, app):
        self.app = app
        self._icon: Optional[pystray.Icon] = None
        self._thread: Optional[threading.Thread] = None
        self.current_status = "idle"
        self.is_recording = False
        self.status_lock = threading.Lock()
        
        # Status update callbacks
        self.status_callbacks = []

        # Auto-reset timer for "complete" and "error" states
        self._reset_timer: Optional[threading.Timer] = None
        
    def add_status_callback(self, callback):
        """Add a callback for status updates"""
        self.status_callbacks.append(callback)
    
    def _notify_status_change(self, status: str, recording: bool = False):
        """Notify all callbacks of status change"""
        for callback in self.status_callbacks:
            try:
                callback(status, recording)
            except Exception as e:
                print(f"[EnhancedTray] Status callback error: {e}")
    
    def update_status(self, status: str, recording: bool = False, message: str = None):
        """Update tray icon and visual indicators based on status"""
        with self.status_lock:
            # Cancel any existing reset timer
            if self._reset_timer:
                self._reset_timer.cancel()
                self._reset_timer = None

            self.current_status = status
            self.is_recording = recording

            # Update tray icon
            if self._icon and TRAY_AVAILABLE:
                new_icon = _make_status_icon(16, status, recording)
                if new_icon:
                    self._icon.icon = new_icon

            # Update visual indicators
            if VISUAL_INDICATORS_AVAILABLE:
                self._update_visual_indicator(status, recording, message)

            # Notify callbacks
            self._notify_status_change(status, recording)

            # CRITICAL: Auto-reset timer for "complete" and "error" states
            if status in ["complete", "error"]:
                def reset_to_idle():
                    try:
                        with self.status_lock:
                            if self.current_status in ["complete", "error"]:  # Only reset if still in completion state
                                self.current_status = "idle"
                                self.is_recording = False

                                # Update tray icon to idle
                                if self._icon and TRAY_AVAILABLE:
                                    idle_icon = _make_status_icon(16, "idle", False)
                                    if idle_icon:
                                        self._icon.icon = idle_icon

                                # Hide visual indicators
                                if VISUAL_INDICATORS_AVAILABLE:
                                    from voiceflow.ui.visual_indicators import hide_status
                                    hide_status()

                                # Notify callbacks of reset
                                self._notify_status_change("idle", False)
                    except Exception as e:
                        print(f"[EnhancedTray] Auto-reset error: {e}")

                # Start 2-second timer to reset to idle
                self._reset_timer = threading.Timer(2.0, reset_to_idle)
                self._reset_timer.start()
    
    def _update_visual_indicator(self, status: str, recording: bool, message: str = None):
        """Update the bottom-screen visual indicator"""
        try:
            if status == "idle":
                hide_status()
            elif status == "listening":
                show_listening()
            elif status == "processing":
                show_processing()  
            elif status == "transcribing":
                show_transcribing()
            elif status == "complete":
                show_complete(message)
            elif status == "error":
                show_error(message)
        except Exception as e:
            print(f"[EnhancedTray] Visual indicator update error: {e}")
    
    def _menu(self):
        """Create the tray context menu"""
        if pystray is None:
            return None

        def toggle_code_mode(icon, item):
            self.app.code_mode = not self.app.code_mode
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
                self._notify("VoiceFlow", f"Code Mode: {'ON' if self.app.code_mode else 'OFF'}")
            except Exception:
                pass

        def toggle_paste(icon, item):
            self.app.cfg.paste_injection = not self.app.cfg.paste_injection
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
                mode = "Paste" if self.app.cfg.paste_injection else "Type"
                self._notify("VoiceFlow", f"Text Injection: {mode}")
            except Exception:
                pass

        def toggle_enter(icon, item):
            self.app.cfg.press_enter_after_paste = not self.app.cfg.press_enter_after_paste
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
                self._notify("VoiceFlow", f"Auto-Enter: {'ON' if self.app.cfg.press_enter_after_paste else 'OFF'}")
            except Exception:
                pass
                
        def toggle_visual_indicators(icon, item):
            """Toggle visual indicators on/off"""
            if hasattr(self.app.cfg, 'visual_indicators_enabled'):
                self.app.cfg.visual_indicators_enabled = not self.app.cfg.visual_indicators_enabled
            else:
                self.app.cfg.visual_indicators_enabled = False
            
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
                status = "ON" if getattr(self.app.cfg, 'visual_indicators_enabled', True) else "OFF"
                self._notify("VoiceFlow", f"Visual Indicators: {status}")
            except Exception:
                pass

        def toggle_dock(icon, item):
            """Toggle always-on dock visibility."""
            current = bool(getattr(self.app.cfg, "visual_dock_enabled", True))
            new_state = not current
            self.app.cfg.visual_dock_enabled = new_state
            try:
                set_dock_enabled(new_state)
            except Exception:
                pass
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
                self._notify("VoiceFlow", f"Dock: {'ON' if new_state else 'OFF'}")
            except Exception:
                pass

        def show_recent_history(icon, item):
            """Open/close recent history panel from tray."""
            try:
                toggle_recent_history()
            except Exception:
                pass

        def show_status_test(icon, item):
            """Test the visual indicators"""
            def test_sequence():
                self.update_status("listening", True, "Testing...")
                time.sleep(1.5)
                self.update_status("processing", False, "Processing test...")
                time.sleep(1.5)  
                self.update_status("transcribing", False, "Transcribing test...")
                time.sleep(1.5)
                self.update_status("complete", False, "Test complete!")
                time.sleep(2)
                self.update_status("idle", False)
            
            threading.Thread(target=test_sequence, daemon=True).start()

        def quit_app(icon, item):
            try:
                if VISUAL_INDICATORS_AVAILABLE:
                    from voiceflow.ui.visual_indicators import cleanup_indicators
                    cleanup_indicators()
                
                if self._icon:
                    self._icon.stop()
            finally:
                import os
                os._exit(0)

        # PTT presets (keeping existing functionality)
        def set_ptt(ctrl: bool, shift: bool, alt: bool, key: str):
            self.app.cfg.hotkey_ctrl = ctrl
            self.app.cfg.hotkey_shift = shift
            self.app.cfg.hotkey_alt = alt
            self.app.cfg.hotkey_key = key
            try:
                from voiceflow.utils.settings import save_config
                save_config(self.app.cfg)
            except Exception:
                pass
            hotkey_str = f"{'Ctrl+' if ctrl else ''}{'Shift+' if shift else ''}{'Alt+' if alt else ''}{key.upper() if key else ''}"
            self._notify("VoiceFlow", f"PTT Hotkey: {hotkey_str}")

        def is_ptt(ctrl: bool, shift: bool, alt: bool, key: str):
            return (
                self.app.cfg.hotkey_ctrl == ctrl
                and self.app.cfg.hotkey_shift == shift
                and self.app.cfg.hotkey_alt == alt
                and (self.app.cfg.hotkey_key or '') == (key or '')
            )

        ptt_menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: "Ctrl+Shift (default)",
                lambda icon, item: set_ptt(True, True, False, ""),
                checked=lambda item: is_ptt(True, True, False, ""),
            ),
            pystray.MenuItem(
                lambda item: "Ctrl+Shift+Space",
                lambda icon, item: set_ptt(True, True, False, "space"),
                checked=lambda item: is_ptt(True, True, False, "space"),
            ),
            pystray.MenuItem(
                lambda item: "Ctrl+Alt+Space",
                lambda icon, item: set_ptt(True, False, True, "space"),
                checked=lambda item: is_ptt(True, False, True, "space"),
            ),
            pystray.MenuItem(
                lambda item: "Ctrl+Alt (no key)",
                lambda icon, item: set_ptt(True, False, True, ""),
                checked=lambda item: is_ptt(True, False, True, ""),
            ),
            pystray.MenuItem(
                lambda item: "Ctrl+Space",
                lambda icon, item: set_ptt(True, False, False, "space"),
                checked=lambda item: is_ptt(True, False, False, "space"),
            ),
            pystray.MenuItem(
                lambda item: "Alt+Space",
                lambda icon, item: set_ptt(False, False, True, "space"),
                checked=lambda item: is_ptt(False, False, True, "space"),
            ),
        )

        return pystray.Menu(
            pystray.MenuItem(
                lambda item: f"Code Mode: {'ON' if self.app.code_mode else 'OFF'}",
                toggle_code_mode,
                checked=lambda item: self.app.code_mode,
            ),
            pystray.MenuItem(
                lambda item: f"Injection: {'Paste' if self.app.cfg.paste_injection else 'Type'}",
                toggle_paste,
                checked=lambda item: self.app.cfg.paste_injection,
            ),
            pystray.MenuItem(
                lambda item: f"Auto-Enter: {'ON' if self.app.cfg.press_enter_after_paste else 'OFF'}",
                toggle_enter,
                checked=lambda item: self.app.cfg.press_enter_after_paste,
            ),
            pystray.MenuItem(
                lambda item: f"Visual Indicators: {'ON' if getattr(self.app.cfg, 'visual_indicators_enabled', True) else 'OFF'}",
                toggle_visual_indicators,
                checked=lambda item: getattr(self.app.cfg, 'visual_indicators_enabled', True),
            ),
            pystray.MenuItem(
                lambda item: f"Dock: {'ON' if getattr(self.app.cfg, 'visual_dock_enabled', True) else 'OFF'}",
                toggle_dock,
                checked=lambda item: getattr(self.app.cfg, 'visual_dock_enabled', True),
            ),
            pystray.MenuItem("Recent History", show_recent_history),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("PTT Hotkey", ptt_menu),
            pystray.MenuItem("Test Visual Indicators", show_status_test),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", quit_app),
        )

    def _notify(self, title: str, message: str):
        """Show system notification"""
        try:
            if self._icon and hasattr(self._icon, "notify"):
                self._icon.notify(message, title=title)
        except Exception:
            pass

    def start(self):
        """Start the enhanced tray controller"""
        if not TRAY_AVAILABLE:
            print("Enhanced tray disabled: pystray/Pillow not installed.")
            return
            
        if self._icon is not None:
            return
            
        # Create initial icon
        image = _make_status_icon(16, self.current_status, self.is_recording)
        self._icon = pystray.Icon("VoiceFlow", image, "VoiceFlow - Enhanced", self._menu())

        def _run():
            if self._icon:
                self._icon.run()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

        # Apply dock visibility preference on startup.
        if VISUAL_INDICATORS_AVAILABLE:
            try:
                set_dock_enabled(True)
                self.app.cfg.visual_dock_enabled = True
            except Exception:
                pass
        
        # Welcome notification
        def _welcome():
            time.sleep(1.0)
            self._notify("VoiceFlow Enhanced", "Visual indicators active. PTT: see tray menu.")
            
        threading.Thread(target=_welcome, daemon=True).start()

    def stop(self):
        """Stop the tray controller"""
        if self._icon is not None:
            try:
                if VISUAL_INDICATORS_AVAILABLE:
                    from voiceflow.ui.visual_indicators import cleanup_indicators
                    cleanup_indicators()

                self._icon.stop()
            finally:
                self._icon = None
                self._thread = None

    # ITrayManager interface implementation
    def initialize(self) -> bool:
        """
        Initialize the system tray
        Returns: True if successful, False otherwise
        """
        try:
            self.start()
            return self._icon is not None
        except Exception as e:
            print(f"[EnhancedTray] Initialization failed: {e}")
            return False

    def update_status(self, status, recording: bool = False, message: str = None) -> None:
        """
        Update tray status and icon - enhanced to support both interface and original signatures
        Args:
            status: TrayStatus enum or string
            recording: Whether recording is active (for backward compatibility)
            message: Optional status message for tooltip
        """
        # Convert enum to string if needed
        status_str = status.value if hasattr(status, 'value') else str(status)

        with self.status_lock:
            # Cancel any existing reset timer
            if self._reset_timer:
                self._reset_timer.cancel()
                self._reset_timer = None

            self.current_status = status_str
            self.is_recording = recording

            # Update tray icon
            if self._icon and TRAY_AVAILABLE:
                new_icon = _make_status_icon(16, status_str, recording)
                if new_icon:
                    self._icon.icon = new_icon

            # Update visual indicators
            if VISUAL_INDICATORS_AVAILABLE:
                self._update_visual_indicator(status_str, recording, message)

            # Notify callbacks
            self._notify_status_change(status_str, recording)

            # CRITICAL: Auto-reset timer for "complete" and "error" states
            if status_str in ["complete", "error"]:
                def reset_to_idle():
                    try:
                        with self.status_lock:
                            if self.current_status in ["complete", "error"]:  # Only reset if still in completion state
                                self.current_status = "idle"
                                self.is_recording = False

                                # Update tray icon to idle
                                if self._icon and TRAY_AVAILABLE:
                                    idle_icon = _make_status_icon(16, "idle", False)
                                    if idle_icon:
                                        self._icon.icon = idle_icon

                                # Hide visual indicators
                                if VISUAL_INDICATORS_AVAILABLE:
                                    from voiceflow.ui.visual_indicators import hide_status
                                    hide_status()

                                # Notify callbacks of reset
                                self._notify_status_change("idle", False)
                    except Exception as e:
                        print(f"[EnhancedTray] Auto-reset error: {e}")

                # Start 2-second timer to reset to idle
                self._reset_timer = threading.Timer(2.0, reset_to_idle)
                self._reset_timer.start()

    def update_menu(self, items) -> None:
        """
        Update tray context menu
        Args:
            items: List of TrayMenuItem objects to display
        """
        # This would require rebuilding the tray icon with new menu
        # For now, we'll log the request as the current implementation uses a static menu
        print(f"[EnhancedTray] Menu update requested with {len(items)} items")

    def show_notification(self, title: str, message: str, duration: int = 3000) -> None:
        """
        Show system notification
        Args:
            title: Notification title
            message: Notification message
            duration: Display duration in milliseconds (currently not used)
        """
        self._notify(title, message)

    def set_tooltip(self, text: str) -> None:
        """
        Set tray icon tooltip
        Args:
            text: Tooltip text (max 64 chars for Windows)
        """
        # Truncate to Windows 64-character limit
        if len(text) > 64:
            text = text[:61] + "..."

        if self._icon and hasattr(self._icon, 'title'):
            self._icon.title = text

    def get_current_status(self):
        """
        Get current tray status
        Returns: Current status as TrayStatus enum or string
        """
        # Import TrayStatus if available
        if TrayStatus:
            status_map = {
                "idle": TrayStatus.IDLE,
                "listening": TrayStatus.RECORDING,  # Map listening to recording
                "processing": TrayStatus.PROCESSING,
                "error": TrayStatus.ERROR
            }
            return status_map.get(self.current_status, TrayStatus.IDLE)
        return self.current_status

    def register_status_callback(self, callback) -> None:
        """
        Register callback for status changes
        Args:
            callback: Function to call when status changes
        """
        # Wrap callback to match our existing callback format
        def wrapped_callback(status: str, recording: bool = False):
            if TrayStatus:
                status_map = {
                    "idle": TrayStatus.IDLE,
                    "listening": TrayStatus.RECORDING,
                    "processing": TrayStatus.PROCESSING,
                    "error": TrayStatus.ERROR
                }
                callback(status_map.get(status, TrayStatus.IDLE))
            else:
                callback(status)

        self.add_status_callback(wrapped_callback)

    def shutdown(self) -> None:
        """Cleanup tray resources (alias for stop)"""
        self.stop()

# Convenience functions for status updates
def update_tray_status(tray_controller, status: str, recording: bool = False, message: str = None):
    """Update tray status if controller exists"""
    if tray_controller and isinstance(tray_controller, EnhancedTrayController):
        tray_controller.update_status(status, recording, message)
