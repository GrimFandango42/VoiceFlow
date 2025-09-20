#!/usr/bin/env python3
"""
Enhanced Tray Controller with Visual Indicators
===============================================
Improved system tray with dynamic status icons and visual feedback integration
"""

from __future__ import annotations

import threading
from typing import Optional
import time

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
    from voiceflow.utils.visual_indicators import (
        show_listening, show_processing, show_transcribing, 
        show_complete, show_error, hide_status,
        TranscriptionStatus, show_transcription_status
    )
    VISUAL_INDICATORS_AVAILABLE = True
except ImportError:
    VISUAL_INDICATORS_AVAILABLE = False

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

class EnhancedTrayController:
    """Enhanced system tray controller with visual status indicators"""
    
    def __init__(self, app):
        self.app = app
        self._icon: Optional[pystray.Icon] = None
        self._thread: Optional[threading.Thread] = None
        self.current_status = "idle"
        self.is_recording = False
        self.status_lock = threading.Lock()
        
        # Status update callbacks
        self.status_callbacks = []
        
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
                    from voiceflow.utils.visual_indicators import cleanup_indicators
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
                    from voiceflow.utils.visual_indicators import cleanup_indicators
                    cleanup_indicators()
                    
                self._icon.stop()
            finally:
                self._icon = None
                self._thread = None

# Convenience functions for status updates
def update_tray_status(tray_controller, status: str, recording: bool = False, message: str = None):
    """Update tray status if controller exists"""
    if tray_controller and isinstance(tray_controller, EnhancedTrayController):
        tray_controller.update_status(status, recording, message)