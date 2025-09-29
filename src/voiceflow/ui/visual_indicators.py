#!/usr/bin/env python3
"""
VoiceFlow Visual Indicators
===========================
Bottom-screen transcription status overlay similar to Wispr Flow
"""

import logging
import tkinter as tk
from tkinter import ttk
import threading
import time
from typing import Optional, Callable, Dict, Any
from enum import Enum
from .visual_config import get_visual_config, VisualConfigManager
from ..utils.guardrails import safe_visual_update, process_visual_update_queue, with_error_recovery

logger = logging.getLogger(__name__)

class TranscriptionStatus(Enum):
    """Status states for visual indication"""
    IDLE = "idle"
    LISTENING = "listening" 
    PROCESSING = "processing"
    TRANSCRIBING = "transcribing"
    COMPLETE = "complete"
    ERROR = "error"

class BottomScreenIndicator:
    """
    Bottom-screen overlay indicator for transcription status
    Similar to Wispr Flow - small, unobtrusive, informative
    Thread-safe for background hotkey calls
    """

    def __init__(self):
        self.window: Optional[tk.Toplevel] = None
        self.root: Optional[tk.Tk] = None
        self.status_var: Optional[tk.StringVar] = None
        self.progress_var: Optional[tk.DoubleVar] = None
        self.current_status = TranscriptionStatus.IDLE
        self.auto_hide_timer: Optional[threading.Timer] = None
        self.lock = threading.Lock()
        self.gui_thread: Optional[threading.Thread] = None
        self.gui_running = False
        self.gui_ready = False
        self.command_queue = None
        self.ready_event = threading.Event()

        # Configuration manager
        self.config_manager = get_visual_config()
        self._update_visual_settings()

        # Start GUI in separate thread for background compatibility
        self._start_gui_thread()

        # Wait for GUI to be ready
        self._wait_for_gui_ready()

    def _update_visual_settings(self):
        """Update visual settings from configuration"""
        self.width, self.height = self.config_manager.get_overlay_dimensions()
        colors = self.config_manager.get_color_scheme()

        self.bg_color = colors['bg_color']
        self.text_color = colors['text_color']
        self.accent_color = colors['accent_color']
        self.error_color = colors['error_color']
    
    def _start_gui_thread(self):
        """Start GUI thread for thread-safe visual indicators"""
        import queue
        self.command_queue = queue.Queue()
        self.gui_thread = threading.Thread(target=self._gui_thread_worker, daemon=True)
        self.gui_thread.start()

    def _wait_for_gui_ready(self):
        """Wait for GUI thread to be ready"""
        try:
            # Wait up to 5 seconds for GUI to be ready
            if self.ready_event.wait(timeout=5.0):
                print("[VisualIndicator] GUI ready for use")
            else:
                print("[VisualIndicator] Warning: GUI startup timeout")
        except Exception as e:
            print(f"[VisualIndicator] GUI ready wait error: {e}")

    def _gui_thread_worker(self):
        """GUI thread worker - runs Tkinter mainloop"""
        try:
            # Create root window in this thread
            self.root = tk.Tk()
            self.root.withdraw()  # Hide main window
            self.gui_running = True

            # Setup window
            self._setup_window()

            # Mark as ready
            self.gui_ready = True
            self.ready_event.set()

            # Process commands from queue
            self.root.after(50, self._process_command_queue)

            # Run mainloop
            self.root.mainloop()

        except Exception as e:
            print(f"[VisualIndicator] GUI thread error: {e}")
            self.ready_event.set()  # Signal ready even on error
        finally:
            self.gui_running = False
            self.gui_ready = False

    def _process_command_queue(self):
        """Process commands from other threads"""
        try:
            import queue
            while not self.command_queue.empty():
                try:
                    command, args, kwargs = self.command_queue.get_nowait()
                    command(*args, **kwargs)
                except queue.Empty:
                    break
                except Exception as e:
                    print(f"[VisualIndicator] Command error: {e}")
        except Exception as e:
            print(f"[VisualIndicator] Queue processing error: {e}")
        finally:
            # Schedule next check
            if self.gui_running and self.root:
                self.root.after(50, self._process_command_queue)

    def _setup_window(self):
        """Initialize the bottom overlay window"""
        try:
            if not self.root:
                return

            # Create overlay window
            self.window = tk.Toplevel(self.root)
            self.window.title("VoiceFlow Status")

            # Get screen dimensions
            screen_width = self.window.winfo_screenwidth()
            screen_height = self.window.winfo_screenheight()

            # Calculate position and size based on configuration
            x, y = self.config_manager.get_position_coordinates(screen_width, screen_height)

            self.window.geometry(f"{self.width}x{self.height}+{x}+{y}")

            # Window properties for overlay behavior
            config = self.config_manager.config
            self.window.wm_attributes("-topmost", config.always_on_top)
            self.window.wm_attributes("-alpha", config.opacity)
            self.window.overrideredirect(True)  # No title bar
            self.window.configure(bg=self.bg_color)

            # Create UI elements
            self._create_ui()

            # Start hidden
            self.window.withdraw()

        except (tk.TclError, AttributeError, ValueError) as e:
            print(f"[VisualIndicator] Failed to setup window: {e}")
            self.window = None
        except Exception as e:
            print(f"[VisualIndicator] Unexpected error during window setup: {type(e).__name__}: {e}")
            self.window = None
    
    def _create_ui(self):
        """Create the UI elements for the status display"""
        if not self.window:
            return
            
        # Main frame
        main_frame = tk.Frame(self.window, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Status text
        self.status_var = tk.StringVar(value="VoiceFlow Ready")
        status_label = tk.Label(
            main_frame,
            textvariable=self.status_var,
            bg=self.bg_color,
            fg=self.text_color,
            font=("Segoe UI", 11, "bold")
        )
        status_label.pack(pady=(0, 5))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            main_frame,
            length=280,
            mode='indeterminate',
            variable=self.progress_var
        )
        self.progress_bar.pack()
        
        # Configure progress bar style
        style = ttk.Style()
        style.configure(
            "Custom.Horizontal.TProgressbar",
            background=self.accent_color,
            troughcolor=self.bg_color,
            borderwidth=0,
            lightcolor=self.accent_color,
            darkcolor=self.accent_color
        )
        self.progress_bar.configure(style="Custom.Horizontal.TProgressbar")
    
    @with_error_recovery(fallback_value=None)
    def show_status(self, status: TranscriptionStatus, message: str = None, duration: float = None):
        """
        Show status indicator with message - Thread-safe with CRITICAL GUARDRAILS

        Args:
            status: TranscriptionStatus enum
            message: Custom message (optional)
            duration: Auto-hide after seconds (optional)
        """
        # CRITICAL GUARDRAIL: Use safe visual update wrapper
        def _safe_status_update():
            if not self.gui_ready or not self.command_queue:
                logger.debug(f"GUI not ready, status: {status.value}")
                return

            with self.lock:
                self.current_status = status

                # Cancel existing auto-hide timer
                if self.auto_hide_timer:
                    self.auto_hide_timer.cancel()

                # Update message
                if message:
                    display_message = message
                else:
                    display_message = self._get_default_message(status)

                # Queue command for GUI thread with error protection
                try:
                    self.command_queue.put((self._update_ui, (status, display_message), {}))

                    # Auto-hide timer
                    if duration:
                        self.auto_hide_timer = threading.Timer(duration, self.hide)
                        self.auto_hide_timer.start()

                except Exception as e:
                    logger.error(f"Failed to queue status update: {e}")

        return safe_visual_update(_safe_status_update)
    
    @with_error_recovery(fallback_value=None)
    def _update_ui(self, status: TranscriptionStatus, message: str):
        """Update UI elements (must run on main thread) - CRITICAL GUARDRAIL PROTECTED"""
        if not self.window or not self.status_var:
            logger.debug("Window or status_var not available for UI update")
            return

        try:
            # Show window
            self.window.deiconify()
            self.window.lift()
            
            # Update text
            self.status_var.set(message)
            
            # Update progress bar based on status
            if status == TranscriptionStatus.LISTENING:
                self.progress_bar.configure(mode='indeterminate')
                self.progress_bar.start(10)  # Slow pulse
            elif status == TranscriptionStatus.PROCESSING:
                self.progress_bar.configure(mode='indeterminate') 
                self.progress_bar.start(5)   # Fast pulse
            elif status == TranscriptionStatus.TRANSCRIBING:
                self.progress_bar.configure(mode='indeterminate')
                self.progress_bar.start(3)   # Very fast pulse
            else:
                self.progress_bar.stop()
                if status == TranscriptionStatus.COMPLETE:
                    self.progress_bar.configure(mode='determinate')
                    self.progress_var.set(100)
                else:
                    self.progress_var.set(0)
            
            # Update colors based on status
            color = self.text_color
            if status == TranscriptionStatus.ERROR:
                color = self.error_color
            elif status in [TranscriptionStatus.LISTENING, TranscriptionStatus.PROCESSING, TranscriptionStatus.TRANSCRIBING]:
                color = self.accent_color
            
            # Apply color (find the label widget)
            for widget in self.window.winfo_children():
                if isinstance(widget, tk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Label):
                            child.configure(fg=color)
                            break
                    break
        
        except Exception as e:
            print(f"[VisualIndicator] UI update error: {e}")
    
    def _get_default_message(self, status: TranscriptionStatus) -> str:
        """Get default message for status"""
        messages = {
            TranscriptionStatus.IDLE: "VoiceFlow Ready",
            TranscriptionStatus.LISTENING: "Listening... (Hold Ctrl+Shift)",
            TranscriptionStatus.PROCESSING: "🔄 Processing audio...",
            TranscriptionStatus.TRANSCRIBING: "✍️ Transcribing...",
            TranscriptionStatus.COMPLETE: "✅ Transcription complete",
            TranscriptionStatus.ERROR: "❌ Transcription failed"
        }
        return messages.get(status, "VoiceFlow")
    
    def hide(self):
        """Hide the status indicator - Thread-safe"""
        if not self.gui_ready or not self.command_queue:
            return

        try:
            self.command_queue.put((self._hide_window, (), {}))
        except Exception as e:
            print(f"[VisualIndicator] Failed to queue hide command: {e}")

    def _hide_window(self):
        """Hide window on GUI thread and reset all state"""
        try:
            # CRITICAL: Cancel any pending auto-hide timer
            if self.auto_hide_timer:
                self.auto_hide_timer.cancel()
                self.auto_hide_timer = None

            # Reset status to idle to prevent persistence
            self.current_status = TranscriptionStatus.IDLE

            # Hide the window
            if self.window:
                self.window.withdraw()

            # Stop any progress animations
            if hasattr(self, 'progress_bar'):
                self.progress_bar.stop()

            # Clear status text to ensure nothing persists
            if self.status_var:
                self.status_var.set("")

        except Exception as e:
            print(f"[VisualIndicator] Hide error: {e}")
    
    def destroy(self):
        """Clean up the indicator"""
        with self.lock:
            if self.auto_hide_timer:
                self.auto_hide_timer.cancel()
            
            if self.window:
                try:
                    self.window.after(0, self._destroy_window)
                except Exception:
                    pass
    
    def _destroy_window(self):
        """Destroy window on main thread"""
        try:
            if self.window:
                self.window.destroy()
            if hasattr(self, 'root'):
                self.root.destroy()
        except Exception:
            pass

# Global indicator instance
_indicator: Optional[BottomScreenIndicator] = None
_indicator_lock = threading.Lock()

def get_indicator() -> BottomScreenIndicator:
    """Get or create the global status indicator"""
    global _indicator
    
    with _indicator_lock:
        if _indicator is None:
            _indicator = BottomScreenIndicator()
    
    return _indicator

@with_error_recovery(fallback_value=None)
def show_transcription_status(status: TranscriptionStatus, message: str = None, duration: float = None):
    """Convenient function to show transcription status - CRITICAL GUARDRAIL PROTECTED"""
    def _safe_show():
        indicator = get_indicator()
        indicator.show_status(status, message, duration)

    return safe_visual_update(_safe_show)

@with_error_recovery(fallback_value=None)
def hide_status():
    """Hide the status indicator - CRITICAL GUARDRAIL PROTECTED"""
    def _safe_hide():
        if _indicator:
            _indicator.hide()

    return safe_visual_update(_safe_hide)

def cleanup_indicators():
    """Clean up visual indicators"""
    global _indicator
    with _indicator_lock:
        if _indicator:
            _indicator.destroy()
            _indicator = None

def force_cleanup_all():
    """Force cleanup of all persistent visual state - EMERGENCY CLEANUP"""
    try:
        # Force hide any visible indicators
        hide_status()

        # Wait a moment for GUI thread to process
        time.sleep(0.1)

        # Destroy everything
        cleanup_indicators()

        print("[VisualIndicator] Force cleanup completed")
    except Exception as e:
        print(f"[VisualIndicator] Force cleanup error: {e}")

def ensure_clean_startup():
    """Ensure clean startup by clearing any persistent state"""
    try:
        force_cleanup_all()
        # Small delay to let any GUI threads settle
        time.sleep(0.2)
        print("[VisualIndicator] Clean startup ensured")
    except Exception as e:
        print(f"[VisualIndicator] Startup cleanup error: {e}")

# Convenience functions for common status updates
def show_listening():
    show_transcription_status(TranscriptionStatus.LISTENING)

def show_processing():
    show_transcription_status(TranscriptionStatus.PROCESSING)

def show_transcribing():
    show_transcription_status(TranscriptionStatus.TRANSCRIBING)

def show_complete(message: str = None):
    show_transcription_status(TranscriptionStatus.COMPLETE, message, duration=2.0)

def show_error(message: str = None):
    show_transcription_status(TranscriptionStatus.ERROR, message, duration=3.0)

# Test function
def test_visual_indicators():
    """Test the visual indicators"""
    print("Testing VoiceFlow Visual Indicators...")
    
    # Test sequence
    show_listening()
    time.sleep(2)
    
    show_processing() 
    time.sleep(2)
    
    show_transcribing()
    time.sleep(2)
    
    show_complete("Test transcription complete!")
    time.sleep(3)
    
    show_error("Test error message")
    time.sleep(3)
    
    hide_status()
    print("Visual indicator test complete")

if __name__ == "__main__":
    test_visual_indicators()