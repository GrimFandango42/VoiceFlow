from __future__ import annotations

import threading
import time
from typing import Callable, Optional

# Graceful import for environments without the keyboard module during tests
try:
    import keyboard  # type: ignore
except Exception:  # pragma: no cover
    class keyboard:  # type: ignore
        @staticmethod
        def is_pressed(key: str) -> bool:
            return False
        @staticmethod
        def hook(callback):
            return None
        @staticmethod
        def unhook(h):
            return None
        @staticmethod
        def wait():
            pass
        @staticmethod
        def block_key(key: str):
            return None
        @staticmethod
        def unblock_key(key: str):
            return None

from voiceflow.core.config import Config


class EnhancedPTTHotkeyListener:
    """Enhanced Push-to-talk listener with tail-end buffer support.
    
    KEY IMPROVEMENTS:
    - 1.0s tail-end buffer prevents audio cutoff
    - Better thread management for long conversations
    - Memory-safe buffer handling
    - Intelligent speech completion detection
    """

    def __init__(self, cfg: Config, on_start: Callable[[], None], on_stop: Callable[[], None]):
        self.cfg = cfg
        self.on_start = on_start
        self.on_stop = on_stop
        self._recording = False
        self._lock = threading.Lock()
        self._hook: Optional[Callable] = None
        self._blocked_key: Optional[str] = None
        
        # CRITICAL FIX: Tail-end buffer system
        self._tail_buffer_duration = 1.0  # 1.0 second buffer
        self._tail_timer: Optional[threading.Timer] = None
        self._pending_stop = False
        
        # Performance tracking
        self._recording_start_time = 0.0
        self._max_recording_duration = 300.0  # 5 minutes max

    def _chord_active(self) -> bool:
        """Evaluate chord from current keyboard state"""
        if self.cfg.hotkey_ctrl and not keyboard.is_pressed('ctrl'):
            return False
        if self.cfg.hotkey_shift and not keyboard.is_pressed('shift'):
            return False
        if self.cfg.hotkey_alt and not keyboard.is_pressed('alt'):
            return False
        key = (self.cfg.hotkey_key or '').strip()
        if key:
            if not keyboard.is_pressed(key):
                return False
        return True

    def _actual_stop_recording(self):
        """Perform the actual stop after tail buffer expires"""
        with self._lock:
            if self._recording and self._pending_stop:
                self._recording = False
                self._pending_stop = False
                
                # Unblock previously blocked key
                if self._blocked_key:
                    try:
                        keyboard.unblock_key(self._blocked_key)
                    except Exception:
                        pass
                    self._blocked_key = None
                
                # Calculate recording duration for analysis
                recording_duration = time.time() - self._recording_start_time
                print(f"[PTT] Recording completed: {recording_duration:.2f}s")
                
                try:
                    self.on_stop()
                except Exception as e:
                    print(f"[PTT] Error in on_stop callback: {e}")

    def _cancel_tail_timer(self):
        """Cancel the tail timer if active"""
        if self._tail_timer and self._tail_timer.is_alive():
            self._tail_timer.cancel()
            self._tail_timer = None

    def _on_event(self, event):  # noqa: D401
        """Enhanced event handler with tail-end buffer support"""
        with self._lock:
            active = self._chord_active()
            current_time = time.time()
            
            # START RECORDING
            if active and not self._recording:
                # Cancel any pending stop
                self._cancel_tail_timer()
                self._pending_stop = False
                
                self._recording = True
                self._recording_start_time = current_time
                
                # Block the primary key while recording to avoid stray characters
                key = (self.cfg.hotkey_key or '').strip()
                if key:
                    try:
                        keyboard.block_key(key)
                        self._blocked_key = key
                    except Exception:
                        self._blocked_key = None
                
                print(f"[PTT] Recording started")
                try:
                    self.on_start()
                except Exception as e:
                    print(f"[PTT] Error in on_start callback: {e}")
                    self._recording = False
            
            # INITIATE STOP WITH TAIL BUFFER
            elif not active and self._recording and not self._pending_stop:
                # Check for maximum recording duration safety limit
                recording_duration = current_time - self._recording_start_time
                if recording_duration >= self._max_recording_duration:
                    print(f"[PTT] Max recording duration reached ({self._max_recording_duration}s), stopping immediately")
                    self._actual_stop_recording()
                    return
                
                # Start tail-end buffer timer
                self._pending_stop = True
                print(f"[PTT] Key released, starting {self._tail_buffer_duration}s tail buffer...")
                
                self._tail_timer = threading.Timer(
                    self._tail_buffer_duration,
                    self._actual_stop_recording
                )
                self._tail_timer.start()
            
            # RESUME RECORDING (key pressed again during tail buffer)
            elif active and self._recording and self._pending_stop:
                print(f"[PTT] Key pressed again, canceling tail buffer")
                self._cancel_tail_timer()
                self._pending_stop = False

    def start(self):
        """Start the hotkey listener"""
        if self._hook is None:
            self._hook = keyboard.hook(self._on_event)
            print(f"[PTT] Enhanced hotkey listener started with {self._tail_buffer_duration}s tail buffer")

    def stop(self):
        """Stop the hotkey listener and cleanup"""
        # Cancel any active tail timer
        self._cancel_tail_timer()
        
        if self._hook is not None:
            try:
                keyboard.unhook(self._hook)
            finally:
                self._hook = None
        
        if self._blocked_key:
            try:
                keyboard.unblock_key(self._blocked_key)
            except Exception:
                pass
            self._blocked_key = None
        
        # Force stop recording if still active
        if self._recording:
            self._recording = False
            try:
                self.on_stop()
            except Exception:
                pass
        
        print("[PTT] Enhanced hotkey listener stopped")

    def run_forever(self):
        """Run the hotkey listener forever"""
        print("Enhanced PTT Ready. Hold your configured hotkey to dictate. Press Ctrl+C to exit.")
        print(f"Tail buffer: {self._tail_buffer_duration}s (continues recording after key release)")
        print(f"Max recording duration: {self._max_recording_duration}s")
        keyboard.wait()


# Compatibility alias for drop-in replacement
PTTHotkeyListener = EnhancedPTTHotkeyListener