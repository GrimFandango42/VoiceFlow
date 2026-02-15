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
        self._poll_thread: Optional[threading.Thread] = None
        self._poll_stop = threading.Event()

        # CRITICAL: Track actual key down/up lifecycle instead of polling
        self._pressed_keys = set()  # Normalize key names: "left ctrl" -> "ctrl"
        self._chord_first_active_time = 0.0  # Track when chord FIRST became active
        self._chord_was_active = False  # Track if chord was active in previous event
        self._minimum_hold_duration = 0.05  # 50ms minimum hold to prevent flutter
        self._blocked_key: Optional[str] = None
        self._event_suppress_until = 0.0
        self._release_candidate_since = 0.0
        self._release_confirm_seconds = max(
            0.03,
            float(getattr(cfg, "ptt_release_confirm_seconds", 0.12)),
        )
        
        # Tail-end buffer tuned for lower latency while preserving word endings.
        self._tail_buffer_duration = max(0.0, float(getattr(cfg, "ptt_tail_buffer_seconds", 0.25)))
        self._min_recording_for_tail_buffer = max(
            0.0,
            float(getattr(cfg, "ptt_tail_min_recording_seconds", 0.35)),
        )
        self._tail_timer: Optional[threading.Timer] = None
        self._pending_stop = False
        
        # Performance tracking
        self._recording_start_time = 0.0
        self._max_recording_duration = 300.0  # 5 minutes max

    def _poll_physical_state_loop(self) -> None:
        """
        Fallback safety net for missed key-up events.
        Polls physical key state and triggers the same release/stop logic.
        """
        while not self._poll_stop.is_set():
            try:
                with self._lock:
                    if not self._recording:
                        self._release_candidate_since = 0.0
                    else:
                        current_time = time.time()
                        physical_active = self._chord_active_physical()
                        if physical_active:
                            self._sync_pressed_keys_from_physical()
                            self._release_candidate_since = 0.0
                            if self._pending_stop:
                                self._cancel_tail_timer()
                                self._pending_stop = False
                        else:
                            if self._release_candidate_since <= 0.0:
                                self._release_candidate_since = current_time
                            elapsed = current_time - self._release_candidate_since
                            if elapsed >= self._release_confirm_seconds and not self._pending_stop:
                                recording_duration = current_time - self._recording_start_time
                                if recording_duration < self._min_recording_for_tail_buffer:
                                    self._actual_stop_recording(force=True)
                                else:
                                    self._pending_stop = True
                                    self._tail_timer = threading.Timer(
                                        self._tail_buffer_duration,
                                        self._actual_stop_recording
                                    )
                                    self._tail_timer.start()
            except Exception:
                pass
            self._poll_stop.wait(0.03)

    def _normalize_key_name(self, key_name: str) -> str:
        """Normalize key names for consistent tracking"""
        key_lower = key_name.lower()
        # Normalize modifier keys
        if 'ctrl' in key_lower:
            return 'ctrl'
        elif 'shift' in key_lower:
            return 'shift'
        elif 'alt' in key_lower:
            return 'alt'
        else:
            return key_lower

    def _chord_active(self) -> bool:
        """Check if the hotkey combination is currently pressed using tracked keys"""
        # Check required modifier keys
        if self.cfg.hotkey_ctrl and 'ctrl' not in self._pressed_keys:
            return False
        if self.cfg.hotkey_shift and 'shift' not in self._pressed_keys:
            return False
        if self.cfg.hotkey_alt and 'alt' not in self._pressed_keys:
            return False

        # Check primary key
        key = (self.cfg.hotkey_key or '').strip().lower()
        if key:
            if key not in self._pressed_keys:
                return False
        return True

    def _chord_active_physical(self) -> bool:
        """
        Check physical key state directly from OS.
        This protects against synthetic/injected key events corrupting tracked state.
        """
        try:
            if self.cfg.hotkey_ctrl and not keyboard.is_pressed('ctrl'):
                return False
            if self.cfg.hotkey_shift and not keyboard.is_pressed('shift'):
                return False
            if self.cfg.hotkey_alt and not keyboard.is_pressed('alt'):
                return False

            key = (self.cfg.hotkey_key or '').strip().lower()
            if key and not keyboard.is_pressed(key):
                return False
            return True
        except Exception:
            return False

    def _sync_pressed_keys_from_physical(self) -> None:
        """Rebuild tracked pressed key set from physical state."""
        refreshed = set()
        try:
            if self.cfg.hotkey_ctrl and keyboard.is_pressed('ctrl'):
                refreshed.add('ctrl')
            if self.cfg.hotkey_shift and keyboard.is_pressed('shift'):
                refreshed.add('shift')
            if self.cfg.hotkey_alt and keyboard.is_pressed('alt'):
                refreshed.add('alt')
            key = (self.cfg.hotkey_key or '').strip().lower()
            if key and keyboard.is_pressed(key):
                refreshed.add(key)
        except Exception:
            pass
        self._pressed_keys = refreshed

    def suppress_event_side_effects(self, duration_seconds: float = 0.35) -> None:
        """
        Temporarily suppress stop-trigger side effects from synthetic key events.
        Used during live checkpoint text injection while PTT is still physically held.
        """
        now = time.time()
        self._event_suppress_until = max(self._event_suppress_until, now + max(0.05, float(duration_seconds)))

    def _actual_stop_recording(self, force: bool = False):
        """Perform the actual stop after tail buffer expires."""
        with self._lock:
            if self._recording and (self._pending_stop or force):
                # Guard against synthetic event glitches: if hotkey is still physically held,
                # do not stop even if a pending stop was scheduled.
                if not force and self._chord_active_physical():
                    self._sync_pressed_keys_from_physical()
                    self._pending_stop = False
                    return

                self._recording = False
                self._pending_stop = False
                self._release_candidate_since = 0.0
                
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
        """Enhanced event handler with explicit key tracking to prevent Ctrl-only activation."""
        if not hasattr(event, 'name') or not hasattr(event, 'event_type'):
            return

        key_name = self._normalize_key_name(event.name)
        if event.event_type == keyboard.KEY_DOWN:
            self._pressed_keys.add(key_name)
        elif event.event_type == keyboard.KEY_UP:
            self._pressed_keys.discard(key_name)

        with self._lock:
            current_time = time.time()

            # During synthetic injection windows, trust physical state to avoid false release detection.
            if self._recording and current_time < self._event_suppress_until:
                if self._chord_active_physical():
                    self._sync_pressed_keys_from_physical()
                    self._chord_was_active = True
                    return

            # Check if chord is currently active
            chord_active = self._chord_active()
            if self._recording and not chord_active:
                # Recovery path: injected typing can generate synthetic key events.
                # Before initiating stop, verify real physical key state.
                if self._chord_active_physical():
                    self._sync_pressed_keys_from_physical()
                    chord_active = True
            if self._recording:
                if chord_active:
                    self._release_candidate_since = 0.0
                else:
                    # Require a short, continuous release period before stop logic.
                    if self._release_candidate_since <= 0.0:
                        self._release_candidate_since = current_time
                        return
                    if (current_time - self._release_candidate_since) < self._release_confirm_seconds:
                        return
                    # Final physical-state check before honoring release.
                    if self._chord_active_physical():
                        self._sync_pressed_keys_from_physical()
                        self._release_candidate_since = 0.0
                        chord_active = True

            # Track when chord first becomes active
            if chord_active and not self._chord_was_active:
                # Chord just became active - start timing
                self._chord_first_active_time = current_time
            elif not chord_active:
                # Chord is not active - reset timing
                self._chord_first_active_time = 0.0

            self._chord_was_active = chord_active

            # START RECORDING - when chord becomes active
            if chord_active and not self._recording:
                # Cancel any pending stop
                self._cancel_tail_timer()
                self._pending_stop = False

                self._recording = True
                self._recording_start_time = current_time
                self._release_candidate_since = 0.0

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

            # INITIATE STOP WITH TAIL BUFFER - only when all keys released
            elif not chord_active and self._recording and not self._pending_stop:
                # Check for maximum recording duration safety limit
                recording_duration = current_time - self._recording_start_time
                if recording_duration >= self._max_recording_duration:
                    print(f"[PTT] Max recording duration reached ({self._max_recording_duration}s), stopping immediately")
                    self._actual_stop_recording(force=True)
                    return

                # CRITICAL FIX: Only use tail buffer for recordings longer than minimum duration
                # This prevents "OK OK OK" spam from quick press/release without speaking
                if recording_duration < self._min_recording_for_tail_buffer:
                    print(
                        f"[PTT] Short recording ({recording_duration:.1f}s < "
                        f"{self._min_recording_for_tail_buffer}s), stopping immediately without tail buffer"
                    )
                    self._actual_stop_recording(force=True)
                    return

                # Start tail-end buffer timer for longer recordings
                self._pending_stop = True
                print(f"[PTT] All keys released after {recording_duration:.1f}s, starting {self._tail_buffer_duration}s tail buffer...")

                self._tail_timer = threading.Timer(
                    self._tail_buffer_duration,
                    self._actual_stop_recording
                )
                self._tail_timer.start()
            
            # RESUME RECORDING (key pressed again during tail buffer)
            elif chord_active and self._recording and self._pending_stop:
                print(f"[PTT] Key pressed again, canceling tail buffer")
                self._cancel_tail_timer()
                self._pending_stop = False
                self._release_candidate_since = 0.0

    def start(self):
        """Start the hotkey listener"""
        if self._hook is None:
            self._hook = keyboard.hook(self._on_event)
            self._poll_stop.clear()
            self._poll_thread = threading.Thread(
                target=self._poll_physical_state_loop,
                name="PTTPhysicalPoll",
                daemon=True,
            )
            self._poll_thread.start()
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
        self._poll_stop.set()
        
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
