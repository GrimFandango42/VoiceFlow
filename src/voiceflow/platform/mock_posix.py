from __future__ import annotations

import time
from typing import Any, Dict, Optional

from voiceflow.core.config import Config


class MockPosixInjectorBackend:
    """No-op injector backend used as a safe cross-platform scaffold."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._target_context: Dict[str, Any] = {
            "platform": "mock-posix",
            "window_title": "",
            "process_name": "",
            "window_width": 0,
            "window_height": 0,
        }
        self._last_text: str = ""

    def inject(self, text: str) -> bool:
        self._last_text = str(text or "")
        return False

    def inject_live_checkpoint(self, text: str) -> bool:
        self._last_text = str(text or "")
        return False

    def copy_text_to_clipboard(self, text: str) -> bool:
        self._last_text = str(text or "")
        return False

    def capture_target_window(self) -> None:
        return None

    def clear_target_window(self) -> None:
        return None

    def get_target_context(self, refresh: bool = False) -> Dict[str, Any]:
        return dict(self._target_context)


class MockPosixHotkeyBackend:
    """Idle hotkey backend stub for non-Windows bring-up/testing."""

    def __init__(self, cfg: Config, on_start, on_stop):
        self.cfg = cfg
        self.on_start = on_start
        self.on_stop = on_stop
        self._running = False

    def suppress_event_side_effects(self, duration_seconds: float = 0.35) -> None:
        return None

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run_forever(self) -> None:
        self._running = True
        try:
            while self._running:
                time.sleep(0.25)
        except KeyboardInterrupt:
            self._running = False


class MockPosixTrayBackend:
    """Tray no-op backend for environments without native tray implementation."""

    def __init__(self, app: Any):
        self.app = app
        self._running = False
        self.current_status = "idle"
        self.is_recording = False

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def update_status(self, status: Any, recording: bool = False, message: Optional[str] = None) -> None:
        self.current_status = str(getattr(status, "value", status))
        self.is_recording = bool(recording)

