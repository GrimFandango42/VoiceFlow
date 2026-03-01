from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable


@runtime_checkable
class HotkeyBackend(Protocol):
    def start(self) -> None:
        ...

    def stop(self) -> None:
        ...

    def run_forever(self) -> None:
        ...

    def suppress_event_side_effects(self, duration_seconds: float = 0.35) -> None:
        ...


@runtime_checkable
class InjectorBackend(Protocol):
    def inject(self, text: str) -> bool:
        ...

    def inject_live_checkpoint(self, text: str) -> bool:
        ...

    def copy_text_to_clipboard(self, text: str) -> bool:
        ...

    def capture_target_window(self) -> None:
        ...

    def clear_target_window(self) -> None:
        ...

    def get_target_context(self, refresh: bool = False) -> Dict[str, Any]:
        ...


@runtime_checkable
class TrayBackend(Protocol):
    def start(self) -> None:
        ...

    def stop(self) -> None:
        ...

    def update_status(self, status: Any, recording: bool = False, message: str = None) -> None:
        ...
