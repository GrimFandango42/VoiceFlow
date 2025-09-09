"""Compatibility layer for older tests expecting `voiceflow.voiceflow_core`.

Provides a minimal `create_engine` factory that returns an object with a
`start()` method. In real runs, entry points may construct a richer engine,
but tests typically patch this function and assert interactions.
"""
from __future__ import annotations

from typing import Any, Dict


class _NoopEngine:
    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def start(self) -> None:  # pragma: no cover - does nothing in runtime
        return None


def create_engine(config: Dict[str, Any] | None = None) -> _NoopEngine:
    return _NoopEngine(config=config)

