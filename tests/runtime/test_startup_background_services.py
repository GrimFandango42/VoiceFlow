from __future__ import annotations

import logging
from types import SimpleNamespace

from voiceflow.ui.cli_enhanced import EnhancedApp


class _DummyApp:
    start_background_services = EnhancedApp.start_background_services

    def __init__(self) -> None:
        self.cfg = SimpleNamespace(
            daily_learning_autorun_enabled=True,
            longrun_housekeeping_enabled=True,
        )
        self._background_services_started = False
        self._daily_learning_calls = 0
        self._housekeeping_calls = 0
        self._log_records: list[str] = []
        self._log = logging.getLogger("test.start_background_services")
        self._log.handlers = []
        self._log.setLevel(logging.INFO)
        self._log.propagate = False
        self._log.addHandler(_ListHandler(self._log_records))

    def _start_daily_learning_guardrail(self) -> None:
        self._daily_learning_calls += 1

    def _start_longrun_housekeeping_thread(self) -> None:
        self._housekeeping_calls += 1


class _ListHandler(logging.Handler):
    def __init__(self, sink: list[str]) -> None:
        super().__init__()
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        self.sink.append(record.getMessage())


def test_start_background_services_starts_workers_once() -> None:
    app = _DummyApp()

    app.start_background_services()
    app.start_background_services()

    assert app._background_services_started is True
    assert app._daily_learning_calls == 1
    assert app._housekeeping_calls == 1
    assert app._log_records
    assert "background_services_started" in app._log_records[0]
