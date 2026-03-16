from __future__ import annotations

import logging
import logging.handlers
import os
import queue
import tempfile
import threading
from pathlib import Path


class AsyncLogger:
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / "localflow.log"
        self.active_log_path = self.log_path
        self.active_log_marker_path = self.log_dir / "active_log_path.txt"

        self.queue: queue.Queue = queue.Queue(maxsize=1000)
        self.logger = logging.getLogger("localflow")
        self.logger.setLevel(logging.INFO)

        file_handler, selected_path = self._build_file_handler()
        if selected_path is not None:
            self.active_log_path = selected_path
        fmt = logging.Formatter(
            fmt="%(asctime)s %(levelname)s [%(threadName)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(fmt)

        self.queue_handler = logging.handlers.QueueHandler(self.queue)
        self.logger.addHandler(self.queue_handler)

        self.listener = logging.handlers.QueueListener(self.queue, file_handler)
        self.listener.start()
        self._write_active_log_marker()

        if self.active_log_path != self.log_path:
            self.logger.warning(
                "log_path_fallback primary=%s active=%s",
                self.log_path,
                self.active_log_path,
            )

    def _write_active_log_marker(self) -> None:
        marker_text = str(self.active_log_path)
        marker_targets = [self.active_log_marker_path]
        if self.active_log_path.parent != self.log_dir:
            marker_targets.append(self.active_log_path.parent / "active_log_path.txt")

        seen: set[str] = set()
        for marker in marker_targets:
            marker_key = str(marker).lower()
            if marker_key in seen:
                continue
            seen.add(marker_key)
            try:
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text(marker_text, encoding="utf-8")
            except Exception:
                continue

    def _build_file_handler(self) -> tuple[logging.Handler, Path | None]:
        pid = os.getpid()
        fallback_dir = Path(tempfile.gettempdir()) / "LocalFlow"
        candidates = [
            self.log_path,
            self.log_dir / f"localflow-{pid}.log",
            fallback_dir / f"localflow-{pid}.log",
        ]
        for candidate in candidates:
            try:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                handler = logging.handlers.RotatingFileHandler(
                    candidate,
                    maxBytes=2 * 1024 * 1024,
                    backupCount=3,
                    encoding="utf-8",
                )
                return handler, candidate
            except PermissionError:
                continue
            except OSError:
                continue

        return logging.StreamHandler(), None

    def stop(self):
        try:
            self.listener.stop()
        except Exception:
            pass

    def get(self) -> logging.Logger:
        return self.logger


def default_log_dir() -> Path:
    # Windows: %LOCALAPPDATA%\LocalFlow\logs
    base = Path.home()
    # Try LOCALAPPDATA if available
    import os

    lad = os.environ.get("LOCALAPPDATA")
    if lad:
        return Path(lad) / "LocalFlow" / "logs"
    return base / ".localflow" / "logs"

