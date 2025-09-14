from __future__ import annotations

import logging
import logging.handlers
import queue
import threading
from pathlib import Path


class AsyncLogger:
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / "localflow.log"

        self.queue: queue.Queue = queue.Queue(maxsize=1000)
        self.logger = logging.getLogger("localflow")
        self.logger.setLevel(logging.INFO)

        file_handler = logging.handlers.RotatingFileHandler(
            self.log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        fmt = logging.Formatter(
            fmt="%(asctime)s %(levelname)s [%(threadName)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(fmt)

        self.queue_handler = logging.handlers.QueueHandler(self.queue)
        self.logger.addHandler(self.queue_handler)

        self.listener = logging.handlers.QueueListener(self.queue, file_handler)
        self.listener.start()

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

