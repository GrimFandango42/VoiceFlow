from __future__ import annotations

import logging
import logging.handlers
import os
import queue
import shutil
import tempfile
from pathlib import Path


class AsyncLogger:
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / "voiceflow.log"
        self.active_log_path = self.log_path
        self.active_log_marker_path = self.log_dir / "active_log_path.txt"

        self.queue: queue.Queue = queue.Queue(maxsize=1000)
        self.logger = logging.getLogger("voiceflow")
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
        fallback_dir = Path(tempfile.gettempdir()) / "VoiceFlow"
        candidates = [
            self.log_path,
            self.log_dir / f"voiceflow-{pid}.log",
            fallback_dir / f"voiceflow-{pid}.log",
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


def _migrate_localflow_data_dir() -> None:
    """One-time migration: move %LOCALAPPDATA%\\LocalFlow → %LOCALAPPDATA%\\VoiceFlow.

    Safe conditions for migration:
      - Old directory exists
      - New directory does not yet exist (or is empty)
    If either condition fails, or if anything goes wrong, the function is silent.
    """
    lad = os.environ.get("LOCALAPPDATA")
    if not lad:
        return
    old_root = Path(lad) / "LocalFlow"
    new_root = Path(lad) / "VoiceFlow"
    if not old_root.exists():
        return
    if new_root.exists() and any(new_root.iterdir()):
        # New directory already has content — don't clobber it.
        return
    try:
        if new_root.exists():
            new_root.rmdir()  # Remove if empty so rename works
        shutil.move(str(old_root), str(new_root))
    except Exception:
        pass  # Never crash on migration failure; fall through to normal startup


def default_log_dir() -> Path:
    # Windows: %LOCALAPPDATA%\VoiceFlow\logs
    lad = os.environ.get("LOCALAPPDATA")
    if lad:
        _migrate_localflow_data_dir()
        return Path(lad) / "VoiceFlow" / "logs"
    return Path.home() / ".voiceflow" / "logs"
