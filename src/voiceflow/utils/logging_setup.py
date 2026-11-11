from __future__ import annotations

import logging
import logging.handlers
import os
import queue
import shutil
import tempfile
import time
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
        self.async_delivery = True

        # Re-initialising would otherwise stack a second set of handlers on the
        # module-level logger and double every line.
        for existing in list(self.logger.handlers):
            self.logger.removeHandler(existing)

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
        self._verify_delivery_or_fall_back(file_handler)

        if self.active_log_path != self.log_path:
            self.logger.warning(
                "log_path_fallback primary=%s active=%s",
                self.log_path,
                self.active_log_path,
            )

    def _verify_delivery_or_fall_back(self, file_handler: logging.Handler) -> None:
        """
        Prove a record actually reaches disk, or stop going through the queue.

        The QueueHandler/QueueListener pair moves disk I/O off the calling
        thread, which matters on the audio path. But when the listener thread
        does not drain, nothing says so: the handler has the file open, every
        log call succeeds, the queue fills to its 1000-record cap and
        QueueHandler then discards records through handleError. The app looks
        healthy and writes nothing.

        That is not hypothetical. VoiceFlow ran for days at a time with an open
        voiceflow.log and no output, but only when started by
        Win32_Process::Create -- the watchdog, Task Scheduler and the Startup
        shortcut, so in practice every real launch. Started from a shell it
        logged normally. The underlying cause is still unknown, and that is the
        point of checking rather than assuming: a diagnostic channel that fails
        silently is worse than none, because it is trusted.

        So emit one record and watch the file grow. If it does not, drop the
        queue and let the file handler take writes directly -- slower per call,
        and still a working log.
        """
        try:
            before = self.active_log_path.stat().st_size if self.active_log_path.exists() else 0
        except Exception:
            before = 0

        self.logger.info("logging_delivery_check pid=%d", os.getpid())

        deadline = time.monotonic() + 2.0
        delivered = False
        while time.monotonic() < deadline:
            try:
                if self.active_log_path.exists() and self.active_log_path.stat().st_size > before:
                    delivered = True
                    break
            except Exception:
                pass
            time.sleep(0.05)

        if delivered:
            return

        try:
            self.listener.stop()
        except Exception:
            pass
        try:
            self.logger.removeHandler(self.queue_handler)
        except Exception:
            pass

        self.logger.addHandler(file_handler)
        self.queue_handler = None
        self.async_delivery = False
        self.logger.warning(
            "logging_queue_listener_not_delivering fallback=direct_file_handler pid=%d",
            os.getpid(),
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
