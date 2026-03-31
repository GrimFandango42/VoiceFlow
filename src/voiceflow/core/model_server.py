"""
VoiceFlow Model Server

Long-running process that loads Whisper models once and serves transcription
requests over localhost HTTP. Stays alive across hot-reload restarts of the app
process, eliminating per-restart model load time (typically 5-60s).

Endpoints:
  GET  /health      — readiness check
  POST /transcribe  — transcribe base64-encoded float32 audio
  POST /shutdown    — graceful shutdown

Usage (standalone):
  python -m voiceflow.core.model_server [--port 8765]

Environment variables:
  VOICEFLOW_MODEL_SERVER_PORT   — override default port (default: 8765)
"""

from __future__ import annotations

import base64
import http.server
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_PORT = 8765
_PORT_ENV = "VOICEFLOW_MODEL_SERVER_PORT"


def _port_from_env(default: int = DEFAULT_PORT) -> int:
    try:
        return int(os.environ.get(_PORT_ENV, default))
    except (ValueError, TypeError):
        return default


def _result_to_dict(result) -> dict:
    """Convert TranscriptionResult to a JSON-serializable dict."""
    segments = []
    for seg in getattr(result, "segments", []):
        segments.append({
            "text": seg.text,
            "start": seg.start,
            "end": seg.end,
            "speaker": getattr(seg, "speaker", None),
            "confidence": getattr(seg, "confidence", 1.0),
            "words": getattr(seg, "words", None),
        })
    return {
        "text": getattr(result, "text", ""),
        "segments": segments,
        "language": getattr(result, "language", "en"),
        "duration": getattr(result, "duration", 0.0),
        "processing_time": getattr(result, "processing_time", 0.0),
        "confidence": getattr(result, "confidence", 1.0),
        "words": getattr(result, "words", None),
        "speaker_count": getattr(result, "speaker_count", 0),
    }


class _ModelState:
    """Thread-safe container for loaded model state."""

    def __init__(self):
        self._lock = threading.Lock()
        self._status = "loading"  # loading | ready | failed
        self._error: Optional[str] = None
        self._asr_primary = None
        self._asr_fast = None
        self._start_time = time.time()

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    @property
    def error(self) -> Optional[str]:
        with self._lock:
            return self._error

    def get_asr(self, model_path: str = "primary"):
        with self._lock:
            if model_path == "fast" and self._asr_fast is not None:
                return self._asr_fast
            return self._asr_primary

    def set_ready(self, asr_primary, asr_fast=None) -> None:
        with self._lock:
            self._asr_primary = asr_primary
            self._asr_fast = asr_fast
            self._status = "ready"

    def set_failed(self, error: str) -> None:
        with self._lock:
            self._status = "failed"
            self._error = error

    def health_dict(self) -> dict:
        with self._lock:
            return {
                "status": self._status,
                "uptime": time.time() - self._start_time,
                "error": self._error,
                "has_fast_model": self._asr_fast is not None,
            }


def _load_models(state: _ModelState) -> None:
    """Background thread: load primary and optional fast ASR models."""
    try:
        from voiceflow.core.config import Config
        from voiceflow.core.asr_engine import ModernWhisperASR
        from voiceflow.utils.settings import load_config

        cfg = load_config(Config())
        tier = getattr(cfg, "model_tier", "quick")
        logger.info("model_server: loading primary model (tier=%s)", tier)
        print(f"[model-server] Loading primary model (tier={tier})...", flush=True)

        primary = ModernWhisperASR(cfg)
        primary.load()
        logger.info("model_server: primary model ready")
        print("[model-server] Primary model ready", flush=True)

        # Optionally load the fast (latency-boost) model
        fast_asr = None
        if getattr(cfg, "latency_boost_enabled", True):
            fast_tier = str(getattr(cfg, "latency_boost_model_tier", "tiny")).strip().lower()
            base_tier = str(getattr(cfg, "model_tier", "quick")).strip().lower()
            if fast_tier != base_tier:
                try:
                    from types import SimpleNamespace
                    fast_cfg = SimpleNamespace(**cfg.__dict__)
                    fast_cfg.model_tier = fast_tier
                    if fast_tier == "tiny":
                        fast_cfg.model_name = "tiny.en"
                    fast_asr = ModernWhisperASR(fast_cfg)
                    fast_asr.load()
                    logger.info("model_server: fast model ready (tier=%s)", fast_tier)
                    print(f"[model-server] Fast model ready (tier={fast_tier})", flush=True)
                except Exception as e:
                    logger.warning("model_server: fast model unavailable: %s", e)
                    print(f"[model-server] Fast model unavailable: {e}", flush=True)
                    fast_asr = None

        state.set_ready(primary, fast_asr)
        print("[model-server] All models ready — accepting requests", flush=True)

    except Exception as e:
        logger.error("model_server: failed to load models: %s", e)
        print(f"[model-server] FAILED to load models: {e}", flush=True)
        state.set_failed(str(e))


def _make_handler(state: _ModelState, shutdown_event: threading.Event):
    """Return a request handler class bound to the given state."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # suppress default access log
            logger.debug("model_server request: " + fmt % args)

        def do_GET(self):
            if self.path == "/health":
                self._send_json(200, state.health_dict())
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw)
            except Exception:
                self._send_json(400, {"error": "invalid JSON"})
                return

            if self.path == "/transcribe":
                self._handle_transcribe(body)
            elif self.path == "/shutdown":
                self._send_json(200, {"ok": True})
                shutdown_event.set()
            else:
                self._send_json(404, {"error": "not found"})

        def _handle_transcribe(self, body: dict):
            if state.status != "ready":
                self._send_json(503, {
                    "error": f"model not ready: {state.status}",
                    "details": state.error,
                })
                return
            try:
                audio_bytes = base64.b64decode(body.get("audio_b64", ""))
                audio = np.frombuffer(audio_bytes, dtype=np.float32)
                model_path = body.get("model", "primary")
                asr = state.get_asr(model_path)
                result = asr.transcribe(audio)
                self._send_json(200, _result_to_dict(result))
            except Exception as e:
                logger.error("model_server transcription error: %s", e)
                self._send_json(500, {"error": str(e)})

        def _send_json(self, status: int, data: dict):
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _Handler


def run_server(port: int = DEFAULT_PORT) -> None:
    """Start the model server and block until a /shutdown request or SIGINT."""
    state = _ModelState()
    shutdown_event = threading.Event()

    # Begin model loading in background immediately
    loader = threading.Thread(
        target=_load_models, args=(state,), name="ModelLoader", daemon=True
    )
    loader.start()

    handler_cls = _make_handler(state, shutdown_event)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    logger.info("model_server: listening on http://127.0.0.1:%d", port)
    print(f"[model-server] Listening on http://127.0.0.1:{port}", flush=True)

    server_thread = threading.Thread(
        target=server.serve_forever, name="HTTPServer", daemon=True
    )
    server_thread.start()

    try:
        shutdown_event.wait()
    except KeyboardInterrupt:
        pass

    print("[model-server] Shutting down...", flush=True)
    server.shutdown()


def main() -> int:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="VoiceFlow Model Server")
    parser.add_argument(
        "--port",
        type=int,
        default=_port_from_env(),
        help=f"Port to listen on (default: {DEFAULT_PORT})",
    )
    args = parser.parse_args()
    run_server(args.port)
    return 0


if __name__ == "__main__":
    # Allow running as a script from repo root: python src/voiceflow/core/model_server.py
    _here = Path(__file__).resolve()
    _src = _here.parents[2]  # src/voiceflow/core/model_server.py -> src/
    if str(_src) not in sys.path:
        sys.path.insert(0, str(_src))
    raise SystemExit(main())
