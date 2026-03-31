"""
VoiceFlow Model Server Client

Drop-in replacement for ModernWhisperASR that delegates transcription to the
model server process running on localhost. Used by the app logic process in
hot-reload dev mode so Whisper never has to reload on code changes.

The model server (model_server.py) must already be running when load() is
called. load() polls /health until the server reports "ready" (or "failed").

Environment variables:
  VOICEFLOW_MODEL_SERVER_PORT          — port the server listens on (default: 8765)
  VOICEFLOW_MODEL_SERVER_LOAD_TIMEOUT  — seconds to wait for ready (default: 120)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Optional

import numpy as np

# Re-use the result types from asr_engine so callers get the same objects.
from voiceflow.core.asr_engine import TranscriptionResult, TranscriptionSegment

logger = logging.getLogger(__name__)

DEFAULT_PORT = 8765
_PORT_ENV = "VOICEFLOW_MODEL_SERVER_PORT"


def _server_url(path: str = "") -> str:
    port = int(os.environ.get(_PORT_ENV, DEFAULT_PORT))
    return f"http://127.0.0.1:{port}{path}"


def _get_json(url: str, timeout: float = 2.0) -> Optional[dict]:
    try:
        resp = urllib.request.urlopen(url, timeout=timeout)
        return json.loads(resp.read())
    except Exception:
        return None


def _post_json(url: str, payload: dict, timeout: float = 120.0) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Model server HTTP {e.code}: {body}") from e


def _result_from_dict(data: dict) -> TranscriptionResult:
    segments = []
    for seg in data.get("segments", []):
        segments.append(TranscriptionSegment(
            text=seg.get("text", ""),
            start=seg.get("start", 0.0),
            end=seg.get("end", 0.0),
            speaker=seg.get("speaker"),
            confidence=seg.get("confidence", 1.0),
            words=seg.get("words"),
        ))
    return TranscriptionResult(
        text=data.get("text", ""),
        segments=segments,
        language=data.get("language", "en"),
        duration=data.get("duration", 0.0),
        processing_time=data.get("processing_time", 0.0),
        confidence=data.get("confidence", 1.0),
        words=data.get("words"),
        speaker_count=data.get("speaker_count", 0),
    )


class ModelServerASR:
    """
    Drop-in replacement for ModernWhisperASR backed by the model server.

    Accepts the same constructor signature (cfg, optional model_path) so
    cli_enhanced.py can swap backends via an env var without touching call
    sites.  The "primary" and "fast" model_path values map to the
    corresponding models loaded in the server process.
    """

    def __init__(self, cfg, model_path: str = "primary"):
        self.cfg = cfg
        # Allow the caller to embed a routing hint directly on the config
        # object (e.g. cfg._model_server_path = "fast") so that code paths
        # that construct ASR engines without extra keyword arguments still
        # reach the right server-side model.
        self.model_path = getattr(cfg, "_model_server_path", model_path)
        self.sample_rate: int = getattr(cfg, "sample_rate", 16000)
        self._loaded = False

    # ------------------------------------------------------------------
    # Interface matching ModernWhisperASR / ASREngine
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Block until the model server is ready (or timeout)."""
        timeout = float(os.environ.get("VOICEFLOW_MODEL_SERVER_LOAD_TIMEOUT", "120"))
        deadline = time.time() + timeout
        last_status: Optional[str] = None

        while time.time() < deadline:
            health = _get_json(_server_url("/health"))
            status = health.get("status", "unknown") if health else "unreachable"

            if status != last_status:
                print(f"[model-client] Server status: {status}", flush=True)
                last_status = status

            if status == "ready":
                self._loaded = True
                return

            if status == "failed":
                err = health.get("error", "unknown") if health else "connection refused"
                raise RuntimeError(f"Model server failed to load models: {err}")

            time.sleep(0.5)

        raise TimeoutError(
            f"Model server not ready after {timeout:.0f}s "
            f"(last status: {last_status})"
        )

    def is_loaded(self) -> bool:
        if self._loaded:
            return True
        health = _get_json(_server_url("/health"))
        if health and health.get("status") == "ready":
            self._loaded = True
            return True
        return False

    def transcribe(self, audio: np.ndarray) -> TranscriptionResult:
        if not self._loaded and not self.is_loaded():
            self.load()

        audio_b64 = base64.b64encode(
            audio.astype(np.float32).tobytes()
        ).decode("ascii")

        data = _post_json(
            _server_url("/transcribe"),
            {"audio_b64": audio_b64, "model": self.model_path},
        )
        return _result_from_dict(data)

    def cleanup(self) -> None:
        pass  # model lifecycle is managed by the server process
