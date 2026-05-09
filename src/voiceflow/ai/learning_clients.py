"""Pluggable LLM clients for the daily learning batch.

Supports two backends, in fallback order:

1. ``ClaudeCLIClient`` — invokes the user's locally-installed Claude Code CLI
   (``claude -p ... --output-format json``). Free under Claude Max; no API
   key required. Same model the user trusts day-to-day.
2. ``GeminiRESTClient`` — calls Google's Gemini API using ``GEMINI_API_KEY``
   from the environment. Only used when the Claude CLI is unavailable or
   times out.

Both clients return a uniform ``LearningClientResponse``.

The Ollama-backed ``OllamaClient`` in ``llm_client.py`` remains in use by
``course_corrector`` and ``command_mode``, but is no longer the daily-batch
default — it was failing silently every night because Ollama wasn't running
on this machine.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class LearningClientResponse:
    """Uniform response from any learning-batch LLM backend."""

    text: str
    success: bool
    backend: str
    model: str = ""
    duration_ms: float = 0.0
    error: Optional[str] = None


class ClaudeCLIClient:
    """Invoke Claude Code's CLI in non-interactive mode under Claude Max.

    Uses ``claude -p <prompt> --output-format json --max-turns 1``. The CLI
    returns a JSON envelope with a ``result`` field that contains the model's
    output. This client extracts that field and returns it as ``response.text``.
    """

    def __init__(self, executable: Optional[str] = None, timeout: float = 120.0,
                 max_turns: int = 1) -> None:
        self.executable = executable or shutil.which("claude")
        self.timeout = float(timeout)
        self.max_turns = max(1, int(max_turns))
        self.backend = "claude_cli"

    def is_available(self) -> bool:
        return bool(self.executable) and os.path.exists(self.executable)

    def generate(self, *, system: str, user: str) -> LearningClientResponse:
        if not self.is_available():
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                error="claude CLI not found on PATH",
            )

        prompt = system.strip() + "\n\n" + user.strip()
        # The Claude CLI ships as a Node.js script. Windows .ps1/.cmd shims must
        # be resolved through the shell, but the .cmd shim is more reliable for
        # subprocess.run. Try the .cmd first if present.
        executable = self.executable
        cmd_variant = executable
        if os.name == "nt" and executable.endswith(".ps1"):
            candidate = executable[:-4] + ".cmd"
            if os.path.exists(candidate):
                cmd_variant = candidate

        cmd = [
            cmd_variant,
            "-p", prompt,
            "--output-format", "json",
            "--max-turns", str(self.max_turns),
        ]
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                # On Windows, .cmd shims need shell=False but a string command form
                # — but using a list with the .cmd path resolved usually works.
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=(time.perf_counter() - start) * 1000.0,
                error=f"timeout after {self.timeout:.0f}s",
            )
        except Exception as exc:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=(time.perf_counter() - start) * 1000.0,
                error=f"subprocess_failed:{exc}",
            )

        duration_ms = (time.perf_counter() - start) * 1000.0
        if proc.returncode != 0:
            stderr_tail = (proc.stderr or "").strip().splitlines()[-3:]
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=duration_ms,
                error=f"exit_code={proc.returncode}; {' / '.join(stderr_tail)}",
            )

        # Parse the CLI envelope. The text result is in `result`; the conversation
        # JSON also includes session_id, total_cost_usd, etc. — we only need result.
        envelope_text = (proc.stdout or "").strip()
        if not envelope_text:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=duration_ms,
                error="empty stdout",
            )
        try:
            envelope = json.loads(envelope_text)
        except json.JSONDecodeError as exc:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=duration_ms,
                error=f"envelope_parse_failed:{exc}",
            )

        result_text = ""
        model_label = ""
        if isinstance(envelope, dict):
            result_text = str(envelope.get("result", "") or "").strip()
            model_label = str(envelope.get("model", "") or "claude-code").strip()
        elif isinstance(envelope, list) and envelope:
            # Stream-style output; pull the last assistant turn's content.
            last = envelope[-1] if isinstance(envelope[-1], dict) else {}
            result_text = str(last.get("result", last.get("content", "")) or "").strip()
            model_label = "claude-code"

        if not result_text:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=duration_ms,
                error="empty result field in CLI envelope",
            )

        return LearningClientResponse(
            text=result_text,
            success=True,
            backend=self.backend,
            model=model_label or "claude-code",
            duration_ms=duration_ms,
        )


class GeminiRESTClient:
    """Minimal REST client for Google Gemini API. Used only as a fallback."""

    DEFAULT_MODEL = "gemini-2.5-flash"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None,
                 timeout: float = 60.0) -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "").strip()
        self.model = model or self.DEFAULT_MODEL
        self.timeout = float(timeout)
        self.backend = "gemini_rest"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate(self, *, system: str, user: str) -> LearningClientResponse:
        if not self.is_available():
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                error="GEMINI_API_KEY not set",
            )

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        payload = {
            "system_instruction": {"parts": [{"text": system.strip()}]},
            "contents": [{"role": "user", "parts": [{"text": user.strip()}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"},
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=(time.perf_counter() - start) * 1000.0,
                error=f"http_{exc.code}",
            )
        except Exception as exc:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=(time.perf_counter() - start) * 1000.0,
                error=f"request_failed:{exc}",
            )
        duration_ms = (time.perf_counter() - start) * 1000.0
        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError as exc:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=duration_ms,
                error=f"envelope_parse_failed:{exc}",
            )

        candidates = envelope.get("candidates") if isinstance(envelope, dict) else None
        if not candidates:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=duration_ms,
                error="no candidates in response",
            )

        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict)).strip()
        if not text:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                duration_ms=duration_ms,
                error="empty content text",
            )

        return LearningClientResponse(
            text=text, success=True, backend=self.backend,
            model=self.model, duration_ms=duration_ms,
        )


def select_client(prefer: Optional[str] = None) -> Optional[object]:
    """Pick the first available learning client.

    The selection order is: explicit ``prefer`` value, then Claude CLI, then
    Gemini REST. Returns ``None`` if nothing is available.
    """
    candidates: list = []
    if prefer == "gemini":
        candidates = [GeminiRESTClient(), ClaudeCLIClient()]
    else:
        candidates = [ClaudeCLIClient(), GeminiRESTClient()]
    for client in candidates:
        try:
            if client.is_available():
                return client
        except Exception as exc:
            logger.debug("Client availability probe failed: %s", exc)
    return None
