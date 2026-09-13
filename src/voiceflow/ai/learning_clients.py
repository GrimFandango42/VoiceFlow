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


#: Flags that keep the learning batch a text-only call. Without them a ``claude -p``
#: subprocess inherits the user's full MCP configuration, hooks and shell tools —
#: and the prompt it carries is transcript text. Same boundary Atlas uses
#: (``Atlas/src/utils/claude_execution.py``); never remove these as a
#: compatibility fallback. An older CLI that lacks ``--safe-mode`` fails
#: closed rather than running with tools.
CLAUDE_CLI_SAFE_FLAGS: tuple = (
    "--safe-mode",
    "--tools", "",
    "--strict-mcp-config",
    "--permission-mode", "dontAsk",
    "--no-session-persistence",
)


#: Test-only env override for the managed-settings candidate list. When set, its
#: ``os.pathsep``-separated value replaces the production paths below, so a test
#: run never depends on the host machine's real managed policy. Never set this in
#: production; production code always reads :data:`MANAGED_SETTINGS_PATHS`.
_MANAGED_SETTINGS_ENV = "VOICEFLOW_TEST_MANAGED_SETTINGS_PATHS"

#: Windows registry subkey (probed under both HKLM and HKCU) whose mere existence
#: means a managed Claude Code policy is in force. We do not parse policy out of the
#: registry; its presence alone means hook isolation cannot be established from a
#: plain ``--safe-mode`` call, so we refuse rather than guess.
_WINDOWS_POLICY_REGISTRY_KEY = r"SOFTWARE\Policies\ClaudeCode"


def _default_managed_settings_paths() -> tuple:
    r"""Canonical managed-settings.json locations per platform.

    Windows exposes two: the installer's ``%ProgramFiles%\ClaudeCode`` path (the
    one the installed CLI actually reads) and the older ``%ProgramData%\ClaudeCode``
    path (kept as a harmless extra candidate). macOS and Linux each have one.
    """
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    return (
        os.path.join(program_files, "ClaudeCode", "managed-settings.json"),
        os.path.join(program_data, "ClaudeCode", "managed-settings.json"),
        "/Library/Application Support/ClaudeCode/managed-settings.json",
        "/etc/claude-code/managed-settings.json",
    )


#: Canonical managed-settings locations. ``--safe-mode`` disables the *user's* own
#: hooks but NOT hooks installed by managed (enterprise) policy, per the official
#: CLI reference. Transcript text must never pass through a process that a managed
#: hook could observe. Kept intact so it can be asserted against directly; tests
#: redirect via the env override above, never by reassigning this tuple.
MANAGED_SETTINGS_PATHS: tuple = _default_managed_settings_paths()


def _expand_with_dropins(paths: tuple) -> tuple:
    """Return ``paths`` plus every drop-in ``*.json`` fragment beside them.

    Each candidate's sibling ``managed-settings.d`` directory is scanned, because
    managed policy can be split across drop-in fragments and each must be inspected
    too. A missing drop-in directory is the normal case and is ignored.
    """
    expanded: list = []
    for path in paths:
        expanded.append(path)
        dropin_dir = os.path.join(os.path.dirname(path), "managed-settings.d")
        try:
            names = sorted(os.listdir(dropin_dir))
        except (FileNotFoundError, NotADirectoryError):
            # No drop-in directory beside this candidate: the normal case.
            names = []
        # Any other OSError (e.g. PermissionError) propagates: we cannot enumerate
        # the fragments, so we cannot prove none declare hooks. The caller turns
        # this into a fail-closed refusal rather than silently skipping the dir.
        for name in names:
            if name.lower().endswith(".json"):
                expanded.append(os.path.join(dropin_dir, name))
    return tuple(expanded)


def _managed_settings_candidates(paths: Optional[tuple] = None) -> tuple:
    """Managed-settings files to inspect, drop-in fragments included.

    Honors the test-only env override when ``paths`` is not passed explicitly.
    """
    if paths is None:
        override = os.environ.get(_MANAGED_SETTINGS_ENV)
        if override is not None:
            base = tuple(p for p in override.split(os.pathsep) if p)
        else:
            base = MANAGED_SETTINGS_PATHS
    else:
        base = paths
    return _expand_with_dropins(base)


def _windows_managed_policy_present() -> bool:
    """True if the Windows managed-policy registry key exists in HKLM or HKCU.

    Anthropic documents managed policy delivered under both hives, so both are
    probed. Existence alone is disqualifying: we do not parse policy out of the
    registry, so we cannot prove it installs no hooks. ``FileNotFoundError`` on a
    hive means no policy there (safe); any other ``OSError`` is treated as present
    (fail closed), consistent with how an unreadable managed-settings file is
    handled. Gated on Windows so ``winreg`` is never imported on macOS/Linux.
    """
    if os.name != "nt":
        return False
    try:
        import winreg
    except ImportError:
        return False
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, _WINDOWS_POLICY_REGISTRY_KEY):
                return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def managed_policy_block(paths: Optional[tuple] = None) -> Optional[str]:
    """Return an error code if a managed policy blocks a locked-down CLI call.

    ``--safe-mode`` suppresses the *user's* own hooks but NOT hooks installed by a
    managed (enterprise) policy, so transcript text must never pass through the CLI
    while such a policy is in force. Returns ``None`` when it is safe to spawn, or
    one of three refusal reasons:

    * ``"managed_policy_present"`` — the Windows managed-policy registry key exists
      (HKLM or HKCU).
    * ``"managed_hooks_present"`` — a managed-settings file (or drop-in fragment)
      declares ``hooks``, or a managed candidate exists but holds malformed JSON
      (fail closed: we cannot prove it declares none).
    * ``"managed_policy_unreadable"`` — a candidate file or a ``managed-settings.d``
      directory exists but cannot be read/listed (e.g. ``PermissionError``). Only
      ``FileNotFoundError``/``NotADirectoryError`` count as genuinely absent; every
      other ``OSError`` fails closed, because an unreadable candidate could carry
      hooks we can never inspect.
    """
    if _windows_managed_policy_present():
        return "managed_policy_present"
    try:
        candidates = _managed_settings_candidates(paths)
    except OSError:
        # A managed-settings.d directory exists but could not be listed.
        return "managed_policy_unreadable"
    for path in candidates:
        # No os.path.exists() gate: it swallows OSError and returns False, which
        # would fail *open* on an unreadable-but-present file. Go straight to open()
        # and classify by exception instead.
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (FileNotFoundError, NotADirectoryError):
            # Genuinely absent: the only safe reason to skip a candidate.
            continue
        except OSError:
            # Present but unreadable (e.g. PermissionError): fail closed.
            return "managed_policy_unreadable"
        except Exception:
            # Malformed JSON: fail closed.
            return "managed_hooks_present"
        if isinstance(data, dict) and data.get("hooks"):
            return "managed_hooks_present"
    return None


def claude_cli_command(executable: str, max_turns: int = 1) -> list:
    """Build the locked-down ``claude`` command. The prompt goes on stdin."""
    return [
        executable,
        "--print",
        *CLAUDE_CLI_SAFE_FLAGS,
        "--output-format", "json",
        "--max-turns", str(max(1, int(max_turns))),
    ]


class ClaudeCLIClient:
    """Invoke Claude Code's CLI in non-interactive mode under Claude Max.

    Uses ``claude --print`` with :data:`CLAUDE_CLI_SAFE_FLAGS` (no tools, no
    MCP servers, no hooks, no session persistence) and ``--output-format json``.
    The prompt is written to stdin rather than passed as an argument, so long
    transcript batches cannot hit the Windows command-line length limit or
    show up in process listings. The CLI returns a JSON envelope with a
    ``result`` field; this client extracts that field as ``response.text``.
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

        # Refuse before spawning if a managed policy could inject hooks that
        # --safe-mode does not suppress. Fail closed; do not run transcript text.
        policy_block = managed_policy_block()
        if policy_block is not None:
            return LearningClientResponse(
                text="", success=False, backend=self.backend,
                error=policy_block,
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

        cmd = claude_cli_command(cmd_variant, self.max_turns)
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                input=prompt,
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

        # The key travels in a header, never the query string — query strings
        # land in proxy logs, crash reports and exception text.
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
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
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": self.api_key,
            },
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
