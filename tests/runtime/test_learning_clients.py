"""VF-03: the nightly cloud step is opt-in, disclosed, and locked down.

These tests never launch the real Claude CLI or touch the network: the
subprocess and urllib entry points are monkeypatched and every assertion is
about what *would* have been sent.
"""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

from voiceflow.ai import learning_clients
from voiceflow.ai.learning_clients import (
    CLAUDE_CLI_SAFE_FLAGS,
    ClaudeCLIClient,
    GeminiRESTClient,
    claude_cli_command,
)
from voiceflow.core.config import Config

# --- default ---------------------------------------------------------------


def test_cloud_analysis_is_off_by_default():
    assert Config().adaptive_ai_analysis_enabled is False


def test_guardrails_backfill_missing_flag_as_off():
    from voiceflow.utils.guardrails import validate_config

    cfg = Config()
    delattr(cfg, "adaptive_ai_analysis_enabled")
    validate_config(cfg)
    assert cfg.adaptive_ai_analysis_enabled is False


# --- Claude CLI boundary -----------------------------------------------------

REQUIRED_FLAGS = (
    "--print",
    "--safe-mode",
    "--strict-mcp-config",
    "--no-session-persistence",
)


def test_claude_command_has_every_safety_flag_and_no_prompt_argument():
    cmd = claude_cli_command("claude.cmd", max_turns=1)
    for flag in REQUIRED_FLAGS:
        assert flag in cmd, flag
    # tools explicitly emptied, permission mode never asks (so it can never be
    # granted), and the prompt is NOT on the command line.
    assert cmd[cmd.index("--tools") + 1] == ""
    assert cmd[cmd.index("--permission-mode") + 1] == "dontAsk"
    assert "-p" not in cmd
    assert cmd[cmd.index("--max-turns") + 1] == "1"
    assert cmd[cmd.index("--output-format") + 1] == "json"


def test_no_permission_bypass_flag_is_ever_present():
    forbidden = {"--dangerously-skip-permissions", "--yes", "-y", "--allow-all"}
    assert forbidden.isdisjoint(set(CLAUDE_CLI_SAFE_FLAGS))
    assert forbidden.isdisjoint(set(claude_cli_command("claude", 3)))


def test_claude_client_sends_prompt_on_stdin_with_safe_flags(monkeypatch, tmp_path):
    fake_exe = tmp_path / "claude.cmd"
    fake_exe.write_text("rem fake", encoding="utf-8")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"result": "ok", "model": "test"}),
            stderr="",
        )

    monkeypatch.setattr(learning_clients.subprocess, "run", fake_run)
    client = ClaudeCLIClient(executable=str(fake_exe), timeout=5.0)
    resp = client.generate(system="SYS", user="the user's private transcript")

    assert resp.success is True and resp.text == "ok"
    cmd = captured["cmd"]
    assert cmd[0] == str(fake_exe)
    for flag in REQUIRED_FLAGS:
        assert flag in cmd
    # Transcript text must never appear in argv — only on stdin.
    assert all("private transcript" not in part for part in cmd)
    assert "private transcript" in captured["kwargs"]["input"]
    assert captured["kwargs"]["shell"] is False


def test_claude_client_reports_timeout_not_exception(monkeypatch, tmp_path):
    fake_exe = tmp_path / "claude.cmd"
    fake_exe.write_text("rem fake", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

    monkeypatch.setattr(learning_clients.subprocess, "run", fake_run)
    resp = ClaudeCLIClient(executable=str(fake_exe), timeout=1.0).generate(
        system="s", user="u"
    )
    assert resp.success is False
    assert resp.error and resp.error.startswith("timeout")


# --- Gemini key handling -----------------------------------------------------


def test_gemini_key_goes_in_header_never_in_url(monkeypatch):
    seen = {}

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(
                {"candidates": [{"content": {"parts": [{"text": "{}"}]}}]}
            ).encode("utf-8")

    def fake_urlopen(req, timeout=0):
        seen["url"] = req.full_url
        seen["headers"] = {k.lower(): v for k, v in req.header_items()}
        return _Resp()

    monkeypatch.setattr(learning_clients.urllib.request, "urlopen", fake_urlopen)
    client = GeminiRESTClient(api_key="SECRET-KEY-123", timeout=1.0)
    resp = client.generate(system="s", user="u")

    assert resp.success is True
    assert "SECRET-KEY-123" not in seen["url"]
    assert "key=" not in seen["url"]
    assert seen["headers"].get("x-goog-api-key") == "SECRET-KEY-123"


# --- Ollama client typo (VF-01 finding 3c) -----------------------------------


def test_ollama_refresh_availability_resets_the_real_attribute(monkeypatch):
    from voiceflow.ai.llm_client import OllamaClient

    client = OllamaClient()
    client._available = True
    client._availability_checked_at = 12345.0
    monkeypatch.setattr(client, "is_available", lambda: False)
    client.refresh_availability()
    assert client._available is None
    assert client._availability_checked_at == 0.0
    assert not hasattr(client, "_availability")
