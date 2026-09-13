"""VF-03: the nightly cloud step is opt-in, disclosed, and locked down.

These tests never launch the real Claude CLI or touch the network: the
subprocess and urllib entry points are monkeypatched and every assertion is
about what *would* have been sent.
"""

from __future__ import annotations

import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from voiceflow.ai import learning_clients
from voiceflow.ai.learning_clients import (
    CLAUDE_CLI_SAFE_FLAGS,
    ClaudeCLIClient,
    GeminiRESTClient,
    claude_cli_command,
)
from voiceflow.core.config import Config


@pytest.fixture(autouse=True)
def _neutralize_managed_settings(monkeypatch, tmp_path):
    """Hermeticity: never probe the real machine's managed policy.

    Without this, every test that reaches ``ClaudeCLIClient.generate`` would read
    whatever managed-settings file / registry policy happens to be on the runner
    (including the reviewer's), so a green run would prove nothing. Redirect the
    candidate list to a path that does not exist via the test-only env override
    (the production tuple stays intact), and stub the Windows registry probe to
    report no policy. The managed-policy tests below re-point these to their own
    state.
    """
    absent = str(tmp_path / "no-managed-settings.json")
    monkeypatch.setenv(learning_clients._MANAGED_SETTINGS_ENV, absent)
    monkeypatch.setattr(
        learning_clients, "_windows_managed_policy_present", lambda: False
    )


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


# --- managed-policy hook isolation (VF-03 P1) --------------------------------
#
# ``--safe-mode`` suppresses the user's own hooks but NOT hooks installed by a
# managed (enterprise) policy. When such a policy declares hooks, generate() must
# fail closed *before* spawning the process, so transcript text is never exposed
# to a hook that could observe it.


def _client_with_managed_file(monkeypatch, tmp_path, contents: str):
    managed = tmp_path / "managed-settings.json"
    managed.write_text(contents, encoding="utf-8")
    monkeypatch.setenv(learning_clients._MANAGED_SETTINGS_ENV, str(managed))
    fake_exe = tmp_path / "claude.cmd"
    fake_exe.write_text("rem fake", encoding="utf-8")
    return ClaudeCLIClient(executable=str(fake_exe), timeout=5.0)


def test_generate_refuses_when_managed_hooks_present(monkeypatch, tmp_path):
    client = _client_with_managed_file(
        monkeypatch, tmp_path, json.dumps({"hooks": {"PreToolUse": [{"command": "x"}]}})
    )

    def never(cmd, **kwargs):
        raise AssertionError("subprocess.run must not run with managed hooks present")

    monkeypatch.setattr(learning_clients.subprocess, "run", never)
    resp = client.generate(system="s", user="the user's private transcript")
    assert resp.success is False
    assert resp.error == "managed_hooks_present"


def test_generate_spawns_safely_when_managed_file_has_no_hooks(monkeypatch, tmp_path):
    client = _client_with_managed_file(
        monkeypatch, tmp_path, json.dumps({"permissions": {"allow": []}})
    )
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(
            returncode=0, stdout=json.dumps({"result": "ok"}), stderr=""
        )

    monkeypatch.setattr(learning_clients.subprocess, "run", fake_run)
    resp = client.generate(system="s", user="u")
    assert resp.success is True
    for flag in REQUIRED_FLAGS:
        assert flag in captured["cmd"], flag


def test_generate_fails_closed_when_managed_file_is_unreadable(monkeypatch, tmp_path):
    # Deliberate deviation from the finding's literal "declares hooks": a managed
    # file that exists but cannot be parsed is treated as if it declared hooks.
    client = _client_with_managed_file(monkeypatch, tmp_path, "{ not valid json")

    def never(cmd, **kwargs):
        raise AssertionError("subprocess.run must not run on unreadable managed file")

    monkeypatch.setattr(learning_clients.subprocess, "run", never)
    resp = client.generate(system="s", user="u")
    assert resp.success is False
    assert resp.error == "managed_hooks_present"


def test_generate_refuses_when_windows_managed_policy_registry_present(
    monkeypatch, tmp_path
):
    # No managed-settings file, but the Windows managed-policy registry key exists:
    # hook isolation cannot be established, so refuse without spawning. We never
    # parse the registry — mere existence is disqualifying.
    monkeypatch.setattr(
        learning_clients, "_windows_managed_policy_present", lambda: True
    )
    fake_exe = tmp_path / "claude.cmd"
    fake_exe.write_text("rem fake", encoding="utf-8")

    def never(cmd, **kwargs):
        raise AssertionError("subprocess.run must not run with managed policy present")

    monkeypatch.setattr(learning_clients.subprocess, "run", never)
    resp = ClaudeCLIClient(executable=str(fake_exe), timeout=5.0).generate(
        system="s", user="the user's private transcript"
    )
    assert resp.success is False
    assert resp.error == "managed_policy_present"


def test_generate_refuses_when_dropin_fragment_declares_hooks(monkeypatch, tmp_path):
    # The main managed file is clean; a *.json fragment in the sibling
    # managed-settings.d directory declares hooks -> still refuse without spawning.
    main = tmp_path / "managed-settings.json"
    main.write_text(json.dumps({"permissions": {"allow": []}}), encoding="utf-8")
    dropin_dir = tmp_path / "managed-settings.d"
    dropin_dir.mkdir()
    (dropin_dir / "10-hooks.json").write_text(
        json.dumps({"hooks": {"PreToolUse": [{"command": "x"}]}}), encoding="utf-8"
    )
    monkeypatch.setenv(learning_clients._MANAGED_SETTINGS_ENV, str(main))
    fake_exe = tmp_path / "claude.cmd"
    fake_exe.write_text("rem fake", encoding="utf-8")

    def never(cmd, **kwargs):
        raise AssertionError("subprocess.run must not run when drop-in declares hooks")

    monkeypatch.setattr(learning_clients.subprocess, "run", never)
    resp = ClaudeCLIClient(executable=str(fake_exe), timeout=5.0).generate(
        system="s", user="u"
    )
    assert resp.success is False
    assert resp.error == "managed_hooks_present"


def test_production_candidate_list_includes_windows_program_files_path():
    # The production tuple must stay intact so detection works on a real install;
    # tests redirect via the env override, never by reassigning it. The Program
    # Files path is the one the installed CLI actually reads.
    expected = os.path.join(
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        "ClaudeCode",
        "managed-settings.json",
    )
    assert expected in learning_clients.MANAGED_SETTINGS_PATHS


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
