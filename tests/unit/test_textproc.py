from __future__ import annotations

import json

from voiceflow.core.textproc import (
    apply_code_mode,
    format_transcript_text,
    format_transcript_for_destination,
    infer_destination_profile,
    normalize_context_terms,
)


def test_basic_symbols():
    assert apply_code_mode("open bracket x close bracket") == "[x]"
    assert apply_code_mode("open paren x close paren") == "(x)"
    assert apply_code_mode("open brace x close brace") == "{x}"


def test_punctuation_and_ops():
    s = apply_code_mode("a equals b double equals c comma d")
    assert s == "a = b == c, d"


def test_controls():
    s = apply_code_mode("new line tab")
    assert s == "\n\t"


def test_format_transcript_text():
    """Test the new transcript formatting functionality"""
    # Test basic capitalization
    assert format_transcript_text("hello world") == "Hello world."

    # Test sentence capitalization after period
    assert format_transcript_text("hello. world") == "Hello. World."

    # Test missing space after period
    result = format_transcript_text("hello.world")
    assert result.startswith("Hello.") and "world" in result

    # Test bullet point formatting
    result = format_transcript_text("first, make sure you do it. second, continue listening.")
    assert result.startswith("• First,") and "• Second," in result

    # Test punctuation spacing
    result = format_transcript_text("hello , world")
    assert "Hello," in result and "world" in result


def test_technical_term_dictionary_defaults():
    text = "configure oath for cli login and api token exchange"
    normalized = normalize_context_terms(text)
    assert "OAuth" in normalized
    assert "CLI" in normalized
    assert "API" in normalized


def test_technical_term_dictionary_context_guard():
    text = "i bought oat milk today"
    normalized = normalize_context_terms(text)
    assert "oat milk" in normalized.lower()
    assert "OAuth" not in normalized


def test_custom_technical_term_dictionary(monkeypatch, tmp_path):
    custom_path = tmp_path / "engineering_terms.json"
    custom_path.write_text(
        json.dumps(
            {
                "exact": {
                    "fast api": "FastAPI",
                },
                "engineering_exact": {
                    "oat": "OAuth",
                },
                "engineering_regex": [
                    {
                        "pattern": r"\\bc\\s*l\\s*i\\b",
                        "replacement": "CLI",
                    }
                ],
            },
            ensure_ascii=True,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("VOICEFLOW_TERMS_PATH", str(custom_path))
    normalized = normalize_context_terms("set up oat token flow with c l i and fast api")
    assert "OAuth token flow" in normalized
    assert "CLI" in normalized
    assert "FastAPI" in normalized


def test_infer_destination_profile():
    assert infer_destination_profile({"process_name": "WindowsTerminal.exe"}) == "terminal"
    assert infer_destination_profile({"process_name": "Code.exe"}) == "editor"
    assert infer_destination_profile({"process_name": "Slack.exe"}) == "chat"
    assert infer_destination_profile({"process_name": "WINWORD.EXE"}) == "document"


def test_format_transcript_for_destination_chat_wrap():
    src = (
        "okay this is a long transcript and also we need this to be easier to read in a chat window "
        "because otherwise it turns into one giant wall of text and that is harder to scan quickly."
    )
    out = format_transcript_for_destination(
        src,
        destination={
            "process_name": "Slack.exe",
            "window_width": 520,
            "destination_chat_chars": 48,
        },
        audio_duration=9.0,
    )
    assert "\n" in out
    assert "Also" in out or "also" in out

