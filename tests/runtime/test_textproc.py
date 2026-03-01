from __future__ import annotations

import json

from voiceflow.core.textproc import (
    apply_code_mode,
    apply_second_pass_cleanup,
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
    assert result.startswith("Hello.") and "world" in result.lower()

    # Test bullet point formatting
    result = format_transcript_text("first, make sure you do it. second, continue listening.")
    assert result.startswith("• First,") and "• Second," in result

    # Test punctuation spacing
    result = format_transcript_text("hello , world")
    assert "Hello," in result and "world" in result


def test_format_transcript_text_capitalizes_after_line_break():
    result = format_transcript_text('"hello world.\nthis should be capitalized next line')
    assert result.startswith('"Hello world.')
    assert "\nThis should be" in result


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


def test_normalize_context_terms_light_typo_cleanup_can_be_enabled_without_aggressive_rules():
    text = "teh and and dont forget to recieve updates"
    normalized = normalize_context_terms(text, aggressive=False, light=True)
    assert "the and don't forget to receive updates" in normalized.lower()


def test_normalize_context_terms_aggressive_rules_are_opt_in():
    text = "cloud code works well for coding assistant prompts"
    safe = normalize_context_terms(text, aggressive=False, light=True)
    aggressive = normalize_context_terms(text, aggressive=True, light=True)
    assert "cloud code" in safe.lower()
    assert "Claude Code" in aggressive


def test_second_pass_cleanup_safe_pass_is_low_risk():
    src = "hello  ,   world!!!    this is is is fine"
    out = apply_second_pass_cleanup(src, heavy=False)
    assert "hello, world!!!" in out
    assert "is is is is" not in out


def test_second_pass_cleanup_heavy_pass_collapses_repeated_pairs():
    src = "deploy now deploy now deploy now deploy now"
    out = apply_second_pass_cleanup(src, heavy=True)
    assert out.lower().count("deploy now") <= 2


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


def test_format_transcript_for_destination_inserts_paragraph_breaks_for_medium_dictation():
    src = (
        "this is a medium length dictation sample that should feel easier to read, also it needs clearer "
        "paragraph breaks for scanning because otherwise everything lands in one dense block and is hard to review quickly."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "notepad.exe", "window_width": 780},
        audio_duration=5.4,
    )
    assert "\n\nAlso" in out


def test_format_transcript_for_destination_rebalances_long_dense_paragraph():
    src = (
        "this is sentence one about planning. this is sentence two with implementation details. "
        "this is sentence three with risk notes. this is sentence four with rollout steps."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "notepad.exe", "window_width": 920},
        audio_duration=8.0,
    )
    assert out.count("\n\n") >= 1


def test_format_transcript_for_destination_breaks_before_making_that():
    src = (
        "the workflow is mostly working now and we are saving corrections. making that easier to keep open "
        "during repeated dictation cycles would improve speed."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "notepad.exe", "window_width": 900},
        audio_duration=7.5,
    )
    assert "\n\nMaking that" in out


def test_format_transcript_for_destination_splits_unpunctuated_topic_transition():
    src = (
        "this is the end of topic one and now let's start topic two and talk through "
        "option two with a clearer structure for the next section"
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "notepad.exe", "window_width": 900},
        audio_duration=8.0,
    )
    assert "end of topic one.\n\nAnd now" in out


def test_format_transcript_text_splits_long_run_on_clause():
    src = (
        "we should capture the baseline audio quality and then compare it with the corrected pass "
        "because otherwise we cannot tell if the latter half was clipped after the cough pause"
    )
    out = format_transcript_text(src)
    assert ". And then" in out or ". Because" in out

