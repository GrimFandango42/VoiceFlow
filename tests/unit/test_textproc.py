from __future__ import annotations

from voiceflow.core.textproc import apply_code_mode, format_transcript_text


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

