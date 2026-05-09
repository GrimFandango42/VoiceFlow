"""Regression tests: chat destinations must never receive newlines.

Chat apps (Claude, ChatGPT, Gemini, Slack, Discord, Teams, Signal, etc.) treat
a newline in pasted text as "send message". Long-form dictation that gets
paragraph breaks added would prematurely submit before the user can review.
"""
from __future__ import annotations

from voiceflow.core.textproc import (
    format_transcript_for_destination,
    infer_destination_profile,
)


def _chat_destination(process_name: str = "firefox.exe", title: str = "Claude") -> dict:
    return {
        "process_name": process_name,
        "window_title": title,
        "destination_aware_formatting": True,
        "destination_wrap_enabled": True,
    }


def _editor_destination() -> dict:
    return {
        "process_name": "code.exe",
        "window_title": "doc.txt",
        "destination_aware_formatting": True,
        "destination_wrap_enabled": True,
    }


def test_chat_profile_detected_for_claude_in_browser_title():
    assert infer_destination_profile(_chat_destination(title="Claude")) == "chat"


def test_chat_profile_detected_for_chatgpt_title():
    assert infer_destination_profile(_chat_destination(title="ChatGPT")) == "chat"


def test_chat_profile_detected_for_gemini_title():
    assert infer_destination_profile(_chat_destination(title="Gemini")) == "chat"


def test_chat_profile_detected_for_native_claude_desktop():
    dst = _chat_destination(process_name="claude.exe", title="Untitled")
    assert infer_destination_profile(dst) == "chat"


def test_chat_destination_strips_inserted_paragraph_breaks():
    # Long-form dictation with an explicit paragraph signal ("second", "third",
    # "in addition", "finally") that triggers _insert_light_paragraph_breaks.
    long_chat = (
        "Okay, second thing to think about: we should use Claude Code for this. "
        "Third thing, in addition we need to consider Gemini. "
        "Finally, lets review the full plan."
    )

    out = format_transcript_for_destination(long_chat, destination=_chat_destination(), audio_duration=15.0)

    assert "\n" not in out, f"chat output must not contain newlines, got: {out!r}"


def test_editor_destination_keeps_paragraph_breaks():
    long_chat = (
        "Okay, second thing to think about: we should use Claude Code for this. "
        "Third thing, in addition we need to consider Gemini. "
        "Finally, lets review the full plan."
    )

    out = format_transcript_for_destination(long_chat, destination=_editor_destination(), audio_duration=15.0)

    # Editors benefit from paragraph breaks.
    assert "\n\n" in out


def test_chat_destination_collapses_pre_existing_newlines():
    # Even if some upstream pass already inserted newlines, chat profile
    # must scrub them out as a defense-in-depth measure.
    text_with_newlines = "First sentence here.\n\nSecond paragraph below.\nThird line on its own."

    out = format_transcript_for_destination(text_with_newlines, destination=_chat_destination(), audio_duration=15.0)

    assert "\n" not in out
    assert "  " not in out  # also no double spaces from the substitution
