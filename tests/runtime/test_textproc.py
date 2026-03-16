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
    assert "Claude Code" in safe
    assert "Claude Code" in aggressive


def test_normalize_context_terms_safe_defaults_fix_claude_product_names():
    text = "i switch between cloud code and cloud desktop while reviewing prompts"
    normalized = normalize_context_terms(text, aggressive=False, light=True)
    assert "Claude Code" in normalized
    assert "Claude Desktop" in normalized


def test_normalize_context_terms_safe_defaults_fix_claude_ai_assistant_phrase():
    text = "cloud, the ai assistant, did a better job on that diff"
    normalized = normalize_context_terms(text, aggressive=False, light=True)
    assert normalized.startswith("Claude, the ai assistant")


def test_normalize_context_terms_safe_defaults_keep_google_cloud():
    text = "we deploy to google cloud and aws for the current rollout"
    normalized = normalize_context_terms(text, aggressive=False, light=True)
    assert "google cloud" in normalized.lower()
    assert "Claude" not in normalized


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


def test_format_transcript_for_destination_chat_keeps_plain_prose_soft_wrapped():
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
    assert "\n" not in out
    assert "Also" in out or "also" in out


def test_format_transcript_for_destination_keeps_medium_dictation_as_one_paragraph_when_transition_is_weak():
    src = (
        "this is a medium length dictation sample that should feel easier to read, also it needs clearer "
        "paragraph breaks for scanning because otherwise everything lands in one dense block and is hard to review quickly."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "notepad.exe", "window_width": 780},
        audio_duration=5.4,
    )
    assert "\n\n" not in out


def test_format_transcript_for_destination_keeps_single_topic_long_dictation_as_one_block():
    src = (
        "I'd still say the formatting of the paragraphs isn't perfect. I'll kind of start talking right now. "
        "Specifically, this response that I'm giving you as something that has been transcribed through voice flow. "
        "And you should be able to see where line breaks, paragraph breaks, and things like that exist that feel "
        "unnecessary compared to kind of the whole text that I'm putting out. So this is in its entirety about a "
        "30 to 60 second transcription that I'm going through and I have pauses and things in the middle, evaluate "
        "where you end up putting line breaks here and take a stab at what ideally should have been kind of a start "
        "to finish nicely formatted output and evaluate what changes you might need to make into the post processing "
        "engine for the formatting to make sure that the final text. That is formatted looks good overall yeah so "
        "that's about it."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "Cursor.exe", "window_width": 920},
        audio_duration=42.0,
    )
    assert "\n" not in out


def test_format_transcript_for_destination_rebalances_very_long_dense_paragraph():
    src = (
        "this is sentence one about planning and it includes extra context about resourcing, milestones, and the "
        "tradeoffs we still need to confirm before rollout. this is sentence two with implementation details that "
        "cover the service boundaries, migration path, and the instrumentation we need for debugging. this is "
        "sentence three with risk notes that call out fallback behavior, support load, and edge cases around partial "
        "failures in production. this is sentence four with rollout steps that explain the phased release, operator "
        "checkpoints, and validation expectations for the first wave. this is sentence five with testing notes that "
        "cover regression scope, representative audio samples, and the success criteria we expect before signoff. "
        "this is sentence six with follow-up actions for documentation, cleanup, and ownership after the release "
        "stabilizes. this is sentence seven with ownership details across engineering, product, and support so the "
        "work does not drift after launch. this is sentence eight with next week timing and sequencing so the plan "
        "stays readable even though the dictation itself is long and still dense enough to merit a visual split. "
        "this is sentence nine with additional implementation detail, exception handling, and cleanup expectations "
        "so the final paragraph remains intentionally heavy. this is sentence ten with rollout nuance, owner "
        "handoffs, and follow-through items that keep the overall block long and structurally dense."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "notepad.exe", "window_width": 920},
        audio_duration=24.0,
    )
    assert out.count("\n\n") >= 1


def test_format_transcript_for_destination_keeps_making_that_in_same_paragraph():
    src = (
        "the workflow is mostly working now and we are saving corrections. making that easier to keep open "
        "during repeated dictation cycles would improve speed."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "notepad.exe", "window_width": 900},
        audio_duration=7.5,
    )
    assert "\n\nMaking that" not in out
    assert "Making that easier" in out


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


def test_format_transcript_for_destination_terminal_still_hard_wraps():
    src = (
        "this is a long transcript intended for terminal output where a bounded width can still help "
        "keep inline prose readable when the destination is a shell style surface."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "WindowsTerminal.exe", "window_width": 720},
        audio_duration=9.0,
    )
    assert "\n" not in out


def test_format_transcript_for_destination_terminal_keeps_explicit_paragraph_breaks():
    src = (
        "the first paragraph explains the baseline behavior and why the current output is closer to usable. "
        "in addition, the next paragraph should stay visually separate even for terminal destinations."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "WindowsTerminal.exe", "window_width": 1029},
        audio_duration=16.0,
    )
    assert "\n\nIn addition" in out


def test_format_transcript_for_destination_converts_spoken_points_to_bullets():
    src = (
        "i want to see how bullet points work as well. if i talk through three points where i kind of lay it out as "
        "1. item one here. 2. item two here. 2. 3. item three here. ideally i'd want those listed out as "
        "three bullets, then i'd start below that."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "Code.exe", "window_width": 900},
        audio_duration=20.0,
    )
    assert "• Item one here." in out
    assert "• Item two here." in out
    assert "• Item three here." in out
    assert "2. 3." not in out
    assert "\n\nIdeally" in out


def test_format_transcript_for_destination_repairs_fragmented_spoken_list_lines():
    src = (
        "i want you to see how bullet points work as well. so if i talk through three points where i kind of lay it "
        "out as 1. is talking about something. 2.\n\nis talking about. 2. 3. is talking about a third topic. "
        "ideally i'd want those listed out as three bullets."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "WindowsTerminal.exe", "window_width": 1000},
        audio_duration=28.0,
    )
    assert "• Is talking about something." in out
    assert out.count("• Is talking about.") >= 1
    assert "• Is talking about a third topic." in out
    assert "\n2.\n" not in out
    assert "2. 3." not in out


def test_format_transcript_for_destination_keeps_long_feedback_sample_to_few_paragraphs():
    src = (
        "okay, things seem to be working. quality is good. speed of transcription is good. i like the visualization "
        "overall as well now. so the thing to still fix probably is how we're separating line breaks. i feel like "
        "we're adding too many line breaks specifically when i type into a terminal. again, it doesn't matter for "
        "the quality of transcript. since i'm primarily talking to an ai agent, but it helps me sometimes to read "
        "things in a way that would be more digestible, in a way how you'd expect kind of a blob of text to be "
        "written out when people write to each other. so again, take a stab at what i have typed out here. it has "
        "entirely been done with the voice flow transcription. i feel like we're going overboard in adding line "
        "breaks, but i also so don't want to go down completely the other end, which was the issue we had before "
        "where we had no paragraph breaks, and it was just one giant lump of text. in addition, i want you to see "
        "how bullet points work as well."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "Code.exe", "window_width": 668},
        audio_duration=55.0,
    )
    assert out.count("\n\n") <= 1
    assert "\n\nIn addition" in out


def test_format_transcript_for_destination_terminal_splits_feedback_sections_on_spoken_ordinals():
    src = (
        "the terminal output is better and the punctuation looks good overall. okay, second, commit all changes to "
        "git and evaluate the read me for updates. third, look at the mac and linux directions as well. otherwise, "
        "keep going and make the changes happen."
    )
    out = format_transcript_for_destination(
        src,
        destination={"process_name": "WindowsTerminal.exe", "window_width": 1000},
        audio_duration=24.0,
    )
    assert "\n\nOkay, second," in out
    assert "\n\nThird," in out
    assert "\n\nOtherwise," in out


def test_format_transcript_text_splits_long_run_on_clause():
    src = (
        "we should capture the baseline audio quality and then compare it with the corrected pass "
        "because otherwise we cannot tell if the latter half was clipped after the cough pause"
    )
    out = format_transcript_text(src)
    assert ". And then" in out or ". Because" in out

