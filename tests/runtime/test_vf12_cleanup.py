"""VF-12 item 4 (formatting for AI prompts) and the word-drop report for cleanup."""
from __future__ import annotations

import re
from collections import Counter

import pytest

from voiceflow.ai.course_corrector import CourseCorrector
from voiceflow.core.dictation_format import (
    apply_spoken_commands,
    clean_dictation,
    prepare_prompt_text,
)
from voiceflow.core.textproc import (
    apply_second_pass_cleanup,
    format_transcript_for_destination,
    format_transcript_preserving_breaks,
    format_transcript_text,
)

CHAT = {"process_name": "claude.exe", "window_title": "Claude"}
EDITOR = {"process_name": "notepad.exe", "window_title": "notes"}


# ------------------------------------------------------------------ frozen "before"

class _OldRules:
    """The rule-based corrector exactly as it was before VF-12 (kept as the baseline)."""

    CORRECTION = [re.compile(p, re.I) for p in [
        r"\b(no|nope),?\s*(wait|actually|I mean|sorry|scratch that|never mind)",
        r"\b(actually|wait),?\s*(no|let me)", r"\bI mean\b", r"\bsorry,?\s*(I meant|let me)",
        r"\bscratch that\b", r"\blet me (start over|rephrase|try again)\b", r"\bwhat I meant (was|is)\b"]]
    FILLER = [re.compile(p, re.I) for p in [
        r"\b(um+|uh+|er+|ah+)\b", r"\b(like,?\s+){2,}", r"\b(so,?\s+){2,}", r"\byou know,?\s*",
        r"\bI guess,?\s*", r"\bkind of\s+like\b", r"\bsort of\s+like\b"]]
    REPEAT = [re.compile(p, re.I) for p in [r"\b(\w+)\s+\1\b", r"\b(the|a|an|to|I|is|it)\s+\1\b"]]

    @classmethod
    def correct(cls, text: str) -> str:
        result = text
        for pattern in cls.CORRECTION:
            match = pattern.search(result)
            if match:
                after = result[match.end():].strip()
                if after and len(after) > 3:
                    result = after
                    break
        for pattern in cls.FILLER:
            result = pattern.sub(" ", result)
        for pattern in cls.REPEAT:
            result = pattern.sub(r"\1", result)
        result = re.sub(r"\s+", " ", result).strip()
        return result[0].upper() + result[1:] if result else result


# (input, expected). Most inputs are fluent speech that must NOT change.
CORPUS = [
    ("I mean, the, the thing is broken.", "The thing is broken."),
    ("I think we should refactor this module. I mean the loader is fragile.",
     "I think we should refactor this module. I mean the loader is fragile."),
    ("Do you know the answer to that?", "Do you know the answer to that?"),
    ("I guess so, but let's check.", "I guess so, but let's check."),
    ("He said that that was fine.", "He said that that was fine."),
    ("She had had enough of it.", "She had had enough of it."),
    ("It was very very good.", "It was very very good."),
    ("No no no, use the other branch.", "No no no, use the other branch."),
    ("Um, so, uh, we need to ship it.", "So we need to ship it."),
    ("Open config.yaml, uh, and check the the logs.", "Open config.yaml and check the logs."),
    ("We can scratch that itch later.", "We can scratch that itch later."),
    ("Write the intro. Scratch that. Write the summary.", "Write the summary."),
    ("Send it to John, no wait, send it to Jane.", "Send it to Jane."),
    ("I'll meet at five, no wait, six.", "I'll meet at five, no wait, six."),
    ("I mean it, we need this by Friday.", "I mean it, we need this by Friday."),
    ("You know, the deployment is fine.", "You know, the deployment is fine."),
    ("As you know, the deadline moved.", "As you know, the deadline moved."),
    ("Honestly, I think I think we should wait.", "Honestly, I think we should wait."),
    ("The ui_state.json file and the getUserName function.", "The ui_state.json file and the getUserName function."),
    ("Bye bye, see you tomorrow.", "Bye bye, see you tomorrow."),
    ("Which one, the blue one or the the red one?", "Which one, the blue one or the red one?"),
    ("Check src/voiceflow/core/vocab.py um before we merge.", "Check src/voiceflow/core/vocab.py before we merge."),
]


def _words(text: str):
    return Counter(re.findall(r"[a-z0-9_.'/-]+", text.lower()))


def _score(fn):
    dropped = leftover = exact = 0
    for given, expected in CORPUS:
        out = fn(given)
        dropped += sum((_words(expected) - _words(out)).values())      # real words lost
        leftover += sum((_words(out) - _words(expected)).values())     # filler/stutter left in
        exact += int(out == expected)
    return dropped, leftover, exact


def test_cleanup_word_drop_before_and_after(capsys):
    before = _score(_OldRules.correct)
    after = _score(lambda t: prepare_prompt_text(t, spoken_commands=False))
    total_words = sum(sum(_words(e).values()) for _, e in CORPUS)
    with capsys.disabled():
        print(f"\n[VF-12] cleanup on {len(CORPUS)} utterances / {total_words} expected words: "
              f"real words dropped before={before[0]} after={after[0]}; "
              f"filler left before={before[1]} after={after[1]}; "
              f"exact matches before={before[2]} after={after[2]}")
    assert after[0] == 0, "the new cleanup must never drop a real word on this corpus"
    assert after[1] == 0
    assert after[2] == len(CORPUS)
    assert before[0] > 0, "baseline sanity: the old rules did drop words"


def test_course_corrector_rule_path_is_now_conservative():
    cc = CourseCorrector(use_llm=False)
    result = cc.correct("I think we should refactor this module. I mean the loader is fragile.")
    assert "refactor this module" in result.text
    assert cc.correct("Um, so we ship it.").text == "So we ship it."


# ------------------------------------------------------------------ spoken commands

def test_new_line_and_new_paragraph_commands():
    assert prepare_prompt_text("Here is the list. New line. First item. New paragraph. Second part.") == (
        "Here is the list.\nFirst item.\n\nSecond part."
    )
    assert prepare_prompt_text("alpha, new line, beta") == "Alpha\nBeta"


def test_command_words_inside_a_sentence_stay_literal():
    for sentence in [
        "I need a new line of products for the store.",
        "Add a new paragraph to the report.",
        "The new line item is wrong.",
    ]:
        assert "\n" not in prepare_prompt_text(sentence), sentence


def test_bullet_commands():
    out = prepare_prompt_text("Plan: bullet, buy milk. Bullet, call mom.")
    assert out == "Plan:\n- Buy milk.\n- Call mom."
    assert prepare_prompt_text("Bullet point: ship it.").startswith("- Ship it")
    assert "\n" not in prepare_prompt_text("Bullet points are useful for slides.")
    assert "\n" not in prepare_prompt_text("He took a bullet in the war.")


def test_commands_can_be_turned_off():
    text = "First item. New line. Second item."
    assert "\n" not in prepare_prompt_text(text, spoken_commands=False)


# ------------------------------------------------------------------ code-ish tokens

@pytest.mark.parametrize("token", [
    "config.yaml", "vocab.py", "src/voiceflow/core/vocab.py", r"C:\AI_Projects\VoiceFlow", "getUserName",
    "ui_state.json", "VoiceFlow", "ChatGPT", "--no-verify", "README.md",
])
def test_code_ish_tokens_survive_formatting_and_cleanup(token):
    text = f"um open {token} and then check the the logs"
    out = format_transcript_for_destination(prepare_prompt_text(text), EDITOR, 3.0)
    assert token in out, out
    assert "um" not in out.lower().split()


@pytest.mark.parametrize("token", [
    "config.yaml", "src/voiceflow/core/vocab.py", "getUserName", "ui_state.json", "README.md",
])
def test_a_code_ish_token_can_open_the_sentence(token):
    # The first real word after a leading token used to be capitalised instead
    # ("config.yaml Is broken"); the token itself must stay exactly as spoken.
    out = format_transcript_text(f"{token} is broken")
    assert out == f"{token} is broken."
    out = format_transcript_for_destination(prepare_prompt_text(f"um {token} is broken"), EDITOR, 3.0)
    assert out == f"{token} is broken."
    assert format_transcript_text(f"we fixed it. {token} is next") == f"We fixed it. {token} is next."


def test_filler_stripping_does_not_teach_the_adaptive_learner_anything():
    # raw -> cleaned deltas now reach the learner on every dictation; deletions must not
    # become replacement rules (extract_learning_pairs ignores pure deletions).
    from voiceflow.ai.adaptive_memory import extract_learning_pairs

    for raw, cleaned in [
        ("um so the the thing is broken", "So the thing is broken"),
        ("I think I think we should go", "I think we should go"),
        ("Send it to John, no wait, send it to Jane.", "Send it to Jane."),
    ]:
        assert extract_learning_pairs(raw, cleaned, max_phrase_tokens=4) == []


def test_a_missing_space_after_a_period_is_still_fixed():
    assert format_transcript_text("hello.world").startswith("Hello. World")


# ------------------------------------------------------------------ punctuation

@pytest.mark.parametrize("spoken,expected", [
    ("when will that happen", "When will that happen?"),
    ("can you open the file", "Can you open the file?"),
    ("is that the right branch", "Is that the right branch?"),
    ("how does this work", "How does this work?"),
    ("we should ship it today", "We should ship it today."),
    ("will is coming tomorrow", "Will is coming tomorrow."),
])
def test_final_punctuation_question_vs_statement(spoken, expected):
    assert format_transcript_text(spoken) == expected


def test_existing_punctuation_is_respected():
    assert format_transcript_text("what time is it?") == "What time is it?"


# ------------------------------------------------------------------ explicit structure

def test_pause_paragraphs_survive_in_a_document_destination():
    text = "This is the first thought.\n\nHere is a second one."
    out = format_transcript_preserving_breaks(text, EDITOR, 9.0)
    assert out == "This is the first thought.\n\nHere is a second one."


def test_whole_text_formatter_would_have_merged_them():
    text = "This is the first thought.\n\nHere is a second one."
    assert "\n" not in format_transcript_for_destination(text, EDITOR, 9.0)


def test_chat_strips_breaks_unless_pasting():
    text = "First thought.\n\nSecond thought."
    stripped = format_transcript_preserving_breaks(text, CHAT, 9.0, keep_chat_newlines=False)
    kept = format_transcript_preserving_breaks(text, CHAT, 9.0, keep_chat_newlines=True)
    assert "\n" not in stripped
    assert kept == "First thought.\n\nSecond thought."


def test_bullet_without_comma_is_never_a_command():
    """Review VF-12-review-codex-20261107-190306 finding 1: literal 'bullet' is not rewritten."""
    for sentence in [
        "Bullet train tickets are expensive.",
        "Bullet wound care is covered in the first aid course.",
        "Bullet journal ideas for the week.",
        "Bullet points are useful for slides.",
        "Plan: bullet buy milk. Bullet call mom.",
        "I read about the bullet train in Japan. Bullet trains are fast.",
        "He took a bullet in the war.",
    ]:
        out = prepare_prompt_text(sentence)
        assert "\n" not in out and "- " not in out, (sentence, out)
        assert out.lower().count("bullet") == sentence.lower().count("bullet"), (sentence, out)


def test_bullets_keep_their_dash():
    out = format_transcript_preserving_breaks("Plan:\n- Buy milk.\n- Call mom.", EDITOR, 3.0)
    assert out == "Plan:\n- Buy milk.\n- Call mom."


def test_second_pass_cleanup_keeps_line_breaks():
    text = "First item.\n\nSecond item.\n- Third item."
    assert apply_second_pass_cleanup(text, heavy=False).count("\n") >= 3


def test_full_prompt_pipeline_on_a_spoken_prompt():
    spoken = ("um I want you to review config.yaml new paragraph bullet check the the schema "
              "bullet list the missing keys new paragraph thanks")
    # Without punctuation the commands are literal -- Whisper normally supplies it.
    assert "\n" not in prepare_prompt_text(spoken)
    punctuated = ("Um, I want you to review config.yaml. New paragraph. Bullet, check the the schema. "
                  "Bullet, list the missing keys. New paragraph. Thanks.")
    out = format_transcript_preserving_breaks(prepare_prompt_text(punctuated), EDITOR, 12.0)
    assert out == ("I want you to review config.yaml.\n\n- Check the schema.\n- List the missing keys.\n\nThanks.")


def test_clean_dictation_is_idempotent():
    for given, _ in CORPUS:
        once = clean_dictation(given)
        assert clean_dictation(once) == once
