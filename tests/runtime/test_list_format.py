"""Spoken lists become lists; prose, placeholders and stray ordinals do not."""

from voiceflow.core.list_format import format_lists


def words(text):
    return [w.strip(".,:;").lower() for w in text.replace("\n", " ").split() if w.strip(".,:;-")]


def test_point_markers_become_a_numbered_list():
    out = format_lists(
        "Okay so for tomorrow I need to do three things. Point one, call the roofer about the siding quote. "
        "Point two, book the vet for Arthur. Point three, send Trey the deck. That's it for now."
    )
    assert out == (
        "Okay so for tomorrow I need to do three things:\n"
        "1. Call the roofer about the siding quote.\n"
        "2. Book the vet for Arthur.\n"
        "3. Send Trey the deck.\n\n"
        "That's it for now."
    )


def test_placeholders_without_items_are_left_exactly_as_spoken():
    text = ("These are the three things that I expect to happen, followed by point one, point two, "
            "and then point three. In your post-processing I want bullets.")
    assert format_lists(text) == text


def test_number_markers_with_items():
    out = format_lists("My priorities are as follows. Number one, reliability. Number two, accuracy. Number three, speed.")
    assert out == "My priorities are as follows:\n1. Reliability.\n2. Accuracy.\n3. Speed."


def test_number_one_in_prose_is_not_a_list():
    text = "Reliability is my number one priority, and accuracy is number two on the list."
    assert format_lists(text) == text


def test_bullet_markers_become_dashes():
    out = format_lists("Here's what I want: bullet the caption should be bigger, bullet the history should show failures, "
                       "bullet the paste should be faster.")
    assert out == ("Here's what I want:\n- The caption should be bigger\n- The history should show failures\n"
                   "- The paste should be faster.")


def test_ordinal_sentences_in_order_become_a_list():
    out = format_lists("There are three things I need from you. First, fix the history panel. "
                       "Second, make the caption bigger. Third, ship it tonight.")
    assert out == ("There are three things I need from you:\n1. Fix the history panel.\n"
                   "2. Make the caption bigger.\n3. Ship it tonight.")


def test_finally_closes_an_ordinal_list():
    out = format_lists("First, fix the bug. Second, add a test. Finally, ship it. Then we rest.")
    assert out == "1. Fix the bug.\n2. Add a test.\n3. Ship it.\n\nThen we rest."


def test_out_of_order_or_lone_ordinals_stay_prose():
    for text in (
        "Second thought, I'd rather we just ship it as is. First, though, let me check the logs.",
        "First, I want to say thanks. That was quick.",
        "I came second. Third place went to Sam.",
    ):
        assert format_lists(text) == text


def test_only_marker_and_connector_words_are_removed():
    src = ("I need three things. Point one, call the roofer. Point two, and then book the vet. "
           "Point three, send the deck.")
    out = format_lists(src)
    assert words(out) == ["i", "need", "three", "things", "1", "call", "the", "roofer", "2", "book", "the", "vet",
                          "3", "send", "the", "deck"]


def test_existing_structure_is_left_alone():
    text = "Things to do:\n- one\n- two"
    assert format_lists(text) == text


def test_lists_are_found_inside_one_paragraph_of_several():
    out = format_lists("Some intro paragraph here.\n\nWe need two things. Point one, speed. Point two, accuracy.")
    assert out.startswith("Some intro paragraph here.\n\nWe need two things:\n1. Speed.\n2. Accuracy.")


def test_plain_series_in_a_sentence_is_not_a_list():
    text = "I need you to pick up milk, eggs, and bread on the way home."
    assert format_lists(text) == text


def test_whole_pipeline_on_the_dictation_that_lost_words():
    """2026-11-10 23:32: "followed by point one, point two, and then point three" pasted as "• And then. •"."""
    from voiceflow.core.dictation_format import prepare_prompt_text
    from voiceflow.core.textproc import auto_paragraphs, format_transcript_preserving_breaks

    dest = {"process_name": "claude.exe", "window_title": "Claude", "window_width": 1294}
    raw = ("For example, if I say, these are the three things that I expect to happen, followed by point one, "
           "point two, and then point three. It's how whisperflow works today.")
    out = auto_paragraphs(format_transcript_preserving_breaks(
        format_lists(prepare_prompt_text(raw)), destination=dest, audio_duration=20.0, keep_chat_newlines=True))
    assert "•" not in out
    assert "point one, point two, and then point three" in out
    assert "Wispr Flow" in out


def test_whole_pipeline_keeps_a_spoken_list_as_lines_in_a_chat_box():
    from voiceflow.core.textproc import format_transcript_preserving_breaks

    dest = {"process_name": "claude.exe", "window_title": "Claude", "window_width": 1294}
    listed = format_lists("I need three things. Point one, call the roofer. Point two, book the vet. "
                          "Point three, send the deck.")
    out = format_transcript_preserving_breaks(listed, destination=dest, audio_duration=10.0, keep_chat_newlines=True)
    out = format_transcript_preserving_breaks(out, destination=dest, audio_duration=10.0, keep_chat_newlines=True)
    assert out == "I need three things:\n1. Call the roofer.\n2. Book the vet.\n3. Send the deck."
