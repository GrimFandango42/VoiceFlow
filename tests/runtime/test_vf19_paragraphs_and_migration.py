"""VF-19: long dictations get paragraphs; existing installs get the new defaults once."""

from __future__ import annotations

from voiceflow.core.config import Config
from voiceflow.core.textproc import auto_paragraphs
from voiceflow.utils import settings

DICTATION = (
    "Okay, so I am trying out VoiceFlow. The live transcription is working, so that is good. "
    "It's not catching some words well. So overall seems to work well, the animations are also a lot "
    "smoother, I like it. Remember, you own this code, so feel free to go ahead and make relevant changes "
    "that you see fit that you might not have noticed before, now that you are a more capable model. "
    "I can see that you made the animations itself a lot smoother, and I do like that a lot. That is "
    "awesome, and you're also showing the timer count for how long I've been transcribing, great. "
    "So yeah, take a look at this conversation, make sure our history pieces are working well, our "
    "learning pieces are working well as well, and come back to me with what else you may have decided "
    "to change, and give me a summary of kind of where we are and where we could go from here once "
    "you made your changes. Thank you."
)


def test_long_dictation_breaks_where_the_subject_changes():
    shaped = auto_paragraphs(DICTATION)
    paragraphs = shaped.split("\n\n")
    assert len(paragraphs) == 3
    assert paragraphs[1].startswith("Remember, you own this code")
    assert paragraphs[2].startswith("So yeah, take a look")
    assert paragraphs[2].endswith("Thank you."), "a sign-off does not stand alone"


def test_words_are_never_changed():
    assert auto_paragraphs(DICTATION).split() == DICTATION.split()


def test_short_text_and_existing_breaks_are_left_alone():
    short = "Please rename the function. Then run the tests. Thanks."
    assert auto_paragraphs(short) == short
    broken = DICTATION.replace(" Remember,", "\n\nRemember,")
    assert auto_paragraphs(broken) == broken


def test_a_run_of_sentences_with_no_cue_still_gets_broken_up():
    text = " ".join(f"This is plain sentence number {n} with a few more words in it." for n in range(1, 13))
    paragraphs = auto_paragraphs(text).split("\n\n")
    assert len(paragraphs) >= 2
    assert all(len(p.split(". ")) <= 5 for p in paragraphs)


def test_abbreviations_and_decimals_do_not_split_sentences():
    text = ("We shipped version 3.2 of the app to e.g. the beta group last week and it went fine overall. " * 8).strip()
    for paragraph in auto_paragraphs(text).split("\n\n"):
        assert not paragraph.startswith("2 of") and not paragraph.startswith("the beta")


def test_migration_runs_once_and_respects_later_choices(monkeypatch):
    monkeypatch.setattr("voiceflow.core.asr_engine._cuda_runtime_ready", lambda: True, raising=False)
    cfg = Config()
    cfg.enable_gpu_acceleration, cfg.device = True, "cuda"
    cfg.enable_pause_compaction, cfg.reconstruction_max_chars, cfg.live_caption_max_chars = True, 2000, 380
    assert settings._apply_vf19_migration(cfg) is True
    assert cfg.enable_pause_compaction is False
    assert cfg.reconstruction_max_chars == 400 and cfg.live_caption_max_chars == 150
    cfg.enable_pause_compaction = True  # the user turns it back on
    assert settings._apply_vf19_migration(cfg) is False
    assert cfg.enable_pause_compaction is True


def test_migration_leaves_compaction_on_without_a_gpu():
    cfg = Config()
    cfg.enable_gpu_acceleration, cfg.device, cfg.enable_pause_compaction = False, "cpu", True
    settings._apply_vf19_migration(cfg)
    assert cfg.enable_pause_compaction is True
