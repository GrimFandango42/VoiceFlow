"""Terms the user pins must reach Whisper even when the budget is full.

The initial_prompt budget holds far fewer terms than a real vocabulary file
contains, so *which* terms get in matters more than how many. Ordering by
position in the file means a term appended today loses to one written months
ago — observed directly: "transcription", the word most often misheard in this
project, could not get into the prompt because it was added at the bottom.
"""

from __future__ import annotations

from voiceflow.core import vocab


class TestPriorityWins:
    def test_priority_terms_come_first(self, monkeypatch):
        monkeypatch.setattr(vocab, "_read_corrections", lambda p: (
            ["Pinned Term"] if "priority" in str(p) else ["Ordinary Term"]
        ))
        vocab.invalidate_cache()
        terms = [t.strip() for t in vocab.initial_prompt().split(",")]
        assert terms[0] == "Pinned Term"
        assert terms.index("Pinned Term") < terms.index("Ordinary Term")

    def test_a_pinned_term_survives_a_full_vocabulary(self, monkeypatch):
        crowd = [f"Filler Term Number {i}" for i in range(200)]
        monkeypatch.setattr(vocab, "_read_corrections", lambda p: (
            ["transcription"] if "priority" in str(p) else crowd
        ))
        vocab.invalidate_cache()
        prompt = vocab.initial_prompt()
        assert "transcription" in prompt
        assert len(prompt) <= vocab.INITIAL_PROMPT_MAX_CHARS

    def test_pinning_makes_position_irrelevant(self, monkeypatch):
        # A multi-word term at the end of a full file is crowded out; the same
        # term pinned always gets in. Position stops mattering, which is the
        # whole point.
        long_term = "Veeva LIMS validation workflow"
        crowd = [f"Filler Term Number {i}" for i in range(200)]

        monkeypatch.setattr(vocab, "_read_corrections", lambda p: (
            [] if "priority" in str(p) else [*crowd, long_term]
        ))
        vocab.invalidate_cache()
        assert long_term not in vocab.initial_prompt(), (
            "sanity: a long trailing term is crowded out when unpinned"
        )

        monkeypatch.setattr(vocab, "_read_corrections", lambda p: (
            [long_term] if "priority" in str(p) else crowd
        ))
        vocab.invalidate_cache()
        assert long_term in vocab.initial_prompt()


class TestNoPriorityFile:
    def test_absent_file_changes_nothing(self, monkeypatch):
        monkeypatch.setattr(vocab, "_read_corrections", lambda p: (
            [] if "priority" in str(p) else ["Ordinary Term"]
        ))
        vocab.invalidate_cache()
        assert "Ordinary Term" in vocab.initial_prompt()

    def test_path_sits_beside_the_main_vocabulary(self):
        assert vocab._priority_vocab_path().parent == vocab._user_vocab_path().parent
        assert vocab._priority_vocab_path().name == "priority_vocabulary.txt"


class TestCacheInvalidation:
    def test_cache_key_covers_the_priority_file(self, monkeypatch, tmp_path):
        # Editing only the priority file must not serve a stale prompt.
        pri = tmp_path / "priority_vocabulary.txt"
        main = tmp_path / "custom_vocabulary.txt"
        main.write_text("x -> Ordinary Term\n", encoding="utf-8")
        pri.write_text("y -> First Pin\n", encoding="utf-8")
        monkeypatch.setattr(vocab, "_user_vocab_path", lambda: main)
        vocab.invalidate_cache()
        assert "First Pin" in vocab.initial_prompt()

        pri.write_text("y -> Second Pin\n", encoding="utf-8")
        import os
        os.utime(pri, (pri.stat().st_atime, pri.stat().st_mtime + 10))
        assert "Second Pin" in vocab.initial_prompt()
