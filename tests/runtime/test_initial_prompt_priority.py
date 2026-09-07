"""User vocabulary must actually reach Whisper.

The 200-character initial_prompt budget holds roughly 25 terms, and the
built-in INITIAL_PROMPT_TERMS list alone is longer than that. While the
built-ins were ordered first, every user-curated term fell outside the budget
and was silently dropped -- observed on a real installation with 74 curated
rules, none of which appeared in the prompt.
"""

from __future__ import annotations

from voiceflow.core import vocab


def _prompt_terms(text: str) -> list[str]:
    return [t.strip() for t in text.split(",") if t.strip()]


class TestUserTermsWin:
    def test_user_terms_appear_before_builtins(self, monkeypatch):
        monkeypatch.setattr(vocab, "_read_corrections", lambda _p: ["Veeva LIMS", "Caddyfile"])
        vocab.invalidate_cache()

        terms = _prompt_terms(vocab.initial_prompt())
        assert terms[0] == "Veeva LIMS"
        assert terms[1] == "Caddyfile"

    def test_user_terms_survive_a_full_builtin_list(self, monkeypatch):
        monkeypatch.setattr(vocab, "_read_corrections", lambda _p: ["Zzyzx Widget"])
        vocab.invalidate_cache()

        # The real INITIAL_PROMPT_TERMS list overflows the budget on its own.
        assert "Zzyzx Widget" in vocab.initial_prompt()

    def test_the_regression_this_prevents(self, monkeypatch):
        # With built-ins first, this term never made it in.
        monkeypatch.setattr(vocab, "_read_corrections", lambda _p: ["Veeva LIMS"])
        vocab.invalidate_cache()
        assert "Veeva LIMS" in vocab.initial_prompt()


class TestBudget:
    def test_respects_max_chars(self, monkeypatch):
        monkeypatch.setattr(vocab, "_read_corrections", lambda _p: [])
        vocab.invalidate_cache()
        for budget in (50, 120, 200, 700):
            assert len(vocab.initial_prompt(max_chars=budget)) <= budget

    def test_budget_stays_inside_whispers_prompt_limit(self):
        # Whisper takes ~224 prompt tokens; ~4 chars/token is the usual rule.
        assert vocab.INITIAL_PROMPT_MAX_CHARS <= 880

    def test_one_oversized_term_does_not_discard_the_rest(self, monkeypatch):
        oversized = "X" * (vocab.INITIAL_PROMPT_MAX_CHARS + 100)
        monkeypatch.setattr(
            vocab, "_read_corrections", lambda _p: [oversized, "Caddyfile"]
        )
        vocab.invalidate_cache()
        prompt = vocab.initial_prompt()
        assert "Caddyfile" in prompt, "a long term must be skipped, not terminate the loop"
        assert oversized not in prompt

    def test_deduplicates_case_insensitively(self, monkeypatch):
        monkeypatch.setattr(vocab, "_read_corrections", lambda _p: ["claude", "Claude"])
        vocab.invalidate_cache()
        terms = [t.lower() for t in _prompt_terms(vocab.initial_prompt())]
        assert terms.count("claude") == 1

    def test_builtin_spelling_wins_over_user_casing(self, monkeypatch):
        # Priority is the user's; spelling is canonical.
        monkeypatch.setattr(vocab, "_read_corrections", lambda _p: ["claude"])
        vocab.invalidate_cache()
        assert "Claude" in _prompt_terms(vocab.initial_prompt())
