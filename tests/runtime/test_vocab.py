from __future__ import annotations

from pathlib import Path

import pytest

from voiceflow.core import vocab


@pytest.fixture(autouse=True)
def _redirect_user_vocab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point _user_vocab_path() at a temp file and clear the prompt cache."""
    target = tmp_path / "custom_vocabulary.txt"
    monkeypatch.setattr(vocab, "_user_vocab_path", lambda: target)
    vocab.invalidate_cache()
    return target


def test_initial_prompt_includes_canonical_seed_terms(_redirect_user_vocab: Path) -> None:
    prompt = vocab.initial_prompt(max_chars=200)

    # First few canonical terms should always fit in a 200-char budget.
    assert "Claude" in prompt
    assert "MCP" in prompt
    assert "Anthropic" in prompt


def test_initial_prompt_respects_character_budget(_redirect_user_vocab: Path) -> None:
    prompt = vocab.initial_prompt(max_chars=40)

    # Truncation must happen on a term boundary — no half-terms.
    assert len(prompt) <= 40
    # Should not end mid-comma.
    assert not prompt.endswith(",")
    assert not prompt.endswith(", ")


def test_initial_prompt_appends_user_corrections(_redirect_user_vocab: Path) -> None:
    _redirect_user_vocab.write_text(
        "# user comment\n"
        "fooble -> Foobleizer\n"
        "bar baz -> BarBaz\n",
        encoding="utf-8",
    )

    prompt = vocab.initial_prompt(max_chars=400)

    assert "Foobleizer" in prompt
    assert "BarBaz" in prompt


def test_initial_prompt_dedupes_case_insensitively(_redirect_user_vocab: Path) -> None:
    # User vocab repeats a canonical seed term in lowercase. Should appear exactly
    # once as a comma-separated entry — not as both "Claude" and "claude".
    _redirect_user_vocab.write_text("anything -> claude\n", encoding="utf-8")

    prompt = vocab.initial_prompt(max_chars=400)
    terms = [t.strip() for t in prompt.split(",")]

    # "Claude" (the canonical) appears; "claude" lowercase duplicate must not.
    assert "Claude" in terms
    assert "claude" not in terms


def test_initial_prompt_invalidates_cache_on_file_change(_redirect_user_vocab: Path) -> None:
    first = vocab.initial_prompt(max_chars=400)
    assert "FreshTerm" not in first

    _redirect_user_vocab.write_text("anything -> FreshTerm\n", encoding="utf-8")

    second = vocab.initial_prompt(max_chars=400)
    assert "FreshTerm" in second


def test_seed_default_vocabulary_creates_user_file_when_missing(_redirect_user_vocab: Path) -> None:
    assert not _redirect_user_vocab.exists()

    written = vocab.seed_default_vocabulary()

    assert written == _redirect_user_vocab
    assert _redirect_user_vocab.exists()
    contents = _redirect_user_vocab.read_text(encoding="utf-8")
    # Spot-check: known seed entry should be present.
    assert "cloud -> Claude" in contents


def test_seed_default_vocabulary_respects_existing_file(_redirect_user_vocab: Path) -> None:
    _redirect_user_vocab.write_text("user_only -> UserOnly\n", encoding="utf-8")

    result = vocab.seed_default_vocabulary()

    assert result is None
    assert _redirect_user_vocab.read_text(encoding="utf-8") == "user_only -> UserOnly\n"


def test_seed_default_vocabulary_handles_missing_bundled_default(
    _redirect_user_vocab: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(vocab, "_bundled_default_path", lambda: tmp_path / "missing.txt")

    result = vocab.seed_default_vocabulary()

    assert result is None
    assert not _redirect_user_vocab.exists()
