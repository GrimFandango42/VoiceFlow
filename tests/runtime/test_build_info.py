"""The running build must be identifiable, and identifying it must never crash.

This exists because "am I testing the fix or yesterday's binary?" was
unanswerable from the UI, and the answer arrived four messages late.
"""

from __future__ import annotations

from voiceflow.utils import build_info as bi


class TestShortLabel:
    def test_never_empty(self):
        assert bi.short_label().strip()

    def test_starts_with_a_version(self):
        assert bi.short_label().startswith("v")

    def test_is_short_enough_for_a_status_bar(self):
        # It shares a narrow dock with the status text and two buttons.
        assert len(bi.short_label()) <= 48

    def test_survives_a_broken_source(self, monkeypatch):
        def boom():
            raise RuntimeError("no")

        monkeypatch.setattr(bi, "build_info", boom)
        assert bi.short_label().startswith("v")


class TestFormatting:
    def test_full_label(self):
        info = bi.BuildInfo(
            version="3.2.1", commit="abc1234", built_at="09-08 07:15", source="stamp"
        )
        assert info.short_label() == "v3.2.1 · abc1234 · 09-08 07:15"

    def test_dirty_tree_is_marked(self):
        info = bi.BuildInfo(
            version="3.2.1",
            commit="abc1234",
            built_at="09-08 07:15",
            source="git",
            dirty=True,
        )
        assert "abc1234*" in info.short_label()

    def test_unknown_fields_are_omitted_not_printed(self):
        info = bi.BuildInfo(
            version="3.2.1", commit="unknown", built_at="unknown", source="mtime"
        )
        assert info.short_label() == "v3.2.1"
        assert "unknown" not in info.short_label()

    def test_detail_names_the_source(self):
        info = bi.BuildInfo(
            version="3.2.1", commit="abc1234", built_at="x", source="stamp"
        )
        assert "source=stamp" in info.detail()


class TestSourcePriority:
    def test_stamp_wins_over_git(self, monkeypatch):
        stamped = bi.BuildInfo(
            version="9.9.9", commit="stamped", built_at="x", source="stamp"
        )
        monkeypatch.setattr(bi, "_from_stamp", lambda: stamped)
        monkeypatch.setattr(
            bi, "_from_git", lambda: bi.BuildInfo("0", "gitref", "y", "git")
        )
        assert bi.build_info().commit == "stamped"

    def test_falls_through_to_executable_mtime(self, monkeypatch):
        monkeypatch.setattr(bi, "_from_stamp", lambda: None)
        monkeypatch.setattr(bi, "_from_git", lambda: None)
        assert bi.build_info().source == "mtime"

    def test_a_raising_source_does_not_break_the_chain(self, monkeypatch):
        def boom():
            raise OSError("git exploded")

        monkeypatch.setattr(bi, "_from_stamp", boom)
        monkeypatch.setattr(bi, "_from_git", lambda: None)
        assert bi.build_info().source == "mtime"
