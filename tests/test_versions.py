"""Tests for version management."""

from wirecov.versions import STABLE_TAG_RE, RC_TAG_RE, filter_tags


class TestTagFiltering:
    SAMPLE_TAGS = [
        {"name": "v4.6.5", "date": "2026-03-15", "commit": "abc123"},
        {"name": "v4.6.5rc0", "date": "2026-03-10", "commit": "def456"},
        {"name": "v4.6.4", "date": "2026-02-25", "commit": "ghi789"},
        {"name": "v4.4.14", "date": "2026-02-25", "commit": "jkl012"},
        {"name": "v4.4.14rc0", "date": "2026-02-20", "commit": "mno345"},
    ]

    def test_stable_regex(self):
        assert STABLE_TAG_RE.match("v4.6.5")
        assert STABLE_TAG_RE.match("v4.4.14")
        assert not STABLE_TAG_RE.match("v4.6.5rc0")
        assert not STABLE_TAG_RE.match("master")
        assert not STABLE_TAG_RE.match("v4.6")

    def test_rc_regex(self):
        assert RC_TAG_RE.match("v4.6.5rc0")
        assert not RC_TAG_RE.match("v4.6.5")

    def test_filter_stable_only(self):
        result = filter_tags(self.SAMPLE_TAGS, show_all=False)
        names = [t["name"] for t in result]
        assert "v4.6.5" in names
        assert "v4.6.4" in names
        assert "v4.4.14" in names
        assert "v4.6.5rc0" not in names

    def test_filter_show_all(self):
        result = filter_tags(self.SAMPLE_TAGS, show_all=True)
        assert len(result) == len(self.SAMPLE_TAGS)
