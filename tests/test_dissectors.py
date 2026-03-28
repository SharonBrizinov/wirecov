"""Tests for dissector extraction and classification."""

from wirecov.coverage import parse_lcov
from wirecov.dissectors import compute_summary, extract_dissectors


class TestExtractDissectors:
    def test_extract_from_sample(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        dissectors = extract_dissectors(report)

        # Should find tcp, http, dns (not ftype-bytes)
        assert len(dissectors) == 3
        names = [d.name for d in dissectors]
        assert "packet-tcp" in names
        assert "packet-http" in names
        assert "packet-dns" in names

    def test_name_mapping(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        dissectors = extract_dissectors(report)
        by_name = {d.name: d for d in dissectors}

        assert by_name["packet-tcp"].source_file == "packet-tcp.c"
        assert by_name["packet-http"].source_file == "packet-http.c"

    def test_sort_order(self, sample_lcov_file):
        """Dissectors should be sorted by line_rate descending."""
        report = parse_lcov(sample_lcov_file)
        dissectors = extract_dissectors(report)

        rates = [d.line_rate for d in dissectors]
        assert rates == sorted(rates, reverse=True)

    def test_classification(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        dissectors = extract_dissectors(report)
        by_name = {d.name: d for d in dissectors}

        # packet-tcp: 5/7 = 71.4% -> medium
        assert by_name["packet-tcp"].classification == "medium"
        # packet-http: 3/5 = 60% -> medium
        assert by_name["packet-http"].classification == "medium"
        # packet-dns: 0/3 = 0% -> none
        assert by_name["packet-dns"].classification == "none"


class TestComputeSummary:
    def test_summary(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        dissectors = extract_dissectors(report)
        summary = compute_summary(dissectors)

        assert summary["total_dissectors"] == 3
        assert summary["covered_dissectors"] == 2  # tcp, http
        assert summary["uncovered_dissectors"] == 1  # dns
        assert summary["total_lines"] == 15  # 7 + 5 + 3
        assert summary["total_lines_hit"] == 8  # 5 + 3 + 0
