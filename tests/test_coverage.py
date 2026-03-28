"""Tests for the lcov parser and coverage module."""

from wirecov.coverage import (
    CoverageReport,
    diff_reports,
    filter_report,
    merge_reports,
    parse_lcov,
)


class TestParseLcov:
    def test_parse_basic(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        assert len(report.files) == 4

    def test_parse_line_counts(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        tcp = report.files["/src/wireshark/epan/dissectors/packet-tcp.c"]
        assert tcp.lines_found == 7
        assert tcp.lines_hit == 5

    def test_parse_function_counts(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        tcp = report.files["/src/wireshark/epan/dissectors/packet-tcp.c"]
        assert tcp.functions_found == 2
        assert tcp.functions_hit == 2
        assert tcp.function_data["dissect_tcp"] == 42

    def test_parse_zero_coverage(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        dns = report.files["/src/wireshark/epan/dissectors/packet-dns.c"]
        assert dns.lines_hit == 0
        assert dns.line_rate == 0.0

    def test_parse_totals(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        # tcp: 5/7, http: 3/5, dns: 0/3, ftype-bytes: 2/2
        assert report.total_lines_found == 17
        assert report.total_lines_hit == 10

    def test_parse_empty_file(self, tmp_path):
        path = tmp_path / "empty.info"
        path.write_text("")
        report = parse_lcov(path)
        assert len(report.files) == 0

    def test_parse_malformed_lines(self, tmp_path):
        """Malformed lines should be skipped without error."""
        content = """\
TN:
SF:/src/test.c
DA:not_a_number,5
DA:1,5
DA:2,abc
end_of_record
"""
        path = tmp_path / "bad.info"
        path.write_text(content)
        report = parse_lcov(path)
        assert len(report.files) == 1
        assert report.files["/src/test.c"].lines_found == 1


class TestMergeReports:
    def test_merge_two(self, sample_lcov_file, sample_lcov_file_b):
        a = parse_lcov(sample_lcov_file)
        b = parse_lcov(sample_lcov_file_b)
        merged = merge_reports(a, b)

        # tcp in both, http in both, dns only in a, udp only in b, ftype only in a
        assert len(merged.files) == 5

        # tcp line 102: 0 in A, 50 in B -> 50 in merged
        tcp = merged.files["/src/wireshark/epan/dissectors/packet-tcp.c"]
        assert tcp.line_data[102] == 50

    def test_merge_empty(self):
        merged = merge_reports()
        assert len(merged.files) == 0


class TestFilterReport:
    def test_filter_dissectors(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        filtered = filter_report(report, ["epan/dissectors"])
        assert len(filtered.files) == 3  # tcp, http, dns (not ftype-bytes)

    def test_filter_no_match(self, sample_lcov_file):
        report = parse_lcov(sample_lcov_file)
        filtered = filter_report(report, ["nonexistent"])
        assert len(filtered.files) == 0


class TestDiffReports:
    def test_diff_basic(self, sample_lcov_file, sample_lcov_file_b):
        a = parse_lcov(sample_lcov_file)
        b = parse_lcov(sample_lcov_file_b)
        diff = diff_reports(a, b)

        assert diff.total_lines_gained > 0  # tcp got more coverage in B
        # http lost line 51 coverage (10->0)
        assert diff.total_lines_lost > 0
