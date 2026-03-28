"""Tests for pcap set optimization."""

from wirecov.optimize import greedy_set_cover


class TestGreedySetCover:
    def test_basic(self):
        """Pcap A covers lines 1-3, pcap B covers 2-5. Need both for full."""
        per_pcap = {
            "a": {"file.c": {1, 2, 3}},
            "b": {"file.c": {2, 3, 4, 5}},
        }
        result = greedy_set_cover(per_pcap)
        names = [r[0] for r in result]

        # B covers more (4 lines), should be picked first
        assert names[0] == "b"
        assert len(result) == 2

    def test_redundant_pcap(self):
        """Pcap C is a subset of A+B, should not be needed."""
        per_pcap = {
            "a": {"file.c": {1, 2, 3, 4, 5}},
            "b": {"file.c": {6, 7, 8, 9, 10}},
            "c": {"file.c": {1, 2, 6, 7}},  # subset of a+b
        }
        result = greedy_set_cover(per_pcap)
        names = [r[0] for r in result]

        # Only need a and b
        assert len(result) == 2
        assert "c" not in names

    def test_target_rate(self):
        """With target_rate < 1.0, stop early."""
        per_pcap = {
            "a": {"file.c": {1, 2, 3, 4, 5}},
            "b": {"file.c": {6, 7, 8, 9, 10}},
        }
        result = greedy_set_cover(per_pcap, target_rate=0.5)
        # 50% of 10 lines = 5 lines. Pcap A covers 5, should be enough.
        assert len(result) == 1

    def test_empty(self):
        result = greedy_set_cover({})
        assert result == []

    def test_multi_file(self):
        """Coverage spans multiple source files."""
        per_pcap = {
            "a": {"tcp.c": {1, 2}, "http.c": {1}},
            "b": {"tcp.c": {3, 4}, "dns.c": {1, 2, 3}},
        }
        result = greedy_set_cover(per_pcap)
        # b covers 5 lines (2+3), a covers 3 (2+1)
        assert result[0][0] == "b"
        assert len(result) == 2

        # Cumulative should be 8 total
        assert result[-1][2] == 8
