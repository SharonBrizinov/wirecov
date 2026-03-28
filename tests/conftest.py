"""Shared test fixtures."""

import pytest

# Sample lcov tracefile content for testing
SAMPLE_LCOV = """\
TN:test
SF:/src/wireshark/epan/dissectors/packet-tcp.c
FN:100,dissect_tcp
FN:200,proto_register_tcp
FNDA:42,dissect_tcp
FNDA:1,proto_register_tcp
DA:100,42
DA:101,42
DA:102,0
DA:103,42
DA:200,1
DA:201,1
DA:202,0
LF:7
LH:5
end_of_record
SF:/src/wireshark/epan/dissectors/packet-http.c
FN:50,dissect_http
FNDA:10,dissect_http
DA:50,10
DA:51,10
DA:52,0
DA:53,0
DA:54,10
LF:5
LH:3
end_of_record
SF:/src/wireshark/epan/dissectors/packet-dns.c
FN:10,dissect_dns
FNDA:0,dissect_dns
DA:10,0
DA:11,0
DA:12,0
LF:3
LH:0
end_of_record
SF:/src/wireshark/epan/ftypes/ftype-bytes.c
FN:1,bytes_fvalue_new
FNDA:5,bytes_fvalue_new
DA:1,5
DA:2,5
LF:2
LH:2
end_of_record
"""

SAMPLE_LCOV_B = """\
TN:test2
SF:/src/wireshark/epan/dissectors/packet-tcp.c
FN:100,dissect_tcp
FNDA:100,dissect_tcp
DA:100,100
DA:101,100
DA:102,50
DA:103,100
DA:200,1
DA:201,1
DA:202,1
LF:7
LH:7
end_of_record
SF:/src/wireshark/epan/dissectors/packet-http.c
FN:50,dissect_http
FNDA:5,dissect_http
DA:50,5
DA:51,0
DA:52,0
DA:53,0
DA:54,5
LF:5
LH:2
end_of_record
SF:/src/wireshark/epan/dissectors/packet-udp.c
FN:30,dissect_udp
FNDA:20,dissect_udp
DA:30,20
DA:31,20
DA:32,10
LF:3
LH:3
end_of_record
"""


@pytest.fixture
def sample_lcov_file(tmp_path):
    """Write sample lcov data to a temp file."""
    path = tmp_path / "test.info"
    path.write_text(SAMPLE_LCOV)
    return path


@pytest.fixture
def sample_lcov_file_b(tmp_path):
    """Write second sample lcov data for diff testing."""
    path = tmp_path / "test_b.info"
    path.write_text(SAMPLE_LCOV_B)
    return path


@pytest.fixture
def sample_per_pcap_dir(tmp_path):
    """Create per-pcap directory structure for attribution testing."""
    per_pcap = tmp_path / "per-pcap"
    per_pcap.mkdir()

    # pcap1 covers tcp
    (per_pcap / "capture1.info").write_text("""\
TN:
SF:/src/wireshark/epan/dissectors/packet-tcp.c
DA:100,10
DA:101,10
DA:102,0
LF:3
LH:2
end_of_record
""")

    # pcap2 covers tcp + http
    (per_pcap / "capture2.info").write_text("""\
TN:
SF:/src/wireshark/epan/dissectors/packet-tcp.c
DA:100,5
DA:101,0
DA:102,5
LF:3
LH:2
end_of_record
SF:/src/wireshark/epan/dissectors/packet-http.c
DA:50,3
DA:51,3
LF:2
LH:2
end_of_record
""")

    return tmp_path
