"""Configuration defaults and constants."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class WirecovConfig:
    # Wireshark source
    wireshark_repo: str = "https://gitlab.com/wireshark/wireshark.git"
    gitlab_api: str = "https://gitlab.com/api/v4/projects/wireshark%2Fwireshark"

    # Docker
    docker_image_prefix: str = "wirecov-tshark"
    tmpfs_size: str = "6G"

    # tshark flags for maximum dissection coverage (two passes)
    # Pass 1: full reassembly — exercises reassembly/defrag/checksum code paths
    tshark_flags_pass1: List[str] = field(default_factory=lambda: ["-V", "-x", "-2"])
    # Pass 2: no reassembly — forces per-packet dissection of upper-layer protocols
    tshark_flags_pass2: List[str] = field(default_factory=lambda: [
        "-V", "-x",
        "-o", "ip.defragment:FALSE",
        "-o", "tcp.desegment_tcp_streams:FALSE",
        "-o", "tcp.check_checksum:FALSE",
        "-o", "udp.check_checksum:FALSE",
        "-o", "tls.desegment_ssl_records:FALSE",
        "-o", "http.desegment_body:FALSE",
    ])

    # Coverage directories to include in reports
    coverage_dirs: List[str] = field(
        default_factory=lambda: ["epan/dissectors", "epan", "wiretap", "wsutil"]
    )

    # Pcap file extensions to scan
    pcap_extensions: List[str] = field(
        default_factory=lambda: [".pcap", ".pcapng", ".cap"]
    )

    # Cache
    cache_dir: Path = field(
        default_factory=lambda: Path.home() / ".cache" / "wirecov"
    )
    tag_cache_ttl_seconds: int = 3600  # 1 hour

    # Output
    default_output_dir: str = "wirecov-output"

    def image_tag(self, version: str) -> str:
        """Return full Docker image tag for a Wireshark version."""
        return f"{self.docker_image_prefix}:{version}"


# Global singleton
CONFIG = WirecovConfig()
