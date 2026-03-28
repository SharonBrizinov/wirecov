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

    # tshark flags for maximum dissection coverage
    tshark_flags: List[str] = field(default_factory=lambda: ["-V", "-x", "-2"])

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
