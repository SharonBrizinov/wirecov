"""Typed exception hierarchy for wirecov."""


class WirecovError(Exception):
    """Base exception for all wirecov errors."""


class DockerNotFoundError(WirecovError):
    """Docker CLI is not installed or not accessible."""

    def __init__(self):
        super().__init__(
            "Docker is not installed or not in PATH. "
            "Install Docker: https://docs.docker.com/get-docker/"
        )


class DockerDaemonError(WirecovError):
    """Docker daemon is not running."""

    def __init__(self):
        super().__init__(
            "Docker daemon is not running. Start Docker and try again."
        )


class DockerBuildError(WirecovError):
    """Docker image build failed."""

    def __init__(self, version: str, detail: str = ""):
        msg = f"Failed to build wirecov image for Wireshark {version}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)
        self.version = version


class DockerRunError(WirecovError):
    """Docker container execution failed."""

    def __init__(self, detail: str = ""):
        msg = "Container execution failed"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class VersionNotFoundError(WirecovError):
    """Specified Wireshark version/tag does not exist."""

    def __init__(self, version: str):
        super().__init__(
            f"Wireshark version '{version}' not found. "
            "Run 'wirecov versions' to see available versions."
        )
        self.version = version


class NoPcapsFoundError(WirecovError):
    """No pcap files found at the specified path."""

    def __init__(self, path: str):
        super().__init__(
            f"No .pcap, .pcapng, or .cap files found at '{path}'"
        )
        self.path = path


class LcovParseError(WirecovError):
    """Failed to parse lcov tracefile."""

    def __init__(self, path: str, detail: str = ""):
        msg = f"Failed to parse lcov tracefile '{path}'"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)
        self.path = path


class GitLabApiError(WirecovError):
    """Failed to reach GitLab API."""

    def __init__(self, detail: str = ""):
        msg = "Cannot reach GitLab API"
        if detail:
            msg += f": {detail}"
        msg += ". Use --version to specify a version manually."
        super().__init__(msg)
