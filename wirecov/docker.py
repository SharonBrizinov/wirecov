"""Docker image build and container management via subprocess."""

import subprocess
import sys
from pathlib import Path
from typing import Generator, List, Optional

from rich.console import Console

from wirecov.config import CONFIG
from wirecov.exceptions import (
    DockerBuildError,
    DockerDaemonError,
    DockerNotFoundError,
    DockerRunError,
)


def _run_docker(args: List[str], capture: bool = True,
                timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Run a docker command, raising typed errors on common failures."""
    try:
        result = subprocess.run(
            ["docker"] + args,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result
    except FileNotFoundError:
        raise DockerNotFoundError()
    except subprocess.TimeoutExpired:
        raise DockerRunError("command timed out")


def check_docker():
    """Verify Docker CLI is available and daemon is running."""
    result = _run_docker(["info"], timeout=10)
    if result.returncode != 0:
        stderr = result.stderr.lower()
        if "not found" in stderr or "not recognized" in stderr:
            raise DockerNotFoundError()
        if "cannot connect" in stderr or "daemon" in stderr:
            raise DockerDaemonError()
        raise DockerRunError(result.stderr.strip())


def image_exists(version: str) -> bool:
    """Check if a wirecov Docker image exists for the given version."""
    tag = CONFIG.image_tag(version)
    result = _run_docker(["images", "-q", tag], timeout=10)
    return bool(result.stdout.strip())


def build_image(version: str, no_cache: bool = False, jobs: int = 0,
                verbose: bool = False, console: Console = None):
    """Build instrumented tshark Docker image for a Wireshark version.

    Streams build output in real-time. The image is tagged as
    wirecov-tshark:{version} for caching.
    """
    console = console or Console()
    tag = CONFIG.image_tag(version)
    project_root = Path(__file__).parent.parent

    cmd = [
        "docker", "build",
        "--tag", tag,
        "--build-arg", f"WIRESHARK_VERSION={version}",
        "--build-arg", f"BUILD_JOBS={jobs}",
    ]

    if no_cache:
        cmd.append("--no-cache")

    cmd.append(str(project_root))

    if verbose:
        console.print(f"[dim]$ {' '.join(cmd)}[/dim]")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        with console.status(
            f"[bold]Building instrumented tshark {version}...[/bold]\n"
            f"  Source: {CONFIG.wireshark_repo}\n"
            f"  This may take 10-20 minutes on first build.",
            spinner="dots",
        ):
            output_lines = []
            for line in process.stdout:
                line = line.rstrip()
                output_lines.append(line)
                if verbose:
                    console.print(f"  [dim]{line}[/dim]")

            process.wait()

        if process.returncode != 0:
            # Try to extract useful error info
            tail = "\n".join(output_lines[-20:])
            if "tag not found" in tail.lower() or "not found" in tail.lower():
                raise DockerBuildError(
                    version,
                    f"Version '{version}' not found in Wireshark repository",
                )
            raise DockerBuildError(version, f"exit code {process.returncode}")

        console.print(f"[green]Image built successfully:[/green] {tag}")

    except FileNotFoundError:
        raise DockerNotFoundError()


def run_container(version: str, pcap_path: Path, output_path: Path,
                  per_pcap: bool = False, protocols: bool = False,
                  verbose: bool = False,
                  console: Console = None) -> Generator[str, None, None]:
    """Run the wirecov container and yield output lines.

    Mounts pcap path (file or directory) and output directory into the
    container. Yields lines prefixed with WIRECOV_* for progress tracking.
    """
    console = console or Console()
    tag = CONFIG.image_tag(version)

    # Resolve pcap mounting
    pcap_path = pcap_path.resolve()
    output_path = output_path.resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    if pcap_path.is_file():
        # Mount parent directory, tell container to process single file
        mount_dir = pcap_path.parent
        env_single = pcap_path.name
    else:
        mount_dir = pcap_path
        env_single = ""

    # Mount entrypoint.sh from host so changes don't require image rebuild
    project_root = Path(__file__).parent.parent
    entrypoint_host = project_root / "docker" / "entrypoint.sh"

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{mount_dir}:/pcaps:ro",
        "-v", f"{output_path}:/output",
        "-e", f"PER_PCAP={'1' if per_pcap else '0'}",
        "-e", f"PROTOCOLS={'1' if protocols else '0'}",
        "-e", f"SINGLE_PCAP={env_single}",
        "-e", f"TSHARK_FLAGS_PASS1={' '.join(CONFIG.tshark_flags_pass1)}",
        "-e", f"TSHARK_FLAGS_PASS2={' '.join(CONFIG.tshark_flags_pass2)}",
        # tmpfs for scratch space (not build tree — that's in the image)
        "--tmpfs", "/tmp:exec,size=2G",
    ]

    # Mount local entrypoint over the baked-in one for live development.
    # Use --entrypoint bash to avoid permission issues with the mounted file.
    if entrypoint_host.exists():
        cmd.extend([
            "-v", f"{entrypoint_host.resolve()}:/entrypoint.sh:ro",
            "--entrypoint", "bash",
        ])
        cmd.extend([tag, "/entrypoint.sh", "run"])
    else:
        cmd.extend([tag, "run"])

    if verbose:
        console.print(f"[dim]$ {' '.join(cmd)}[/dim]")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        for line in process.stdout:
            line = line.rstrip()
            yield line

        process.wait()

        if process.returncode != 0:
            raise DockerRunError(f"container exited with code {process.returncode}")

    except FileNotFoundError:
        raise DockerNotFoundError()
    except KeyboardInterrupt:
        # Try to stop the container gracefully
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        raise


def list_images(console: Console = None) -> List[dict]:
    """List all wirecov Docker images with their tags and sizes."""
    result = _run_docker(
        ["images", CONFIG.docker_image_prefix,
         "--format", "{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}\t{{.ID}}"],
        timeout=10,
    )

    images = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] != "<none>":
            images.append({
                "tag": parts[0],
                "size": parts[1],
                "created": parts[2],
                "id": parts[3],
            })
    return images


def remove_image(version: str, console: Console = None):
    """Remove a specific wirecov Docker image by version tag."""
    console = console or Console()
    tag = CONFIG.image_tag(version)

    if not image_exists(version):
        console.print(f"[yellow]Image {tag} not found.[/yellow]")
        return False

    console.print(f"  Removing {tag}...")
    result = _run_docker(["rmi", "-f", tag], timeout=60)
    if result.returncode != 0:
        console.print(f"  [red]Failed to remove {tag}:[/red] {result.stderr.strip()}")
        return False

    console.print(f"  [green]Removed {tag}[/green]")
    return True


def remove_all_images(console: Console = None):
    """Remove all wirecov Docker images."""
    console = console or Console()
    images = list_images()

    if not images:
        console.print("No wirecov images found.")
        return

    removed = 0
    for img in images:
        tag = CONFIG.image_tag(img["tag"])
        console.print(f"  Removing {tag} ({img['size']})...")
        result = _run_docker(["rmi", "-f", tag], timeout=60)
        if result.returncode == 0:
            removed += 1
        else:
            console.print(f"  [yellow]Warning:[/yellow] Failed to remove {tag}")

    console.print(f"\n[green]Removed {removed}/{len(images)} image(s).[/green]")


def cleanup_images(keep_latest: int = 3, console: Console = None):
    """Remove old wirecov Docker images, keeping the N most recent."""
    console = console or Console()
    images = list_images()

    if len(images) <= keep_latest:
        console.print(f"Only {len(images)} image(s) found, nothing to clean up.")
        return

    to_remove = images[keep_latest:]

    for img in to_remove:
        tag = CONFIG.image_tag(img["tag"])
        console.print(f"  Removing {tag} ({img['size']})...")
        result = _run_docker(["rmi", tag], timeout=30)
        if result.returncode != 0:
            console.print(f"  [yellow]Warning:[/yellow] Failed to remove {tag}")

    console.print(
        f"[green]Cleaned up {len(to_remove)} image(s), "
        f"kept {keep_latest} most recent.[/green]"
    )
