"""CLI definition using Click."""

import sys
from pathlib import Path

import click
from rich.console import Console

from wirecov import __version__
from wirecov.exceptions import WirecovError

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="wirecov")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.option("--json", "json_output", is_flag=True, help="Machine-readable JSON output.")
@click.pass_context
def main(ctx, verbose, json_output):
    """wirecov - Wireshark/tshark code coverage analysis tool.

    Build instrumented tshark inside Docker, run pcap files through it,
    and generate coverage reports.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["json_output"] = json_output
    ctx.obj["console"] = console


@main.command()
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option("-V", "--version", "ws_version", default=None,
              help="Wireshark version: tag (v4.4.14), branch (master), or commit hash.")
@click.option("-o", "--output", "output_dir", default="wirecov-output",
              type=click.Path(), help="Output directory for reports.")
@click.option("--no-cache", is_flag=True, help="Force rebuild Docker image.")
@click.option("--format", "report_format",
              type=click.Choice(["table", "json", "csv", "html", "all"]),
              default="all", help="Report output format.")
@click.option("-j", "--jobs", type=int, default=0,
              help="Parallel build jobs in container (0 = auto).")
@click.option("--per-pcap", is_flag=True,
              help="Track per-pcap coverage attribution (slower).")
@click.option("--protocols", is_flag=True,
              help="Collect protocol tree information.")
@click.pass_context
def run(ctx, pcap_path, ws_version, output_dir, no_cache, report_format,
        jobs, per_pcap, protocols):
    """Run coverage analysis on pcap file(s).

    PCAP_PATH can be a single .pcap/.pcapng file or a directory containing them.
    """
    from wirecov.runner import run_coverage

    try:
        run_coverage(
            pcap_path=Path(pcap_path),
            ws_version=ws_version,
            output_dir=Path(output_dir),
            no_cache=no_cache,
            report_format=report_format,
            jobs=jobs,
            per_pcap=per_pcap,
            protocols=protocols,
            verbose=ctx.obj["verbose"],
            json_output=ctx.obj["json_output"],
            console=ctx.obj["console"],
        )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


@main.command()
@click.option("--all", "show_all", is_flag=True,
              help="Show all versions including release candidates.")
@click.option("--refresh", is_flag=True,
              help="Force refresh from GitLab API (bypass cache).")
@click.pass_context
def versions(ctx, show_all, refresh):
    """List available Wireshark versions.

    Shows remote releases from GitLab and locally cached Docker images.
    """
    from wirecov.versions import list_versions

    try:
        list_versions(
            show_all=show_all,
            refresh=refresh,
            json_output=ctx.obj["json_output"],
            console=ctx.obj["console"],
        )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command()
@click.argument("report_a", type=click.Path(exists=True))
@click.argument("report_b", type=click.Path(exists=True))
@click.pass_context
def diff(ctx, report_a, report_b):
    """Compare two coverage reports.

    Accepts report.json or .info tracefile paths.
    """
    from wirecov.diff import diff_runs

    try:
        diff_runs(
            path_a=Path(report_a),
            path_b=Path(report_b),
            json_output=ctx.obj["json_output"],
            console=ctx.obj["console"],
        )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command()
@click.argument("pcap_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--target", type=float, default=1.0,
              help="Target coverage rate (0.0-1.0, default: 1.0 = full).")
@click.pass_context
def optimize(ctx, pcap_dir, target):
    """Find minimal pcap subset achieving maximum coverage.

    Requires a previous run with --per-pcap.
    """
    from wirecov.optimize import optimize_pcap_set

    try:
        optimize_pcap_set(
            pcap_dir=Path(pcap_dir),
            target_rate=target,
            json_output=ctx.obj["json_output"],
            console=ctx.obj["console"],
        )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command()
@click.argument("coverage_data", type=click.Path(exists=True))
@click.option("--format", "report_format",
              type=click.Choice(["table", "json", "csv", "html", "all"]),
              default="all", help="Report output format.")
@click.option("-o", "--output", "output_dir", default="wirecov-output",
              type=click.Path(), help="Output directory for reports.")
@click.pass_context
def report(ctx, coverage_data, report_format, output_dir):
    """Re-generate reports from saved coverage data.

    COVERAGE_DATA is a path to a .info tracefile or report.json.
    """
    from wirecov.reports import regenerate_report

    try:
        regenerate_report(
            data_path=Path(coverage_data),
            report_format=report_format,
            output_dir=Path(output_dir),
            json_output=ctx.obj["json_output"],
            console=ctx.obj["console"],
        )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command()
@click.argument("coverage_data", type=click.Path(exists=True))
@click.option("-o", "--output", "output_path", default=None,
              type=click.Path(), help="Output path for badge JSON.")
@click.pass_context
def badge(ctx, coverage_data, output_path):
    """Generate shields.io badge JSON from coverage data."""
    from wirecov.badges import generate_badge

    try:
        generate_badge(
            data_path=Path(coverage_data),
            output_path=Path(output_path) if output_path else None,
            json_output=ctx.obj["json_output"],
            console=ctx.obj["console"],
        )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command()
@click.argument("pcap_path", type=click.Path(exists=True))
@click.option("--versions", "-V", "versions_str", required=True,
              help="Comma-separated Wireshark versions (e.g. v4.4.14,v4.6.4,master).")
@click.option("-o", "--output", "output_dir", default="wirecov-output",
              type=click.Path(), help="Output directory for reports.")
@click.option("-j", "--jobs", type=int, default=0,
              help="Parallel build jobs in container (0 = auto).")
@click.pass_context
def matrix(ctx, pcap_path, versions_str, output_dir, jobs):
    """Run same pcaps against multiple Wireshark versions and compare.

    Builds/reuses images for each version, runs coverage, and shows a
    comparison matrix highlighting per-dissector differences.

    \b
    Examples:
      wirecov matrix ./pcaps/ -V v4.4.14,v4.6.4
      wirecov matrix capture.pcap -V v4.4.14,v4.6.4,master
      wirecov matrix ./pcaps/ -V v4.6.4,abc1234def  # commit hash
    """
    from wirecov.matrix import run_matrix
    from wirecov.versions import validate_version

    try:
        versions = [v.strip() for v in versions_str.split(",") if v.strip()]
        # Validate each version
        validated = []
        for v in versions:
            version, is_known = validate_version(v)
            if not is_known and not ctx.obj["json_output"]:
                console.print(
                    f"  [yellow]Warning:[/yellow] Version '{version}' not found "
                    "in GitLab tags (proceeding anyway)"
                )
            validated.append(version)

        run_matrix(
            pcap_path=Path(pcap_path),
            versions=validated,
            output_dir=Path(output_dir),
            jobs=jobs,
            verbose=ctx.obj["verbose"],
            json_output=ctx.obj["json_output"],
            console=ctx.obj["console"],
        )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)


@main.command()
@click.option("--keep", type=int, default=3,
              help="Number of most recent images to keep.")
@click.pass_context
def cleanup(ctx, keep):
    """Remove old wirecov Docker images."""
    from wirecov.docker import cleanup_images

    try:
        cleanup_images(
            keep_latest=keep,
            console=ctx.obj["console"],
        )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command()
@click.argument("ws_version", required=False, default=None)
@click.option("--all", "clean_all", is_flag=True,
              help="Remove ALL wirecov Docker images.")
@click.pass_context
def clean(ctx, ws_version, clean_all):
    """Remove wirecov Docker image(s).

    Provide a VERSION to remove a specific image, or use --all to remove all.

    \b
    Examples:
      wirecov clean v4.4.14        Remove a specific version
      wirecov clean master         Remove master image
      wirecov clean --all          Remove all wirecov images
    """
    from wirecov.docker import list_images, remove_all_images, remove_image

    try:
        if clean_all:
            remove_all_images(console=ctx.obj["console"])
        elif ws_version:
            remove_image(ws_version, console=ctx.obj["console"])
        else:
            # Show what's available and ask
            images = list_images()
            if not images:
                console.print("No wirecov images found.")
                return
            console.print("\n[bold]Cached wirecov images:[/bold]\n")
            for img in images:
                console.print(f"  {img['tag']:20s} {img['size']:>10s}   {img['created']}")
            console.print(
                "\n[dim]Use 'wirecov clean <version>' or 'wirecov clean --all'[/dim]\n"
            )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@main.command()
@click.argument("ws_version", required=False, default=None)
@click.option("-j", "--jobs", type=int, default=0,
              help="Parallel build jobs in container (0 = auto).")
@click.pass_context
def rebuild(ctx, ws_version, jobs):
    """Remove and rebuild a wirecov Docker image.

    Removes the existing image (if any) and rebuilds from scratch.
    If VERSION is omitted, shows an interactive picker.

    \b
    Examples:
      wirecov rebuild v4.4.14      Rebuild a specific version
      wirecov rebuild master        Rebuild master
      wirecov rebuild               Interactive version picker
    """
    from wirecov.docker import build_image, check_docker, remove_image
    from wirecov.versions import select_version_interactive, validate_version

    try:
        check_docker()

        if ws_version:
            version, _ = validate_version(ws_version)
        else:
            version = select_version_interactive(console=ctx.obj["console"])

        c = ctx.obj["console"]
        c.print(f"\n  Rebuilding [bold]{version}[/bold]...")

        # Remove existing image first
        remove_image(version, console=c)

        # Build fresh (always --no-cache since we're explicitly rebuilding)
        build_image(
            version, no_cache=True, jobs=jobs,
            verbose=ctx.obj["verbose"],
            console=c,
        )
    except WirecovError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
