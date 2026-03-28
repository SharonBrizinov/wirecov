"""Multi-version matrix: run the same pcaps against multiple Wireshark versions."""

import json as json_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table

from wirecov.config import CONFIG
from wirecov.dissectors import DissectorInfo, extract_dissectors
from wirecov.exceptions import WirecovError


def _run_single_version(pcap_path: Path, version: str, output_dir: Path,
                        jobs: int, verbose: bool, json_output: bool,
                        console: Console) -> Optional[Dict[str, DissectorInfo]]:
    """Run coverage for a single version, return {name: DissectorInfo} or None."""
    from wirecov.coverage import parse_lcov
    from wirecov.dissectors import load_dissector_dates
    from wirecov.docker import build_image, image_exists, run_container
    from wirecov.runner import _make_timestamped_dir, _write_run_metadata, find_pcaps

    pcaps = find_pcaps(pcap_path)

    # Build image if needed
    if not image_exists(version):
        if not json_output:
            console.print(f"\n  Building image for [bold]{version}[/bold]...")
        build_image(version, jobs=jobs, verbose=verbose, console=console)

    # Create output dir for this version's run
    run_dir = _make_timestamped_dir(output_dir, version)
    _write_run_metadata(run_dir, version, pcaps, pcap_path.resolve())

    if not json_output:
        console.print(f"  Running {len(pcaps)} pcap(s) against [bold]{version}[/bold]...")

    # Run container
    for line in run_container(
        version=version,
        pcap_path=pcap_path,
        output_path=run_dir,
        verbose=verbose,
        console=console,
    ):
        if verbose and not json_output and not line.startswith("WIRECOV_"):
            console.print(f"    [dim]{line}[/dim]")

    # Parse results
    lcov_dir = run_dir / "lcov"
    total_info = lcov_dir / "total.info"
    if not total_info.exists():
        total_info = run_dir / "total.info"
    if not total_info.exists():
        if not json_output:
            console.print(f"  [yellow]Warning: No coverage data for {version}[/yellow]")
        return None

    report = parse_lcov(total_info)
    dates = load_dissector_dates(run_dir)
    dissectors = extract_dissectors(report, dates=dates)
    return {d.name: d for d in dissectors}


def run_matrix(pcap_path: Path, versions: List[str],
               output_dir: Path = None, jobs: int = 0,
               verbose: bool = False, json_output: bool = False,
               console: Console = None):
    """Run the same pcaps against multiple Wireshark versions and compare."""
    from wirecov.docker import check_docker

    console = console or Console()
    output_dir = output_dir or Path(CONFIG.default_output_dir)
    output_dir = output_dir.resolve()

    check_docker()

    if len(versions) < 2:
        raise WirecovError("Matrix requires at least 2 versions to compare.")

    if not json_output:
        console.print(f"\n[bold]Multi-Version Matrix[/bold]")
        console.print(f"  Source: [dim]{CONFIG.wireshark_repo}[/dim]")
        console.print(f"  Versions: {', '.join(versions)}")

    # Run each version
    results: Dict[str, Dict[str, DissectorInfo]] = {}
    for version in versions:
        try:
            data = _run_single_version(
                pcap_path, version, output_dir, jobs,
                verbose, json_output, console,
            )
            if data is not None:
                results[version] = data
        except WirecovError as e:
            if not json_output:
                console.print(f"  [red]Error for {version}:[/red] {e}")

    if len(results) < 2:
        raise WirecovError("Need at least 2 successful runs to build a matrix.")

    completed_versions = list(results.keys())

    # Collect all dissector names across all versions
    all_names = set()
    for data in results.values():
        all_names.update(data.keys())

    # Build matrix entries
    entries = []
    for name in sorted(all_names):
        rates = {}
        for v in completed_versions:
            d = results[v].get(name)
            rates[v] = d.line_rate if d else 0.0

        rate_values = list(rates.values())
        delta = rate_values[-1] - rate_values[0]

        entries.append({
            "dissector": name,
            "rates": rates,
            "lines_found": max(
                (results[v].get(name, _zero_info(name)).lines_found
                 for v in completed_versions), default=0
            ),
            "delta": delta,
        })

    # Sort: biggest absolute delta first
    entries.sort(key=lambda e: -abs(e["delta"]))

    # Compute per-version summaries
    version_summaries = {}
    for v in completed_versions:
        data = results[v]
        total_lines = sum(d.lines_found for d in data.values())
        total_hit = sum(d.lines_hit for d in data.values())
        covered = sum(1 for d in data.values() if d.lines_hit > 0)
        version_summaries[v] = {
            "dissectors": len(data),
            "covered": covered,
            "total_lines": total_lines,
            "total_hit": total_hit,
            "line_rate": round(total_hit / total_lines, 4) if total_lines else 0,
        }

    if json_output:
        _output_json(completed_versions, entries, version_summaries, console)
    else:
        _output_table(completed_versions, entries, version_summaries, console)

    # Write matrix JSON to output dir
    matrix_path = output_dir / "matrix.json"
    matrix_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "versions": completed_versions,
        "version_summaries": version_summaries,
        "dissectors": entries,
    }
    matrix_path.write_text(json_mod.dumps(matrix_data, indent=2) + "\n")
    if not json_output:
        console.print(f"\n  Matrix JSON: {matrix_path}")
        console.print()


def _zero_info(name: str) -> DissectorInfo:
    return DissectorInfo(
        name=name, source_file="", full_path="",
        lines_found=0, lines_hit=0, functions_found=0, functions_hit=0,
    )


def _output_json(versions, entries, summaries, console):
    data = {
        "versions": versions,
        "version_summaries": summaries,
        "dissectors": entries,
    }
    console.print_json(json_mod.dumps(data, indent=2))


def _output_table(versions, entries, summaries, console):
    # Summary table
    console.print()
    console.print("[bold]Version Summary[/bold]")

    sum_table = Table(show_lines=False, pad_edge=True)
    sum_table.add_column("Version", style="bold")
    sum_table.add_column("Dissectors", justify="right")
    sum_table.add_column("Covered", justify="right")
    sum_table.add_column("Lines Hit", justify="right")
    sum_table.add_column("Total Lines", justify="right")
    sum_table.add_column("Line %", justify="right")

    for v in versions:
        s = summaries[v]
        rate_str = f"{s['line_rate'] * 100:.1f}%"
        sum_table.add_row(
            v, str(s["dissectors"]), str(s["covered"]),
            f"{s['total_hit']:,}", f"{s['total_lines']:,}", rate_str,
        )

    console.print(sum_table)

    # Changed dissectors table
    changed = [e for e in entries if abs(e["delta"]) >= 0.001]
    if not changed:
        console.print("\n  [dim]No dissector-level differences detected.[/dim]")
        return

    console.print()
    console.print(f"[bold]Dissector Changes[/bold] ({len(changed)} dissectors differ)")

    table = Table(show_lines=False, pad_edge=True, expand=False)
    table.add_column("Dissector", style="bold", min_width=20)
    for v in versions:
        table.add_column(v, justify="right")
    table.add_column("Delta", justify="right")

    # Show top 50 changes
    for e in changed[:50]:
        row = [e["dissector"]]
        for v in versions:
            rate = e["rates"].get(v, 0)
            row.append(f"{rate * 100:.1f}%")

        delta = e["delta"]
        delta_str = f"{delta * 100:+.1f}%"
        if delta > 0:
            delta_str = f"[green]{delta_str}[/green]"
        elif delta < 0:
            delta_str = f"[red]{delta_str}[/red]"
        row.append(delta_str)

        table.add_row(*row)

    if len(changed) > 50:
        pad = [""] * (len(versions) + 1)
        table.add_row(f"[dim]... and {len(changed) - 50} more[/dim]", *pad)

    console.print(table)

    # Unchanged count
    unchanged = len(entries) - len(changed)
    if unchanged > 0:
        console.print(f"\n  [dim]{unchanged} dissectors unchanged across versions[/dim]")
