"""Diff mode: compare two coverage runs."""

import json as json_mod
from pathlib import Path

from rich.console import Console
from rich.table import Table

from wirecov.coverage import CoverageReport, diff_reports, parse_lcov
from wirecov.dissectors import extract_dissectors
from wirecov.exceptions import WirecovError


def _load_report(path: Path) -> CoverageReport:
    """Load a CoverageReport from either .info or find the .info from a dir."""
    if path.suffix == ".info":
        return parse_lcov(path)
    elif path.suffix == ".json":
        # Try to find companion .info file
        info_path = path.parent / "total.info"
        if info_path.exists():
            return parse_lcov(info_path)
        # Try dissectors.info
        info_path = path.parent / "dissectors.info"
        if info_path.exists():
            return parse_lcov(info_path)
        raise WirecovError(
            f"No .info tracefile found alongside {path}. "
            "Provide a .info file directly."
        )
    elif path.is_dir():
        for name in ["total.info", "dissectors.info"]:
            candidate = path / name
            if candidate.exists():
                return parse_lcov(candidate)
        raise WirecovError(f"No .info tracefile found in {path}")
    else:
        raise WirecovError(f"Unsupported file type: {path}")


def diff_runs(path_a: Path, path_b: Path,
              json_output: bool = False, console: Console = None):
    """Compare two coverage runs and display the diff."""
    console = console or Console()

    report_a = _load_report(path_a)
    report_b = _load_report(path_b)

    # Get dissector-level view
    dissectors_a = {d.name: d for d in extract_dissectors(report_a)}
    dissectors_b = {d.name: d for d in extract_dissectors(report_b)}
    all_names = sorted(set(dissectors_a.keys()) | set(dissectors_b.keys()))

    # Build diff entries
    entries = []
    for name in all_names:
        da = dissectors_a.get(name)
        db = dissectors_b.get(name)

        rate_a = da.line_rate if da else 0.0
        rate_b = db.line_rate if db else 0.0
        delta = rate_b - rate_a

        if abs(delta) < 0.0001 and da and db:
            continue  # No change, skip

        entries.append({
            "dissector": name,
            "rate_a": rate_a,
            "rate_b": rate_b,
            "delta": delta,
            "lines_a": da.lines_hit if da else 0,
            "lines_b": db.lines_hit if db else 0,
            "status": "new" if not da else "removed" if not db else "changed",
        })

    # Sort by delta descending (biggest gains first)
    entries.sort(key=lambda e: -e["delta"])

    # Summary
    full_diff = diff_reports(report_a, report_b)

    if json_output:
        data = {
            "path_a": str(path_a),
            "path_b": str(path_b),
            "total_lines_gained": full_diff.total_lines_gained,
            "total_lines_lost": full_diff.total_lines_lost,
            "dissector_changes": entries,
        }
        console.print_json(json_mod.dumps(data, indent=2))
        return

    # Rich table
    console.print()
    console.print("[bold]Coverage Diff[/bold]")
    console.print(f"  A: {path_a}")
    console.print(f"  B: {path_b}")
    console.print(
        f"  Lines gained: [green]+{full_diff.total_lines_gained:,}[/green]  "
        f"Lines lost: [red]-{full_diff.total_lines_lost:,}[/red]"
    )
    console.print()

    if not entries:
        console.print("  [dim]No dissector-level changes detected.[/dim]")
        return

    table = Table(show_lines=False)
    table.add_column("Dissector", style="bold")
    table.add_column("A %", justify="right")
    table.add_column("B %", justify="right")
    table.add_column("Delta", justify="right")
    table.add_column("Status")

    for e in entries:
        delta_str = f"{e['delta'] * 100:+.1f}%"
        if e["delta"] > 0:
            delta_str = f"[green]{delta_str}[/green]"
        elif e["delta"] < 0:
            delta_str = f"[red]{delta_str}[/red]"

        status_str = {
            "new": "[green]new[/green]",
            "removed": "[red]removed[/red]",
            "changed": "",
        }.get(e["status"], "")

        table.add_row(
            e["dissector"],
            f"{e['rate_a'] * 100:.1f}%",
            f"{e['rate_b'] * 100:.1f}%",
            delta_str,
            status_str,
        )

    console.print(table)
    console.print()
