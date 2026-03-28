"""Pcap set optimization using greedy set-cover algorithm."""

import json as json_mod
from pathlib import Path
from typing import Dict, List, Set, Tuple

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from wirecov.attribution import load_per_pcap_data
from wirecov.coverage import CoverageReport
from wirecov.exceptions import WirecovError


def _get_covered_lines(report: CoverageReport) -> Dict[str, Set[int]]:
    """Extract covered lines per source file from a report."""
    result = {}
    for source, fcov in report.files.items():
        covered = {ln for ln, cnt in fcov.line_data.items() if cnt > 0}
        if covered:
            result[source] = covered
    return result


def _count_universe(per_pcap: Dict[str, Dict[str, Set[int]]]) -> int:
    """Count total unique lines across all pcaps."""
    all_lines: Dict[str, Set[int]] = {}
    for pcap_lines in per_pcap.values():
        for source, lines in pcap_lines.items():
            if source not in all_lines:
                all_lines[source] = set()
            all_lines[source] |= lines
    return sum(len(ls) for ls in all_lines.values())


def greedy_set_cover(
    per_pcap_lines: Dict[str, Dict[str, Set[int]]],
    target_rate: float = 1.0,
    progress: Progress = None,
    task_id=None,
) -> List[Tuple[str, int, int]]:
    """Greedy set-cover: find minimal pcap subset for maximum coverage.

    Args:
        per_pcap_lines: {pcap_name: {source_file: set_of_covered_lines}}
        target_rate: stop when this fraction of total coverage is reached

    Returns:
        [(pcap_name, new_lines_added, cumulative_total), ...]
    """
    # Compute universe
    universe: Dict[str, Set[int]] = {}
    for pcap_lines in per_pcap_lines.values():
        for source, lines in pcap_lines.items():
            if source not in universe:
                universe[source] = set()
            universe[source] |= lines

    total_universe = sum(len(ls) for ls in universe.values())
    target_lines = int(total_universe * target_rate)

    # Greedy loop
    remaining = dict(per_pcap_lines)
    covered: Dict[str, Set[int]] = {}
    covered_count = 0
    result = []

    while remaining and covered_count < target_lines:
        best_name = None
        best_new = 0

        for pcap_name, pcap_lines in remaining.items():
            new_count = 0
            for source, lines in pcap_lines.items():
                existing = covered.get(source, set())
                new_count += len(lines - existing)

            if new_count > best_new:
                best_new = new_count
                best_name = pcap_name

        if best_name is None or best_new == 0:
            break

        # Add best pcap
        pcap_lines = remaining.pop(best_name)
        for source, lines in pcap_lines.items():
            if source not in covered:
                covered[source] = set()
            covered[source] |= lines

        covered_count = sum(len(ls) for ls in covered.values())
        result.append((best_name, best_new, covered_count))

        if progress and task_id is not None:
            progress.update(task_id, completed=covered_count)

    return result


def optimize_pcap_set(pcap_dir: Path, target_rate: float = 1.0,
                      json_output: bool = False, console: Console = None):
    """Find minimal pcap subset achieving target coverage.

    Reads per-pcap .info files from a previous wirecov run with --per-pcap.
    """
    console = console or Console()

    # Load per-pcap data
    per_pcap_reports = load_per_pcap_data(pcap_dir)
    if not per_pcap_reports:
        raise WirecovError(
            f"No per-pcap .info files found in {pcap_dir / 'per-pcap'}. "
            "Run 'wirecov run --per-pcap' first."
        )

    # Extract covered lines per pcap
    per_pcap_lines = {
        name: _get_covered_lines(report)
        for name, report in per_pcap_reports.items()
    }

    total_universe = _count_universe(per_pcap_lines)

    console.print(
        f"\n  Optimizing {len(per_pcap_lines)} pcaps "
        f"({total_universe:,} total coverable lines)...\n"
    )

    with Progress(console=console) as progress:
        task = progress.add_task(
            "Set cover optimization",
            total=int(total_universe * target_rate),
        )
        result = greedy_set_cover(
            per_pcap_lines, target_rate, progress, task,
        )

    if json_output:
        data = {
            "total_pcaps": len(per_pcap_reports),
            "selected_pcaps": len(result),
            "total_lines": total_universe,
            "covered_lines": result[-1][2] if result else 0,
            "target_rate": target_rate,
            "selected": [
                {"pcap": name, "new_lines": new, "cumulative": cum}
                for name, new, cum in result
            ],
        }
        console.print_json(json_mod.dumps(data, indent=2))
        return

    # Rich table
    table = Table(title="Optimal Pcap Subset", show_lines=False)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Pcap", style="bold")
    table.add_column("New Lines", justify="right", style="green")
    table.add_column("Cumulative", justify="right")
    table.add_column("Coverage", justify="right")

    for i, (name, new_lines, cumulative) in enumerate(result, 1):
        rate = cumulative / total_universe if total_universe else 0
        table.add_row(
            str(i),
            name,
            f"+{new_lines:,}",
            f"{cumulative:,}",
            f"{rate * 100:.1f}%",
        )

    console.print()
    console.print(table)
    console.print()
    console.print(
        f"  [bold]Result:[/bold] {len(result)} of {len(per_pcap_reports)} pcaps "
        f"needed for {target_rate * 100:.0f}% target coverage"
    )
    console.print()
