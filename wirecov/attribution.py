"""Per-pcap coverage attribution: track which pcap contributed what."""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

from rich.console import Console
from rich.table import Table

from wirecov.coverage import CoverageReport, parse_lcov
from wirecov.dissectors import DissectorInfo, extract_dissectors


@dataclass
class PcapAttribution:
    """Attribution data for a single pcap file."""

    pcap_name: str
    dissectors_touched: int
    total_lines_covered: int
    unique_lines: int  # lines covered only by this pcap


def load_per_pcap_data(output_dir: Path) -> Dict[str, CoverageReport]:
    """Load per-pcap .info files from the per-pcap/ subdirectory."""
    per_pcap_dir = output_dir / "per-pcap"
    if not per_pcap_dir.exists():
        return {}

    reports = {}
    for info_file in sorted(per_pcap_dir.glob("*.info")):
        pcap_name = info_file.stem
        reports[pcap_name] = parse_lcov(info_file)

    return reports


def compute_attribution(
    per_pcap_reports: Dict[str, CoverageReport],
) -> Dict[str, List[DissectorInfo]]:
    """Extract per-pcap dissector coverage."""
    result = {}
    for pcap_name, report in per_pcap_reports.items():
        result[pcap_name] = extract_dissectors(report)
    return result


def compute_unique_contributions(
    per_pcap_reports: Dict[str, CoverageReport],
) -> Dict[str, Dict[str, Set[int]]]:
    """Compute which lines are uniquely covered by each pcap.

    Returns {pcap_name: {source_file: set_of_unique_line_numbers}}.
    A line is "unique" to a pcap if no other pcap covers it.
    """
    # First pass: collect all (file, line) -> set of pcaps that cover it
    line_to_pcaps: Dict[Tuple[str, int], Set[str]] = {}

    for pcap_name, report in per_pcap_reports.items():
        for source, fcov in report.files.items():
            for lineno, count in fcov.line_data.items():
                if count > 0:
                    key = (source, lineno)
                    if key not in line_to_pcaps:
                        line_to_pcaps[key] = set()
                    line_to_pcaps[key].add(pcap_name)

    # Second pass: lines covered by exactly one pcap
    unique: Dict[str, Dict[str, Set[int]]] = {}
    for (source, lineno), pcaps in line_to_pcaps.items():
        if len(pcaps) == 1:
            pcap_name = next(iter(pcaps))
            if pcap_name not in unique:
                unique[pcap_name] = {}
            if source not in unique[pcap_name]:
                unique[pcap_name][source] = set()
            unique[pcap_name][source].add(lineno)

    return unique


def compute_marginal_contribution(
    per_pcap_reports: Dict[str, CoverageReport],
) -> List[Tuple[str, int]]:
    """Compute marginal contribution of each pcap in order of impact.

    Returns [(pcap_name, new_lines_added), ...] sorted by descending contribution.
    This is the order in which pcaps should be processed for maximum
    incremental coverage.
    """
    remaining = dict(per_pcap_reports)
    covered: Dict[str, Set[int]] = {}  # source -> covered lines
    result = []

    while remaining:
        # Find pcap with most new lines
        best_name = None
        best_new = 0

        for pcap_name, report in remaining.items():
            new_lines = 0
            for source, fcov in report.files.items():
                existing = covered.get(source, set())
                for lineno, count in fcov.line_data.items():
                    if count > 0 and lineno not in existing:
                        new_lines += 1
            if new_lines > best_new:
                best_new = new_lines
                best_name = pcap_name

        if best_name is None or best_new == 0:
            # Remaining pcaps add nothing new
            for name in remaining:
                result.append((name, 0))
            break

        # Add best pcap's lines to covered set
        report = remaining.pop(best_name)
        for source, fcov in report.files.items():
            if source not in covered:
                covered[source] = set()
            for lineno, count in fcov.line_data.items():
                if count > 0:
                    covered[source].add(lineno)

        result.append((best_name, best_new))

    return result


def render_attribution_table(per_pcap_reports: Dict[str, CoverageReport],
                             console: Console = None):
    """Render a Rich table showing per-pcap attribution."""
    console = console or Console()

    marginal = compute_marginal_contribution(per_pcap_reports)
    unique = compute_unique_contributions(per_pcap_reports)

    table = Table(title="Per-Pcap Coverage Attribution", show_lines=False)
    table.add_column("Pcap", style="bold")
    table.add_column("Dissectors", justify="right")
    table.add_column("Lines Covered", justify="right")
    table.add_column("Marginal +", justify="right", style="green")
    table.add_column("Unique Lines", justify="right", style="cyan")

    for pcap_name, marginal_lines in marginal:
        report = per_pcap_reports.get(pcap_name)
        if not report:
            continue

        dissector_count = len([
            s for s in report.files
            if "epan/dissectors/packet-" in s
            and any(c > 0 for c in report.files[s].line_data.values())
        ])

        total_lines = sum(
            sum(1 for c in fcov.line_data.values() if c > 0)
            for fcov in report.files.values()
        )

        unique_count = sum(
            len(lines)
            for lines in unique.get(pcap_name, {}).values()
        )

        table.add_row(
            pcap_name,
            str(dissector_count),
            str(total_lines),
            f"+{marginal_lines}" if marginal_lines > 0 else "0",
            str(unique_count),
        )

    console.print()
    console.print(table)
    console.print()
