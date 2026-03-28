"""Terminal table report using Rich."""

from typing import List, Optional

from rich.console import Console
from rich.table import Table

from wirecov.dissectors import DissectorInfo, compute_summary

CLASS_COLORS = {
    "none": "red",
    "low": "bright_red",
    "medium": "yellow",
    "high": "green",
    "full": "bright_green",
}


def _format_rate(rate: float) -> str:
    return f"{rate * 100:.1f}%"


def _colored_rate(rate: float, classification: str) -> str:
    color = CLASS_COLORS.get(classification, "white")
    return f"[{color}]{_format_rate(rate)}[/{color}]"


def render_table(dissectors: List[DissectorInfo], ws_version: str = "",
                 pcap_list: Optional[List[str]] = None,
                 console: Console = None):
    """Render dissector coverage as a Rich terminal table."""
    console = console or Console()
    summary = compute_summary(dissectors)
    has_dates = any(d.first_created or d.last_updated for d in dissectors)

    console.print()
    title = "Dissector Coverage Report"
    if ws_version:
        title += f"  ({ws_version})"
    console.print(f"[bold]{title}[/bold]")
    if pcap_list:
        console.print(f"  [dim]Pcaps: {len(pcap_list)} file(s)[/dim]")
    console.print()

    console.print(
        f"  Dissectors: {summary['total_dissectors']}  |  "
        f"Covered: [green]{summary['covered_dissectors']}[/green]  |  "
        f"Uncovered: [red]{summary['uncovered_dissectors']}[/red]  |  "
        f"Overall: {_format_rate(summary['overall_line_rate'])}"
    )
    console.print()

    table = Table(show_lines=False, pad_edge=True, expand=False)
    table.add_column("#", justify="right", style="dim", width=5)
    table.add_column("Dissector", style="bold", min_width=20)
    table.add_column("Lines", justify="right")
    table.add_column("Hit", justify="right")
    table.add_column("Line %", justify="right")
    table.add_column("Funcs", justify="right")
    table.add_column("Func Hit", justify="right")
    table.add_column("Level", justify="center")
    if has_dates:
        table.add_column("Created", justify="center", style="dim")
        table.add_column("Updated", justify="center", style="dim")

    covered = [d for d in dissectors if d.lines_hit > 0]
    uncovered = [d for d in dissectors if d.lines_hit == 0]

    row_num = 0
    for d in covered:
        row_num += 1
        color = CLASS_COLORS.get(d.classification, "white")
        row = [
            str(row_num),
            d.name,
            str(d.lines_found),
            str(d.lines_hit),
            _colored_rate(d.line_rate, d.classification),
            str(d.functions_found),
            str(d.functions_hit),
            f"[{color}]{d.classification}[/{color}]",
        ]
        if has_dates:
            row.extend([d.first_created or "-", d.last_updated or "-"])
        table.add_row(*row)

    if uncovered:
        table.add_section()
        for d in uncovered[:10]:
            row_num += 1
            row = [
                f"[dim]{row_num}[/dim]",
                f"[dim]{d.name}[/dim]",
                str(d.lines_found),
                "0",
                "[red]0.0%[/red]",
                str(d.functions_found),
                "0",
                "[red]none[/red]",
            ]
            if has_dates:
                row.extend([
                    f"[dim]{d.first_created or '-'}[/dim]",
                    f"[dim]{d.last_updated or '-'}[/dim]",
                ])
            table.add_row(*row)
        if len(uncovered) > 10:
            pad = [""] * (3 if has_dates else 1)
            table.add_row(
                "", f"[dim]... and {len(uncovered) - 10} more uncovered[/dim]",
                "", "", "", "", "", "", *pad,
            )

    console.print(table)
    console.print()
