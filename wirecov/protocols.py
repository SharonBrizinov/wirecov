"""Protocol tree coverage: cross-reference frame.protocols with dissectors."""

from pathlib import Path
from typing import Dict, List, Set

from rich.console import Console
from rich.table import Table

from wirecov.dissectors import DissectorInfo


def parse_protocol_files(output_dir: Path) -> Dict[str, Set[str]]:
    """Parse protocol tree files from the protocols/ subdirectory.

    Each file contains unique frame.protocols lines, where each line
    is a colon-separated protocol stack (e.g., "eth:ethertype:ip:tcp:http").

    Returns {pcap_name: set_of_protocol_names}.
    """
    proto_dir = output_dir / "protocols"
    if not proto_dir.exists():
        return {}

    result = {}
    for proto_file in sorted(proto_dir.glob("*.protocols")):
        pcap_name = proto_file.stem
        protocols = set()

        for line in proto_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            # Split protocol stack and collect all protocol names
            for proto in line.split(":"):
                proto = proto.strip()
                if proto:
                    protocols.add(proto)

        result[pcap_name] = protocols

    return result


def get_all_protocols(proto_data: Dict[str, Set[str]]) -> Set[str]:
    """Get union of all protocols seen across all pcaps."""
    all_protos = set()
    for protos in proto_data.values():
        all_protos |= protos
    return all_protos


def cross_reference(
    proto_data: Dict[str, Set[str]],
    dissectors: List[DissectorInfo],
) -> List[Dict]:
    """Cross-reference observed protocols with dissector coverage.

    Returns a list of dicts with:
        - protocol: protocol name from frame.protocols
        - dissector: matching dissector name (or None)
        - seen_in_pcaps: number of pcaps that contained this protocol
        - coverage: line_rate of the matching dissector (or None)
        - status: "covered", "uncovered", "no_dissector"
    """
    all_protos = get_all_protocols(proto_data)
    dissector_map = {d.name: d for d in dissectors}

    # Count how many pcaps each protocol appears in
    proto_counts = {}
    for pcap_protos in proto_data.values():
        for proto in pcap_protos:
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

    results = []
    for proto in sorted(all_protos):
        dissector = dissector_map.get(proto)

        if dissector is None:
            # Try common name variations
            # e.g., "wlan" might map to "ieee80211"
            status = "no_dissector"
            coverage = None
            dissector_name = None
        elif dissector.lines_hit > 0:
            status = "covered"
            coverage = dissector.line_rate
            dissector_name = dissector.name
        else:
            status = "uncovered"
            coverage = 0.0
            dissector_name = dissector.name

        results.append({
            "protocol": proto,
            "dissector": dissector_name,
            "seen_in_pcaps": proto_counts.get(proto, 0),
            "coverage": coverage,
            "status": status,
        })

    return results


def render_protocol_table(cross_ref: List[Dict], console: Console = None):
    """Render protocol cross-reference as a Rich table."""
    console = console or Console()

    table = Table(title="Protocol Tree Coverage", show_lines=False)
    table.add_column("Protocol", style="bold")
    table.add_column("Dissector")
    table.add_column("Pcaps", justify="right")
    table.add_column("Coverage", justify="right")
    table.add_column("Status")

    status_styles = {
        "covered": "[green]covered[/green]",
        "uncovered": "[red]uncovered[/red]",
        "no_dissector": "[yellow]no match[/yellow]",
    }

    for entry in cross_ref:
        cov_str = ""
        if entry["coverage"] is not None:
            cov_str = f"{entry['coverage'] * 100:.1f}%"

        table.add_row(
            entry["protocol"],
            entry["dissector"] or "[dim]-[/dim]",
            str(entry["seen_in_pcaps"]),
            cov_str,
            status_styles.get(entry["status"], entry["status"]),
        )

    console.print()
    console.print(table)
    console.print()
