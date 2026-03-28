"""shields.io badge JSON endpoint generation."""

import json as json_mod
from pathlib import Path

from rich.console import Console

from wirecov.coverage import parse_lcov
from wirecov.dissectors import compute_summary, extract_dissectors
from wirecov.exceptions import WirecovError


def _rate_to_color(rate: float) -> str:
    """Map coverage rate to shields.io color name."""
    if rate >= 0.90:
        return "brightgreen"
    elif rate >= 0.75:
        return "green"
    elif rate >= 0.50:
        return "yellow"
    elif rate >= 0.25:
        return "orange"
    else:
        return "red"


def generate_badge(data_path: Path, output_path: Path = None,
                   json_output: bool = False, console: Console = None):
    """Generate a shields.io-compatible JSON endpoint badge.

    Output format:
        {
            "schemaVersion": 1,
            "label": "wirecov",
            "message": "42.3%",
            "color": "yellow"
        }
    """
    console = console or Console()

    # Load coverage data
    if data_path.suffix == ".info":
        report = parse_lcov(data_path)
        dissectors = extract_dissectors(report)
    elif data_path.suffix == ".json":
        # Try companion .info
        info_path = data_path.parent / "dissectors.info"
        if not info_path.exists():
            info_path = data_path.parent / "total.info"
        if not info_path.exists():
            raise WirecovError(f"No .info file found alongside {data_path}")
        report = parse_lcov(info_path)
        dissectors = extract_dissectors(report)
    else:
        raise WirecovError(f"Unsupported file type: {data_path.suffix}")

    summary = compute_summary(dissectors)
    rate = summary["overall_line_rate"]

    badge_data = {
        "schemaVersion": 1,
        "label": "wirecov",
        "message": f"{rate * 100:.1f}%",
        "color": _rate_to_color(rate),
    }

    if output_path is None:
        output_path = data_path.parent / "badge.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json_mod.dumps(badge_data, indent=2) + "\n")

    if json_output:
        console.print_json(json_mod.dumps(badge_data, indent=2))
    else:
        console.print(f"  Badge generated: {output_path}")
        console.print(
            f"  Coverage: {badge_data['message']} "
            f"(color: {badge_data['color']})"
        )
