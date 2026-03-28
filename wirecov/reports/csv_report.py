"""CSV report generation."""

import csv
from pathlib import Path
from typing import Dict, List, Optional

from wirecov.dissectors import DissectorInfo

CSV_FIELDS = [
    "rank",
    "dissector",
    "source_file",
    "gitlab_url",
    "lines_found",
    "lines_hit",
    "line_rate",
    "functions_found",
    "functions_hit",
    "function_rate",
    "classification",
    "first_created",
    "last_updated",
]

CSV_FIELDS_DIFF = CSV_FIELDS + [
    "init_lines_hit",
    "pcap_added_pct",
]


def write_csv(dissectors: List[DissectorInfo], output_path: Path = None,
              ws_version: str = "master",
              init_hits: Optional[Dict[str, int]] = None):
    """Write dissector coverage as CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fields = CSV_FIELDS_DIFF if init_hits else CSV_FIELDS

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for i, d in enumerate(dissectors, 1):
            row = {
                "rank": i,
                "dissector": d.name,
                "source_file": d.source_file,
                "gitlab_url": d.gitlab_url(ws_version),
                "lines_found": d.lines_found,
                "lines_hit": d.lines_hit,
                "line_rate": f"{d.line_rate:.4f}",
                "functions_found": d.functions_found,
                "functions_hit": d.functions_hit,
                "function_rate": f"{d.function_rate:.4f}",
                "classification": d.classification,
                "first_created": d.first_created,
                "last_updated": d.last_updated,
            }
            if init_hits:
                ih = init_hits.get(d.name, 0)
                row["init_lines_hit"] = ih
                row["pcap_added_pct"] = f"{d.line_rate * 100:.1f}" if d.lines_found else "0.0"
            writer.writerow(row)
