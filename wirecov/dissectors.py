"""Dissector-level coverage extraction and classification."""

import json as json_mod
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from wirecov.coverage import CoverageReport

# Match dissector source files: packet-tcp.c, packet-http2.c, etc.
DISSECTOR_RE = re.compile(r"(packet-.+)\.c$")


@dataclass
class DissectorInfo:
    """Coverage information for a single protocol dissector."""

    name: str           # e.g., "tcp", "http2"
    source_file: str    # e.g., "packet-tcp.c"
    full_path: str      # full path as in lcov data
    lines_found: int
    lines_hit: int
    functions_found: int
    functions_hit: int
    first_created: str = ""   # YYYY-MM-DD or empty
    last_updated: str = ""    # YYYY-MM-DD or empty

    @property
    def line_rate(self) -> float:
        if self.lines_found == 0:
            return 0.0
        return self.lines_hit / self.lines_found

    @property
    def function_rate(self) -> float:
        if self.functions_found == 0:
            return 0.0
        return self.functions_hit / self.functions_found

    @property
    def classification(self) -> str:
        """Classify coverage level."""
        rate = self.line_rate
        if rate == 0.0:
            return "none"
        elif rate < 0.25:
            return "low"
        elif rate < 0.75:
            return "medium"
        elif rate < 1.0:
            return "high"
        else:
            return "full"

    def gitlab_url(self, version: str = "master") -> str:
        """Return a GitLab URL to the source file for this dissector."""
        # Convert version tag to branch ref: v4.6.5 -> release-4.6
        if version.startswith("v"):
            parts = version[1:].split(".")
            if len(parts) >= 2:
                ref = f"release-{parts[0]}.{parts[1]}"
            else:
                ref = "master"
        elif version == "master":
            ref = "master"
        else:
            ref = version
        return (
            f"https://gitlab.com/wireshark/wireshark/-/blob/{ref}"
            f"/epan/dissectors/{self.source_file}?ref_type=heads"
        )

    def to_dict(self, version: str = "master") -> dict:
        return {
            "name": self.name,
            "source_file": self.source_file,
            "gitlab_url": self.gitlab_url(version),
            "lines_found": self.lines_found,
            "lines_hit": self.lines_hit,
            "line_rate": round(self.line_rate, 4),
            "functions_found": self.functions_found,
            "functions_hit": self.functions_hit,
            "function_rate": round(self.function_rate, 4),
            "classification": self.classification,
            "first_created": self.first_created,
            "last_updated": self.last_updated,
        }


def load_dissector_dates(output_dir: Path) -> Dict[str, Dict[str, str]]:
    """Load dissector dates from metadata/dissector_dates.json."""
    dates_path = output_dir / "metadata" / "dissector_dates.json"
    if dates_path.exists():
        try:
            return json_mod.loads(dates_path.read_text())
        except (json_mod.JSONDecodeError, OSError):
            pass
    return {}


def extract_dissectors(report: CoverageReport,
                       dates: Optional[Dict[str, Dict[str, str]]] = None,
                       ) -> List[DissectorInfo]:
    """Extract per-dissector coverage from a CoverageReport.

    Filters for files matching */epan/dissectors/packet-*.c and maps
    each to a DissectorInfo with the protocol name derived from the filename.
    """
    dates = dates or {}
    dissectors = []

    for source, fcov in report.files.items():
        if "epan/dissectors/" not in source:
            continue

        basename = os.path.basename(source)
        match = DISSECTOR_RE.match(basename)
        if not match:
            continue

        proto_name = match.group(1)
        file_dates = dates.get(basename, {})

        dissectors.append(DissectorInfo(
            name=proto_name,
            source_file=basename,
            full_path=source,
            lines_found=fcov.lines_found,
            lines_hit=fcov.lines_hit,
            functions_found=fcov.functions_found,
            functions_hit=fcov.functions_hit,
            first_created=file_dates.get("first_created", ""),
            last_updated=file_dates.get("last_updated", ""),
        ))

    dissectors.sort(key=lambda d: (-d.line_rate, d.name))
    return dissectors


def compute_summary(dissectors: List[DissectorInfo]) -> dict:
    """Compute aggregate summary statistics."""
    total = len(dissectors)
    covered = sum(1 for d in dissectors if d.lines_hit > 0)
    uncovered = total - covered
    total_lines = sum(d.lines_found for d in dissectors)
    total_hit = sum(d.lines_hit for d in dissectors)

    by_class = {}
    for d in dissectors:
        c = d.classification
        by_class[c] = by_class.get(c, 0) + 1

    return {
        "total_dissectors": total,
        "covered_dissectors": covered,
        "uncovered_dissectors": uncovered,
        "total_lines": total_lines,
        "total_lines_hit": total_hit,
        "overall_line_rate": round(total_hit / total_lines, 4) if total_lines else 0.0,
        "by_classification": by_class,
    }
