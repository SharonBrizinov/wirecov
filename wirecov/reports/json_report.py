"""JSON report generation."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from wirecov.config import CONFIG
from wirecov.dissectors import DissectorInfo, compute_summary


def build_json(dissectors: List[DissectorInfo],
               ws_version: str = "",
               pcap_list: Optional[List[str]] = None,
               unchanged_dissectors: Optional[List[DissectorInfo]] = None,
               diff_stats: Optional[Dict] = None,
               init_hits: Optional[Dict[str, int]] = None) -> dict:
    """Build the JSON report structure."""
    dissector_entries = []
    for i, d in enumerate(dissectors):
        entry = {**d.to_dict(version=ws_version), "rank": i + 1}
        if init_hits and d.name in init_hits:
            entry["init_lines_hit"] = init_hits[d.name]
            entry["pcap_added_pct"] = round(
                d.lines_hit / d.lines_found * 100, 1
            ) if d.lines_found else 0
        dissector_entries.append(entry)

    data = {
        "wireshark_version": ws_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "wirecov",
        "pcap_files": pcap_list or [],
        "pcap_count": len(pcap_list) if pcap_list else 0,
        "tshark_passes": {
            "pass1": {
                "description": "Full reassembly — exercises reassembly, defragmentation, and checksum code paths",
                "flags": CONFIG.tshark_flags_pass1,
            },
            "pass2": {
                "description": "No reassembly — forces per-packet dissection of upper-layer protocols",
                "flags": CONFIG.tshark_flags_pass2,
            },
        },
        "summary": compute_summary(dissectors),
        "dissectors": dissector_entries,
    }

    if diff_stats:
        data["diff_stats"] = diff_stats

    if unchanged_dissectors:
        data["unchanged_dissectors"] = [
            d.to_dict(version=ws_version)
            for d in unchanged_dissectors
        ]

    return data


def write_json(dissectors: List[DissectorInfo], ws_version: str = "",
               pcap_list: Optional[List[str]] = None,
               output_path: Path = None,
               unchanged_dissectors: Optional[List[DissectorInfo]] = None,
               diff_stats: Optional[Dict] = None,
               init_hits: Optional[Dict[str, int]] = None):
    """Write dissector coverage as JSON."""
    data = build_json(dissectors, ws_version=ws_version, pcap_list=pcap_list,
                      unchanged_dissectors=unchanged_dissectors,
                      diff_stats=diff_stats, init_hits=init_hits)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(data, indent=2) + "\n")
    else:
        print(json.dumps(data, indent=2))
