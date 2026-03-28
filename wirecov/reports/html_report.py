"""HTML report generation using Jinja2."""

from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from wirecov.dissectors import DissectorInfo, compute_summary

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def write_html(dissectors: List[DissectorInfo], ws_version: str = "",
               pcap_list: Optional[List[str]] = None,
               output_path: Path = None,
               title_suffix: str = "",
               unchanged_dissectors: Optional[List[DissectorInfo]] = None,
               diff_stats: Optional[Dict] = None,
               init_hits: Optional[Dict[str, int]] = None):
    """Render and write the dissector coverage HTML report."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")

    summary = compute_summary(dissectors)
    all_dissectors = dissectors + (unchanged_dissectors or [])
    has_dates = any(d.first_created or d.last_updated for d in all_dissectors)

    html = template.render(
        ws_version=ws_version,
        summary=summary,
        dissectors=dissectors,
        pcap_list=pcap_list or [],
        pcap_count=len(pcap_list) if pcap_list else 0,
        has_dates=has_dates,
        title_suffix=title_suffix,
        unchanged_dissectors=unchanged_dissectors or [],
        diff_stats=diff_stats,
        init_hits=init_hits or {},
    )

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html)
