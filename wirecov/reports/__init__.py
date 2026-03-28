"""Report generation dispatcher."""

from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console

from wirecov.coverage import CoverageReport, parse_lcov
from wirecov.dissectors import (
    DissectorInfo,
    compute_summary,
    extract_dissectors,
    load_dissector_dates,
)


def _write_reports(dissectors: List[DissectorInfo], formats: List[str],
                   output_dir: Path, ws_version: str,
                   pcap_list: List[str], title_suffix: str = "",
                   unchanged_dissectors: Optional[List[DissectorInfo]] = None,
                   diff_stats: Optional[Dict] = None,
                   init_hits: Optional[Dict[str, int]] = None,
                   json_output: bool = False, console: Console = None):
    """Write report files for the given dissector list."""
    output_dir.mkdir(parents=True, exist_ok=True)
    console = console or Console()

    for fmt in formats:
        if fmt == "table" and not json_output:
            from wirecov.reports.terminal import render_table
            render_table(dissectors, ws_version=ws_version,
                         pcap_list=pcap_list, console=console)

        elif fmt == "json":
            from wirecov.reports.json_report import write_json
            path = output_dir / "report.json"
            write_json(dissectors, ws_version=ws_version,
                       pcap_list=pcap_list, output_path=path,
                       unchanged_dissectors=unchanged_dissectors,
                       diff_stats=diff_stats,
                       init_hits=init_hits)
            if not json_output:
                console.print(f"  JSON report: {path}")

        elif fmt == "csv":
            from wirecov.reports.csv_report import write_csv
            path = output_dir / "report.csv"
            write_csv(dissectors, output_path=path, ws_version=ws_version,
                      init_hits=init_hits)
            if not json_output:
                console.print(f"  CSV report:  {path}")

        elif fmt == "html":
            from wirecov.reports.html_report import write_html
            path = output_dir / "dissector-report.html"
            write_html(dissectors, ws_version=ws_version,
                       pcap_list=pcap_list, output_path=path,
                       title_suffix=title_suffix,
                       unchanged_dissectors=unchanged_dissectors,
                       diff_stats=diff_stats,
                       init_hits=init_hits)
            if not json_output:
                console.print(f"  HTML report: {path}")


def generate_reports(report: CoverageReport, report_format: str,
                     output_dir: Path, ws_version: str,
                     pcap_list: Optional[List[str]] = None,
                     dates: Optional[Dict] = None,
                     json_output: bool = False, console: Console = None):
    """Generate dissector reports in the requested format(s).

    Reports are written to output_dir/reports/.
    """
    dissectors = extract_dissectors(report, dates=dates)
    console = console or Console()
    pcap_list = pcap_list or []

    reports_dir = output_dir / "reports"

    formats = (
        ["table", "json", "csv", "html"] if report_format == "all"
        else [report_format]
    )

    _write_reports(
        dissectors, formats, reports_dir, ws_version,
        pcap_list, title_suffix="Pcap Coverage",
        json_output=json_output, console=console,
    )

    return dissectors


def generate_diff_reports(pcap_report: CoverageReport,
                          init_report: CoverageReport,
                          report_format: str,
                          output_dir: Path, ws_version: str,
                          pcap_list: Optional[List[str]] = None,
                          dates: Optional[Dict] = None,
                          json_output: bool = False,
                          console: Console = None):
    """Generate diff-from-baseline reports.

    Shows only the coverage that the pcap(s) actually contributed beyond
    tshark's initialization code (proto_register/proto_handoff).
    Reports are written to output_dir/reports-diff/.
    """
    console = console or Console()
    pcap_list = pcap_list or []

    # Extract dissectors from both reports
    pcap_dissectors = {d.name: d for d in extract_dissectors(pcap_report, dates=dates)}
    init_dissectors = {d.name: d for d in extract_dissectors(init_report, dates=dates)}

    # Build diff dissectors: subtract init coverage from pcap coverage
    diff_list = []
    unchanged_list = []
    total_init_lines_hit = 0
    total_pcap_lines_hit = 0
    total_pcap_lines_found = 0

    for name, pd in pcap_dissectors.items():
        init_d = init_dissectors.get(name)
        total_pcap_lines_hit += pd.lines_hit
        total_pcap_lines_found += pd.lines_found

        if init_d:
            total_init_lines_hit += init_d.lines_hit
            diff_lines_hit = max(0, pd.lines_hit - init_d.lines_hit)
            diff_funcs_hit = max(0, pd.functions_hit - init_d.functions_hit)
        else:
            diff_lines_hit = pd.lines_hit
            diff_funcs_hit = pd.functions_hit

        if diff_lines_hit > 0 or diff_funcs_hit > 0:
            diff_list.append(DissectorInfo(
                name=pd.name,
                source_file=pd.source_file,
                full_path=pd.full_path,
                lines_found=pd.lines_found,
                lines_hit=diff_lines_hit,
                functions_found=pd.functions_found,
                functions_hit=diff_funcs_hit,
                first_created=pd.first_created,
                last_updated=pd.last_updated,
            ))
        else:
            # Unchanged: no pcap-specific contribution
            unchanged_list.append(DissectorInfo(
                name=pd.name,
                source_file=pd.source_file,
                full_path=pd.full_path,
                lines_found=pd.lines_found,
                lines_hit=0,
                functions_found=pd.functions_found,
                functions_hit=0,
                first_created=pd.first_created,
                last_updated=pd.last_updated,
            ))

    diff_list.sort(key=lambda d: (-d.line_rate, d.name))
    unchanged_list.sort(key=lambda d: d.name)

    # Compute diff-specific statistics
    total_dissectors = len(pcap_dissectors)
    diff_lines_hit_total = sum(d.lines_hit for d in diff_list)
    diff_funcs_hit_total = sum(d.functions_hit for d in diff_list)
    diff_funcs_found_total = sum(d.functions_found for d in diff_list)

    # By classification breakdown for changed dissectors
    by_class = {}
    for d in diff_list:
        c = d.classification
        by_class[c] = by_class.get(c, 0) + 1

    diff_stats = {
        "total_dissectors": total_dissectors,
        "exercised_dissectors": len(diff_list),
        "unchanged_dissectors": len(unchanged_list),
        "exercised_pct": round(len(diff_list) / total_dissectors * 100, 1) if total_dissectors else 0,
        "total_lines_found": total_pcap_lines_found,
        "init_lines_hit": total_init_lines_hit,
        "pcap_lines_hit": total_pcap_lines_hit,
        "pcap_only_lines_hit": diff_lines_hit_total,
        "pcap_only_funcs_hit": diff_funcs_hit_total,
        "pcap_only_line_rate": round(
            diff_lines_hit_total / total_pcap_lines_found * 100, 1
        ) if total_pcap_lines_found else 0,
        "init_line_rate": round(
            total_init_lines_hit / total_pcap_lines_found * 100, 1
        ) if total_pcap_lines_found else 0,
        "by_classification": by_class,
    }

    diff_dir = output_dir / "reports-diff"

    formats = (
        ["json", "csv", "html"] if report_format == "all"
        else [f for f in [report_format] if f != "table"]
    )

    if not json_output:
        console.print()
        console.print("[bold]Generating diff-from-baseline reports...[/bold]")
        console.print(f"  Dissectors exercised by pcap(s): {len(diff_list)} / {total_dissectors}")
        console.print(f"  Pcap-only lines: {diff_lines_hit_total:,} "
                      f"(init: {total_init_lines_hit:,}, total: {total_pcap_lines_hit:,})")

    # Build per-dissector init hit counts for the diff report columns
    init_hits = {}
    for name in pcap_dissectors:
        init_d = init_dissectors.get(name)
        init_hits[name] = init_d.lines_hit if init_d else 0

    _write_reports(
        diff_list, formats, diff_dir, ws_version,
        pcap_list, title_suffix="Pcap-Only Coverage (minus init)",
        unchanged_dissectors=unchanged_list,
        diff_stats=diff_stats,
        init_hits=init_hits,
        json_output=json_output, console=console,
    )

    return diff_list


def regenerate_report(data_path: Path, report_format: str,
                      output_dir: Path, json_output: bool = False,
                      console: Console = None):
    """Re-generate reports from saved coverage data (.info or report.json)."""
    console = console or Console()
    pcap_list = []
    ws_version = "unknown"

    if data_path.suffix == ".json":
        import json as json_mod
        raw = json_mod.loads(data_path.read_text())
        ws_version = raw.get("wireshark_version", "unknown")
        pcap_list = raw.get("pcap_files", [])
        info_path = data_path.parent / "lcov" / "total.info"
        if not info_path.exists():
            info_path = data_path.parent / "total.info"
        if info_path.exists():
            report = parse_lcov(info_path)
        else:
            console.print("[yellow]Warning:[/yellow] No .info file found, "
                          "regenerating from JSON data only.")
            return
    else:
        report = parse_lcov(data_path)
        # Try to load metadata from same directory
        meta_path = data_path.parent / "metadata" / "run_metadata.json"
        if not meta_path.exists():
            meta_path = data_path.parent / "run_metadata.json"
        if meta_path.exists():
            import json as json_mod
            meta = json_mod.loads(meta_path.read_text())
            ws_version = meta.get("wireshark_version", "unknown")
            pcap_list = meta.get("pcap_files", [])

    # Load dates if available
    dates = load_dissector_dates(output_dir)

    generate_reports(
        report, report_format, output_dir,
        ws_version=ws_version, pcap_list=pcap_list,
        dates=dates,
        json_output=json_output, console=console,
    )
