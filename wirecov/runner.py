"""Main runner: orchestrates the full wirecov pipeline."""

import json as json_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from wirecov.config import CONFIG
from wirecov.exceptions import NoPcapsFoundError


def find_pcaps(pcap_path: Path) -> List[Path]:
    """Find all pcap files at the given path (file or directory)."""
    pcap_path = pcap_path.resolve()

    if pcap_path.is_file():
        if pcap_path.suffix.lower() in [e.lower() for e in CONFIG.pcap_extensions]:
            return [pcap_path]
        raise NoPcapsFoundError(str(pcap_path))

    # Directory: recursive scan
    pcaps = []
    for ext in CONFIG.pcap_extensions:
        pcaps.extend(pcap_path.rglob(f"*{ext}"))
        # Also try uppercase
        pcaps.extend(pcap_path.rglob(f"*{ext.upper()}"))

    # Deduplicate and sort
    pcaps = sorted(set(pcaps))
    if not pcaps:
        raise NoPcapsFoundError(str(pcap_path))

    return pcaps


def _make_timestamped_dir(base_output_dir: Path, ws_version: str) -> Path:
    """Create a timestamped subdirectory inside the output dir.

    Format: wirecov-output/v4.4.14_20260328_143021/
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_version = ws_version.replace("/", "_")
    subdir = f"{safe_version}_{ts}"
    run_dir = base_output_dir / subdir
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _write_run_metadata(run_dir: Path, ws_version: str, pcaps: List[Path],
                        pcap_path: Path):
    """Write run metadata (version, pcap list, timestamp) to the output dir."""
    metadata = {
        "wirecov_version": "0.1.0",
        "wireshark_version": ws_version,
        "wireshark_repo": CONFIG.wireshark_repo,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pcap_input": str(pcap_path),
        "pcap_count": len(pcaps),
        "pcap_files": [str(p.name) for p in pcaps],
    }
    meta_dir = run_dir / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    (meta_dir / "run_metadata.json").write_text(
        json_mod.dumps(metadata, indent=2) + "\n"
    )


def _write_full_coverage_summary(run_dir: Path, report, ws_version: str,
                                 console: Console):
    """Write a full coverage summary (all source, not just dissectors)."""
    from wirecov.coverage import filter_report

    summary = {
        "wireshark_version": ws_version,
        "wireshark_repo": CONFIG.wireshark_repo,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": {
            "files": len(report.files),
            "lines_found": report.total_lines_found,
            "lines_hit": report.total_lines_hit,
            "line_rate": round(report.line_rate, 4),
            "functions_found": report.total_functions_found,
            "functions_hit": report.total_functions_hit,
            "function_rate": round(report.function_rate, 4),
        },
        "by_component": {},
    }

    # Break down by component directory
    components = {
        "epan/dissectors": "Dissectors",
        "epan/ftypes": "Field Types",
        "epan/dfilter": "Display Filters",
        "epan/wslua": "Lua API",
        "epan": "Core Protocol Engine (epan)",
        "wiretap": "File Format Parsers (wiretap)",
        "wsutil": "Utilities (wsutil)",
    }

    for pattern, label in components.items():
        filtered = filter_report(report, [pattern])
        if filtered.files:
            summary["by_component"][label] = {
                "pattern": pattern,
                "files": len(filtered.files),
                "lines_found": filtered.total_lines_found,
                "lines_hit": filtered.total_lines_hit,
                "line_rate": round(filtered.line_rate, 4),
            }

    meta_dir = run_dir / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    (meta_dir / "full_coverage_summary.json").write_text(
        json_mod.dumps(summary, indent=2) + "\n"
    )

    # Also print to terminal
    console.print()
    console.print("[bold]Full Coverage Summary[/bold]")
    console.print(
        f"  Total: {report.total_lines_hit:,} / {report.total_lines_found:,} lines "
        f"({report.line_rate * 100:.1f}%) across {len(report.files)} files"
    )
    console.print(
        f"  Functions: {report.total_functions_hit:,} / {report.total_functions_found:,} "
        f"({report.function_rate * 100:.1f}%)"
    )
    console.print()

    for label, data in summary["by_component"].items():
        rate_pct = data["line_rate"] * 100
        console.print(
            f"  {label:40s} {data['lines_hit']:>7,} / {data['lines_found']:>7,}  "
            f"({rate_pct:5.1f}%)  [{data['files']} files]"
        )

    console.print()
    return summary


def run_coverage(
    pcap_path: Path,
    ws_version: str = None,
    output_dir: Path = None,
    no_cache: bool = False,
    report_format: str = "all",
    jobs: int = 0,
    per_pcap: bool = False,
    protocols: bool = False,
    verbose: bool = False,
    json_output: bool = False,
    console: Console = None,
):
    """Run the full coverage pipeline: build -> run -> report."""
    from wirecov.coverage import parse_lcov
    from wirecov.dissectors import load_dissector_dates
    from wirecov.docker import build_image, check_docker, image_exists, run_container
    from wirecov.reports import generate_diff_reports, generate_reports
    from wirecov.versions import select_version_interactive, validate_version

    console = console or Console()
    output_dir = output_dir or Path(CONFIG.default_output_dir)

    # Step 1: Validate pcap input
    pcaps = find_pcaps(pcap_path)
    if not json_output:
        console.print(f"\n  Found [bold]{len(pcaps)}[/bold] pcap file(s)")
        if len(pcaps) <= 10:
            for p in pcaps:
                console.print(f"    - {p.name}")
        else:
            for p in pcaps[:5]:
                console.print(f"    - {p.name}")
            console.print(f"    ... and {len(pcaps) - 5} more")

    # Step 2: Check Docker is available
    check_docker()

    # Step 3: Resolve Wireshark version
    if ws_version:
        version, is_known = validate_version(ws_version)
        if not is_known and not json_output:
            console.print(
                f"  [yellow]Warning:[/yellow] Version '{version}' not found "
                "in GitLab tags (proceeding anyway)"
            )
    else:
        version = select_version_interactive(console=console)

    if not json_output:
        console.print(f"  Wireshark version: [bold]{version}[/bold]")
        console.print(f"  Source: [dim]{CONFIG.wireshark_repo}[/dim]")

    # Step 4: Build or reuse Docker image
    if image_exists(version) and not no_cache:
        if not json_output:
            console.print(f"  Using cached image: {CONFIG.image_tag(version)}")
    else:
        if not json_output:
            console.print()
        build_image(
            version, no_cache=no_cache, jobs=jobs,
            verbose=verbose, console=console,
        )

    # Step 5: Create timestamped output directory
    run_dir = _make_timestamped_dir(output_dir.resolve(), version)
    if not json_output:
        console.print(f"  Output directory: {run_dir}")

    # Write run metadata
    _write_run_metadata(run_dir, version, pcaps, pcap_path.resolve())

    # Step 6: Run container
    if not json_output:
        console.print()

    total_pcaps = len(pcaps)
    processed = 0
    warnings = []

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
        disable=json_output,
    )

    with progress:
        task = progress.add_task("Processing pcaps", total=total_pcaps)

        for line in run_container(
            version=version,
            pcap_path=pcap_path,
            output_path=run_dir,
            per_pcap=per_pcap,
            protocols=protocols,
            verbose=verbose,
            console=console,
        ):
            if line.startswith("WIRECOV_DONE:"):
                processed += 1
                progress.update(task, completed=processed)
            elif line.startswith("WIRECOV_WARN:"):
                warnings.append(line[len("WIRECOV_WARN:"):].strip())
            elif line.startswith("WIRECOV_STATUS:"):
                status = line[len("WIRECOV_STATUS:"):].strip()
                progress.update(task, description=status)
            elif line.startswith("WIRECOV_PROCESSING:"):
                pcap_name = line[len("WIRECOV_PROCESSING:"):].strip()
                progress.update(task, description=f"Processing {pcap_name}")
            elif verbose and not json_output:
                console.print(f"  [dim]{line}[/dim]")

    # Show warnings
    if warnings and not json_output:
        console.print()
        for w in warnings:
            console.print(f"  [yellow]Warning:[/yellow] {w}")

    # Step 7: Parse coverage data and generate reports
    # The entrypoint.sh writes to lcov/ subdirectory
    lcov_dir = run_dir / "lcov"
    total_info = lcov_dir / "total.info"
    # Fallback: check old location
    if not total_info.exists():
        total_info = run_dir / "total.info"

    if not total_info.exists():
        console.print("[red]Error:[/red] No coverage data generated. "
                      "Check that tshark processed the pcap(s) successfully.")
        return

    if not json_output:
        console.print()
        console.print("[bold]Generating reports...[/bold]")

    report = parse_lcov(total_info)

    # Load dissector dates from metadata
    dates = load_dissector_dates(run_dir)

    # Step 8: Full coverage summary (all components)
    if not json_output:
        _write_full_coverage_summary(run_dir, report, version, console)

    # Step 9: Dissector-specific reports (into reports/)
    pcap_names = [p.name for p in pcaps]
    generate_reports(
        report=report,
        report_format=report_format,
        output_dir=run_dir,
        ws_version=version,
        pcap_list=pcap_names,
        dates=dates,
        json_output=json_output,
        console=console,
    )

    # Step 10: Diff-from-baseline reports (into reports-diff/)
    init_info = lcov_dir / "init.info"
    if not init_info.exists():
        init_info = run_dir / "init.info"

    if init_info.exists():
        init_report = parse_lcov(init_info)
        generate_diff_reports(
            pcap_report=report,
            init_report=init_report,
            report_format=report_format,
            output_dir=run_dir,
            ws_version=version,
            pcap_list=pcap_names,
            dates=dates,
            json_output=json_output,
            console=console,
        )

    # Step 11: Generate badge
    from wirecov.badges import generate_badge
    badge_dir = run_dir / "metadata"
    badge_dir.mkdir(parents=True, exist_ok=True)
    generate_badge(
        data_path=total_info,
        output_path=badge_dir / "badge.json",
        json_output=False,
        console=Console(quiet=True),
    )

    # Step 12: Optional - per-pcap attribution
    if per_pcap:
        from wirecov.attribution import (
            load_per_pcap_data,
            render_attribution_table,
        )
        per_pcap_reports = load_per_pcap_data(run_dir)
        if per_pcap_reports and not json_output:
            render_attribution_table(per_pcap_reports, console=console)

    # Step 13: Optional - protocol cross-reference
    if protocols:
        from wirecov.dissectors import extract_dissectors
        from wirecov.protocols import (
            cross_reference,
            parse_protocol_files,
            render_protocol_table,
        )
        proto_data = parse_protocol_files(run_dir)
        if proto_data and not json_output:
            dissectors = extract_dissectors(report, dates=dates)
            cross_ref = cross_reference(proto_data, dissectors)
            render_protocol_table(cross_ref, console=console)

    # Final summary
    if not json_output:
        console.print()
        console.print(f"  [bold green]Done![/bold green] Output: {run_dir}")
        console.print()
        console.print("  [bold]Output Directory Layout:[/bold]")
        console.print(f"    {run_dir}/")

        # lcov/
        console.print(f"    ├── lcov/")
        console.print(f"    │   ├── total.info              (aggregate lcov)")
        console.print(f"    │   ├── dissectors.info         (dissector-only)")
        if init_info.exists():
            console.print(f"    │   └── init.info               (init-only baseline)")

        # metadata/
        console.print(f"    ├── metadata/")
        console.print(f"    │   ├── run_metadata.json")
        console.print(f"    │   ├── full_coverage_summary.json")
        console.print(f"    │   └── badge.json")

        # reports/
        reports_dir = run_dir / "reports"
        if reports_dir.exists():
            console.print(f"    ├── reports/                    (pcap coverage)")
            console.print(f"    │   ├── dissector-report.html")
            console.print(f"    │   ├── report.json")
            console.print(f"    │   └── report.csv")

        # reports-diff/
        diff_dir = run_dir / "reports-diff"
        if diff_dir.exists():
            console.print(f"    ├── reports-diff/               (minus init baseline)")
            console.print(f"    │   ├── dissector-report.html")
            console.print(f"    │   ├── report.json")
            console.print(f"    │   └── report.csv")

        # html dirs from genhtml
        if (run_dir / "html-full" / "index.html").exists():
            console.print(f"    ├── html-full/                  (genhtml full report)")
        if (run_dir / "html-dissectors" / "index.html").exists():
            console.print(f"    └── html-dissectors/            (genhtml dissectors)")

        console.print()
