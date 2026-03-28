"""Pure-Python lcov tracefile parser and coverage data structures."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class FileCoverage:
    """Coverage data for a single source file."""

    source_file: str
    line_data: Dict[int, int] = field(default_factory=dict)       # line -> exec count
    function_data: Dict[str, int] = field(default_factory=dict)   # func -> call count
    function_lines: Dict[str, int] = field(default_factory=dict)  # func -> line number

    @property
    def lines_found(self) -> int:
        return len(self.line_data)

    @property
    def lines_hit(self) -> int:
        return sum(1 for c in self.line_data.values() if c > 0)

    @property
    def functions_found(self) -> int:
        return len(self.function_data)

    @property
    def functions_hit(self) -> int:
        return sum(1 for c in self.function_data.values() if c > 0)

    @property
    def line_rate(self) -> float:
        if self.lines_found == 0:
            return 0.0
        return self.lines_hit / self.lines_found

    @property
    def covered_lines(self) -> set:
        """Set of line numbers that were executed at least once."""
        return {ln for ln, count in self.line_data.items() if count > 0}


@dataclass
class CoverageReport:
    """Aggregate coverage report across multiple source files."""

    files: Dict[str, FileCoverage] = field(default_factory=dict)

    @property
    def total_lines_found(self) -> int:
        return sum(f.lines_found for f in self.files.values())

    @property
    def total_lines_hit(self) -> int:
        return sum(f.lines_hit for f in self.files.values())

    @property
    def total_functions_found(self) -> int:
        return sum(f.functions_found for f in self.files.values())

    @property
    def total_functions_hit(self) -> int:
        return sum(f.functions_hit for f in self.files.values())

    @property
    def line_rate(self) -> float:
        if self.total_lines_found == 0:
            return 0.0
        return self.total_lines_hit / self.total_lines_found

    @property
    def function_rate(self) -> float:
        if self.total_functions_found == 0:
            return 0.0
        return self.total_functions_hit / self.total_functions_found


@dataclass
class DiffEntry:
    """Coverage diff for a single source file."""

    source_file: str
    lines_found_a: int
    lines_found_b: int
    lines_hit_a: int
    lines_hit_b: int
    lines_gained: int  # lines newly covered in B
    lines_lost: int    # lines covered in A but not in B

    @property
    def rate_a(self) -> float:
        return self.lines_hit_a / self.lines_found_a if self.lines_found_a else 0.0

    @property
    def rate_b(self) -> float:
        return self.lines_hit_b / self.lines_found_b if self.lines_found_b else 0.0

    @property
    def rate_delta(self) -> float:
        return self.rate_b - self.rate_a


@dataclass
class DiffReport:
    """Coverage diff between two reports."""

    entries: List[DiffEntry] = field(default_factory=list)
    total_lines_gained: int = 0
    total_lines_lost: int = 0


def parse_lcov(path: Path) -> CoverageReport:
    """Parse an lcov .info tracefile into a CoverageReport.

    Handles the standard lcov format:
        TN: test name
        SF: source file path
        FN: line,function_name
        FNDA: count,function_name
        DA: line,count
        LF: lines found (ignored, computed from DA)
        LH: lines hit (ignored, computed from DA)
        end_of_record
    """
    report = CoverageReport()
    current: Optional[FileCoverage] = None

    text = path.read_text(errors="replace")

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("TN:"):
            continue

        elif line.startswith("SF:"):
            source = line[3:]
            current = FileCoverage(source_file=source)

        elif line.startswith("FN:") and current is not None:
            parts = line[3:].split(",", 1)
            if len(parts) == 2:
                try:
                    lineno = int(parts[0])
                    func_name = parts[1]
                    current.function_lines[func_name] = lineno
                    if func_name not in current.function_data:
                        current.function_data[func_name] = 0
                except ValueError:
                    pass

        elif line.startswith("FNDA:") and current is not None:
            parts = line[5:].split(",", 1)
            if len(parts) == 2:
                try:
                    count = int(parts[0])
                    func_name = parts[1]
                    current.function_data[func_name] = count
                except ValueError:
                    pass

        elif line.startswith("DA:") and current is not None:
            parts = line[3:].split(",")
            if len(parts) >= 2:
                try:
                    lineno = int(parts[0])
                    count = int(parts[1])
                    current.line_data[lineno] = current.line_data.get(lineno, 0) + count
                except ValueError:
                    pass

        elif line == "end_of_record" and current is not None:
            # Merge into report (handle duplicate source files)
            if current.source_file in report.files:
                existing = report.files[current.source_file]
                for ln, cnt in current.line_data.items():
                    existing.line_data[ln] = existing.line_data.get(ln, 0) + cnt
                for fn, cnt in current.function_data.items():
                    existing.function_data[fn] = existing.function_data.get(fn, 0) + cnt
                existing.function_lines.update(current.function_lines)
            else:
                report.files[current.source_file] = current
            current = None

    return report


def merge_reports(*reports: CoverageReport) -> CoverageReport:
    """Merge multiple coverage reports, summing execution counts."""
    merged = CoverageReport()

    for report in reports:
        for source, fcov in report.files.items():
            if source in merged.files:
                existing = merged.files[source]
                for ln, cnt in fcov.line_data.items():
                    existing.line_data[ln] = existing.line_data.get(ln, 0) + cnt
                for fn, cnt in fcov.function_data.items():
                    existing.function_data[fn] = existing.function_data.get(fn, 0) + cnt
                existing.function_lines.update(fcov.function_lines)
            else:
                # Deep copy
                merged.files[source] = FileCoverage(
                    source_file=source,
                    line_data=dict(fcov.line_data),
                    function_data=dict(fcov.function_data),
                    function_lines=dict(fcov.function_lines),
                )

    return merged


def filter_report(report: CoverageReport, patterns: List[str]) -> CoverageReport:
    """Filter report to only include files matching any of the glob patterns.

    Patterns are matched against the full source file path using simple
    substring matching (e.g., 'epan/dissectors' matches any file with
    that in its path).
    """
    filtered = CoverageReport()

    for source, fcov in report.files.items():
        if any(pattern in source for pattern in patterns):
            filtered.files[source] = fcov

    return filtered


def diff_reports(base: CoverageReport, head: CoverageReport) -> DiffReport:
    """Compute per-file coverage diff between base and head reports."""
    all_files = set(base.files.keys()) | set(head.files.keys())
    entries = []
    total_gained = 0
    total_lost = 0

    for source in sorted(all_files):
        base_fc = base.files.get(source)
        head_fc = head.files.get(source)

        base_covered = base_fc.covered_lines if base_fc else set()
        head_covered = head_fc.covered_lines if head_fc else set()

        gained = len(head_covered - base_covered)
        lost = len(base_covered - head_covered)
        total_gained += gained
        total_lost += lost

        if gained > 0 or lost > 0:
            entries.append(DiffEntry(
                source_file=source,
                lines_found_a=base_fc.lines_found if base_fc else 0,
                lines_found_b=head_fc.lines_found if head_fc else 0,
                lines_hit_a=base_fc.lines_hit if base_fc else 0,
                lines_hit_b=head_fc.lines_hit if head_fc else 0,
                lines_gained=gained,
                lines_lost=lost,
            ))

    return DiffReport(
        entries=entries,
        total_lines_gained=total_gained,
        total_lines_lost=total_lost,
    )
