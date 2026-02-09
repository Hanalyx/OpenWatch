"""Output formatters for check and remediate results.

This module provides structured output formats for Aegis compliance results.
Formatters convert the internal result objects into JSON, CSV, or PDF for
reporting, CI/CD integration, and archival purposes.

Output Formats:
    - JSON: Structured data with full details, ideal for programmatic parsing
    - CSV: Flat tabular format, one row per host+rule, for spreadsheets
    - PDF: Formatted report with color-coded status, for human review

Usage Pattern:
    Results flow through: RuleResult -> HostResult -> RunResult -> formatter

Example:
-------
    >>> from runner.output import RunResult, HostResult, write_output
    >>>
    >>> # Build results (normally done by CLI)
    >>> run = RunResult(command="check")
    >>> run.hosts.append(HostResult(hostname="server1", ...))
    >>>
    >>> # Write to stdout
    >>> print(write_output(run, "json"))
    >>>
    >>> # Write to file
    >>> write_output(run, "csv", "results.csv")
    >>>
    >>> # Multiple formats
    >>> write_output(run, "json", "results.json")
    >>> write_output(run, "pdf", "report.pdf")

"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner._types import RuleResult

from runner.output.csv_fmt import format_csv
from runner.output.json_fmt import format_json
from runner.output.pdf_fmt import format_pdf

__all__ = [
    "HostResult",
    "RunResult",
    "format_json",
    "format_csv",
    "format_pdf",
    "write_output",
    "parse_output_spec",
]


# ── Result containers ──────────────────────────────────────────────────────


@dataclass
class HostResult:
    """Results from a single host.

    Collects all rule results for one host along with platform info and
    capabilities. Used by formatters to generate per-host sections in output.

    Attributes:
        hostname: The target host's address or hostname.
        platform_family: Detected OS family (e.g., "rhel", "ubuntu"), or None.
        platform_version: Detected major version number, or None.
        capabilities: Dict of capability name -> bool from detect_capabilities().
        results: List of RuleResult objects from rule evaluation.
        error: Connection or execution error message, or None if successful.

    Properties:
        pass_count: Number of rules that passed (not skipped).
        fail_count: Number of rules that failed (not skipped).
        skip_count: Number of rules that were skipped.
        fixed_count: Number of rules successfully remediated.
    """

    hostname: str
    platform_family: str | None = None
    platform_version: int | None = None
    capabilities: dict[str, bool] = field(default_factory=dict)
    results: list[RuleResult] = field(default_factory=list)
    error: str | None = None

    @property
    def pass_count(self) -> int:
        """Count of passed rules (excludes skipped)."""
        return sum(1 for r in self.results if r.passed and not r.skipped)

    @property
    def fail_count(self) -> int:
        """Count of failed rules (excludes skipped)."""
        return sum(1 for r in self.results if not r.passed and not r.skipped)

    @property
    def skip_count(self) -> int:
        """Count of skipped rules."""
        return sum(1 for r in self.results if r.skipped)

    @property
    def fixed_count(self) -> int:
        """Count of successfully remediated rules."""
        return sum(1 for r in self.results if r.remediated and r.passed)


@dataclass
class RunResult:
    """Aggregated results from a full compliance run.

    Top-level container that holds results from all hosts. Created by the CLI
    and passed to formatters for output generation.

    Attributes:
        timestamp: When the run started (UTC).
        command: The command type ("check" or "remediate").
        hosts: List of HostResult objects, one per target host.

    Properties:
        total_pass: Sum of passed rules across all hosts.
        total_fail: Sum of failed rules across all hosts.
        total_skip: Sum of skipped rules across all hosts.
        total_fixed: Sum of remediated rules across all hosts.
        host_count: Number of hosts that connected successfully.

    Example:
    -------
        >>> run = RunResult(command="check")
        >>> run.hosts.append(host_result)
        >>> print(f"Total: {run.total_pass} pass, {run.total_fail} fail")

    """

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    command: str = "check"  # "check" or "remediate"
    hosts: list[HostResult] = field(default_factory=list)

    @property
    def total_pass(self) -> int:
        """Sum of passed rules across all hosts."""
        return sum(h.pass_count for h in self.hosts)

    @property
    def total_fail(self) -> int:
        """Sum of failed rules across all hosts."""
        return sum(h.fail_count for h in self.hosts)

    @property
    def total_skip(self) -> int:
        """Sum of skipped rules across all hosts."""
        return sum(h.skip_count for h in self.hosts)

    @property
    def total_fixed(self) -> int:
        """Sum of remediated rules across all hosts."""
        return sum(h.fixed_count for h in self.hosts)

    @property
    def host_count(self) -> int:
        """Number of hosts that connected successfully (no error)."""
        return len([h for h in self.hosts if h.error is None])


# ── Output utilities ───────────────────────────────────────────────────────


def parse_output_spec(spec: str) -> tuple[str, str | None]:
    """Parse an output specification into format and filepath.

    Output specs can be just a format name (output to stdout) or
    format:filepath (output to file).

    Args:
        spec: Output specification string (e.g., "json" or "json:results.json").

    Returns:
        Tuple of (format, filepath) where filepath is None for stdout output.

    Example:
    -------
        >>> parse_output_spec("json")
        ('json', None)
        >>> parse_output_spec("csv:results.csv")
        ('csv', 'results.csv')
        >>> parse_output_spec("PDF:Report.pdf")
        ('pdf', 'Report.pdf')

    """
    if ":" in spec:
        fmt, path = spec.split(":", 1)
        return fmt.lower(), path
    return spec.lower(), None


def write_output(run_result: RunResult, fmt: str, filepath: str | None = None) -> str:
    """Format results and optionally write to a file.

    Dispatches to the appropriate formatter based on format name. Text formats
    (JSON, CSV) can write to stdout or file; PDF always requires a filepath.

    Args:
        run_result: The aggregated run results to format.
        fmt: Output format name ("json", "csv", or "pdf").
        filepath: Optional file path to write output. Required for PDF.

    Returns:
        The formatted output string. Empty string for PDF (binary format).

    Raises:
        ValueError: If format is unknown or PDF requested without filepath.

    Example:
    -------
        >>> # To stdout
        >>> json_output = write_output(run_result, "json")
        >>> print(json_output)
        >>>
        >>> # To file
        >>> write_output(run_result, "csv", "results.csv")
        >>>
        >>> # PDF requires filepath
        >>> write_output(run_result, "pdf", "report.pdf")

    """
    # PDF requires a filepath (binary format)
    if fmt == "pdf":
        if not filepath:
            raise ValueError("PDF format requires a filepath (e.g., -o pdf:report.pdf)")
        format_pdf(run_result, filepath)
        return ""

    formatters = {
        "json": format_json,
        "csv": format_csv,
    }

    if fmt not in formatters:
        valid_formats = list(formatters.keys()) + ["pdf"]
        raise ValueError(f"Unknown output format: {fmt} (valid: {', '.join(valid_formats)})")

    output = formatters[fmt](run_result)

    if filepath:
        with open(filepath, "w") as f:
            f.write(output)

    return output
