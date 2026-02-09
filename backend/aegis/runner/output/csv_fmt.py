"""CSV output formatter for compliance results.

Produces flat CSV output suitable for:
- Import into spreadsheet applications (Excel, Google Sheets)
- Data analysis with pandas or similar tools
- Simple grep/awk processing
- Bulk reporting

Output Structure:
    One row per host+rule combination. Columns vary by command type:

    Check command columns:
        host, platform, rule_id, title, severity, passed, skipped, detail

    Remediate command columns:
        host, platform, rule_id, title, severity, passed, skipped, remediated, detail

    Connection errors produce a single row per host with empty rule fields
    and the error message in the detail column.

Example:
-------
    >>> from runner.output import RunResult, format_csv
    >>> result = RunResult(command="check")
    >>> csv_str = format_csv(result)
    >>> print(csv_str)
    host,platform,rule_id,title,severity,passed,skipped,detail
    server1,rhel 9,ssh-root-login,Disable root SSH,high,true,false,PermitRootLogin=no

"""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.output import RunResult


# ── Column definitions ─────────────────────────────────────────────────────
#
# Columns are ordered for readability: identification first (host, rule),
# then status (passed, skipped), then details last.

CHECK_COLUMNS = [
    "host",
    "platform",
    "rule_id",
    "framework_section",
    "title",
    "severity",
    "passed",
    "skipped",
    "detail",
]

REMEDIATE_COLUMNS = [
    "host",
    "platform",
    "rule_id",
    "framework_section",
    "title",
    "severity",
    "passed",
    "skipped",
    "remediated",
    "detail",
]


def format_csv(run_result: RunResult) -> str:
    """Format compliance results as CSV.

    Produces a flat CSV with one row per host+rule combination. Boolean
    values are lowercased ("true"/"false") for consistency.

    Args:
        run_result: Aggregated results from a compliance run.

    Returns:
        CSV string with header row and data rows.

    Column Details:
        - host: Target hostname or IP address
        - platform: "family version" (e.g., "rhel 9") or empty
        - rule_id: Rule identifier (e.g., "ssh-disable-root-login")
        - title: Human-readable rule title
        - severity: Rule severity level (high, medium, low)
        - passed: "true" or "false"
        - skipped: "true" or "false"
        - remediated: (remediate only) "true" or "false"
        - detail: Check result detail, skip reason, or error message

    Note:
        Hosts with connection errors produce a single row with empty
        rule fields and "Connection error: <message>" in detail column.

    """
    output = io.StringIO()

    # Select columns based on command type
    fieldnames = REMEDIATE_COLUMNS if run_result.command == "remediate" else CHECK_COLUMNS

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for host in run_result.hosts:
        if host.error:
            # Write error row for failed hosts
            row = _build_error_row(host.hostname, host.error, run_result.command)
            writer.writerow(row)
            continue

        platform_str = _format_platform(host.platform_family, host.platform_version)

        for result in host.results:
            row = _build_result_row(host.hostname, platform_str, result, run_result.command)
            writer.writerow(row)

    return output.getvalue()


def _format_platform(family: str | None, version: int | None) -> str:
    """Format platform info as 'family version' string.

    Args:
        family: OS family (e.g., "rhel") or None.
        version: Major version number or None.

    Returns:
        Formatted string like "rhel 9", or empty string if no family.

    """
    if not family:
        return ""
    return f"{family} {version or ''}"


def _build_error_row(hostname: str, error: str, command: str) -> dict:
    """Build a CSV row for a host connection error.

    Args:
        hostname: The host that failed to connect.
        error: The error message.
        command: "check" or "remediate".

    Returns:
        Dict with all columns, rule fields empty, error in detail.

    """
    row = {
        "host": hostname,
        "platform": "",
        "rule_id": "",
        "framework_section": "",
        "title": "",
        "severity": "",
        "passed": "",
        "skipped": "",
        "detail": f"Connection error: {error}",
    }
    if command == "remediate":
        row["remediated"] = ""
    return row


def _build_result_row(hostname: str, platform: str, result, command: str) -> dict:
    """Build a CSV row for a rule result.

    Args:
        hostname: The target host.
        platform: Formatted platform string.
        result: RuleResult object.
        command: "check" or "remediate".

    Returns:
        Dict with all columns populated from the result.

    """
    row = {
        "host": hostname,
        "platform": platform,
        "rule_id": result.rule_id,
        "framework_section": result.framework_section or "",
        "title": result.title,
        "severity": result.severity,
        "passed": str(result.passed).lower(),
        "skipped": str(result.skipped).lower(),
        "detail": result.detail or result.skip_reason or "",
    }

    if command == "remediate":
        row["remediated"] = str(result.remediated).lower()

    return row
