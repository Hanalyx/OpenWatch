"""JSON output formatter for compliance results.

Produces structured JSON output suitable for:
- Programmatic parsing by CI/CD pipelines
- Integration with monitoring systems
- Archival and audit trails
- Custom reporting tools

Output Structure:
    {
        "timestamp": "ISO-8601 datetime",
        "command": "check" or "remediate",
        "hosts": [...],
        "summary": {totals}
    }

Each host entry contains platform info, capabilities, and per-rule results.
The summary provides aggregate counts across all hosts.

Example:
-------
    >>> from runner.output import RunResult, format_json
    >>> result = RunResult(command="check")
    >>> json_str = format_json(result)
    >>> import json
    >>> data = json.loads(json_str)
    >>> print(data["summary"]["pass"])

"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from runner.output import RunResult


def format_json(run_result: RunResult) -> str:
    """Format compliance results as JSON.

    Produces a structured JSON document with full details for each host
    and rule. Includes capabilities, platform info, and summary statistics.

    Args:
        run_result: Aggregated results from a compliance run.

    Returns:
        Pretty-printed JSON string (2-space indent).

    Output Structure:
        - timestamp: ISO-8601 UTC timestamp of the run
        - command: "check" or "remediate"
        - hosts[]: Array of host results, each containing:
            - hostname: Target host address
            - platform: {family, version} or null
            - capabilities: Dict of detected capabilities
            - results[]: Array of rule results
            - summary: Per-host counts
            - error: Error message if connection failed
        - summary: Aggregate counts across all hosts

    Note:
        For remediate command, includes additional fields:
        - summary.fixed: Count of successfully remediated rules
        - results[].remediated: Whether rule was remediated
        - results[].remediation_detail: Details of remediation action
        - results[].rolled_back: Whether changes were rolled back

    """
    data: dict[str, Any] = {
        "timestamp": run_result.timestamp.isoformat(),
        "command": run_result.command,
        "hosts": [],
        "summary": {
            "hosts": run_result.host_count,
            "total": run_result.total_pass + run_result.total_fail + run_result.total_skip,
            "pass": run_result.total_pass,
            "fail": run_result.total_fail,
            "skip": run_result.total_skip,
        },
    }

    if run_result.command == "remediate":
        data["summary"]["fixed"] = run_result.total_fixed

    for host in run_result.hosts:
        host_data: dict[str, Any] = {
            "hostname": host.hostname,
            "platform": (
                {
                    "family": host.platform_family,
                    "version": host.platform_version,
                }
                if host.platform_family
                else None
            ),
            "capabilities": host.capabilities,
            "results": [],
            "summary": {
                "total": len(host.results),
                "pass": host.pass_count,
                "fail": host.fail_count,
                "skip": host.skip_count,
            },
        }

        if host.error:
            host_data["error"] = host.error

        if run_result.command == "remediate":
            host_data["summary"]["fixed"] = host.fixed_count

        for result in host.results:
            result_data = {
                "rule_id": result.rule_id,
                "title": result.title,
                "severity": result.severity,
                "passed": result.passed,
                "skipped": result.skipped,
                "detail": result.detail,
            }

            if result.skipped:
                result_data["skip_reason"] = result.skip_reason

            # Include framework section if present (when --framework was used)
            if result.framework_section:
                result_data["framework_section"] = result.framework_section

            # Include implementation if available
            if hasattr(result, "implementation") and result.implementation:
                result_data["implementation"] = result.implementation

            if run_result.command == "remediate":
                result_data["remediated"] = result.remediated
                if result.remediation_detail:
                    result_data["remediation_detail"] = result.remediation_detail
                if result.rolled_back:
                    result_data["rolled_back"] = result.rolled_back

            host_data["results"].append(result_data)

        data["hosts"].append(host_data)

    return json.dumps(data, indent=2)
