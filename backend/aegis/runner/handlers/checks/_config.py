"""Config-related check handlers.

Handlers for verifying configuration file state: key presence,
absence, and values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


# ── Comparator support ─────────────────────────────────────────────────────

# Valid comparators for config_value checks
VALID_COMPARATORS = frozenset({">=", "<=", ">", "<", "=="})


def _compare_values(actual: str, expected: str, comparator: str) -> bool:
    """Compare actual value against expected using the specified comparator.

    For "==" comparator, performs case-insensitive string comparison.
    For numeric comparators (>=, <=, >, <), attempts numeric comparison.

    Args:
        actual: The value found in the config file.
        expected: The expected value from the rule.
        comparator: One of ">=", "<=", ">", "<", "==".

    Returns:
        True if the comparison succeeds.

    """
    if comparator == "==":
        return actual.lower() == expected.lower()

    # For numeric comparators, try to parse as numbers
    try:
        actual_num = float(actual)
        expected_num = float(expected)
    except ValueError:
        # Fall back to string comparison if not numeric
        return actual.lower() == expected.lower()

    # Use dict dispatch for numeric comparators
    comparisons = {
        ">=": actual_num >= expected_num,
        "<=": actual_num <= expected_num,
        ">": actual_num > expected_num,
        "<": actual_num < expected_num,
    }
    return comparisons.get(comparator, actual.lower() == expected.lower())


def _format_comparison_detail(key: str, actual: str, expected: str, comparator: str, passed: bool) -> str:
    """Format the detail message for a comparison result.

    Args:
        key: Config key name.
        actual: Actual value found.
        expected: Expected value.
        comparator: Comparator used.
        passed: Whether the check passed.

    Returns:
        Formatted detail string.

    """
    if passed:
        if comparator == "==":
            return f"{key}={actual}"
        else:
            return f"{key}={actual} ({comparator} {expected})"
    else:
        if comparator == "==":
            return f"{key}={actual} (expected {expected})"
        else:
            return f"{key}={actual} (expected {comparator} {expected})"


def _check_config_value(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a configuration key has an expected value.

    Searches for a key in a config file or directory of config files.
    Supports both 'key value' and 'key=value' formats with optional
    whitespace around separators.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): File path or directory to search.
            - key (str): Configuration key name to find.
            - expected (str): Expected value for the key.
            - comparator (str, optional): Comparison operator.
              One of ">=", "<=", ">", "<", "==". Defaults to "==".
            - scan_pattern (str, optional): Glob for directory mode.
              Defaults to "*.conf".

    Returns:
        CheckResult with passed=True if key exists with expected value
        (or satisfies the comparator condition).

    """
    path = c["path"]
    key = c["key"]
    expected = str(c["expected"])
    comparator = c.get("comparator", "==")
    scan_pattern = c.get("scan_pattern", "*.conf")

    # Validate comparator
    if comparator not in VALID_COMPARATORS:
        return CheckResult(
            passed=False,
            detail=f"Invalid comparator '{comparator}' (must be one of: {', '.join(sorted(VALID_COMPARATORS))})",
        )

    result = shell_util.grep_config_key(ssh, path, key, scan_pattern=scan_pattern)

    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{key} not found in {path}")

    line = result.stdout.strip()
    actual = shell_util.parse_config_value(line, key)

    passed = _compare_values(actual, expected, comparator)
    detail = _format_comparison_detail(key, actual, expected, comparator, passed)

    return CheckResult(passed=passed, detail=detail)


def _check_config_absent(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a configuration key does NOT exist in a file.

    Verifies that a specific key is absent from a config file or directory.
    Used for ensuring deprecated or insecure options are removed.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): File path or directory to search.
            - key (str): Configuration key that should not exist.
            - scan_pattern (str, optional): Glob for directory mode.

    Returns:
        CheckResult with passed=True if key is not found.

    """
    path = c["path"]
    key = c["key"]
    scan_pattern = c.get("scan_pattern", "*.conf")

    result = shell_util.grep_config_key(ssh, path, key, scan_pattern=scan_pattern)

    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=True, detail=f"{key} not found in {path} (as required)")

    return CheckResult(passed=False, detail=f"{key} found in {path} (should be absent)")
