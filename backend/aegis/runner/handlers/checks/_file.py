"""File-related check handlers.

Handlers for verifying file state: existence, permissions, and content.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_file_permission(ssh: SSHSession, c: dict) -> CheckResult:
    """Check file ownership and permissions.

    Verifies owner, group, and/or mode of one or more files. Supports
    glob patterns to check multiple files matching a pattern.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): File path or glob pattern.
            - owner (str, optional): Expected file owner.
            - group (str, optional): Expected file group.
            - mode (str, optional): Expected octal mode (e.g., "0600").
            - glob (bool, optional): Explicit glob flag.

    Returns:
        CheckResult with passed=True if all specified attributes match.

    """
    path = c["path"]
    is_glob = "glob" in c or shell_util.is_glob_path(path)

    result = shell_util.get_file_stat(ssh, path, allow_glob=is_glob)

    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{path}: not found or not accessible")

    all_failures = []
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        actual_owner, actual_group, actual_mode = parts[0], parts[1], parts[2]
        file_path = " ".join(parts[3:])
        failures = []

        if "owner" in c and actual_owner != c["owner"]:
            failures.append(f"owner={actual_owner} (expected {c['owner']})")
        if "group" in c and actual_group != c["group"]:
            failures.append(f"group={actual_group} (expected {c['group']})")
        if "mode" in c:
            expected_mode = c["mode"].lstrip("0") or "0"
            actual_mode_norm = actual_mode.lstrip("0") or "0"
            if actual_mode_norm != expected_mode:
                failures.append(f"mode={actual_mode} (expected {c['mode']})")

        if failures:
            all_failures.append(f"{file_path}: {', '.join(failures)}")

    if all_failures:
        return CheckResult(passed=False, detail="; ".join(all_failures))
    return CheckResult(passed=True, detail=f"{path}: ok")


def _check_file_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a file exists.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.

    Returns:
        CheckResult with passed=True if file exists.

    """
    path = c["path"]
    if shell_util.file_exists(ssh, path):
        return CheckResult(passed=True, detail=f"{path}: exists")
    return CheckResult(passed=False, detail=f"{path}: not found")


def _check_file_not_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a file does NOT exist.

    Used for ensuring insecure or deprecated files have been removed.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path that should not exist.

    Returns:
        CheckResult with passed=True if file does not exist.

    """
    path = c["path"]
    if not shell_util.file_exists(ssh, path):
        return CheckResult(passed=True, detail=f"{path}: not present (as required)")
    return CheckResult(passed=False, detail=f"{path}: exists (should be absent)")


def _check_file_content_match(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that file content matches a regex pattern.

    Uses grep -E (extended regex) to search for the pattern.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.
            - pattern (str): Extended regex pattern to match.

    Returns:
        CheckResult with passed=True if pattern is found in file.

    """
    path = c["path"]
    pattern = c["pattern"]

    if not shell_util.file_exists(ssh, path):
        return CheckResult(passed=False, detail=f"{path}: not found")

    result = ssh.run(f"grep -qE {shell_util.quote(pattern)} {shell_util.quote(path)}")
    if result.ok:
        return CheckResult(passed=True, detail=f"{path}: contains pattern")
    return CheckResult(passed=False, detail=f"{path}: pattern not found")


def _check_file_content_no_match(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that file content does NOT match a regex pattern.

    Verifies that a prohibited pattern is absent from the file.
    If the file does not exist, the check passes.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - path (str): Absolute path to the file.
            - pattern (str): Extended regex pattern that should not match.

    Returns:
        CheckResult with passed=True if pattern is not found.

    """
    path = c["path"]
    pattern = c["pattern"]

    if not shell_util.file_exists(ssh, path):
        return CheckResult(passed=True, detail=f"{path}: not found (pattern cannot exist)")

    result = ssh.run(f"grep -qE {shell_util.quote(pattern)} {shell_util.quote(path)}")
    if not result.ok:
        return CheckResult(passed=True, detail=f"{path}: pattern not found (as required)")
    return CheckResult(passed=False, detail=f"{path}: contains prohibited pattern")
