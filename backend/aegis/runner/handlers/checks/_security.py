"""Security-related check handlers.

Handlers for verifying security subsystem state: SELinux, audit rules,
and PAM configuration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_selinux_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check SELinux enforcement mode.

    Uses getenforce to check the current SELinux mode.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with optional fields:
            - state (str): Expected mode. Defaults to "Enforcing".

    Returns:
        CheckResult with passed=True if SELinux is in expected mode.

    """
    expected = c.get("state", "Enforcing")

    result = ssh.run("getenforce 2>/dev/null")
    if not result.ok:
        return CheckResult(passed=False, detail="getenforce failed - SELinux may not be installed")

    actual = result.stdout.strip()
    if actual.lower() == expected.lower():
        return CheckResult(passed=True, detail=f"SELinux: {actual}")
    return CheckResult(passed=False, detail=f"SELinux: {actual} (expected {expected})")


def _check_selinux_boolean(ssh: SSHSession, c: dict) -> CheckResult:
    """Check SELinux boolean setting.

    Uses getsebool to check the current value of a SELinux boolean.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): SELinux boolean name.
            - value (bool, optional): Expected value. Defaults to True.

    Returns:
        CheckResult with passed=True if boolean has expected value.

    """
    name = c["name"]
    expected = c.get("value", True)
    expected_str = "on" if expected else "off"

    result = ssh.run(f"getsebool {shell_util.quote(name)} 2>/dev/null")
    if not result.ok:
        return CheckResult(passed=False, detail=f"{name}: not found or SELinux disabled")

    parts = result.stdout.strip().split()
    if len(parts) < 3:
        return CheckResult(passed=False, detail=f"{name}: unexpected output format")

    actual = parts[-1]
    if actual.lower() == expected_str:
        return CheckResult(passed=True, detail=f"{name} = {actual}")
    return CheckResult(passed=False, detail=f"{name} = {actual} (expected {expected_str})")


def _check_audit_rule_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that an audit rule is active.

    Uses auditctl -l to list current audit rules and searches for the
    specified rule.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - rule (str): Full or partial audit rule to search for.

    Returns:
        CheckResult with passed=True if rule is found.

    """
    rule = c["rule"]

    result = ssh.run("auditctl -l 2>/dev/null")
    if not result.ok:
        return CheckResult(passed=False, detail="auditctl failed - auditd may not be running")

    if rule in result.stdout:
        return CheckResult(passed=True, detail="Audit rule found")
    return CheckResult(passed=False, detail=f"Audit rule not found: {rule[:50]}...")


def _check_pam_module(ssh: SSHSession, c: dict) -> CheckResult:
    """Check PAM module configuration in a service's PAM stack.

    Verifies that a PAM module is present in a service's PAM configuration
    with the expected type, control, and optional arguments.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - service (str): PAM service name.
            - module (str): PAM module name.
            - type (str, optional): PAM type to check.
            - control (str, optional): Expected control value.
            - args (str, optional): Expected arguments.

    Returns:
        CheckResult with passed=True if module is configured as expected.

    """
    service = c["service"]
    module = c["module"]
    expected_type = c.get("type")
    expected_control = c.get("control")
    expected_args = c.get("args")

    pam_file = f"/etc/pam.d/{service}"

    if not shell_util.file_exists(ssh, pam_file):
        return CheckResult(passed=False, detail=f"{pam_file}: not found")

    result = ssh.run(f"grep -E '\\s{shell_util.quote(module)}(\\s|$)' {shell_util.quote(pam_file)} 2>/dev/null")
    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{module} not found in {pam_file}")

    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        line_type = parts[0].lstrip("-")
        line_control = parts[1]
        line_module = parts[2]
        line_args = " ".join(parts[3:]) if len(parts) > 3 else ""

        if module not in line_module:
            continue
        if expected_type and line_type != expected_type:
            continue
        if expected_control and line_control != expected_control:
            continue
        if expected_args and expected_args not in line_args:
            continue

        detail = f"{line_type} {line_control} {module}"
        if line_args:
            detail += f" ({line_args[:50]}{'...' if len(line_args) > 50 else ''})"
        return CheckResult(passed=True, detail=detail)

    detail = f"{module} in {pam_file}: "
    if expected_type:
        detail += f"type={expected_type} "
    if expected_control:
        detail += f"control={expected_control} "
    if expected_args:
        detail += f"args containing '{expected_args}' "
    detail += "not found"
    return CheckResult(passed=False, detail=detail)
