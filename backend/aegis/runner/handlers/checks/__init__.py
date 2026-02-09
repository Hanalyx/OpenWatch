"""Check handlers dispatch.

This module aggregates all check handlers and provides the dispatch
function for running checks against remote hosts.

Handler Modules:
    - _config: config_value, config_absent
    - _file: file_permission, file_exists, file_not_exists,
             file_content_match, file_content_no_match
    - _system: sysctl_value, kernel_module_state, mount_option, grub_parameter
    - _service: service_state
    - _package: package_state
    - _security: selinux_state, selinux_boolean, audit_rule_exists, pam_module
    - _command: command

Example:
-------
    >>> from runner.handlers.checks import run_check
    >>> check = {"method": "file_exists", "path": "/etc/passwd"}
    >>> result = run_check(ssh, check)

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner._types import CheckResult
from runner.handlers.checks._command import _check_command
from runner.handlers.checks._config import _check_config_absent, _check_config_value
from runner.handlers.checks._file import (
    _check_file_content_match,
    _check_file_content_no_match,
    _check_file_exists,
    _check_file_not_exists,
    _check_file_permission,
)
from runner.handlers.checks._package import _check_package_state
from runner.handlers.checks._security import (
    _check_audit_rule_exists,
    _check_pam_module,
    _check_selinux_boolean,
    _check_selinux_state,
)
from runner.handlers.checks._service import _check_service_state, _check_systemd_target
from runner.handlers.checks._system import (
    _check_grub_parameter,
    _check_kernel_module_state,
    _check_mount_option,
    _check_sysctl_value,
)

if TYPE_CHECKING:
    from runner.ssh import SSHSession


# ── Handler registry ──────────────────────────────────────────────────────

CHECK_HANDLERS = {
    # Config handlers
    "config_value": _check_config_value,
    "config_absent": _check_config_absent,
    # File handlers
    "file_permission": _check_file_permission,
    "file_exists": _check_file_exists,
    "file_not_exists": _check_file_not_exists,
    "file_content_match": _check_file_content_match,
    "file_content_no_match": _check_file_content_no_match,
    # System handlers
    "sysctl_value": _check_sysctl_value,
    "kernel_module_state": _check_kernel_module_state,
    "mount_option": _check_mount_option,
    "grub_parameter": _check_grub_parameter,
    # Service handlers
    "service_state": _check_service_state,
    "systemd_target": _check_systemd_target,
    # Package handlers
    "package_state": _check_package_state,
    # Security handlers
    "selinux_state": _check_selinux_state,
    "selinux_boolean": _check_selinux_boolean,
    "audit_rule_exists": _check_audit_rule_exists,
    "pam_module": _check_pam_module,
    # Command handler
    "command": _check_command,
}


# ── Dispatch functions ────────────────────────────────────────────────────


def run_check(ssh: SSHSession, check: dict) -> CheckResult:
    """Dispatch a single check definition to the appropriate handler.

    Supports both single checks and multi-condition checks (AND semantics).
    For multi-condition checks, all sub-checks must pass for the overall
    check to pass; evaluation short-circuits on first failure.

    Args:
        ssh: Active SSH session to the target host.
        check: Check definition dict from rule YAML. Must contain either:
            - "method": str - single check method name
            - "checks": list[dict] - multiple checks with AND semantics

    Returns:
        CheckResult with passed=True if all conditions met, False otherwise.

    """
    # Multi-condition check (AND semantics)
    if "checks" in check:
        details = []
        for sub in check["checks"]:
            r = _dispatch_check(ssh, sub)
            if not r.passed:
                return CheckResult(passed=False, detail=r.detail)
            details.append(r.detail)
        return CheckResult(passed=True, detail="; ".join(d for d in details if d))

    return _dispatch_check(ssh, check)


def _dispatch_check(ssh: SSHSession, check: dict) -> CheckResult:
    """Dispatch a single check to its handler.

    Args:
        ssh: Active SSH session.
        check: Check definition with "method" key.

    Returns:
        CheckResult from the handler.

    """
    method = check.get("method", "")
    handler = CHECK_HANDLERS.get(method)
    if handler is None:
        return CheckResult(passed=False, detail=f"Unknown check method: {method}")
    return handler(ssh, check)
