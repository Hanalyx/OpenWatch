"""Remediation handlers package.

This package provides all remediation handlers that modify remote host state
to achieve compliance. Each handler implements a specific remediation mechanism
(e.g., config_set, package_present) defined in the rule schema.

Remediation Handler Pattern:
    All remediation handlers follow a consistent signature and behavior:
    - Accept an SSHSession, a remediation dict, and a dry_run flag
    - Return (success: bool, detail: str)
    - Support dry_run mode to preview changes without applying them
    - Use shell_util.quote() for all values from rule YAML
    - Call shell_util.service_action() for mechanisms that modify service configs

Example:
    >>> from runner.ssh import SSHSession
    >>> from runner.handlers.remediation import run_remediation
    >>>
    >>> remediation = {
    ...     "mechanism": "config_set",
    ...     "path": "/etc/ssh/sshd_config",
    ...     "key": "PermitRootLogin",
    ...     "value": "no",
    ...     "reload": "sshd"
    ... }
    >>> success, detail, steps = run_remediation(ssh, remediation, dry_run=True)
    >>> print(detail)  # "Would set 'PermitRootLogin no' in /etc/ssh/sshd_config"

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner._capture import _dispatch_capture
from runner._checks import run_check
from runner._types import StepResult

# Import handlers from domain modules
from runner.handlers.remediation._command import _remediate_command_exec, _remediate_manual
from runner.handlers.remediation._config import (
    _remediate_config_block,
    _remediate_config_remove,
    _remediate_config_set,
    _remediate_config_set_dropin,
)
from runner.handlers.remediation._file import (
    _remediate_file_absent,
    _remediate_file_content,
    _remediate_file_permissions,
)
from runner.handlers.remediation._package import _remediate_package_absent, _remediate_package_present
from runner.handlers.remediation._security import (
    _remediate_audit_rule_set,
    _remediate_pam_module_configure,
    _remediate_selinux_boolean_set,
)
from runner.handlers.remediation._service import (
    _remediate_service_disabled,
    _remediate_service_enabled,
    _remediate_service_masked,
)
from runner.handlers.remediation._system import (
    _remediate_cron_job,
    _remediate_grub_parameter_remove,
    _remediate_grub_parameter_set,
    _remediate_kernel_module_disable,
    _remediate_mount_option_set,
    _remediate_sysctl_set,
)

if TYPE_CHECKING:
    from runner.ssh import SSHSession


# Registry mapping mechanism names to handler functions
REMEDIATION_HANDLERS = {
    # Config handlers
    "config_set": _remediate_config_set,
    "config_set_dropin": _remediate_config_set_dropin,
    "config_remove": _remediate_config_remove,
    "config_block": _remediate_config_block,
    # File handlers
    "file_permissions": _remediate_file_permissions,
    "file_content": _remediate_file_content,
    "file_absent": _remediate_file_absent,
    # Package handlers
    "package_present": _remediate_package_present,
    "package_absent": _remediate_package_absent,
    # Service handlers
    "service_enabled": _remediate_service_enabled,
    "service_disabled": _remediate_service_disabled,
    "service_masked": _remediate_service_masked,
    # System handlers
    "sysctl_set": _remediate_sysctl_set,
    "kernel_module_disable": _remediate_kernel_module_disable,
    "mount_option_set": _remediate_mount_option_set,
    "grub_parameter_set": _remediate_grub_parameter_set,
    "grub_parameter_remove": _remediate_grub_parameter_remove,
    "cron_job": _remediate_cron_job,
    # Security handlers
    "selinux_boolean_set": _remediate_selinux_boolean_set,
    "audit_rule_set": _remediate_audit_rule_set,
    "pam_module_configure": _remediate_pam_module_configure,
    # Command handlers
    "command_exec": _remediate_command_exec,
    "manual": _remediate_manual,
}


def _dispatch_remediation(ssh: SSHSession, rem: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Dispatch to the appropriate remediation handler.

    Args:
        ssh: Active SSH session to the target host.
        rem: Remediation definition dict with 'mechanism' key.
        dry_run: If True, describe changes without applying them.

    Returns:
        Tuple of (success, detail).

    """
    mechanism = rem.get("mechanism", "")
    handler = REMEDIATION_HANDLERS.get(mechanism)
    if handler is None:
        return False, f"Unknown remediation mechanism: {mechanism}"
    return handler(ssh, rem, dry_run=dry_run)


def run_remediation(
    ssh: SSHSession,
    remediation: dict,
    *,
    dry_run: bool = False,
    check: dict | None = None,
) -> tuple[bool, str, list[StepResult]]:
    """Execute a remediation and optionally verify the result.

    Supports both single-step and multi-step remediations. For multi-step,
    executes sequentially and stops on first failure. Captures pre-state
    for each step to enable rollback.

    Args:
        ssh: Active SSH session to the target host.
        remediation: Remediation definition dict from rule YAML. Must contain:
            - "mechanism": str for single-step, or
            - "steps": list[dict] for multi-step remediation
        dry_run: If True, describe changes without applying them.
        check: Optional check definition for post-remediation verification.

    Returns:
        Tuple of (success, detail, step_results):
            - success: True if all steps completed successfully
            - detail: Human-readable summary of actions taken
            - step_results: List of StepResult for each step (for rollback)

    Example:
        Single-step remediation::

            remediation = {"mechanism": "config_set", "path": "...", "key": "...", "value": "..."}
            success, detail, steps = run_remediation(ssh, remediation)

        Multi-step remediation::

            remediation = {
                "steps": [
                    {"mechanism": "package_present", "name": "aide"},
                    {"mechanism": "command_exec", "run": "aide --init"}
                ]
            }
            success, detail, steps = run_remediation(ssh, remediation)

    """
    # Multi-step remediation
    if "steps" in remediation:
        details = []
        step_results: list[StepResult] = []
        for i, step in enumerate(remediation["steps"]):
            mech = step.get("mechanism", "")
            pre_state = _dispatch_capture(ssh, step) if not dry_run else None
            ok, detail = _dispatch_remediation(ssh, step, dry_run=dry_run)
            details.append(detail)
            sr = StepResult(i, mech, ok, detail, pre_state)
            # Per-step verification (multi-step only, not dry_run)
            if ok and not dry_run and check:
                cr = run_check(ssh, check)
                sr.verified = cr.passed
                sr.verify_detail = cr.detail
            step_results.append(sr)
            if not ok:
                return False, "; ".join(details), step_results
        return True, "; ".join(details), step_results

    # Single-step
    mech = remediation.get("mechanism", "")
    pre_state = _dispatch_capture(ssh, remediation) if not dry_run else None
    ok, detail = _dispatch_remediation(ssh, remediation, dry_run=dry_run)
    sr = StepResult(0, mech, ok, detail, pre_state)
    return ok, detail, [sr]


__all__ = ["REMEDIATION_HANDLERS", "run_remediation"]
