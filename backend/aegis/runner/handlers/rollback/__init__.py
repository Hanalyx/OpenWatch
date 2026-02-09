"""Rollback handlers package.

This package provides handlers for rolling back remediation changes to their
pre-remediation state. Each handler restores state captured by the corresponding
capture handler.

Example:
    >>> from runner.handlers.rollback import execute_rollback
    >>> results = execute_rollback(ssh, step_results)

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner._types import RollbackResult, StepResult
from runner.handlers.rollback._command import _rollback_command_exec, _rollback_manual
from runner.handlers.rollback._config import (
    _rollback_config_block,
    _rollback_config_remove,
    _rollback_config_set,
    _rollback_config_set_dropin,
)
from runner.handlers.rollback._file import _rollback_file_absent, _rollback_file_content, _rollback_file_permissions
from runner.handlers.rollback._package import _rollback_package_absent, _rollback_package_present
from runner.handlers.rollback._security import _rollback_audit_rule_set, _rollback_selinux_boolean_set
from runner.handlers.rollback._service import (
    _rollback_service_disabled,
    _rollback_service_enabled,
    _rollback_service_masked,
)
from runner.handlers.rollback._system import (
    _rollback_cron_job,
    _rollback_grub_parameter_remove,
    _rollback_grub_parameter_set,
    _rollback_kernel_module_disable,
    _rollback_mount_option_set,
    _rollback_sysctl_set,
)

if TYPE_CHECKING:
    from runner.ssh import SSHSession


# Registry mapping mechanism names to rollback handler functions
ROLLBACK_HANDLERS = {
    # Config handlers
    "config_set": _rollback_config_set,
    "config_set_dropin": _rollback_config_set_dropin,
    "config_remove": _rollback_config_remove,
    "config_block": _rollback_config_block,
    # File handlers
    "file_permissions": _rollback_file_permissions,
    "file_content": _rollback_file_content,
    "file_absent": _rollback_file_absent,
    # Package handlers
    "package_present": _rollback_package_present,
    "package_absent": _rollback_package_absent,
    # Service handlers
    "service_enabled": _rollback_service_enabled,
    "service_disabled": _rollback_service_disabled,
    "service_masked": _rollback_service_masked,
    # System handlers
    "sysctl_set": _rollback_sysctl_set,
    "kernel_module_disable": _rollback_kernel_module_disable,
    "mount_option_set": _rollback_mount_option_set,
    "grub_parameter_set": _rollback_grub_parameter_set,
    "grub_parameter_remove": _rollback_grub_parameter_remove,
    "cron_job": _rollback_cron_job,
    # Security handlers
    "selinux_boolean_set": _rollback_selinux_boolean_set,
    "audit_rule_set": _rollback_audit_rule_set,
    # Command handlers
    "command_exec": _rollback_command_exec,
    "manual": _rollback_manual,
}


def _execute_rollback(ssh: SSHSession, step_results: list[StepResult]) -> list[RollbackResult]:
    """Roll back completed steps in reverse order.

    Args:
        ssh: Active SSH session to the target host.
        step_results: List of StepResult from remediation.

    Returns:
        List of RollbackResult for each step.

    """
    results = []
    for sr in reversed(step_results):
        if not sr.success or sr.pre_state is None or not sr.pre_state.capturable:
            results.append(RollbackResult(sr.step_index, sr.mechanism, False, "skipped"))
            continue
        handler = ROLLBACK_HANDLERS.get(sr.mechanism)
        if handler is None:
            results.append(RollbackResult(sr.step_index, sr.mechanism, False, "no handler"))
            continue
        ok, detail = handler(ssh, sr.pre_state)
        results.append(RollbackResult(sr.step_index, sr.mechanism, ok, detail))
    return results


__all__ = ["ROLLBACK_HANDLERS", "_execute_rollback"]
