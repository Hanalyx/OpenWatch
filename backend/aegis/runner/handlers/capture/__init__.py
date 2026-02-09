"""Pre-state capture handlers package.

This package provides handlers for capturing pre-remediation state to enable
rollback. Each handler captures the state that would be modified by the
corresponding remediation mechanism.

Example:
    >>> from runner.handlers.capture import capture_pre_state
    >>> pre_state = capture_pre_state(ssh, {"mechanism": "config_set", ...})
    >>> # pre_state.data contains the current config line

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner._types import PreState
from runner.handlers.capture._command import _capture_command_exec, _capture_manual
from runner.handlers.capture._config import (
    _capture_config_block,
    _capture_config_remove,
    _capture_config_set,
    _capture_config_set_dropin,
)
from runner.handlers.capture._file import _capture_file_absent, _capture_file_content, _capture_file_permissions
from runner.handlers.capture._package import _capture_package_absent, _capture_package_present
from runner.handlers.capture._security import _capture_audit_rule_set, _capture_selinux_boolean_set
from runner.handlers.capture._service import (
    _capture_service_disabled,
    _capture_service_enabled,
    _capture_service_masked,
)
from runner.handlers.capture._system import (
    _capture_cron_job,
    _capture_grub_parameter_remove,
    _capture_grub_parameter_set,
    _capture_kernel_module_disable,
    _capture_mount_option_set,
    _capture_sysctl_set,
)

if TYPE_CHECKING:
    from runner.ssh import SSHSession


# Registry mapping mechanism names to capture handler functions
CAPTURE_HANDLERS = {
    # Config handlers
    "config_set": _capture_config_set,
    "config_set_dropin": _capture_config_set_dropin,
    "config_remove": _capture_config_remove,
    "config_block": _capture_config_block,
    # File handlers
    "file_permissions": _capture_file_permissions,
    "file_content": _capture_file_content,
    "file_absent": _capture_file_absent,
    # Package handlers
    "package_present": _capture_package_present,
    "package_absent": _capture_package_absent,
    # Service handlers
    "service_enabled": _capture_service_enabled,
    "service_disabled": _capture_service_disabled,
    "service_masked": _capture_service_masked,
    # System handlers
    "sysctl_set": _capture_sysctl_set,
    "kernel_module_disable": _capture_kernel_module_disable,
    "mount_option_set": _capture_mount_option_set,
    "grub_parameter_set": _capture_grub_parameter_set,
    "grub_parameter_remove": _capture_grub_parameter_remove,
    "cron_job": _capture_cron_job,
    # Security handlers
    "selinux_boolean_set": _capture_selinux_boolean_set,
    "audit_rule_set": _capture_audit_rule_set,
    # Command handlers
    "command_exec": _capture_command_exec,
    "manual": _capture_manual,
}


def _dispatch_capture(ssh: SSHSession, rem: dict) -> PreState | None:
    """Capture pre-state for a remediation step.

    Args:
        ssh: Active SSH session to the target host.
        rem: Remediation definition dict with 'mechanism' key.

    Returns:
        PreState object or None if no handler for the mechanism.

    """
    mechanism = rem.get("mechanism", "")
    handler = CAPTURE_HANDLERS.get(mechanism)
    if handler is None:
        return None
    return handler(ssh, rem)


__all__ = ["CAPTURE_HANDLERS", "_dispatch_capture"]
