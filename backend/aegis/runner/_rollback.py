"""Rollback handlers and dispatch.

This module re-exports rollback handlers from runner.handlers.rollback for
backward compatibility. All implementations are in the handlers subpackage.
"""

from runner.handlers.rollback import ROLLBACK_HANDLERS, _execute_rollback

# Re-export individual handlers for backward compatibility
from runner.handlers.rollback._command import _rollback_command_exec, _rollback_manual  # noqa: F401
from runner.handlers.rollback._config import (  # noqa: F401
    _rollback_config_block,
    _rollback_config_remove,
    _rollback_config_set,
    _rollback_config_set_dropin,
)
from runner.handlers.rollback._file import (  # noqa: F401
    _rollback_file_absent,
    _rollback_file_content,
    _rollback_file_permissions,
)
from runner.handlers.rollback._package import _rollback_package_absent, _rollback_package_present  # noqa: F401
from runner.handlers.rollback._security import _rollback_audit_rule_set, _rollback_selinux_boolean_set  # noqa: F401
from runner.handlers.rollback._service import (  # noqa: F401
    _rollback_service_disabled,
    _rollback_service_enabled,
    _rollback_service_masked,
)
from runner.handlers.rollback._system import (  # noqa: F401
    _rollback_cron_job,
    _rollback_grub_parameter_remove,
    _rollback_grub_parameter_set,
    _rollback_kernel_module_disable,
    _rollback_mount_option_set,
    _rollback_sysctl_set,
)

__all__ = ["ROLLBACK_HANDLERS", "_execute_rollback"]
