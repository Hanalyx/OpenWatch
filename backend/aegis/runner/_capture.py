"""Pre-state capture handlers and dispatch.

This module re-exports capture handlers from runner.handlers.capture for
backward compatibility. All implementations are in the handlers subpackage.
"""

from runner.handlers.capture import CAPTURE_HANDLERS, _dispatch_capture

# Re-export individual handlers for backward compatibility
from runner.handlers.capture._command import _capture_command_exec, _capture_manual  # noqa: F401
from runner.handlers.capture._config import (  # noqa: F401
    _capture_config_block,
    _capture_config_remove,
    _capture_config_set,
    _capture_config_set_dropin,
)
from runner.handlers.capture._file import (  # noqa: F401
    _capture_file_absent,
    _capture_file_content,
    _capture_file_permissions,
)
from runner.handlers.capture._package import _capture_package_absent, _capture_package_present  # noqa: F401
from runner.handlers.capture._security import _capture_audit_rule_set, _capture_selinux_boolean_set  # noqa: F401
from runner.handlers.capture._service import (  # noqa: F401
    _capture_service_disabled,
    _capture_service_enabled,
    _capture_service_masked,
)
from runner.handlers.capture._system import (  # noqa: F401
    _capture_cron_job,
    _capture_grub_parameter_remove,
    _capture_grub_parameter_set,
    _capture_kernel_module_disable,
    _capture_mount_option_set,
    _capture_sysctl_set,
)

__all__ = ["CAPTURE_HANDLERS", "_dispatch_capture"]
