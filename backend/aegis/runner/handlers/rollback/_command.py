"""Command-related rollback handlers.

Handlers for command execution and manual remediation rollback.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_command_exec(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Cannot rollback arbitrary commands.

    Args:
        ssh: Active SSH session (unused).
        pre_state: Captured pre-state (unused).

    Returns:
        Tuple of (False, error message).

    """
    return False, "Cannot rollback arbitrary commands"


def _rollback_manual(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Nothing to rollback for manual mechanism.

    Args:
        ssh: Active SSH session (unused).
        pre_state: Captured pre-state (unused).

    Returns:
        Tuple of (False, message).

    """
    return False, "Nothing to rollback"
