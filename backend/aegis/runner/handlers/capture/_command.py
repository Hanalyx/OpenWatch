"""Command-related capture handlers.

Handlers for command execution and manual remediation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_command_exec(ssh: SSHSession, r: dict) -> PreState:
    """Command exec cannot capture pre-state.

    Args:
        ssh: Active SSH session (unused).
        r: Remediation definition.

    Returns:
        PreState with capturable=False.

    """
    return PreState(mechanism="command_exec", data={"note": "arbitrary command"}, capturable=False)


def _capture_manual(ssh: SSHSession, r: dict) -> PreState:
    """Manual mechanism cannot capture pre-state.

    Args:
        ssh: Active SSH session (unused).
        r: Remediation definition (unused).

    Returns:
        PreState with capturable=False.

    """
    return PreState(mechanism="manual", data={}, capturable=False)
