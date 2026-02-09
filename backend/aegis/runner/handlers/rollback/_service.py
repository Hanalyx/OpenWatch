"""Service-related rollback handlers.

Handlers for rolling back systemd service changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_service_enabled(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore service to pre-enabled state."""
    d = pre_state.data
    name = d["name"]
    was_enabled = d["was_enabled"]
    was_active = d["was_active"]

    if was_enabled in ("disabled", "masked"):
        ssh.run(f"systemctl disable {shell_util.quote(name)}")
    elif was_enabled == "masked":
        ssh.run(f"systemctl mask {shell_util.quote(name)}")

    if was_active in ("inactive", "failed", "unknown"):
        ssh.run(f"systemctl stop {shell_util.quote(name)}")

    return True, f"Restored {name} to {was_enabled}/{was_active}"


def _rollback_service_disabled(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore service to pre-disabled state."""
    d = pre_state.data
    name = d["name"]
    was_enabled = d["was_enabled"]
    was_active = d["was_active"]

    if was_enabled == "enabled":
        ssh.run(f"systemctl enable {shell_util.quote(name)}")

    if was_active == "active":
        ssh.run(f"systemctl start {shell_util.quote(name)}")

    return True, f"Restored {name} to {was_enabled}/{was_active}"


def _rollback_service_masked(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore service from masked state."""
    d = pre_state.data
    name = d["name"]
    was_enabled = d["was_enabled"]
    was_active = d["was_active"]

    ssh.run(f"systemctl unmask {shell_util.quote(name)}")

    if was_enabled == "enabled":
        ssh.run(f"systemctl enable {shell_util.quote(name)}")

    if was_active == "active":
        ssh.run(f"systemctl start {shell_util.quote(name)}")

    return True, f"Restored {name} to {was_enabled}/{was_active}"
