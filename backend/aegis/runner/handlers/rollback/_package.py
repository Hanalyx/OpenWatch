"""Package-related rollback handlers.

Handlers for rolling back package changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_package_present(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Remove package if it was not installed before."""
    d = pre_state.data
    if d["was_installed"]:
        return True, f"{d['name']} was already installed, nothing to rollback"
    result = ssh.run(f"dnf remove -y {shell_util.quote(d['name'])}", timeout=300)
    if not result.ok:
        return False, f"Failed to remove {d['name']}: {result.stderr}"
    return True, f"Removed {d['name']}"


def _rollback_package_absent(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Re-install package if it was installed before."""
    d = pre_state.data
    if not d["was_installed"]:
        return True, f"{d['name']} was not installed, nothing to restore"
    result = ssh.run(f"dnf install -y {shell_util.quote(d['name'])}", timeout=300)
    if not result.ok:
        return False, f"Failed to reinstall {d['name']}: {result.stderr}"
    return True, f"Reinstalled {d['name']}"
