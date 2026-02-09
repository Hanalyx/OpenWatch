"""File-related rollback handlers.

Handlers for rolling back file changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_file_permissions(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore original file ownership and permissions."""
    entries = pre_state.data.get("entries", [])
    if not entries:
        return False, "No file entries to restore"
    for entry in entries:
        p = shell_util.quote(entry["path"])
        ssh.run(f"chown {entry['owner']}:{entry['group']} {p}")
        ssh.run(f"chmod {entry['mode']} {p}")
    return True, f"Restored permissions on {len(entries)} file(s)"


def _rollback_file_content(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore file to its previous content."""
    d = pre_state.data
    path = d["path"]

    if not d["existed"]:
        result = ssh.run(f"rm -f {shell_util.quote(path)}")
        if not result.ok:
            return False, f"Failed to remove {path}: {result.stderr}"
        return True, f"Removed {path}"

    if d["old_content"] is not None and not shell_util.write_file(ssh, path, d["old_content"]):
        return False, f"Failed to restore {path}"

    if d["old_owner"] or d["old_group"]:
        shell_util.set_file_owner(ssh, path, d["old_owner"], d["old_group"])
    if d["old_mode"]:
        shell_util.set_file_mode(ssh, path, d["old_mode"])

    return True, f"Restored {path}"


def _rollback_file_absent(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore a removed file."""
    d = pre_state.data
    path = d["path"]

    if not d["existed"]:
        return True, f"{path} was already absent, nothing to restore"

    if d["old_content"] is None:
        return False, f"Cannot restore {path}: content not captured"

    if not shell_util.write_file(ssh, path, d["old_content"]):
        return False, f"Failed to restore {path}"

    if d["old_owner"] or d["old_group"]:
        shell_util.set_file_owner(ssh, path, d["old_owner"], d["old_group"])
    if d["old_mode"]:
        shell_util.set_file_mode(ssh, path, d["old_mode"])

    return True, f"Restored {path}"
