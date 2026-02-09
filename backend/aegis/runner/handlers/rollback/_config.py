"""Config-related rollback handlers.

Handlers for rolling back configuration file changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_config_set(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore config file line to pre-remediation state."""
    d = pre_state.data
    path, key = d["path"], d["key"]
    if d["existed"] and d["old_line"]:
        escaped = d["old_line"].replace("/", "\\/")
        cmd = f"sed -i 's/^ *{key}.*/{escaped}/' {shell_util.quote(path)}"
    else:
        cmd = f"sed -i '/^ *{key}/d' {shell_util.quote(path)}"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to restore {key} in {path}: {result.stderr}"
    if d.get("reload") or d.get("restart"):
        shell_util.service_action(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})
    return True, f"Restored {key} in {path}"


def _rollback_config_set_dropin(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore or remove drop-in file."""
    d = pre_state.data
    path = d["path"]
    if not d["existed"]:
        result = ssh.run(f"rm -f {shell_util.quote(path)}")
        if not result.ok:
            return False, f"Failed to remove {path}: {result.stderr}"
        detail = f"Removed {path}"
    else:
        if not shell_util.write_file(ssh, path, d["old_content"]):
            return False, f"Failed to restore {path}"
        detail = f"Restored {path}"
    if d.get("reload") or d.get("restart"):
        shell_util.service_action(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})
    return True, detail


def _rollback_config_remove(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore removed config lines."""
    d = pre_state.data
    path = d["path"]

    if not d["existed"] or d["old_lines"] is None:
        return True, f"No lines to restore in {path}"

    for line in d["old_lines"].splitlines():
        if not shell_util.append_line(ssh, path, line):
            return False, f"Failed to restore line in {path}"

    if d.get("reload") or d.get("restart"):
        shell_util.service_action(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})

    return True, f"Restored removed lines in {path}"


def _rollback_config_block(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore file to state before block was added."""
    d = pre_state.data
    path = d["path"]

    if not d["existed"]:
        ssh.run(f"rm -f {shell_util.quote(path)}")
        return True, f"Removed {path}"

    if d["old_content"] is not None and not shell_util.write_file(ssh, path, d["old_content"]):
        return False, f"Failed to restore {path}"

    if d.get("reload") or d.get("restart"):
        shell_util.service_action(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})

    return True, f"Restored {path}"
