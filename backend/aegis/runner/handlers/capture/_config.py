"""Config-related capture handlers.

Handlers for capturing pre-state of configuration files.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_config_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current config line before modification."""
    path = r["path"]
    key = r["key"]
    result = shell_util.grep_config_key(ssh, path, key)
    old_line = result.stdout.strip() if result.ok and result.stdout.strip() else None
    return PreState(
        mechanism="config_set",
        data={
            "path": path,
            "key": key,
            "old_line": old_line,
            "existed": old_line is not None,
            "reload": r.get("reload"),
            "restart": r.get("restart"),
        },
    )


def _capture_config_set_dropin(ssh: SSHSession, r: dict) -> PreState:
    """Capture drop-in file state before modification."""
    full_path = f"{r['dir']}/{r['file']}"
    exists = shell_util.file_exists(ssh, full_path)
    old_content = shell_util.read_file(ssh, full_path) if exists else None
    return PreState(
        mechanism="config_set_dropin",
        data={
            "path": full_path,
            "old_content": old_content,
            "existed": exists,
            "reload": r.get("reload"),
            "restart": r.get("restart"),
        },
    )


def _capture_config_remove(ssh: SSHSession, r: dict) -> PreState:
    """Capture config line before removal."""
    path = r["path"]
    key = r["key"]
    result = ssh.run(f"grep '^ *{key}' {shell_util.quote(path)} 2>/dev/null")
    old_lines = result.stdout.strip() if result.ok and result.stdout.strip() else None
    return PreState(
        mechanism="config_remove",
        data={
            "path": path,
            "key": key,
            "old_lines": old_lines,
            "existed": old_lines is not None,
            "reload": r.get("reload"),
            "restart": r.get("restart"),
        },
    )


def _capture_config_block(ssh: SSHSession, r: dict) -> PreState:
    """Capture file content before writing block."""
    path = r["path"]
    marker = r.get("marker", "# AEGIS MANAGED BLOCK")
    begin_marker = f"# BEGIN {marker}"

    exists = shell_util.file_exists(ssh, path)
    old_content = shell_util.read_file(ssh, path) if exists else None

    block_exists = ssh.run(f"grep -qF {shell_util.quote(begin_marker)} {shell_util.quote(path)} 2>/dev/null")

    return PreState(
        mechanism="config_block",
        data={
            "path": path,
            "existed": exists,
            "old_content": old_content,
            "block_existed": block_exists.ok,
            "marker": marker,
            "reload": r.get("reload"),
            "restart": r.get("restart"),
        },
    )
