"""File-related capture handlers.

Handlers for capturing pre-state of files.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_file_permissions(ssh: SSHSession, r: dict) -> PreState:
    """Capture current file ownership and permissions."""
    path = r["path"]
    is_glob = r.get("glob") or shell_util.is_glob_path(path)
    quoted = shell_util.quote_path(path, allow_glob=is_glob)
    result = ssh.run(f"stat -c '%U %G %a %n' {quoted} 2>/dev/null")
    entries = []
    if result.ok and result.stdout.strip():
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                entries.append(
                    {
                        "path": " ".join(parts[3:]),
                        "owner": parts[0],
                        "group": parts[1],
                        "mode": parts[2],
                    }
                )
    return PreState(mechanism="file_permissions", data={"entries": entries})


def _capture_file_content(ssh: SSHSession, r: dict) -> PreState:
    """Capture current file content before modification."""
    path = r["path"]
    exists = shell_util.file_exists(ssh, path)
    old_content = None
    old_owner = None
    old_group = None
    old_mode = None

    if exists:
        old_content = shell_util.read_file(ssh, path)
        stat_result = shell_util.get_file_stat(ssh, path)
        if stat_result.ok and stat_result.stdout.strip():
            parts = stat_result.stdout.strip().split()
            if len(parts) >= 3:
                old_owner = parts[0]
                old_group = parts[1]
                old_mode = parts[2]

    return PreState(
        mechanism="file_content",
        data={
            "path": path,
            "existed": exists,
            "old_content": old_content,
            "old_owner": old_owner,
            "old_group": old_group,
            "old_mode": old_mode,
        },
    )


def _capture_file_absent(ssh: SSHSession, r: dict) -> PreState:
    """Capture file state before removal."""
    path = r["path"]
    exists = shell_util.file_exists(ssh, path)
    old_content = None
    old_owner = None
    old_group = None
    old_mode = None

    if exists:
        old_content = shell_util.read_file(ssh, path)
        stat_result = shell_util.get_file_stat(ssh, path)
        if stat_result.ok and stat_result.stdout.strip():
            parts = stat_result.stdout.strip().split()
            if len(parts) >= 3:
                old_owner = parts[0]
                old_group = parts[1]
                old_mode = parts[2]

    return PreState(
        mechanism="file_absent",
        data={
            "path": path,
            "existed": exists,
            "old_content": old_content,
            "old_owner": old_owner,
            "old_group": old_group,
            "old_mode": old_mode,
        },
    )
