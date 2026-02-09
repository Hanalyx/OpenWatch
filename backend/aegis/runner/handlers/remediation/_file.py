"""File-related remediation handlers.

Handlers for modifying file state: permissions, content, and existence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_file_permissions(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Set file ownership and permissions.

    Uses chown and chmod to set the specified attributes.
    Supports glob patterns.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): File path or glob pattern.
            - owner (str, optional): Owner to set.
            - group (str, optional): Group to set.
            - mode (str, optional): Octal mode.
            - glob (bool, optional): Explicit glob flag.

    Returns:
        Tuple of (success, detail).

    """
    path = r["path"]
    is_glob = "glob" in r or shell_util.is_glob_path(path)
    parts = []

    if "owner" in r or "group" in r:
        owner = r.get("owner", "")
        group = r.get("group", "")
        chown_spec = f"{owner}:{group}" if group else owner
        quoted = shell_util.quote_path(path, allow_glob=is_glob)
        parts.append(f"chown {chown_spec} {quoted}")

    if "mode" in r:
        quoted = shell_util.quote_path(path, allow_glob=is_glob)
        parts.append(f"chmod {r['mode']} {quoted}")

    if dry_run:
        return True, f"Would run: {' && '.join(parts)}"

    cmd = " && ".join(parts)
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed: {result.stderr}"
    return True, f"Set permissions on {path}"


def _remediate_file_content(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Write complete content to a file.

    Creates or overwrites a file with specified content.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): File path to write.
            - content (str): Complete file content.
            - owner (str, optional): Owner to set.
            - group (str, optional): Group to set.
            - mode (str, optional): Octal mode.

    Returns:
        Tuple of (success, detail).

    """
    path = r["path"]
    content = r["content"]

    if dry_run:
        return True, f"Would write content to {path}"

    if not shell_util.write_file(ssh, path, content):
        return False, f"Failed to write {path}"

    if "owner" in r or "group" in r:
        shell_util.set_file_owner(ssh, path, r.get("owner"), r.get("group"))
    if "mode" in r:
        shell_util.set_file_mode(ssh, path, r["mode"])

    return True, f"Wrote content to {path}"


def _remediate_file_absent(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Remove a file if it exists.

    Uses rm -f for safe removal. Idempotent.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): File path to remove.

    Returns:
        Tuple of (success, detail).

    """
    path = r["path"]

    if not shell_util.path_exists(ssh, path):
        return True, f"{path}: already absent"

    if dry_run:
        return True, f"Would remove {path}"

    result = ssh.run(f"rm -f {shell_util.quote(path)}")
    if not result.ok:
        return False, f"Failed to remove {path}: {result.stderr}"
    return True, f"Removed {path}"
