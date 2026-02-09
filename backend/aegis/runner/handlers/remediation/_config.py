"""Config-related remediation handlers.

Handlers for modifying configuration files: setting values, removing keys,
and managing configuration blocks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_config_set(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Set a configuration key to a value in a file.

    Replaces an existing key's value or appends the key if not found.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): Config file path.
            - key (str): Configuration key to set.
            - value (str): Value to set.
            - separator (str, optional): Separator. Defaults to " ".
            - reload/restart (str, optional): Service to reload.

    Returns:
        Tuple of (success, detail).

    """
    path = r["path"]
    key = r["key"]
    value = r["value"]
    sep = r.get("separator", " ")
    line = f"{key}{sep}{value}"

    if dry_run:
        return True, f"Would set '{line}' in {path}"

    if shell_util.config_key_exists(ssh, path, key):
        escaped_line = line.replace("/", "\\/")
        cmd = f"sed -i 's/^ *{key}.*/{escaped_line}/' {shell_util.quote(path)}"
        result = ssh.run(cmd)
    else:
        result = ssh.run(f"echo {shell_util.quote(line)} >> {shell_util.quote(path)}")

    if not result.ok:
        return False, f"Failed to set {key} in {path}: {result.stderr}"

    shell_util.service_action(ssh, r)
    return True, f"Set '{line}' in {path}"


def _remediate_config_set_dropin(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Write a configuration key to a drop-in directory file.

    Creates or overwrites a file in a .d-style configuration directory.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - dir (str): Drop-in directory path.
            - file (str): Filename to create.
            - key (str): Configuration key.
            - value (str): Value to set.
            - separator (str, optional): Separator. Defaults to " ".
            - reload/restart (str, optional): Service to reload.

    Returns:
        Tuple of (success, detail).

    """
    dir_path = r["dir"]
    filename = r["file"]
    key = r["key"]
    value = r["value"]
    sep = r.get("separator", " ")

    full_path = f"{dir_path}/{filename}"
    line = f"{key}{sep}{value}"

    if dry_run:
        return True, f"Would write '{line}' to {full_path}"

    if not shell_util.write_file(ssh, full_path, line + "\n"):
        return False, f"Failed to write {full_path}"

    shell_util.service_action(ssh, r)
    return True, f"Wrote '{line}' to {full_path}"


def _remediate_config_remove(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Remove a configuration key from a file.

    Deletes all lines containing the specified key.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): Config file path.
            - key (str): Configuration key to remove.
            - reload/restart (str, optional): Service to reload.

    Returns:
        Tuple of (success, detail).

    """
    path = r["path"]
    key = r["key"]

    if not shell_util.config_key_exists(ssh, path, key):
        return True, f"{key} not found in {path} (already absent)"

    if dry_run:
        return True, f"Would remove '{key}' from {path}"

    if not shell_util.sed_delete_line(ssh, path, f"^ *{key}"):
        return False, f"Failed to remove {key} from {path}"

    shell_util.service_action(ssh, r)
    return True, f"Removed '{key}' from {path}"


def _remediate_config_block(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Write a managed block of content with markers.

    Inserts or replaces a block of content delimited by begin/end markers.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - path (str): Config file path.
            - block (str): Content to insert between markers.
            - marker (str, optional): Marker identifier.
            - reload/restart (str, optional): Service to reload.

    Returns:
        Tuple of (success, detail).

    """
    path = r["path"]
    block = r["block"]
    marker = r.get("marker", "AEGIS MANAGED BLOCK")
    begin_marker = f"# BEGIN {marker}"
    end_marker = f"# END {marker}"

    if dry_run:
        return True, f"Would write block to {path} with marker '{marker}'"

    # Check if block already exists and remove it
    check = ssh.run(f"grep -qF {shell_util.quote(begin_marker)} {shell_util.quote(path)} 2>/dev/null")
    if check.ok:
        shell_util.sed_delete_block(ssh, path, begin_marker, end_marker)

    # Append the new block
    full_block = f"{begin_marker}\n{block}\n{end_marker}"
    if not shell_util.append_line(ssh, path, full_block):
        return False, f"Failed to write block to {path}"

    shell_util.service_action(ssh, r)
    return True, f"Wrote block to {path}"
