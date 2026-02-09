"""Shell command utilities for remote execution.

Provides safe, consistent helpers for common shell operations used
across check and remediation handlers. All functions use proper
quoting to prevent shell injection.

Usage Pattern:
    These utilities are used by handlers in runner/handlers/ to
    perform common operations without duplicating shell command
    construction logic.

Example:
-------
    >>> from runner import shell_util
    >>> from runner.ssh import SSHSession
    >>>
    >>> # Safe quoting
    >>> cmd = f"cat {shell_util.quote('/etc/passwd')}"
    >>>
    >>> # Config key lookup
    >>> result = shell_util.grep_config_key(ssh, '/etc/ssh/sshd_config', 'PermitRootLogin')
    >>> if result.ok:
    ...     print(result.stdout)

"""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.ssh import Result, SSHSession


# ── Quoting utilities ─────────────────────────────────────────────────────


def quote(value: str) -> str:
    r"""Quote a value for safe shell interpolation.

    Args:
        value: String to quote.

    Returns:
        Shell-safe quoted string.

    Example:
    -------
        >>> quote("hello world")
        "'hello world'"
        >>> quote("it's")
        "'it'\"'\"'s'"

    """
    return shlex.quote(str(value))


def is_glob_path(path: str) -> bool:
    """Check if a path contains glob characters.

    Args:
        path: File path to check.

    Returns:
        True if path contains *, ?, or [ characters.

    Example:
    -------
        >>> is_glob_path("/etc/ssh/sshd_config")
        False
        >>> is_glob_path("/etc/ssh/*.conf")
        True

    """
    return any(ch in path for ch in "*?[")


def quote_path(path: str, *, allow_glob: bool = False) -> str:
    """Quote a path, optionally preserving glob characters.

    Args:
        path: File path to quote.
        allow_glob: If True and path contains glob chars, don't quote.

    Returns:
        Quoted path or unquoted glob pattern.

    Example:
    -------
        >>> quote_path("/etc/passwd")
        "'/etc/passwd'"
        >>> quote_path("/etc/*.conf", allow_glob=True)
        "/etc/*.conf"
        >>> quote_path("/etc/*.conf", allow_glob=False)
        "'/etc/*.conf'"

    """
    if allow_glob and is_glob_path(path):
        return path
    return shlex.quote(path)


# ── File existence checks ─────────────────────────────────────────────────


def file_exists(ssh: SSHSession, path: str) -> bool:
    """Check if a file exists.

    Args:
        ssh: Active SSH session.
        path: File path to check.

    Returns:
        True if file exists.

    """
    return ssh.run(f"test -f {quote(path)}").ok


def dir_exists(ssh: SSHSession, path: str) -> bool:
    """Check if a directory exists.

    Args:
        ssh: Active SSH session.
        path: Directory path to check.

    Returns:
        True if directory exists.

    """
    return ssh.run(f"test -d {quote(path)}").ok


def path_exists(ssh: SSHSession, path: str) -> bool:
    """Check if a path (file or directory) exists.

    Args:
        ssh: Active SSH session.
        path: Path to check.

    Returns:
        True if path exists.

    """
    return ssh.run(f"test -e {quote(path)}").ok


# ── File read/write operations ────────────────────────────────────────────


def read_file(ssh: SSHSession, path: str) -> str | None:
    """Read file contents.

    Args:
        ssh: Active SSH session.
        path: File path to read.

    Returns:
        File contents or None if file doesn't exist.

    """
    result = ssh.run(f"cat {quote(path)} 2>/dev/null")
    return result.stdout if result.ok else None


def write_file(ssh: SSHSession, path: str, content: str) -> bool:
    """Write content to a file (overwrites existing).

    Args:
        ssh: Active SSH session.
        path: File path to write.
        content: Content to write.

    Returns:
        True if successful.

    """
    return ssh.run(f"printf %s {quote(content)} > {quote(path)}").ok


def append_line(ssh: SSHSession, path: str, line: str) -> bool:
    """Append a line to a file.

    Args:
        ssh: Active SSH session.
        path: File path.
        line: Line to append.

    Returns:
        True if successful.

    """
    return ssh.run(f"echo {quote(line)} >> {quote(path)}").ok


# ── Config file operations ────────────────────────────────────────────────


def grep_config_key(
    ssh: SSHSession,
    path: str,
    key: str,
    *,
    is_dir: bool | None = None,
    scan_pattern: str = "*.conf",
) -> Result:
    """Search for a config key in a file or directory.

    Searches for lines starting with the key (with optional leading
    whitespace). In directory mode, searches recursively in files
    matching scan_pattern.

    Args:
        ssh: Active SSH session.
        path: File or directory path.
        key: Config key to search for.
        is_dir: If True, search recursively. If None, auto-detect.
        scan_pattern: Glob pattern for directory mode.

    Returns:
        SSH Result with matching lines in stdout.

    Example:
    -------
        >>> result = grep_config_key(ssh, '/etc/ssh/sshd_config', 'PermitRootLogin')
        >>> if result.ok:
        ...     print(result.stdout.strip())
        'PermitRootLogin no'

    """
    # Auto-detect directory if not specified
    if is_dir is None:
        is_dir = dir_exists(ssh, path)

    if is_dir:
        cmd = f"grep -rh '^ *{key}' {quote(path)}/{scan_pattern} 2>/dev/null | tail -1"
    else:
        cmd = f"grep -h '^ *{key}' {quote(path)} 2>/dev/null | tail -1"
    return ssh.run(cmd)


def config_key_exists(
    ssh: SSHSession,
    path: str,
    key: str,
    *,
    is_dir: bool | None = None,
    scan_pattern: str = "*.conf",
) -> bool:
    """Check if a config key exists in a file or directory.

    Args:
        ssh: Active SSH session.
        path: File or directory path.
        key: Config key to search for.
        is_dir: If True, search recursively. If None, auto-detect.
        scan_pattern: Glob pattern for directory mode.

    Returns:
        True if key exists.

    """
    result = grep_config_key(ssh, path, key, is_dir=is_dir, scan_pattern=scan_pattern)
    return result.ok and bool(result.stdout.strip())


def parse_config_value(line: str, key: str) -> str:
    """Parse a config value from a key=value or key value line.

    Handles multiple separators: space, =, tab, and combinations.
    Strips quotes from the value.

    Args:
        line: Full config line (e.g., "PermitRootLogin no").
        key: The key to strip from the line.

    Returns:
        The extracted value.

    Example:
    -------
        >>> parse_config_value("PermitRootLogin no", "PermitRootLogin")
        'no'
        >>> parse_config_value("MaxAuthTries=4", "MaxAuthTries")
        '4'
        >>> parse_config_value('Banner="/etc/issue"', "Banner")
        '/etc/issue'

    """
    # Remove the key prefix
    after_key = line[len(key) :].strip() if key in line else line.split(None, 1)[-1]
    # Remove separators and quotes
    value = after_key.lstrip("= \t").strip().strip('"').strip("'")
    return value


# ── sed operations ────────────────────────────────────────────────────────


def sed_replace_line(
    ssh: SSHSession,
    path: str,
    pattern: str,
    replacement: str,
) -> bool:
    """Replace lines matching pattern using sed.

    Args:
        ssh: Active SSH session.
        path: File path.
        pattern: Regex pattern to match (will be auto-escaped for /).
        replacement: Replacement string (will be auto-escaped for /).

    Returns:
        True if successful.

    Note:
        Automatically escapes / in pattern and replacement.

    """
    escaped_pattern = pattern.replace("/", "\\/")
    escaped_replacement = replacement.replace("/", "\\/")
    cmd = f"sed -i 's/{escaped_pattern}/{escaped_replacement}/' {quote(path)}"
    return ssh.run(cmd).ok


def sed_delete_line(ssh: SSHSession, path: str, pattern: str) -> bool:
    """Delete lines matching pattern using sed.

    Args:
        ssh: Active SSH session.
        path: File path.
        pattern: Regex pattern to match.

    Returns:
        True if successful.

    """
    escaped_pattern = pattern.replace("/", "\\/")
    return ssh.run(f"sed -i '/{escaped_pattern}/d' {quote(path)}").ok


def sed_delete_block(
    ssh: SSHSession,
    path: str,
    start_pattern: str,
    end_pattern: str,
) -> bool:
    """Delete lines between two patterns (inclusive) using sed.

    Args:
        ssh: Active SSH session.
        path: File path.
        start_pattern: Pattern marking block start.
        end_pattern: Pattern marking block end.

    Returns:
        True if successful.

    """
    start_escaped = start_pattern.replace("/", "\\/")
    end_escaped = end_pattern.replace("/", "\\/")
    cmd = f"sed -i '/{start_escaped}/,/{end_escaped}/d' {quote(path)}"
    return ssh.run(cmd).ok


# ── File stat operations ──────────────────────────────────────────────────


def get_file_stat(
    ssh: SSHSession,
    path: str,
    *,
    allow_glob: bool = False,
) -> Result:
    """Get file owner, group, and mode.

    Args:
        ssh: Active SSH session.
        path: File path or glob pattern.
        allow_glob: If True, don't quote glob patterns.

    Returns:
        Result with stdout format: "owner group mode path" per line.

    """
    quoted = quote_path(path, allow_glob=allow_glob)
    return ssh.run(f"stat -c '%U %G %a %n' {quoted} 2>/dev/null")


def set_file_owner(
    ssh: SSHSession,
    path: str,
    owner: str | None = None,
    group: str | None = None,
    *,
    allow_glob: bool = False,
) -> bool:
    """Set file owner and/or group.

    Args:
        ssh: Active SSH session.
        path: File path or glob pattern.
        owner: Owner to set (optional).
        group: Group to set (optional).
        allow_glob: If True, don't quote glob patterns.

    Returns:
        True if successful.

    """
    if not owner and not group:
        return True

    chown_spec = f"{owner or ''}:{group or ''}" if group else owner
    quoted = quote_path(path, allow_glob=allow_glob)
    return ssh.run(f"chown {chown_spec} {quoted}").ok


def set_file_mode(
    ssh: SSHSession,
    path: str,
    mode: str,
    *,
    allow_glob: bool = False,
) -> bool:
    """Set file mode/permissions.

    Args:
        ssh: Active SSH session.
        path: File path or glob pattern.
        mode: Octal mode string (e.g., "0600").
        allow_glob: If True, don't quote glob patterns.

    Returns:
        True if successful.

    """
    quoted = quote_path(path, allow_glob=allow_glob)
    return ssh.run(f"chmod {mode} {quoted}").ok


# ── Service operations ────────────────────────────────────────────────────


def reload_service(ssh: SSHSession, service: str) -> bool:
    """Reload a systemd service, falling back to restart.

    Args:
        ssh: Active SSH session.
        service: Service name.

    Returns:
        True if successful (or service not running).

    """
    cmd = f"systemctl reload {quote(service)} 2>/dev/null || systemctl restart {quote(service)} 2>/dev/null"
    # Don't fail if service isn't running
    ssh.run(cmd)
    return True


def restart_service(ssh: SSHSession, service: str) -> bool:
    """Restart a systemd service.

    Args:
        ssh: Active SSH session.
        service: Service name.

    Returns:
        True if successful (or service not running).

    """
    ssh.run(f"systemctl restart {quote(service)} 2>/dev/null")
    return True


def service_action(ssh: SSHSession, remediation: dict) -> None:
    """Perform reload or restart based on remediation dict.

    Checks for 'reload' or 'restart' keys in the remediation dict
    and performs the appropriate action.

    Args:
        ssh: Active SSH session.
        remediation: Remediation dict that may contain reload/restart keys.

    """
    if "reload" in remediation:
        reload_service(ssh, remediation["reload"])
    elif "restart" in remediation:
        restart_service(ssh, remediation["restart"])
