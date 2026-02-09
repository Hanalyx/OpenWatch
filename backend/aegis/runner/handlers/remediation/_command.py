"""Command-related remediation handlers.

Handlers for arbitrary command execution and manual remediation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_command_exec(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Execute an arbitrary shell command.

    Supports conditional execution with unless/onlyif guards.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - run (str): Shell command to execute.
            - unless (str, optional): Skip if this command succeeds.
            - onlyif (str, optional): Skip if this command fails.
            - reload/restart (str, optional): Service to reload.

    Returns:
        Tuple of (success, detail).

    """
    cmd = r["run"]

    if "unless" in r:
        guard = ssh.run(r["unless"])
        if guard.ok:
            return True, f"Skipped (unless guard passed): {r['unless']}"

    if "onlyif" in r:
        guard = ssh.run(r["onlyif"])
        if not guard.ok:
            return True, f"Skipped (onlyif guard failed): {r['onlyif']}"

    if dry_run:
        return True, f"Would run: {cmd}"

    result = ssh.run(cmd, timeout=120)
    if not result.ok:
        return (
            False,
            f"Command failed (exit {result.exit_code}): {result.stderr or result.stdout}",
        )

    shell_util.service_action(ssh, r)
    return True, f"Executed: {cmd}"


def _remediate_manual(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Indicate that manual remediation is required.

    Always returns failure with the specified note.

    Args:
        ssh: Active SSH session to the target host (unused).
        r: Remediation definition with optional fields:
            - note (str): Explanation of manual steps needed.

    Returns:
        Tuple of (False, "MANUAL: <note>").

    """
    note = r.get("note", "Manual remediation required")
    return False, f"MANUAL: {note}"
