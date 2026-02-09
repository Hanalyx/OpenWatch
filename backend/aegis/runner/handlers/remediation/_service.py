"""Service-related remediation handlers.

Handlers for managing systemd services.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_service_enabled(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Enable and optionally start a systemd service.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Service name.
            - start (bool, optional): Also start the service. Defaults to True.

    Returns:
        Tuple of (success, detail).

    """
    name = r["name"]
    start = r.get("start", True)

    if dry_run:
        action = "enable and start" if start else "enable"
        return True, f"Would {action} {name}"

    result = ssh.run(f"systemctl enable {shell_util.quote(name)}")
    if not result.ok:
        return False, f"Failed to enable {name}: {result.stderr}"

    if start:
        result = ssh.run(f"systemctl start {shell_util.quote(name)}")
        if not result.ok:
            return False, f"Enabled {name} but failed to start: {result.stderr}"
        return True, f"Enabled and started {name}"

    return True, f"Enabled {name}"


def _remediate_service_disabled(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Disable and optionally stop a systemd service.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Service name.
            - stop (bool, optional): Also stop the service. Defaults to True.

    Returns:
        Tuple of (success, detail).

    """
    name = r["name"]
    stop = r.get("stop", True)

    if dry_run:
        action = "disable and stop" if stop else "disable"
        return True, f"Would {action} {name}"

    if stop:
        ssh.run(f"systemctl stop {shell_util.quote(name)}")

    result = ssh.run(f"systemctl disable {shell_util.quote(name)}")
    if not result.ok:
        return False, f"Failed to disable {name}: {result.stderr}"

    if stop:
        return True, f"Stopped and disabled {name}"
    return True, f"Disabled {name}"


def _remediate_service_masked(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Mask a systemd service to prevent it from starting.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Service name.
            - stop (bool, optional): Also stop the service. Defaults to True.

    Returns:
        Tuple of (success, detail).

    """
    name = r["name"]
    stop = r.get("stop", True)

    if dry_run:
        action = "stop and mask" if stop else "mask"
        return True, f"Would {action} {name}"

    if stop:
        ssh.run(f"systemctl stop {shell_util.quote(name)}")

    result = ssh.run(f"systemctl mask {shell_util.quote(name)}")
    if not result.ok:
        return False, f"Failed to mask {name}: {result.stderr}"

    if stop:
        return True, f"Stopped and masked {name}"
    return True, f"Masked {name}"
