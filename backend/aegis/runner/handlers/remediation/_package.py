"""Package-related remediation handlers.

Handlers for managing RPM packages.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_package_present(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Install a package using dnf.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Package name to install.

    Returns:
        Tuple of (success, detail).

    """
    name = r["name"]

    if dry_run:
        return True, f"Would install {name}"

    result = ssh.run(f"dnf install -y {shell_util.quote(name)}", timeout=300)
    if not result.ok:
        return False, f"dnf install failed: {result.stderr}"
    return True, f"Installed {name}"


def _remediate_package_absent(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Remove a package using dnf.

    Idempotent: succeeds if package is already absent.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Package name to remove.

    Returns:
        Tuple of (success, detail).

    """
    name = r["name"]

    # Check if package is installed
    check = ssh.run(f"rpm -q {shell_util.quote(name)} 2>/dev/null")
    if not check.ok:
        return True, f"{name}: already not installed"

    if dry_run:
        return True, f"Would remove {name}"

    result = ssh.run(f"dnf remove -y {shell_util.quote(name)}", timeout=300)
    if not result.ok:
        return False, f"dnf remove failed: {result.stderr}"
    return True, f"Removed {name}"
