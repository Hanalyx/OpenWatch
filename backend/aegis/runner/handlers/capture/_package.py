"""Package-related capture handlers.

Handlers for capturing pre-state of packages.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_package_present(ssh: SSHSession, r: dict) -> PreState:
    """Capture whether package is currently installed."""
    name = r["name"]
    result = ssh.run(f"rpm -q {shell_util.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="package_present",
        data={"name": name, "was_installed": result.ok},
    )


def _capture_package_absent(ssh: SSHSession, r: dict) -> PreState:
    """Capture whether package is currently installed before removal."""
    name = r["name"]
    result = ssh.run(f"rpm -q {shell_util.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="package_absent",
        data={
            "name": name,
            "was_installed": result.ok,
            "version": result.stdout.strip() if result.ok else None,
        },
    )
