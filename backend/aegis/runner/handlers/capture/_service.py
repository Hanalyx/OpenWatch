"""Service-related capture handlers.

Handlers for capturing pre-state of systemd services.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_service_enabled(ssh: SSHSession, r: dict) -> PreState:
    """Capture current service enabled/active state before enabling."""
    name = r["name"]
    enabled = ssh.run(f"systemctl is-enabled {shell_util.quote(name)} 2>/dev/null")
    active = ssh.run(f"systemctl is-active {shell_util.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="service_enabled",
        data={
            "name": name,
            "was_enabled": enabled.stdout.strip() if enabled.ok else "unknown",
            "was_active": active.stdout.strip() if active.ok else "unknown",
        },
    )


def _capture_service_disabled(ssh: SSHSession, r: dict) -> PreState:
    """Capture current service enabled/active state before disabling."""
    name = r["name"]
    enabled = ssh.run(f"systemctl is-enabled {shell_util.quote(name)} 2>/dev/null")
    active = ssh.run(f"systemctl is-active {shell_util.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="service_disabled",
        data={
            "name": name,
            "was_enabled": enabled.stdout.strip() if enabled.ok else "unknown",
            "was_active": active.stdout.strip() if active.ok else "unknown",
        },
    )


def _capture_service_masked(ssh: SSHSession, r: dict) -> PreState:
    """Capture current service enabled/active state before masking."""
    name = r["name"]
    enabled = ssh.run(f"systemctl is-enabled {shell_util.quote(name)} 2>/dev/null")
    active = ssh.run(f"systemctl is-active {shell_util.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="service_masked",
        data={
            "name": name,
            "was_enabled": enabled.stdout.strip() if enabled.ok else "unknown",
            "was_active": active.stdout.strip() if active.ok else "unknown",
        },
    )
