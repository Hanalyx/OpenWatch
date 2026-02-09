"""Package-related check handlers.

Handlers for verifying RPM package state.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_package_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check RPM package installation state.

    Verifies whether a package is installed or absent using rpm -q.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): Package name.
            - state (str, optional): Expected state - "present" or
              "absent". Defaults to "present".

    Returns:
        CheckResult with passed=True if package is in the expected state.

    """
    name = c["name"]
    state = c.get("state", "present")

    result = ssh.run(f"rpm -q {shell_util.quote(name)} 2>/dev/null")

    if state == "present":
        if result.ok:
            return CheckResult(passed=True, detail=f"{name}: {result.stdout.strip()}")
        return CheckResult(passed=False, detail=f"{name}: not installed")
    elif state == "absent":
        if not result.ok:
            return CheckResult(passed=True, detail=f"{name}: not installed (as required)")
        return CheckResult(passed=False, detail=f"{name}: installed (should be absent)")

    return CheckResult(passed=False, detail=f"Unknown package state: {state}")
