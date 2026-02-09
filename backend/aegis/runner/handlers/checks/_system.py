"""System-related check handlers.

Handlers for verifying system state: sysctl parameters, kernel modules,
mount options, and GRUB boot parameters.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import CheckResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _check_sysctl_value(ssh: SSHSession, c: dict) -> CheckResult:
    """Check a kernel sysctl parameter value.

    Reads the current value of a sysctl parameter and compares it
    to the expected value.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - key (str): Sysctl parameter name.
            - expected (str): Expected value.

    Returns:
        CheckResult with passed=True if current value matches expected.

    """
    key = c["key"]
    expected = str(c["expected"])
    result = ssh.run(f"sysctl -n {shell_util.quote(key)} 2>/dev/null")
    if not result.ok:
        return CheckResult(passed=False, detail=f"sysctl {key}: not available")

    actual = result.stdout.strip()
    if actual == expected:
        return CheckResult(passed=True, detail=f"{key}={actual}")
    return CheckResult(passed=False, detail=f"{key}={actual} (expected {expected})")


def _check_kernel_module_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check kernel module load state.

    Verifies whether a kernel module is loaded or properly disabled/blacklisted.
    For disabled modules, checks both that it's not currently loaded
    and that modprobe is configured to prevent loading.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - name (str): Kernel module name.
            - state (str, optional): Desired state - "blacklisted", "disabled",
              or "loaded". Defaults to "blacklisted". "disabled" and
              "blacklisted" are equivalent (both prevent module loading).

    Returns:
        CheckResult with passed=True if module is in the expected state.

    """
    name = c["name"]
    state = c.get("state", "blacklisted")

    # "disabled" and "blacklisted" are equivalent - both prevent module loading
    if state in ("blacklisted", "disabled"):
        # Module should NOT be loaded and should be blacklisted/disabled
        loaded = ssh.run(f"lsmod | grep -q '^{name} '")
        if loaded.ok:
            return CheckResult(passed=False, detail=f"{name}: still loaded")

        # Check for blacklist or install /bin/false|/bin/true directives
        blacklisted = ssh.run(
            f"modprobe -n -v {shell_util.quote(name)} 2>&1 | grep -q 'install /bin/true\\|install /bin/false\\|blacklist'"
        )
        if not blacklisted.ok:
            return CheckResult(passed=False, detail=f"{name}: not blacklisted")

        return CheckResult(passed=True, detail=f"{name}: blacklisted")

    elif state == "loaded":
        loaded = ssh.run(f"lsmod | grep -q '^{name} '")
        if loaded.ok:
            return CheckResult(passed=True, detail=f"{name}: loaded")
        return CheckResult(passed=False, detail=f"{name}: not loaded")

    return CheckResult(passed=False, detail=f"Unknown module state: {state}")


def _check_mount_option(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a mount point has required mount options.

    Uses findmnt to check currently mounted options.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - mount_point (str): Mount point path.
            - options (list[str]): Required mount options.

    Returns:
        CheckResult with passed=True if all options are present.

    """
    mount_point = c["mount_point"]
    required_options = c.get("options", [])

    result = ssh.run(f"findmnt -n -o OPTIONS {shell_util.quote(mount_point)} 2>/dev/null")
    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{mount_point}: not mounted")

    current_options = set(result.stdout.strip().split(","))
    missing = [opt for opt in required_options if opt not in current_options]

    if missing:
        return CheckResult(passed=False, detail=f"{mount_point}: missing options: {', '.join(missing)}")
    return CheckResult(passed=True, detail=f"{mount_point}: has required options")


def _check_grub_parameter(ssh: SSHSession, c: dict) -> CheckResult:
    """Check that a kernel boot parameter is set in GRUB.

    Uses grubby to inspect the default kernel's boot arguments.

    Args:
        ssh: Active SSH session to the target host.
        c: Check definition with required fields:
            - key (str): Kernel parameter name.
            - expected (str, optional): Expected value.

    Returns:
        CheckResult with passed=True if parameter exists with expected value.

    """
    key = c["key"]
    expected = c.get("expected")

    result = ssh.run("grubby --info=DEFAULT 2>/dev/null | grep -E 'args='")
    if result.ok:
        args_line = result.stdout.strip()
        if f"{key}=" in args_line:
            match = re.search(rf"{key}=(\S+)", args_line)
            if match:
                actual = match.group(1).strip('"')
                if expected is None or actual == expected:
                    return CheckResult(passed=True, detail=f"{key}={actual}")
                return CheckResult(passed=False, detail=f"{key}={actual} (expected {expected})")
        elif key in args_line:
            if expected is None or expected == "":
                return CheckResult(passed=True, detail=f"{key} present")
            return CheckResult(passed=False, detail=f"{key} present but expected value {expected}")
        return CheckResult(passed=False, detail=f"{key} not found in kernel args")

    return CheckResult(passed=False, detail="grubby not available")
