"""Capability detection probes for remote hosts.

This module detects host capabilities and platform information to enable
capability-gated rule implementations. Probes are fast, read-only shell
commands that determine what features are available on the target host.

Capability Detection Pattern:
    Each probe is a shell command where exit code 0 = capability present.
    Probes are designed to be:
    - Fast (< 2 seconds)
    - Side-effect free (read-only)
    - Silent (stderr suppressed)

Platform Detection:
    Platform info (family + version) is detected from /etc/os-release with
    fallbacks to /etc/redhat-release and /etc/debian_version. RHEL derivatives
    (Rocky, Alma, CentOS, Oracle Linux) are normalized to family "rhel".

Example:
-------
    >>> from runner.ssh import SSHSession
    >>> from runner.detect import detect_capabilities, detect_platform
    >>>
    >>> with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
    ...     caps = detect_capabilities(ssh)
    ...     platform = detect_platform(ssh)
    ...     print(f"Platform: {platform.family} {platform.version}")
    ...     print(f"Has sshd_config.d: {caps['sshd_config_d']}")

"""

from __future__ import annotations

from collections import namedtuple
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.ssh import SSHSession


# ── Platform detection ─────────────────────────────────────────────────────

PlatformInfo = namedtuple("PlatformInfo", ["family", "version"])
"""Platform information for rule filtering.

Attributes:
    family (str): Normalized OS family (e.g., "rhel", "ubuntu", "debian").
    version (int): Major version number.
"""

# OS IDs that are RHEL-compatible and normalized to family "rhel"
RHEL_FAMILY = {"rhel", "centos", "rocky", "almalinux", "ol"}


def detect_platform(ssh: SSHSession) -> PlatformInfo | None:
    """Detect the remote host's OS family and version.

    Uses a fallback chain to detect platform information:
    1. /etc/os-release (preferred, covers most modern distros)
    2. /etc/redhat-release (fallback for older RHEL/CentOS)
    3. /etc/debian_version (fallback for Debian-based systems)

    RHEL derivatives (Rocky, Alma, CentOS, Oracle Linux) are normalized
    to family "rhel" so rules with `family: rhel` match all derivatives.

    Args:
    ----
        ssh: Active SSH session to the target host.

    Returns:
    -------
        PlatformInfo(family, version) on success, None if detection fails.
        Caller should warn and skip platform filtering if None is returned.

    Example:
    -------
        >>> platform = detect_platform(ssh)
        >>> if platform:
        ...     print(f"Detected: {platform.family} {platform.version}")
        ... else:
        ...     print("Warning: Could not detect platform")

    """
    # Try /etc/os-release first (covers most modern distros)
    result = ssh.run("cat /etc/os-release 2>/dev/null")
    if result.ok and result.stdout.strip():
        fields: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                fields[k.strip()] = v.strip().strip('"')

        os_id = fields.get("ID", "").lower()
        ver_str = fields.get("VERSION_ID", "0")
        try:
            version = int(ver_str.split(".")[0])
        except (ValueError, IndexError):
            version = 0

        family = "rhel" if os_id in RHEL_FAMILY else os_id
        return PlatformInfo(family=family, version=version)

    # Fallback: /etc/redhat-release for older RHEL/CentOS
    result = ssh.run("cat /etc/redhat-release 2>/dev/null")
    if result.ok and result.stdout.strip():
        import re

        content = result.stdout.strip().lower()
        version = 0
        match = re.search(r"(\d+)", content)
        if match:
            version = int(match.group(1))
        return PlatformInfo(family="rhel", version=version)

    # Fallback: /etc/debian_version for Debian-based
    result = ssh.run("cat /etc/debian_version 2>/dev/null")
    if result.ok and result.stdout.strip():
        try:
            version = int(result.stdout.strip().split(".")[0])
        except (ValueError, IndexError):
            version = 0
        return PlatformInfo(family="debian", version=version)

    return None


# ── Capability probes ──────────────────────────────────────────────────────
#
# Each probe maps a capability name to a shell command.
# Exit code 0 = capability present, non-zero = absent.
#
# Probes must be:
#   - Fast (< 2 seconds)
#   - Side-effect free (read-only)
#   - Silent (suppress stderr with 2>/dev/null)
#
# Adding a new probe:
#   1. Add entry to this dict
#   2. Use capability name in rule `when:` gates
#   3. No code changes needed elsewhere

CAPABILITY_PROBES: dict[str, str] = {
    "sshd_config_d": (
        "test -d /etc/ssh/sshd_config.d && { "
        "grep -qi 'Include.*/etc/ssh/sshd_config.d' /etc/ssh/sshd_config 2>/dev/null || "
        "find /etc/ssh/sshd_config.d -name '*.conf' -print -quit 2>/dev/null | grep -q .; "
        "}"
    ),
    "authselect": "command -v authselect >/dev/null 2>&1 && authselect current >/dev/null 2>&1",
    "authselect_sssd": "authselect current 2>/dev/null | grep -q sssd",
    "crypto_policies": "test -f /etc/crypto-policies/config && command -v update-crypto-policies >/dev/null 2>&1",
    "crypto_policy_modules": (
        "update-crypto-policies --show 2>/dev/null | grep -q ':' || "
        "test -d /usr/share/crypto-policies/policies/modules"
    ),
    "fips_mode": "fips-mode-setup --check 2>/dev/null | grep -qi 'is enabled'",
    "firewalld_nftables": (
        "systemctl is-active firewalld >/dev/null 2>&1 && "
        "firewall-cmd --get-default-zone >/dev/null 2>&1 && "
        "grep -q 'FirewallBackend=nftables' /etc/firewalld/firewalld.conf 2>/dev/null"
    ),
    "firewalld_iptables": (
        "systemctl is-active firewalld >/dev/null 2>&1 && "
        "grep -q 'FirewallBackend=iptables' /etc/firewalld/firewalld.conf 2>/dev/null"
    ),
    "systemd_resolved": "systemctl is-active systemd-resolved >/dev/null 2>&1",
    "pam_faillock": "test -f /etc/security/faillock.conf",
    "grub_bls": "test -d /boot/loader/entries && grep -q 'blscfg' /etc/default/grub 2>/dev/null",
    "grub_legacy": "test -f /boot/grub2/grub.cfg && ! test -d /boot/loader/entries",
    "journald_primary": "systemctl is-active systemd-journald >/dev/null 2>&1",
    "rsyslog_active": "systemctl is-active rsyslog >/dev/null 2>&1",
    "fapolicyd": "rpm -q fapolicyd >/dev/null 2>&1",
    "selinux": "command -v getenforce >/dev/null 2>&1 && [ \"$(getenforce 2>/dev/null)\" != 'Disabled' ]",
    "aide": "rpm -q aide >/dev/null 2>&1",
    "tpm2": "test -c /dev/tpmrm0 || test -c /dev/tpm0",
    "usbguard": "rpm -q usbguard >/dev/null 2>&1",
    "dnf_automatic": "rpm -q dnf-automatic >/dev/null 2>&1",
    "gdm": "rpm -q gdm >/dev/null 2>&1",
    "tmux": "command -v tmux >/dev/null 2>&1",
}


def detect_capabilities(ssh: SSHSession, *, verbose: bool = False) -> dict[str, bool]:
    """Run all capability probes and return a dict of results.

    Executes each probe in CAPABILITY_PROBES and records whether it
    succeeded (exit code 0). Results are used by select_implementation()
    to choose capability-gated rule implementations.

    Args:
    ----
        ssh: Active SSH session to the target host.
        verbose: If True, print debug info for failed probes to stderr.

    Returns:
    -------
        Dict mapping capability name to bool (True if present).

    Example:
    -------
        >>> caps = detect_capabilities(ssh, verbose=True)
        >>> if caps["sshd_config_d"]:
        ...     print("Using drop-in config implementation")
        ... else:
        ...     print("Using main config file implementation")

    """
    caps = {}
    for name, cmd in CAPABILITY_PROBES.items():
        result = ssh.run(cmd)
        caps[name] = result.ok
        if verbose and not result.ok:
            import sys

            print(
                f"    [probe] {name}: exit={result.exit_code} stderr={result.stderr!r}",
                file=sys.stderr,
            )
    return caps
