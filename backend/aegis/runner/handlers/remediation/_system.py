"""System-related remediation handlers.

Handlers for system configuration: sysctl, kernel modules, mount options,
GRUB parameters, and cron jobs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _remediate_sysctl_set(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Set a kernel sysctl parameter and persist it.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): Sysctl parameter name.
            - value (str): Value to set.
            - persist_file (str, optional): Custom persistence file.

    Returns:
        Tuple of (success, detail).

    """
    key = r["key"]
    value = r["value"]
    persist_file = r.get("persist_file", f"/etc/sysctl.d/99-aegis-{key.replace('.', '-')}.conf")

    if dry_run:
        return True, f"Would set sysctl {key}={value} and persist to {persist_file}"

    result = ssh.run(f"sysctl -w {shell_util.quote(key)}={shell_util.quote(str(value))}")
    if not result.ok:
        return False, f"sysctl -w failed: {result.stderr}"

    line = f"{key} = {value}"
    if not shell_util.write_file(ssh, persist_file, line + "\n"):
        return False, f"Failed to persist {persist_file}"

    return True, f"Set {key}={value}, persisted to {persist_file}"


def _remediate_kernel_module_disable(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Blacklist and unload a kernel module.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - name (str): Kernel module name.

    Returns:
        Tuple of (success, detail).

    """
    name = r["name"]
    conf_path = f"/etc/modprobe.d/{name}.conf"

    if dry_run:
        return True, f"Would blacklist {name} in {conf_path}"

    content = f"blacklist {name}\ninstall {name} /bin/false\n"
    if not shell_util.write_file(ssh, conf_path, content):
        return False, f"Failed to write {conf_path}"

    ssh.run(f"modprobe -r {shell_util.quote(name)} 2>/dev/null")
    return True, f"Blacklisted {name}"


def _remediate_mount_option_set(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Add mount options to fstab and remount.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - mount_point (str): Mount point path.
            - options (list[str]): Options to add.

    Returns:
        Tuple of (success, detail).

    """
    mount_point = r["mount_point"]
    options = r["options"]

    if dry_run:
        return (
            True,
            f"Would add options {options} to {mount_point} in fstab and remount",
        )

    result = ssh.run(f"grep -E '\\s{shell_util.quote(mount_point)}\\s' /etc/fstab")
    if not result.ok:
        return False, f"{mount_point}: not found in /etc/fstab"

    fstab_line = result.stdout.strip()
    parts = fstab_line.split()
    if len(parts) < 4:
        return False, f"Invalid fstab line for {mount_point}"

    current_opts = set(parts[3].split(","))
    for opt in options:
        current_opts.add(opt)
    new_opts = ",".join(sorted(current_opts))

    escaped_mount = mount_point.replace("/", "\\/")
    cmd = f"sed -i 's|\\(\\s{escaped_mount}\\s\\+\\S\\+\\s\\+\\)\\S\\+|\\1{new_opts}|' /etc/fstab"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to update fstab: {result.stderr}"

    result = ssh.run(f"mount -o remount {shell_util.quote(mount_point)}")
    if not result.ok:
        return False, f"Remount failed: {result.stderr}"

    return True, f"Added options {options} to {mount_point}"


def _remediate_grub_parameter_set(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Add a kernel boot parameter to GRUB.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): Parameter name.
            - value (str, optional): Parameter value.

    Returns:
        Tuple of (success, detail).

    """
    key = r["key"]
    value = r.get("value")
    arg = f"{key}={value}" if value else key

    if dry_run:
        return True, f"Would set kernel arg: {arg}"

    result = ssh.run(f"grubby --update-kernel=ALL --args={shell_util.quote(arg)}")
    if not result.ok:
        return False, f"grubby failed: {result.stderr}"

    return True, f"Set kernel arg: {arg}"


def _remediate_grub_parameter_remove(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Remove a kernel boot parameter from GRUB.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - key (str): Parameter name to remove.

    Returns:
        Tuple of (success, detail).

    """
    key = r["key"]

    if dry_run:
        return True, f"Would remove kernel arg: {key}"

    result = ssh.run(f"grubby --update-kernel=ALL --remove-args={shell_util.quote(key)}")
    if not result.ok:
        return False, f"grubby failed: {result.stderr}"

    return True, f"Removed kernel arg: {key}"


def _remediate_cron_job(ssh: SSHSession, r: dict, *, dry_run: bool = False) -> tuple[bool, str]:
    """Create a cron job in /etc/cron.d/.

    Args:
        ssh: Active SSH session to the target host.
        r: Remediation definition with required fields:
            - schedule (str): Cron schedule.
            - command (str): Command to execute.
            - user (str, optional): User to run as. Defaults to "root".
            - name (str, optional): Job name. Defaults to "aegis-managed".

    Returns:
        Tuple of (success, detail).

    """
    schedule = r["schedule"]
    command = r["command"]
    user = r.get("user", "root")
    name = r.get("name", "aegis-managed")

    cron_file = f"/etc/cron.d/{name}"
    cron_line = f"{schedule} {user} {command}"

    if dry_run:
        return True, f"Would create {cron_file} with: {cron_line}"

    if not shell_util.write_file(ssh, cron_file, cron_line + "\n"):
        return False, "Failed to create cron job"

    shell_util.set_file_mode(ssh, cron_file, "644")
    return True, f"Created cron job: {cron_file}"
