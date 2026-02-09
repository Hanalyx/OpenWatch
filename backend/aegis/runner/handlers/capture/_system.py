"""System-related capture handlers.

Handlers for capturing pre-state of system configuration: sysctl, kernel modules,
mount options, GRUB, and cron jobs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_sysctl_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current sysctl value and persist file state."""
    key = r["key"]
    persist_file = r.get("persist_file", f"/etc/sysctl.d/99-aegis-{key.replace('.', '-')}.conf")
    result = ssh.run(f"sysctl -n {shell_util.quote(key)} 2>/dev/null")
    old_value = result.stdout.strip() if result.ok else None
    old_persist = shell_util.read_file(ssh, persist_file)
    return PreState(
        mechanism="sysctl_set",
        data={
            "key": key,
            "old_value": old_value,
            "persist_file": persist_file,
            "old_persist": old_persist,
            "persist_existed": old_persist is not None,
        },
    )


def _capture_kernel_module_disable(ssh: SSHSession, r: dict) -> PreState:
    """Capture kernel module conf and load state."""
    name = r["name"]
    conf_path = f"/etc/modprobe.d/{name}.conf"
    old_conf = shell_util.read_file(ssh, conf_path)
    loaded = ssh.run(f"lsmod | grep -q '^{name} '")
    return PreState(
        mechanism="kernel_module_disable",
        data={
            "name": name,
            "conf_path": conf_path,
            "old_conf": old_conf,
            "conf_existed": old_conf is not None,
            "was_loaded": loaded.ok,
        },
    )


def _capture_mount_option_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current mount options before modification."""
    mount_point = r["mount_point"]

    fstab_result = ssh.run(f"grep -E '\\s{shell_util.quote(mount_point)}\\s' /etc/fstab")
    old_fstab_line = fstab_result.stdout.strip() if fstab_result.ok else None

    mount_result = ssh.run(f"findmnt -n -o OPTIONS {shell_util.quote(mount_point)} 2>/dev/null")
    old_options = mount_result.stdout.strip() if mount_result.ok else None

    return PreState(
        mechanism="mount_option_set",
        data={
            "mount_point": mount_point,
            "old_fstab_line": old_fstab_line,
            "old_options": old_options,
        },
    )


def _capture_grub_parameter_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current GRUB kernel args before modification."""
    result = ssh.run("grubby --info=DEFAULT 2>/dev/null | grep -E 'args='")
    old_args = result.stdout.strip() if result.ok else None
    return PreState(
        mechanism="grub_parameter_set",
        data={
            "key": r["key"],
            "old_args": old_args,
        },
        capturable=False,  # GRUB changes are complex to rollback
    )


def _capture_grub_parameter_remove(ssh: SSHSession, r: dict) -> PreState:
    """Capture current GRUB kernel args before removal."""
    result = ssh.run("grubby --info=DEFAULT 2>/dev/null | grep -E 'args='")
    old_args = result.stdout.strip() if result.ok else None
    return PreState(
        mechanism="grub_parameter_remove",
        data={
            "key": r["key"],
            "old_args": old_args,
        },
        capturable=False,  # GRUB changes are complex to rollback
    )


def _capture_cron_job(ssh: SSHSession, r: dict) -> PreState:
    """Capture cron file state before creation."""
    name = r.get("name", "aegis-managed")
    cron_file = f"/etc/cron.d/{name}"

    exists = shell_util.file_exists(ssh, cron_file)
    old_content = shell_util.read_file(ssh, cron_file) if exists else None

    return PreState(
        mechanism="cron_job",
        data={
            "cron_file": cron_file,
            "existed": exists,
            "old_content": old_content,
        },
    )
