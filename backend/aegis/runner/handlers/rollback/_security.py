"""Security-related rollback handlers.

Handlers for rolling back security subsystem changes: SELinux and audit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _rollback_selinux_boolean_set(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore SELinux boolean to previous value."""
    d = pre_state.data
    name = d["name"]
    if d["old_value"] is None:
        return False, f"{name}: could not determine previous value"

    value_str = "on" if d["old_value"] else "off"
    cmd = f"setsebool {'-P ' if d['persistent'] else ''}{shell_util.quote(name)} {value_str}"
    result = ssh.run(cmd, timeout=60)
    if not result.ok:
        return False, f"Failed to restore {name}: {result.stderr}"
    return True, f"Restored {name} = {value_str}"


def _rollback_audit_rule_set(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Remove audit rule if it didn't exist before."""
    d = pre_state.data
    rule = d["rule"]
    persist_file = d["persist_file"]

    if d["rule_existed"]:
        return True, "Rule already existed, nothing to rollback"

    # Remove from running config
    # auditctl -d removes a rule (same syntax as -a but with -d)
    delete_rule = rule.replace("-a ", "-d ", 1).replace("-w ", "-W ", 1)
    ssh.run(f"auditctl {delete_rule} 2>/dev/null")

    # Restore persist file
    if d["persist_existed"] and d["old_persist_content"] is not None:
        shell_util.write_file(ssh, persist_file, d["old_persist_content"])
    elif not d["persist_existed"]:
        ssh.run(f"rm -f {shell_util.quote(persist_file)}")

    return True, "Removed audit rule"
