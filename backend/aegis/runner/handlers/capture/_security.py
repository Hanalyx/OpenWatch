"""Security-related capture handlers.

Handlers for capturing pre-state of security subsystems: SELinux and audit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner import shell_util
from runner._types import PreState

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def _capture_selinux_boolean_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture current SELinux boolean value."""
    name = r["name"]
    result = ssh.run(f"getsebool {shell_util.quote(name)} 2>/dev/null")
    old_value = None
    if result.ok:
        parts = result.stdout.strip().split()
        if len(parts) >= 3:
            old_value = parts[-1].lower() == "on"
    return PreState(
        mechanism="selinux_boolean_set",
        data={
            "name": name,
            "old_value": old_value,
            "persistent": r.get("persistent", True),
        },
    )


def _capture_audit_rule_set(ssh: SSHSession, r: dict) -> PreState:
    """Capture audit rule state before adding."""
    rule = r["rule"]
    persist_file = r.get("persist_file", "/etc/audit/rules.d/99-aegis.rules")

    result = ssh.run("auditctl -l 2>/dev/null")
    rule_existed = result.ok and rule in result.stdout

    old_persist_content = shell_util.read_file(ssh, persist_file)

    return PreState(
        mechanism="audit_rule_set",
        data={
            "rule": rule,
            "persist_file": persist_file,
            "rule_existed": rule_existed,
            "old_persist_content": old_persist_content,
            "persist_existed": old_persist_content is not None,
        },
    )
