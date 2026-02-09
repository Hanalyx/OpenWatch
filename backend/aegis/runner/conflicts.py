"""Semantic conflict detection for remediation rules.

This module detects when multiple rules would modify the same configuration
resource to different values, preventing silent non-deterministic behavior.

Example:
    >>> from runner.conflicts import detect_conflicts
    >>> conflicts = detect_conflicts(rules, capabilities)
    >>> if conflicts:
    ...     for c in conflicts:
    ...         print(f"Conflict: {c.rule_ids} both modify {c.resource}")

"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from runner.engine import select_implementation

if TYPE_CHECKING:
    pass


@dataclass
class ConflictEntry:
    """A rule's contribution to a conflict."""

    rule_id: str
    mechanism: str
    value: str | None


@dataclass
class Conflict:
    """A detected conflict between rules."""

    resource_type: str  # "config", "sysctl", "service", "package", "file_perm", "kmod"
    resource_key: str  # e.g., "/etc/ssh/sshd_config::MaxAuthTries"
    entries: list[ConflictEntry]

    @property
    def rule_ids(self) -> list[str]:
        """List of conflicting rule IDs."""
        return [e.rule_id for e in self.entries]

    def describe(self) -> str:
        """Human-readable description of the conflict."""
        lines = [f"Resource: {self.resource_type} {self.resource_key}"]
        for e in self.entries:
            lines.append(f"  - {e.rule_id}: sets {e.value}")
        return "\n".join(lines)


def get_conflict_key(step: dict) -> tuple[str, str] | None:
    """Extract the resource identifier for conflict detection.

    Args:
        step: Remediation step dict with 'mechanism' key.

    Returns:
        Tuple of (resource_type, resource_key) or None if not trackable.

    """
    mech = step.get("mechanism", "")

    if mech == "config_set":
        return ("config", f"{step['path']}::{step['key']}")

    if mech == "config_set_dropin":
        return ("config", f"{step['dir']}/{step['file']}::{step['key']}")

    if mech == "config_remove":
        return ("config", f"{step['path']}::{step['key']}")

    if mech == "sysctl_set":
        return ("sysctl", step["key"])

    if mech == "file_permissions":
        return ("file_perm", step["path"])

    if mech in ("service_enabled", "service_disabled", "service_masked"):
        return ("service", step["name"])

    if mech in ("package_present", "package_absent"):
        return ("package", step["name"])

    if mech == "kernel_module_disable":
        return ("kmod", step["name"])

    if mech == "grub_parameter_set":
        return ("grub", step["key"])

    if mech == "grub_parameter_remove":
        return ("grub", step["key"])

    if mech == "selinux_boolean_set":
        return ("selinux", step["name"])

    # command_exec, manual, file_content, file_absent, config_block, etc.
    # These are harder to track for conflicts
    return None


def extract_value(step: dict) -> str | None:
    """Extract the value being set by a remediation step.

    Args:
        step: Remediation step dict.

    Returns:
        The value being set, or a state description.

    """
    mech = step.get("mechanism", "")

    if mech in ("config_set", "config_set_dropin"):
        return str(step.get("value", ""))

    if mech == "config_remove":
        return "(removed)"

    if mech == "sysctl_set":
        return str(step.get("value", ""))

    if mech == "file_permissions":
        parts = []
        if "owner" in step:
            parts.append(f"owner={step['owner']}")
        if "group" in step:
            parts.append(f"group={step['group']}")
        if "mode" in step:
            parts.append(f"mode={step['mode']}")
        return ", ".join(parts) if parts else None

    if mech == "service_enabled":
        return "enabled"

    if mech == "service_disabled":
        return "disabled"

    if mech == "service_masked":
        return "masked"

    if mech == "package_present":
        return "installed"

    if mech == "package_absent":
        return "removed"

    if mech == "kernel_module_disable":
        return "disabled"

    if mech == "grub_parameter_set":
        value = step.get("value")
        return f"{step['key']}={value}" if value else step["key"]

    if mech == "grub_parameter_remove":
        return "(removed)"

    if mech == "selinux_boolean_set":
        value = step.get("value", True)
        return "on" if value else "off"

    return None


def detect_conflicts(
    rules: list[dict],
    capabilities: dict[str, bool],
) -> list[Conflict]:
    """Detect semantic conflicts before execution.

    Args:
        rules: List of rule dicts.
        capabilities: Detected host capabilities.

    Returns:
        List of Conflict objects describing conflicts found.

    """
    # Map: (resource_type, resource_key) -> [(rule_id, step, value)]
    resource_map: dict[tuple[str, str], list[ConflictEntry]] = {}

    for rule in rules:
        impl = select_implementation(rule, capabilities)
        if impl is None:
            continue

        rem = impl.get("remediation")
        if rem is None:
            continue

        # Handle multi-step remediation
        steps = rem.get("steps", [rem])
        for step in steps:
            if "mechanism" not in step:
                continue

            key = get_conflict_key(step)
            if key is None:
                continue

            value = extract_value(step)
            entry = ConflictEntry(
                rule_id=rule["id"],
                mechanism=step["mechanism"],
                value=value,
            )
            resource_map.setdefault(key, []).append(entry)

    # Find conflicts: multiple rules targeting same resource with different values
    conflicts = []
    for (res_type, res_key), entries in resource_map.items():
        if len(entries) <= 1:
            continue

        # Check if values are different
        values = {e.value for e in entries}
        if len(values) > 1:
            # Different values = conflict
            conflicts.append(
                Conflict(
                    resource_type=res_type,
                    resource_key=res_key,
                    entries=entries,
                )
            )

    return conflicts


def format_conflicts(conflicts: list[Conflict]) -> str:
    """Format conflicts for display.

    Args:
        conflicts: List of detected conflicts.

    Returns:
        Formatted string for terminal output.

    """
    if not conflicts:
        return ""

    lines = ["[red]ERROR:[/red] Conflicting rules detected\n"]

    for conflict in conflicts:
        rule_list = " vs ".join(conflict.rule_ids)
        lines.append(f"  [bold]{rule_list}[/bold]")
        lines.append(f"    Both modify: {conflict.resource_type} :: {conflict.resource_key}")
        for entry in conflict.entries:
            lines.append(f"      {entry.rule_id}: sets {entry.value}")
        lines.append("")

    lines.append("Resolve by:")
    lines.append("  - Remove one rule from the run (--exclude <rule-id>)")
    lines.append("  - Use --allow-conflicts to run anyway (last rule wins)")
    lines.append("")
    lines.append("Aborting. No changes made.")

    return "\n".join(lines)
