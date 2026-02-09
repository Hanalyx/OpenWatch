"""Rule variable configuration loading and resolution.

This module handles loading of configurable variables for rules, allowing
different compliance frameworks (CIS, STIG, NIST) to use different threshold
values for the same control.

Configuration is loaded from:
1. rules/defaults.yml - Base variable definitions and framework overrides
2. rules/rules.d/*.yml - User overrides (loaded alphabetically)

Variables are resolved at rule-load time with this priority (highest first):
1. CLI --var KEY=VALUE overrides
2. rules/rules.d/*.yml (later files override earlier)
3. frameworks.<name> section (when --framework specified)
4. variables section in rules/defaults.yml

Example:
-------
    >>> from runner._config import load_config, resolve_variables
    >>>
    >>> config = load_config("rules/")
    >>> rule = {"check": {"expected": "{{ pam_pwquality_minlen }}"}}
    >>> resolved = resolve_variables(rule, config, framework="stig")
    >>> print(resolved["check"]["expected"])
    '15'

"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ── Variable pattern ───────────────────────────────────────────────────────

# Matches {{ variable_name }} with optional whitespace
VARIABLE_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


# ── Safe fields for substitution ───────────────────────────────────────────
#
# Security: Only substitute variables in value fields, never in paths
# or command fields that could lead to shell injection.
#

SAFE_SUBSTITUTION_FIELDS = frozenset(
    {
        "expected",
        "value",
        "mode",
        "owner",
        "group",
    }
)


# ── Data structures ────────────────────────────────────────────────────────


@dataclass
class RuleConfig:
    """Configuration for rule variables.

    Attributes:
        variables: Default variable values.
        framework_overrides: Framework-specific variable overrides.
            Keys are framework names (e.g., "cis", "stig").
            Values are dicts mapping variable names to values.

    """

    variables: dict[str, Any] = field(default_factory=dict)
    framework_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)


# ── Configuration loading ──────────────────────────────────────────────────


def load_config(rules_path: str | None = None) -> RuleConfig:
    """Load rule configuration from defaults.yml and rules.d overrides.

    Args:
        rules_path: Path to rules directory. If None, looks for rules/
            relative to the current directory.

    Returns:
        RuleConfig with merged variables and framework overrides.

    """
    if rules_path is None:
        rules_path = "rules"

    rules_dir = Path(rules_path)
    if not rules_dir.is_dir():
        # If path is a file, use its parent directory
        rules_dir = rules_dir.parent

    config = RuleConfig()

    # Load defaults.yml
    defaults_path = rules_dir / "defaults.yml"
    if defaults_path.exists():
        try:
            data = yaml.safe_load(defaults_path.read_text())
            if isinstance(data, dict):
                config.variables = data.get("variables", {})
                config.framework_overrides = data.get("frameworks", {})
        except yaml.YAMLError:
            pass  # Silently ignore malformed defaults

    # Load rules.d/*.yml overrides (alphabetically)
    rules_d = rules_dir / "rules.d"
    if rules_d.is_dir():
        for override_file in sorted(rules_d.glob("*.yml")):
            try:
                data = yaml.safe_load(override_file.read_text())
                if isinstance(data, dict):
                    # Merge variables
                    if "variables" in data:
                        config.variables.update(data["variables"])
                    # Merge framework overrides
                    if "frameworks" in data:
                        for fw_name, fw_vars in data["frameworks"].items():
                            if fw_name not in config.framework_overrides:
                                config.framework_overrides[fw_name] = {}
                            config.framework_overrides[fw_name].update(fw_vars)
            except yaml.YAMLError:
                pass  # Silently ignore malformed overrides

    return config


# ── Variable resolution ────────────────────────────────────────────────────


def _get_effective_variables(
    config: RuleConfig,
    *,
    framework: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the effective variable dict with proper priority.

    Priority (highest first):
    1. CLI --var overrides
    2. Framework-specific values
    3. Default values from config

    Args:
        config: Loaded rule configuration.
        framework: Framework name for framework-specific overrides.
        cli_overrides: CLI --var KEY=VALUE overrides.

    Returns:
        Dict of variable names to resolved values.

    """
    # Start with defaults
    effective = dict(config.variables)

    # Apply framework overrides if specified
    if framework:
        # Extract base framework name (e.g., "cis" from "cis-rhel9-v2.0.0")
        fw_base = framework.split("-")[0].lower()
        if fw_base in config.framework_overrides:
            effective.update(config.framework_overrides[fw_base])

    # Apply CLI overrides (highest priority)
    if cli_overrides:
        effective.update(cli_overrides)

    return effective


def _substitute_string(
    value: str,
    variables: dict[str, Any],
    *,
    strict: bool = True,
) -> str:
    """Substitute {{ variable }} patterns in a string.

    Args:
        value: String potentially containing {{ variable }} patterns.
        variables: Dict of variable names to values.
        strict: If True, raise error on undefined variables.

    Returns:
        String with variables substituted.

    Raises:
        ValueError: If strict=True and a variable is undefined.

    """

    def replace_var(match: re.Match) -> str:
        var_name = match.group(1)
        if var_name in variables:
            return str(variables[var_name])
        elif strict:
            raise ValueError(f"Undefined variable: {var_name}")
        else:
            return match.group(0)  # Leave unchanged

    return VARIABLE_PATTERN.sub(replace_var, value)


def _substitute_in_dict(
    d: dict[str, Any],
    variables: dict[str, Any],
    *,
    strict: bool = True,
) -> dict[str, Any]:
    """Recursively substitute variables in a dict's safe fields.

    Args:
        d: Dict to process.
        variables: Variable values.
        strict: If True, raise on undefined variables.

    Returns:
        New dict with substitutions applied.

    """
    result: dict[str, Any] = {}
    for key, value in d.items():
        if isinstance(value, str):
            # Only substitute in safe fields
            if key in SAFE_SUBSTITUTION_FIELDS:
                result[key] = _substitute_string(value, variables, strict=strict)
            else:
                result[key] = value
        elif isinstance(value, dict):
            result[key] = _substitute_in_dict(value, variables, strict=strict)
        elif isinstance(value, list):
            result[key] = _substitute_in_list(value, variables, strict=strict)
        else:
            result[key] = value
    return result


def _substitute_in_list(
    lst: list[Any],
    variables: dict[str, Any],
    *,
    strict: bool = True,
) -> list[Any]:
    """Recursively substitute variables in a list.

    Args:
        lst: List to process.
        variables: Variable values.
        strict: If True, raise on undefined variables.

    Returns:
        New list with substitutions applied.

    """
    result: list[Any] = []
    for item in lst:
        if isinstance(item, dict):
            result.append(_substitute_in_dict(item, variables, strict=strict))
        elif isinstance(item, list):
            result.append(_substitute_in_list(item, variables, strict=strict))
        else:
            result.append(item)
    return result


def resolve_variables(
    rule: dict,
    config: RuleConfig,
    *,
    framework: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    strict: bool = True,
) -> dict:
    """Resolve {{ variable }} placeholders in a rule.

    Only substitutes in safe fields (expected, value, mode, owner, group).
    Never substitutes in path, run, command, or other execution-related fields.

    Args:
        rule: Rule dict to process.
        config: Loaded rule configuration.
        framework: Framework name for framework-specific values.
        cli_overrides: CLI --var KEY=VALUE overrides.
        strict: If True, raise on undefined variables.

    Returns:
        New rule dict with variables resolved.

    Raises:
        ValueError: If strict=True and a variable is undefined.

    """
    variables = _get_effective_variables(config, framework=framework, cli_overrides=cli_overrides)

    # Deep copy and substitute
    return _substitute_in_dict(rule, variables, strict=strict)


def parse_var_overrides(var_flags: tuple[str, ...]) -> dict[str, str]:
    """Parse --var KEY=VALUE flags into a dict.

    Args:
        var_flags: Tuple of "KEY=VALUE" strings from CLI.

    Returns:
        Dict mapping variable names to values.

    Raises:
        ValueError: If a flag is malformed.

    """
    result = {}
    for flag in var_flags:
        if "=" not in flag:
            raise ValueError(f"Invalid --var format: {flag} (expected KEY=VALUE)")
        key, value = flag.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Invalid --var format: {flag} (empty key)")
        result[key] = value
    return result
