"""Rule engine — re-export facade and convenience functions.

All public (and test-visible) symbols are defined in sub-modules and
re-exported here so that ``from runner.engine import X`` continues to work
unchanged for cli.py and the test suite.

This module also provides factory functions for common use cases:
- check_single_rule(): Load and check one rule file
- check_rules_from_path(): Load and check all rules from a path
- quick_host_info(): Get capabilities and platform in one call

Example:
-------
    Quick single-rule check::

        from runner.ssh import SSHSession
        from runner.engine import check_single_rule

        with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
            result = check_single_rule(ssh, "rules/access-control/ssh-disable-root-login.yml")
            print(f"{result.rule_id}: {'PASS' if result.passed else 'FAIL'}")

    Full scan with filtering::

        from runner.engine import check_rules_from_path

        with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
            results = check_rules_from_path(ssh, "rules/", severity=["high", "critical"])
            for r in results:
                print(f"{r.rule_id}: {'PASS' if r.passed else 'FAIL'}")

"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.ssh import SSHSession

# ── Data types ─────────────────────────────────────────────────────────────
# ── Pre-state capture (used by tests) ─────────────────────────────────────
from runner._capture import (  # noqa: F401
    _capture_audit_rule_set,
    _capture_command_exec,
    _capture_config_block,
    _capture_config_remove,
    _capture_config_set,
    _capture_config_set_dropin,
    _capture_cron_job,
    _capture_file_absent,
    _capture_file_content,
    _capture_file_permissions,
    _capture_grub_parameter_remove,
    _capture_grub_parameter_set,
    _capture_kernel_module_disable,
    _capture_manual,
    _capture_mount_option_set,
    _capture_package_absent,
    _capture_package_present,
    _capture_selinux_boolean_set,
    _capture_service_disabled,
    _capture_service_enabled,
    _capture_service_masked,
    _capture_sysctl_set,
)

# ── Check dispatch ─────────────────────────────────────────────────────────
from runner._checks import run_check  # noqa: F401

# ── Rule variable configuration ───────────────────────────────────────────
from runner._config import RuleConfig, load_config, parse_var_overrides, resolve_variables  # noqa: F401

# ── Rule loading & platform filtering ──────────────────────────────────────
from runner._loading import load_rules, rule_applies_to_platform  # noqa: F401

# ── Top-level orchestration ───────────────────────────────────────────────
from runner._orchestration import evaluate_rule, remediate_rule  # noqa: F401

# ── Remediation dispatch ──────────────────────────────────────────────────
from runner._remediation import run_remediation  # noqa: F401

# ── Rollback (used by tests) ──────────────────────────────────────────────
from runner._rollback import (  # noqa: F401
    _execute_rollback,
    _rollback_audit_rule_set,
    _rollback_command_exec,
    _rollback_config_block,
    _rollback_config_remove,
    _rollback_config_set,
    _rollback_config_set_dropin,
    _rollback_cron_job,
    _rollback_file_absent,
    _rollback_file_content,
    _rollback_file_permissions,
    _rollback_grub_parameter_remove,
    _rollback_grub_parameter_set,
    _rollback_kernel_module_disable,
    _rollback_manual,
    _rollback_mount_option_set,
    _rollback_package_absent,
    _rollback_package_present,
    _rollback_selinux_boolean_set,
    _rollback_service_disabled,
    _rollback_service_enabled,
    _rollback_service_masked,
    _rollback_sysctl_set,
)

# ── Implementation selection ───────────────────────────────────────────────
from runner._selection import evaluate_when, select_implementation  # noqa: F401
from runner._types import CheckResult, PreState, RollbackResult, RuleResult, StepResult  # noqa: F401

# ── Convenience factory functions ─────────────────────────────────────────


def quick_host_info(ssh: SSHSession, *, verbose: bool = False) -> tuple[dict[str, bool], tuple | None]:
    """Detect capabilities and platform information in one call.

    Convenience function that combines detect_capabilities() and
    detect_platform() for common setup patterns.

    Args:
    ----
        ssh: Active SSH session to the target host.
        verbose: If True, print debug info for failed probes.

    Returns:
    -------
        Tuple of (capabilities_dict, platform_info):
            - capabilities: Dict mapping capability name to bool
            - platform: PlatformInfo(family, version) or None if detection failed

    Example:
    -------
        >>> with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
        ...     caps, platform = quick_host_info(ssh)
        ...     print(f"Platform: {platform.family} {platform.version}")
        ...     print(f"Capabilities: {sum(caps.values())}/{len(caps)} detected")

    """
    from runner.detect import detect_capabilities, detect_platform

    caps = detect_capabilities(ssh, verbose=verbose)
    platform = detect_platform(ssh)
    return caps, platform


def check_single_rule(
    ssh: SSHSession,
    rule_path: str,
    *,
    capabilities: dict[str, bool] | None = None,
    verbose: bool = False,
) -> RuleResult:
    """Load and check a single rule file.

    Convenience function for checking one rule without manual loading
    and capability detection.

    Args:
    ----
        ssh: Active SSH session to the target host.
        rule_path: Path to a single rule YAML file.
        capabilities: Pre-detected capabilities dict. If None, detects
            capabilities automatically.
        verbose: If True, print debug info for capability probes.

    Returns:
    -------
        RuleResult with check outcome.

    Example:
    -------
        >>> with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
        ...     result = check_single_rule(ssh, "rules/access-control/ssh-disable-root-login.yml")
        ...     if result.passed:
        ...         print(f"PASS: {result.detail}")
        ...     else:
        ...         print(f"FAIL: {result.detail}")

    """
    from runner.detect import detect_capabilities

    rules = load_rules(rule_path)
    if not rules:
        return RuleResult(
            rule_id="unknown",
            title="Unknown",
            severity="unknown",
            passed=False,
            skipped=True,
            skip_reason=f"No rule found at {rule_path}",
        )

    if capabilities is None:
        capabilities = detect_capabilities(ssh, verbose=verbose)

    return evaluate_rule(ssh, rules[0], capabilities)


def check_rules_from_path(
    ssh: SSHSession,
    rules_path: str,
    *,
    capabilities: dict[str, bool] | None = None,
    severity: list[str] | None = None,
    tags: list[str] | None = None,
    category: str | None = None,
    framework: str | None = None,
    var_overrides: dict[str, str] | None = None,
    verbose: bool = False,
) -> list[RuleResult]:
    """Load and check all rules from a path with optional filtering.

    Convenience function for checking multiple rules with common
    filter options. Automatically loads and resolves variables from
    defaults.yml and rules.d/*.yml.

    Args:
    ----
        ssh: Active SSH session to the target host.
        rules_path: Path to a rule file or directory of rules.
        capabilities: Pre-detected capabilities dict. If None, detects
            capabilities automatically.
        severity: Filter by severity levels (e.g., ["high", "critical"]).
        tags: Filter by tags (OR semantics).
        category: Filter by category.
        framework: Framework name for framework-specific variable values
            (e.g., "cis", "stig"). If None, uses default values.
        var_overrides: CLI-style variable overrides (highest priority).
        verbose: If True, print debug info for capability probes.

    Returns:
    -------
        List of RuleResult for each rule checked.

    Example:
    -------
        >>> with SSHSession("192.168.1.100", user="admin", sudo=True) as ssh:
        ...     results = check_rules_from_path(
        ...         ssh, "rules/",
        ...         severity=["high", "critical"],
        ...         category="access-control"
        ...     )
        ...     passed = sum(1 for r in results if r.passed)
        ...     print(f"{passed}/{len(results)} rules passed")

    """
    from runner.detect import detect_capabilities

    rules = load_rules(rules_path, severity=severity, tags=tags, category=category)
    if not rules:
        return []

    # Load variable configuration and resolve variables in rules
    config = load_config(rules_path)
    rules = [
        resolve_variables(
            rule,
            config,
            framework=framework,
            cli_overrides=var_overrides,
            strict=False,  # Don't fail on undefined variables
        )
        for rule in rules
    ]

    if capabilities is None:
        capabilities = detect_capabilities(ssh, verbose=verbose)

    return [evaluate_rule(ssh, rule, capabilities) for rule in rules]
