"""
Aegis Compliance Engine for OpenWatch

This module provides the Aegis compliance scanning engine integration.
Aegis v0.1.0 provides SSH-based compliance checks with 338 canonical YAML rules.

Capabilities:
- CIS RHEL 9 v2.0.0: 95.1% coverage (271/285 controls)
- STIG RHEL 9 V2R7: 75.8% coverage (338/446 controls)
- NIST 800-53 mappings included

The Aegis engine uses the 'runner' package internally. This module provides
a namespace wrapper so OpenWatch can import from 'aegis.*' consistently.

Usage:
    from aegis import SSHSession, check_rules_from_path, RuleResult

    with SSHSession("host", user="admin", sudo=True) as ssh:
        results = check_rules_from_path(ssh, "aegis/rules/")
        for r in results:
            print(f"{r.rule_id}: {'PASS' if r.passed else 'FAIL'}")

Version: 0.1.0
Source: https://github.com/Hanalyx/aegis
"""

__version__ = "0.1.0"
__author__ = "Hanalyx"

from aegis.runner.detect import detect_capabilities, detect_platform
from aegis.runner.engine import (  # Core functions; Rule loading; Types; Configuration
    CheckResult,
    PreState,
    RollbackResult,
    RuleConfig,
    RuleResult,
    StepResult,
    check_rules_from_path,
    check_single_rule,
    evaluate_rule,
    load_config,
    load_rules,
    quick_host_info,
    remediate_rule,
    rule_applies_to_platform,
)
from aegis.runner.mappings import (
    CoverageReport,
    FrameworkMapping,
    check_coverage,
    get_applicable_mappings,
    load_all_mappings,
    load_mapping,
    order_by_framework,
    rules_for_framework,
)

# Re-export from runner module
from aegis.runner.ssh import Result, SSHSession

__all__ = [
    # Version
    "__version__",
    # SSH
    "SSHSession",
    "Result",
    # Core functions
    "check_single_rule",
    "check_rules_from_path",
    "quick_host_info",
    "evaluate_rule",
    "remediate_rule",
    # Rule loading
    "load_rules",
    "rule_applies_to_platform",
    # Types
    "RuleResult",
    "CheckResult",
    "StepResult",
    "PreState",
    "RollbackResult",
    # Configuration
    "RuleConfig",
    "load_config",
    # Detection
    "detect_capabilities",
    "detect_platform",
    # Framework mappings
    "load_mapping",
    "load_all_mappings",
    "get_applicable_mappings",
    "rules_for_framework",
    "order_by_framework",
    "FrameworkMapping",
    "CoverageReport",
    "check_coverage",
]
