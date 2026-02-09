"""Top-level rule evaluation and remediation orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from runner._checks import run_check
from runner._remediation import run_remediation
from runner._rollback import _execute_rollback
from runner._selection import select_implementation
from runner._types import RuleResult

if TYPE_CHECKING:
    from runner.ssh import SSHSession


def evaluate_rule(ssh: SSHSession, rule: dict, capabilities: dict[str, bool]) -> RuleResult:
    """Evaluate a single rule: select implementation and run its check."""
    rule_id = rule["id"]
    title = rule.get("title", rule_id)
    severity = rule.get("severity", "unknown")

    impl = select_implementation(rule, capabilities)
    if impl is None:
        return RuleResult(
            rule_id=rule_id,
            title=title,
            severity=severity,
            passed=False,
            skipped=True,
            skip_reason="No matching implementation",
        )

    check = impl.get("check")
    if check is None:
        return RuleResult(
            rule_id=rule_id,
            title=title,
            severity=severity,
            passed=False,
            skipped=True,
            skip_reason="Implementation has no check",
        )

    try:
        cr = run_check(ssh, check)
    except Exception as exc:
        return RuleResult(
            rule_id=rule_id,
            title=title,
            severity=severity,
            passed=False,
            detail=f"Error: {exc}",
        )

    return RuleResult(
        rule_id=rule_id,
        title=title,
        severity=severity,
        passed=cr.passed,
        detail=cr.detail,
    )


def remediate_rule(
    ssh: SSHSession,
    rule: dict,
    capabilities: dict[str, bool],
    *,
    dry_run: bool = False,
    rollback_on_failure: bool = False,
) -> RuleResult:
    """Check a rule, remediate if failing, then re-check."""
    # Initial check
    result = evaluate_rule(ssh, rule, capabilities)
    if result.passed or result.skipped:
        return result

    impl = select_implementation(rule, capabilities)
    if impl is None:
        result.remediation_detail = "No matching implementation"
        return result

    assert impl is not None  # mypy type narrowing
    remediation = impl.get("remediation")
    if remediation is None:
        result.remediation_detail = "No remediation defined"
        return result

    check = impl.get("check")

    try:
        ok, detail, step_results = run_remediation(
            ssh,
            remediation,
            dry_run=dry_run,
            check=check,
        )
    except Exception as exc:
        result.remediation_detail = f"Error: {exc}"
        return result

    result.remediated = True
    result.remediation_detail = detail
    result.step_results = step_results

    if not ok:
        if rollback_on_failure and not dry_run:
            result.rollback_results = _execute_rollback(ssh, step_results)
            result.rolled_back = True
        return result

    if dry_run:
        return result

    # Re-check after remediation
    if check:
        try:
            cr = run_check(ssh, check)
            result.passed = cr.passed
            result.detail = cr.detail
        except Exception as exc:
            result.detail = f"Re-check error: {exc}"

    # Rollback if re-check failed
    if rollback_on_failure and not result.passed:
        result.rollback_results = _execute_rollback(ssh, step_results)
        result.rolled_back = True

    return result
