"""Result data types for the rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CheckResult:
    """Outcome of a single check."""

    passed: bool
    detail: str = ""


@dataclass
class PreState:
    """Captured state before a remediation step."""

    mechanism: str
    data: dict  # mechanism-specific, all values are str/bool/None/list
    capturable: bool = True  # False for command_exec and manual


@dataclass
class StepResult:
    """Outcome of a single remediation step."""

    step_index: int
    mechanism: str
    success: bool
    detail: str
    pre_state: PreState | None = None
    verified: bool | None = None  # None = not attempted
    verify_detail: str = ""


@dataclass
class RollbackResult:
    """Outcome of rolling back one step."""

    step_index: int
    mechanism: str
    success: bool
    detail: str


@dataclass
class RuleResult:
    """Outcome of evaluating one rule on one host."""

    rule_id: str
    title: str
    severity: str
    passed: bool
    skipped: bool = False
    skip_reason: str = ""
    detail: str = ""
    remediated: bool = False
    remediation_detail: str = ""
    step_results: list[StepResult] = field(default_factory=list)
    rolled_back: bool = False
    rollback_results: list[RollbackResult] = field(default_factory=list)
    framework_section: str | None = None
