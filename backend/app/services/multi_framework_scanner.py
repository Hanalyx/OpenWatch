"""
Multi-Framework Scanner Service
Provides data models for scan results across multiple compliance frameworks
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from ..models.unified_rule_models import RuleExecution


@dataclass
class FrameworkResult:
    """Results for a single compliance framework"""

    framework_id: str
    compliance_percentage: float
    total_rules: int
    compliant_rules: int
    non_compliant_rules: int
    error_rules: int
    rule_executions: List[RuleExecution] = field(default_factory=list)


@dataclass
class HostResult:
    """Results for a single host"""

    host_id: str
    platform_info: Dict[str, Any]
    framework_results: List[FrameworkResult] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete scan result across all hosts and frameworks"""

    scan_id: str
    started_at: datetime
    completed_at: datetime
    total_execution_time: float
    host_results: List[HostResult] = field(default_factory=list)

    @classmethod
    def parse_obj(cls, data: Dict[str, Any]) -> "ScanResult":
        """Parse from dictionary (compatibility method)"""
        return cls(
            scan_id=data["scan_id"],
            started_at=(
                datetime.fromisoformat(data["started_at"])
                if isinstance(data["started_at"], str)
                else data["started_at"]
            ),
            completed_at=(
                datetime.fromisoformat(data["completed_at"])
                if isinstance(data["completed_at"], str)
                else data["completed_at"]
            ),
            total_execution_time=data["total_execution_time"],
            host_results=[
                HostResult(
                    host_id=hr["host_id"],
                    platform_info=hr["platform_info"],
                    framework_results=[
                        FrameworkResult(
                            framework_id=fr["framework_id"],
                            compliance_percentage=fr["compliance_percentage"],
                            total_rules=fr["total_rules"],
                            compliant_rules=fr["compliant_rules"],
                            non_compliant_rules=fr["non_compliant_rules"],
                            error_rules=fr["error_rules"],
                            rule_executions=[
                                RuleExecution(
                                    execution_id=re["execution_id"],
                                    rule_id=re["rule_id"],
                                    execution_success=re["execution_success"],
                                    compliance_status=re["compliance_status"],
                                    execution_time=re["execution_time"],
                                    output_data=re.get("output_data"),
                                    error_message=re.get("error_message"),
                                    executed_at=(
                                        datetime.fromisoformat(re["executed_at"])
                                        if isinstance(re.get("executed_at"), str)
                                        else re.get("executed_at")
                                    ),
                                )
                                for re in fr.get("rule_executions", [])
                            ],
                        )
                        for fr in hr.get("framework_results", [])
                    ],
                )
                for hr in data.get("host_results", [])
            ],
        )
