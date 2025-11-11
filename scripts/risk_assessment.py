#!/usr/bin/env python3
"""
Risk Assessment Engine for GitHub Automation
Calculates risk scores based on Complexity, Severity, and Disruption

Usage:
    python scripts/risk_assessment.py dependabot_alerts.json
    python scripts/risk_assessment.py --type=codeql security_alerts.json
"""

import json
import sys
import argparse
from typing import Dict, List
from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    """Risk level enum"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class RiskScore:
    """Risk score calculation"""
    complexity: RiskLevel
    severity: RiskLevel
    disruption: RiskLevel
    alert_data: Dict = None

    @property
    def average(self) -> float:
        """Calculate average risk score"""
        return (self.complexity.value + self.severity.value + self.disruption.value) / 3

    @property
    def level(self) -> str:
        """Determine overall risk level"""
        score = self.average
        if score <= 1.6:
            return "LOW"
        elif score <= 2.3:
            return "MEDIUM"
        else:
            return "HIGH"

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "complexity": self.complexity.name,
            "severity": self.severity.name,
            "disruption": self.disruption.name,
            "score": round(self.average, 2),
            "level": self.level,
            "can_auto_fix": self.level == "LOW",
            "needs_review": self.level in ["MEDIUM", "HIGH"]
        }

    def __str__(self) -> str:
        return (f"Risk(C:{self.complexity.name}, S:{self.severity.name}, "
                f"D:{self.disruption.name}) = {self.average:.2f} ({self.level})")


class DependabotRiskAssessor:
    """Assess risk for Dependabot alerts"""

    CVE_SEVERITY_MAP = {
        "critical": RiskLevel.HIGH,
        "high": RiskLevel.HIGH,
        "moderate": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
    }

    UPDATE_COMPLEXITY = {
        "patch": RiskLevel.LOW,     # 1.0.0 → 1.0.1
        "minor": RiskLevel.MEDIUM,  # 1.0.0 → 1.1.0
        "major": RiskLevel.HIGH,    # 1.0.0 → 2.0.0
    }

    CRITICAL_PACKAGES = [
        "react", "fastapi", "sqlalchemy", "celery", "redis",
        "typescript", "webpack", "vite", "django", "flask",
        "express", "next", "vue", "angular"
    ]

    def assess_alert(self, alert: Dict) -> RiskScore:
        """Assess risk for Dependabot alert"""
        # Get version info
        vulnerable_version = alert.get("security_vulnerability", {}).get("vulnerable_version_range", "")
        package_name = alert.get("dependency", {}).get("package", {}).get("name", "")
        severity = alert.get("security_vulnerability", {}).get("severity", "low")

        # Determine update type (if we have version info)
        update_type = "minor"  # Default
        if "first_patched_version" in alert.get("security_vulnerability", {}):
            update_type = self._determine_update_type(vulnerable_version)

        complexity = self.UPDATE_COMPLEXITY.get(update_type, RiskLevel.MEDIUM)
        severity_level = self.CVE_SEVERITY_MAP.get(severity.lower(), RiskLevel.LOW)
        disruption = self._assess_disruption(package_name, update_type)

        return RiskScore(complexity, severity_level, disruption, alert)

    def _determine_update_type(self, version_range: str) -> str:
        """Determine update type from version range"""
        if ">=" in version_range and "<" in version_range:
            # Parse semver range
            if ".0 <" in version_range or ".0.0 <" in version_range:
                return "major"
            elif "." in version_range:
                return "minor"
        return "patch"

    def _assess_disruption(self, package: str, update_type: str) -> RiskLevel:
        """Assess disruption based on package criticality"""
        is_critical = any(pkg in package.lower() for pkg in self.CRITICAL_PACKAGES)

        if is_critical:
            if update_type == "major":
                return RiskLevel.HIGH
            elif update_type == "minor":
                return RiskLevel.MEDIUM
            return RiskLevel.LOW
        else:
            if update_type == "major":
                return RiskLevel.MEDIUM
            return RiskLevel.LOW


class CodeScanningRiskAssessor:
    """Assess risk for CodeQL/Trivy/Grype alerts"""

    SEVERITY_MAP = {
        "error": RiskLevel.HIGH,
        "warning": RiskLevel.MEDIUM,
        "note": RiskLevel.LOW,
    }

    # Auto-fixable rules (low complexity)
    AUTO_FIXABLE_RULES = {
        "py/unused-import",
        "js/unused-variable",
        "trailing-whitespace",
        "end-of-file-fixer",
    }

    # Medium complexity rules
    MEDIUM_COMPLEXITY_RULES = {
        "py/log-injection",
        "js/incomplete-sanitization",
        "py/uninitialized-local-variable",
    }

    # High complexity rules
    HIGH_COMPLEXITY_RULES = {
        "py/sql-injection",
        "js/code-injection",
        "authentication-bypass",
    }

    def assess_alert(self, alert: Dict) -> RiskScore:
        """Assess risk for code scanning alert"""
        rule_id = alert.get("rule", {}).get("id", "")
        severity_str = alert.get("rule", {}).get("severity", "note")
        tool = alert.get("tool", {}).get("name", "")

        complexity = self._assess_complexity(rule_id, tool)
        severity = self.SEVERITY_MAP.get(severity_str, RiskLevel.LOW)
        disruption = self._assess_disruption(rule_id, tool, severity)

        return RiskScore(complexity, severity, disruption, alert)

    def _assess_complexity(self, rule_id: str, tool: str) -> RiskLevel:
        """Assess fix complexity"""
        if rule_id in self.AUTO_FIXABLE_RULES:
            return RiskLevel.LOW

        if rule_id in self.MEDIUM_COMPLEXITY_RULES:
            return RiskLevel.MEDIUM

        if rule_id in self.HIGH_COMPLEXITY_RULES:
            return RiskLevel.HIGH

        # CVE fixes
        if "CVE-" in rule_id or tool in ["Trivy", "Grype"]:
            return RiskLevel.MEDIUM

        # Default
        return RiskLevel.MEDIUM

    def _assess_disruption(self, rule_id: str, tool: str, severity: RiskLevel) -> RiskLevel:
        """Assess deployment disruption"""
        # Security issues = higher disruption
        if "injection" in rule_id or "xss" in rule_id or "authentication" in rule_id:
            return RiskLevel.HIGH

        # High severity issues = higher disruption
        if severity == RiskLevel.HIGH:
            return RiskLevel.HIGH

        # Dependency updates
        if tool in ["Trivy", "Grype"]:
            return RiskLevel.MEDIUM

        # Code quality issues
        if "unused" in rule_id or "format" in rule_id or "whitespace" in rule_id:
            return RiskLevel.LOW

        return RiskLevel.MEDIUM


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Assess risk for GitHub security alerts")
    parser.add_argument("alerts_file", help="JSON file containing alerts")
    parser.add_argument("--type", choices=["dependabot", "codeql"], default="dependabot",
                        help="Type of alerts to assess")
    parser.add_argument("--output", default=".", help="Output directory for categorized alerts")
    args = parser.parse_args()

    # Load alerts
    try:
        with open(args.alerts_file, 'r') as f:
            alerts = json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{args.alerts_file}' not found")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in '{args.alerts_file}'")
        sys.exit(1)

    # Ensure alerts is a list
    if not isinstance(alerts, list):
        alerts = [alerts]

    # Choose assessor
    if args.type == "dependabot":
        assessor = DependabotRiskAssessor()
    else:
        assessor = CodeScanningRiskAssessor()

    # Categorize by risk level
    low_risk = []
    medium_risk = []
    high_risk = []

    print("Risk Assessment Results:")
    print("=" * 70)

    for i, alert in enumerate(alerts, 1):
        try:
            score = assessor.assess_alert(alert)
            alert_id = alert.get("number", alert.get("id", i))

            print(f"{i}. Alert #{alert_id}: {score}")

            # Add risk info to alert
            alert["risk_assessment"] = score.to_dict()

            # Categorize
            if score.level == "LOW":
                low_risk.append(alert)
            elif score.level == "MEDIUM":
                medium_risk.append(alert)
            else:
                high_risk.append(alert)

        except Exception as e:
            print(f"Error assessing alert {i}: {e}")
            high_risk.append(alert)  # Default to high risk on error

    print("=" * 70)

    # Write categorized alerts
    import os
    output_dir = args.output

    with open(os.path.join(output_dir, "low_risk_alerts.json"), 'w') as f:
        json.dump(low_risk, f, indent=2)

    with open(os.path.join(output_dir, "medium_risk_alerts.json"), 'w') as f:
        json.dump(medium_risk, f, indent=2)

    with open(os.path.join(output_dir, "high_risk_alerts.json"), 'w') as f:
        json.dump(high_risk, f, indent=2)

    # Summary
    total = len(alerts)
    print(f"\nRisk Assessment Summary:")
    print(f"  Total Alerts:  {total}")

    if total > 0:
        print(f"  LOW Risk:      {len(low_risk)} ({len(low_risk)/total*100:.1f}%) → Auto-fix")
        print(f"  MEDIUM Risk:   {len(medium_risk)} ({len(medium_risk)/total*100:.1f}%) → Claude creates PR")
        print(f"  HIGH Risk:     {len(high_risk)} ({len(high_risk)/total*100:.1f}%) → Human review required")
    else:
        print("  No alerts to assess")

    # GitHub Actions outputs (using modern GITHUB_OUTPUT file syntax)
    if os.getenv("GITHUB_ACTIONS"):
        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, 'a') as f:
                f.write(f"has_low_risk={str(len(low_risk) > 0).lower()}\n")
                f.write(f"has_medium_risk={str(len(medium_risk) > 0).lower()}\n")
                f.write(f"has_high_risk={str(len(high_risk) > 0).lower()}\n")
                f.write(f"low_risk_count={len(low_risk)}\n")
                f.write(f"medium_risk_count={len(medium_risk)}\n")
                f.write(f"high_risk_count={len(high_risk)}\n")

    print(f"\nOutput files created in: {output_dir}/")


if __name__ == "__main__":
    main()
