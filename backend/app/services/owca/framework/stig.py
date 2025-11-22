"""
OWCA Framework Layer - STIG Intelligence

Provides STIG specific compliance intelligence including:
- CAT I/II/III severity analysis
- Finding status distribution
- Automated vs manual check breakdown

Reference: DISA Security Technical Implementation Guides
Security: All database queries use QueryBuilder for SQL injection protection.
"""

import logging
from typing import Dict, List, Optional

from .base import BaseFrameworkIntelligence
from .models import STIGFrameworkIntelligence, STIGSeverity, STIGSeverityScore

logger = logging.getLogger(__name__)


class STIGFrameworkIntelligence(BaseFrameworkIntelligence):
    """
    STIG Framework Intelligence Provider.

    Analyzes compliance against DISA STIGs with CAT I/II/III
    severity classifications.
    """

    def _get_framework_name(self) -> str:
        """Get framework name identifier."""
        return "STIG"

    async def analyze_host_compliance(
        self, host_id: str, scan_results: Optional[Dict] = None
    ) -> STIGFrameworkIntelligence:
        """
        Analyze host compliance using STIG specific intelligence.

        Args:
            host_id: UUID of the host to analyze
            scan_results: Optional pre-fetched scan results

        Returns:
            STIGFrameworkIntelligence with complete STIG analysis
        """
        logger.info(f"Analyzing STIG compliance for host {host_id}")

        # Extract STIG-mapped rules
        stig_rules = self._extract_framework_rules(scan_results or {}, "stig")

        if not stig_rules:
            logger.warning(f"No STIG rules found for host {host_id}")
            return self._create_empty_intelligence()

        # Calculate overall STIG compliance score
        overall_score = self._calculate_framework_score(stig_rules)
        overall_tier = self._get_compliance_tier(overall_score)

        # Analyze CAT I/II/III severity
        severity_scores = self._analyze_severity_categories(stig_rules)

        # Count finding statuses
        total = len(stig_rules)
        open_findings = sum(1 for r in stig_rules if r["result"] == "fail")
        not_a_finding = sum(1 for r in stig_rules if r["result"] == "pass")
        not_applicable = 0  # Would parse from scan metadata
        not_reviewed = 0

        intelligence = STIGFrameworkIntelligence(
            stig_id="Generic_STIG",  # Would extract from scan metadata
            stig_version="V1R1",  # Would extract from scan metadata
            overall_score=overall_score,
            overall_tier=overall_tier,
            severity_scores=severity_scores,
            total_findings=total,
            open_findings=open_findings,
            not_a_finding=not_a_finding,
            not_applicable=not_applicable,
            not_reviewed=not_reviewed,
            automated_checks=total,  # Assume all automated
            manual_checks=0,
        )

        logger.info(f"STIG analysis complete: {overall_score}% ({overall_tier})")
        return intelligence

    async def get_framework_summary(self, scan_results: Dict) -> Dict:
        """Generate STIG summary."""
        stig_rules = self._extract_framework_rules(scan_results, "stig")
        score = self._calculate_framework_score(stig_rules) if stig_rules else 0.0

        return {
            "framework": "STIG",
            "score": round(score, 2),
            "tier": self._get_compliance_tier(score),
            "findings_total": len(stig_rules),
        }

    def _analyze_severity_categories(self, stig_rules: List[Dict]) -> List[STIGSeverityScore]:
        """Analyze STIG CAT I/II/III severity categories."""
        severity_rules = {
            STIGSeverity.CAT_I: [],
            STIGSeverity.CAT_II: [],
            STIGSeverity.CAT_III: [],
        }

        # Map severity to CAT (simplified - would parse from metadata)
        for rule in stig_rules:
            severity = rule.get("severity", "medium").lower()
            if severity == "high":
                cat = STIGSeverity.CAT_I
            elif severity == "medium":
                cat = STIGSeverity.CAT_II
            else:
                cat = STIGSeverity.CAT_III
            severity_rules[cat].append(rule)

        severity_scores = []
        for cat in [STIGSeverity.CAT_I, STIGSeverity.CAT_II, STIGSeverity.CAT_III]:
            rules = severity_rules[cat]
            if not rules:
                continue

            total = len(rules)
            open_findings = sum(1 for r in rules if r["result"] == "fail")
            not_a_finding = sum(1 for r in rules if r["result"] == "pass")
            score = self.score_calculator.calculate_score(not_a_finding, total)

            severity_scores.append(
                STIGSeverityScore(
                    severity=cat,
                    findings_total=total,
                    findings_open=open_findings,
                    findings_not_a_finding=not_a_finding,
                    findings_not_applicable=0,
                    findings_not_reviewed=0,
                    score=round(score, 2),
                    tier=self._get_compliance_tier(score),
                )
            )

        return severity_scores

    def _create_empty_intelligence(self) -> STIGFrameworkIntelligence:
        """Create empty STIG intelligence object."""
        return STIGFrameworkIntelligence(
            stig_id="Unknown",
            stig_version="V0R0",
            overall_score=0.0,
            overall_tier="poor",
            total_findings=0,
            open_findings=0,
            not_a_finding=0,
            not_applicable=0,
            not_reviewed=0,
            automated_checks=0,
            manual_checks=0,
        )
