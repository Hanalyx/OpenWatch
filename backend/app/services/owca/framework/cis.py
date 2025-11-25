"""
OWCA Framework Layer - CIS Benchmark Intelligence

Provides CIS Benchmark specific compliance intelligence including:
- Level 1/2 assessment
- Implementation Group (IG1/IG2/IG3) scoring
- Platform-specific recommendations

Reference: CIS Benchmarks
Security: All database queries use QueryBuilder for SQL injection protection.
"""

import logging
from typing import Dict, List, Optional

from .base import BaseFrameworkIntelligence
from .models import (
    CISFrameworkIntelligence,
    CISImplementationGroup,
    CISImplementationGroupScore,
    CISLevel,
    CISLevelScore,
)

logger = logging.getLogger(__name__)


class CISBenchmarkIntelligence(BaseFrameworkIntelligence):
    """
    CIS Benchmark Framework Intelligence Provider.

    Analyzes compliance against CIS Benchmarks with Level 1/2
    and Implementation Group (IG1/IG2/IG3) assessments.
    """

    def _get_framework_name(self) -> str:
        """Get framework name identifier."""
        return "CIS"

    async def analyze_host_compliance(
        self, host_id: str, scan_results: Optional[Dict] = None
    ) -> CISFrameworkIntelligence:
        """
        Analyze host compliance using CIS Benchmark specific intelligence.

        Args:
            host_id: UUID of the host to analyze
            scan_results: Optional pre-fetched scan results

        Returns:
            CISFrameworkIntelligence with complete CIS analysis
        """
        logger.info(f"Analyzing CIS Benchmark compliance for host {host_id}")

        # Extract CIS-mapped rules
        cis_rules = self._extract_framework_rules(scan_results or {}, "cis")

        if not cis_rules:
            logger.warning(f"No CIS Benchmark rules found for host {host_id}")
            return self._create_empty_intelligence()

        # Calculate overall CIS compliance score
        overall_score = self._calculate_framework_score(cis_rules)
        overall_tier = self._get_compliance_tier(overall_score)

        # Analyze Level 1/2 compliance
        level_scores = self._analyze_levels(cis_rules)

        # Analyze Implementation Group compliance
        ig_scores = self._analyze_implementation_groups(cis_rules)

        # Count scored vs not-scored recommendations
        scored = len([r for r in cis_rules if r.get("scored", True)])
        not_scored = len(cis_rules) - scored

        intelligence = CISFrameworkIntelligence(
            platform="Generic",  # Would extract from scan metadata
            benchmark_version="1.0.0",  # Would extract from scan metadata
            overall_score=overall_score,
            overall_tier=overall_tier,
            level_scores=level_scores,
            implementation_group_scores=ig_scores,
            scored_recommendations=scored,
            not_scored_recommendations=not_scored,
            automated_tests=len(cis_rules),  # Assume all tested are automated
            manual_tests=0,
        )

        logger.info(f"CIS analysis complete: {overall_score}% ({overall_tier})")
        return intelligence

    async def get_framework_summary(self, scan_results: Dict) -> Dict:
        """Generate CIS Benchmark summary."""
        cis_rules = self._extract_framework_rules(scan_results, "cis")
        score = self._calculate_framework_score(cis_rules) if cis_rules else 0.0

        return {
            "framework": "CIS",
            "score": round(score, 2),
            "tier": self._get_compliance_tier(score),
            "recommendations_tested": len(cis_rules),
        }

    def _analyze_levels(self, cis_rules: List[Dict]) -> List[CISLevelScore]:
        """Analyze CIS Level 1/2 compliance."""
        level_rules = {CISLevel.LEVEL_1: [], CISLevel.LEVEL_2: []}

        # Group rules by level (simplified - would parse from metadata)
        for rule in cis_rules:
            # Assume Level 1 unless explicitly marked Level 2
            level = CISLevel.LEVEL_2 if "level_2" in rule.get("rule_id", "").lower() else CISLevel.LEVEL_1
            level_rules[level].append(rule)

        level_scores = []
        for level in [CISLevel.LEVEL_1, CISLevel.LEVEL_2]:
            rules = level_rules[level]
            if not rules:
                continue

            total = len(rules)
            passed = sum(1 for r in rules if r["result"] == "pass")
            score = self.score_calculator.calculate_score(passed, total)

            level_scores.append(
                CISLevelScore(
                    level=level,
                    recommendations_total=total,
                    recommendations_scored=total,
                    recommendations_tested=total,
                    recommendations_passed=passed,
                    score=round(score, 2),
                    tier=self._get_compliance_tier(score),
                    compliant=score >= 80.0,
                )
            )

        return level_scores

    def _analyze_implementation_groups(self, cis_rules: List[Dict]) -> List[CISImplementationGroupScore]:
        """Analyze CIS Implementation Group compliance."""
        # Simplified implementation - would parse from CIS metadata
        total = len(cis_rules)
        passed = sum(1 for r in cis_rules if r["result"] == "pass")
        score = self.score_calculator.calculate_score(passed, total)

        return [
            CISImplementationGroupScore(
                implementation_group=CISImplementationGroup.IG1,
                safeguards_total=total,
                safeguards_tested=total,
                safeguards_passed=passed,
                score=round(score, 2),
                tier=self._get_compliance_tier(score),
            )
        ]

    def _create_empty_intelligence(self) -> CISFrameworkIntelligence:
        """Create empty CIS intelligence object."""
        return CISFrameworkIntelligence(
            platform="Unknown",
            benchmark_version="0.0.0",
            overall_score=0.0,
            overall_tier="poor",
            scored_recommendations=0,
            not_scored_recommendations=0,
            automated_tests=0,
            manual_tests=0,
        )
