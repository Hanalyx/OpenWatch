"""
OWCA Framework Layer - NIST 800-53 Intelligence

Provides NIST 800-53 specific compliance intelligence including:
- Control family analysis (AC, AU, IA, etc.)
- Baseline assessment (LOW, MODERATE, HIGH)
- Control enhancement coverage

Reference: NIST SP 800-53 Revision 5
Security Controls for Information Systems and Organizations

Security: All database queries use QueryBuilder for SQL injection protection.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Optional

from sqlalchemy import text

from backend.app.utils.query_builder import QueryBuilder

from .base import BaseFrameworkIntelligence
from .models import (
    NISTBaseline,
    NISTBaselineScore,
    NISTControlFamily,
    NISTControlFamilyScore,
    NISTFrameworkIntelligence,
)

logger = logging.getLogger(__name__)


# NIST 800-53 Control Family Names (for user-friendly display)
NIST_FAMILY_NAMES = {
    NISTControlFamily.ACCESS_CONTROL: "Access Control",
    NISTControlFamily.AWARENESS_TRAINING: "Awareness and Training",
    NISTControlFamily.AUDIT_ACCOUNTABILITY: "Audit and Accountability",
    NISTControlFamily.ASSESSMENT_AUTHORIZATION: "Assessment, Authorization, and Monitoring",
    NISTControlFamily.CONFIGURATION_MANAGEMENT: "Configuration Management",
    NISTControlFamily.CONTINGENCY_PLANNING: "Contingency Planning",
    NISTControlFamily.IDENTIFICATION_AUTHENTICATION: "Identification and Authentication",
    NISTControlFamily.INCIDENT_RESPONSE: "Incident Response",
    NISTControlFamily.MAINTENANCE: "Maintenance",
    NISTControlFamily.MEDIA_PROTECTION: "Media Protection",
    NISTControlFamily.PHYSICAL_PROTECTION: "Physical and Environmental Protection",
    NISTControlFamily.PLANNING: "Planning",
    NISTControlFamily.PERSONNEL_SECURITY: "Personnel Security",
    NISTControlFamily.RISK_ASSESSMENT: "Risk Assessment",
    NISTControlFamily.SYSTEM_SERVICES_ACQUISITION: "System and Services Acquisition",
    NISTControlFamily.SYSTEM_COMMUNICATIONS_PROTECTION: "System and Communications Protection",
    NISTControlFamily.SYSTEM_INFORMATION_INTEGRITY: "System and Information Integrity",
    NISTControlFamily.SUPPLY_CHAIN_RISK_MANAGEMENT: "Supply Chain Risk Management",
    NISTControlFamily.PROGRAM_MANAGEMENT: "Program Management",
}


class NIST80053FrameworkIntelligence(BaseFrameworkIntelligence):
    """
    NIST 800-53 Framework Intelligence Provider.

    Analyzes compliance against NIST Special Publication 800-53 Rev 5.
    Provides detailed control family analysis and baseline assessments.

    Design Pattern: Strategy pattern implementation for NIST-specific analysis.
    """

    def _get_framework_name(self) -> str:
        """Get framework name identifier."""
        return "NIST_800_53"

    async def analyze_host_compliance(
        self, host_id: str, scan_results: Optional[Dict] = None
    ) -> NISTFrameworkIntelligence:
        """
        Analyze host compliance using NIST 800-53 specific intelligence.

        Provides comprehensive NIST 800-53 analysis including:
        1. Control family breakdown (AC, AU, IA, etc.)
        2. Baseline assessments (LOW, MODERATE, HIGH)
        3. Control enhancement coverage analysis

        Args:
            host_id: UUID of the host to analyze
            scan_results: Optional pre-fetched scan results (MongoDB enriched data)

        Returns:
            NISTFrameworkIntelligence with complete NIST analysis

        Security: Uses QueryBuilder for all database queries to prevent SQL injection.
        """
        logger.info(f"Analyzing NIST 800-53 compliance for host {host_id}")

        # If scan results not provided, fetch from database
        if not scan_results:
            scan_results = await self._fetch_latest_scan_results(host_id)

        if not scan_results:
            logger.warning(f"No scan results found for host {host_id}")
            return self._create_empty_intelligence()

        # Extract NIST-mapped rules from scan results
        nist_rules = self._extract_framework_rules(scan_results, "nist_800_53")

        if not nist_rules:
            logger.warning(f"No NIST 800-53 rules found for host {host_id}")
            return self._create_empty_intelligence()

        # Calculate overall NIST compliance score
        overall_score = self._calculate_framework_score(nist_rules)
        overall_tier = self._get_compliance_tier(overall_score)

        # Analyze control families (AC, AU, IA, etc.)
        control_families = self._analyze_control_families(nist_rules)

        # Assess baseline compliance (LOW, MODERATE, HIGH)
        baseline_scores = self._assess_baselines(nist_rules)

        # Analyze control enhancement coverage
        enhancements_total, enhancements_tested = self._analyze_enhancements(nist_rules)

        # Calculate enhancement coverage percentage
        enhancements_coverage = (enhancements_tested / enhancements_total * 100) if enhancements_total > 0 else 0.0

        # Recommend appropriate baseline based on current compliance
        recommended_baseline = self._recommend_baseline(baseline_scores)

        intelligence = NISTFrameworkIntelligence(
            overall_score=overall_score,
            overall_tier=overall_tier,
            control_families=control_families,
            baseline_scores=baseline_scores,
            enhancements_total=enhancements_total,
            enhancements_tested=enhancements_tested,
            enhancements_coverage=round(enhancements_coverage, 2),
            recommended_baseline=recommended_baseline,
        )

        logger.info(
            f"NIST 800-53 analysis complete: {overall_score}% ({overall_tier}), "
            f"Recommended baseline: {recommended_baseline.value}"
        )

        return intelligence

    async def get_framework_summary(self, scan_results: Dict) -> Dict:
        """
        Generate NIST 800-53 summary from scan results.

        Provides quick summary without detailed analysis.

        Args:
            scan_results: Scan results dictionary

        Returns:
            Summary dictionary with key NIST metrics
        """
        nist_rules = self._extract_framework_rules(scan_results, "nist_800_53")

        if not nist_rules:
            return {
                "framework": "NIST_800_53",
                "score": 0.0,
                "tier": "poor",
                "controls_tested": 0,
            }

        score = self._calculate_framework_score(nist_rules)
        tier = self._get_compliance_tier(score)

        return {
            "framework": "NIST_800_53",
            "score": round(score, 2),
            "tier": tier,
            "controls_tested": len(nist_rules),
            "controls_passed": sum(1 for r in nist_rules if r["result"] == "pass"),
        }

    def _analyze_control_families(self, nist_rules: List[Dict]) -> List[NISTControlFamilyScore]:
        """
        Analyze compliance by NIST 800-53 control family.

        Groups rules by control family (AC, AU, IA, etc.) and calculates
        family-specific compliance scores.

        Args:
            nist_rules: List of rules with NIST 800-53 mappings

        Returns:
            List of control family scores sorted by family code
        """
        # Group rules by control family
        family_rules = defaultdict(list)

        for rule in nist_rules:
            # Extract control family from control ID (e.g., "AC-2" -> "AC")
            for control_id in rule.get("framework_controls", []):
                family_code = control_id.split("-")[0].upper()

                # Validate family code
                try:
                    family = NISTControlFamily(family_code)
                    family_rules[family].append(rule)
                except ValueError:
                    # Unknown control family, skip
                    logger.debug(f"Unknown NIST control family: {family_code}")
                    continue

        # Calculate score for each family
        family_scores = []
        for family in NISTControlFamily:
            rules = family_rules.get(family, [])

            if not rules:
                # Family not tested, skip
                continue

            total = len(rules)
            passed = sum(1 for r in rules if r["result"] == "pass")
            failed = sum(1 for r in rules if r["result"] == "fail")

            # Use OWCA canonical score calculation
            score = self.score_calculator.calculate_score(passed, total)
            tier = self._get_compliance_tier(score)

            family_scores.append(
                NISTControlFamilyScore(
                    family=family,
                    family_name=NIST_FAMILY_NAMES[family],
                    controls_total=total,
                    controls_tested=total,  # All extracted rules are tested
                    controls_passed=passed,
                    controls_failed=failed,
                    score=round(score, 2),
                    tier=tier,
                )
            )

        # Sort by family code for consistent ordering
        family_scores.sort(key=lambda f: f.family.value)

        logger.debug(f"Analyzed {len(family_scores)} NIST control families")
        return family_scores

    def _assess_baselines(self, nist_rules: List[Dict]) -> List[NISTBaselineScore]:
        """
        Assess compliance against NIST 800-53 baselines.

        NIST 800-53 defines three security control baselines:
        - LOW: Minimal impact systems
        - MODERATE: Serious impact systems (most common)
        - HIGH: Severe/catastrophic impact systems

        This method determines which baseline requirements are met based on
        the current compliance score and control coverage.

        Args:
            nist_rules: List of rules with NIST 800-53 mappings

        Returns:
            List of baseline assessment scores
        """
        baseline_scores = []

        # Calculate overall score for baseline assessment
        total_rules = len(nist_rules)
        passed_rules = sum(1 for r in nist_rules if r["result"] == "pass")
        overall_score = self.score_calculator.calculate_score(passed_rules, total_rules)

        # Baseline thresholds (based on typical NIST implementations)
        # LOW: 70% of controls required
        # MODERATE: 85% of controls required
        # HIGH: 95% of controls required

        for baseline in [NISTBaseline.LOW, NISTBaseline.MODERATE, NISTBaseline.HIGH]:
            # Determine threshold based on baseline
            if baseline == NISTBaseline.LOW:
                required_threshold = 70.0
            elif baseline == NISTBaseline.MODERATE:
                required_threshold = 85.0
            else:  # HIGH
                required_threshold = 95.0

            # Calculate baseline score using OWCA
            baseline_score = overall_score
            baseline_tier = self._get_compliance_tier(baseline_score)

            # Determine if baseline requirements are met
            compliant = baseline_score >= required_threshold

            baseline_scores.append(
                NISTBaselineScore(
                    baseline=baseline,
                    controls_required=total_rules,  # Simplified: using total tested
                    controls_tested=total_rules,
                    controls_passed=passed_rules,
                    score=round(baseline_score, 2),
                    tier=baseline_tier,
                    compliant=compliant,
                )
            )

        logger.debug(f"Assessed {len(baseline_scores)} NIST baselines")
        return baseline_scores

    def _analyze_enhancements(self, nist_rules: List[Dict]) -> tuple:
        """
        Analyze NIST 800-53 control enhancement coverage.

        Control enhancements are additions to base controls, indicated by
        parenthetical numbers (e.g., AC-2(1), AC-2(2)).

        Args:
            nist_rules: List of rules with NIST 800-53 mappings

        Returns:
            Tuple of (total_enhancements, tested_enhancements)
        """
        base_controls = set()
        enhancements = set()

        for rule in nist_rules:
            for control_id in rule.get("framework_controls", []):
                if "(" in control_id:
                    # Enhancement (e.g., "AC-2(1)")
                    enhancements.add(control_id)
                    # Extract base control (e.g., "AC-2")
                    base_control = control_id.split("(")[0]
                    base_controls.add(base_control)
                else:
                    # Base control only
                    base_controls.add(control_id)

        total_enhancements = len(enhancements)
        tested_enhancements = total_enhancements  # All extracted enhancements are tested

        logger.debug(
            f"NIST enhancement coverage: {tested_enhancements}/{total_enhancements} "
            f"({len(base_controls)} base controls)"
        )

        return (total_enhancements, tested_enhancements)

    def _recommend_baseline(self, baseline_scores: List[NISTBaselineScore]) -> NISTBaseline:
        """
        Recommend appropriate NIST baseline based on compliance.

        Recommends the highest baseline that is currently met,
        or the lowest baseline if none are met.

        Args:
            baseline_scores: List of baseline assessment scores

        Returns:
            Recommended NIST baseline
        """
        # Find highest compliant baseline
        for baseline_score in reversed(baseline_scores):  # HIGH, MODERATE, LOW
            if baseline_score.compliant:
                logger.debug(f"Recommended baseline: {baseline_score.baseline.value} (compliant)")
                return baseline_score.baseline

        # No baselines met, recommend LOW as starting point
        logger.debug("No baselines met, recommending LOW baseline")
        return NISTBaseline.LOW

    async def _fetch_latest_scan_results(self, host_id: str) -> Optional[Dict]:
        """
        Fetch latest scan results for host from database.

        Uses QueryBuilder for safe query construction.

        Args:
            host_id: UUID of the host

        Returns:
            Scan results dictionary or None if no scans found

        Security: Uses QueryBuilder to prevent SQL injection.
        """
        builder = (
            QueryBuilder("scans s")
            .select("s.id", "s.result_file")
            .join("scan_results sr", "s.id = sr.scan_id", "INNER")
            .where("s.host_id = :host_id", host_id, "host_id")
            .where("s.status = :status", "completed", "status")
            .order_by("s.completed_at", "DESC")
            .limit(1)
        )

        query, params = builder.build()
        result = self.db.execute(text(query), params).fetchone()

        if not result:
            return None

        # Load enriched scan results from MongoDB (via result enrichment service)
        # For now, return placeholder - full integration requires result enrichment
        logger.debug(f"Found scan {result.id} for host {host_id}")
        return {"enriched_rules": {}}  # Placeholder

    def _create_empty_intelligence(self) -> NISTFrameworkIntelligence:
        """
        Create empty NIST intelligence object.

        Used when no scan results are available.

        Returns:
            Empty NISTFrameworkIntelligence
        """
        return NISTFrameworkIntelligence(
            overall_score=0.0,
            overall_tier="poor",
            control_families=[],
            baseline_scores=[],
            enhancements_total=0,
            enhancements_tested=0,
            enhancements_coverage=0.0,
            recommended_baseline=NISTBaseline.LOW,
        )
