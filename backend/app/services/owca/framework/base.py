"""
OWCA Framework Layer - Base Framework Intelligence

Provides abstract base class for framework-specific compliance intelligence.
All framework implementations (NIST, CIS, STIG) inherit from this base.

Security: All database queries use QueryBuilder for SQL injection protection.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from ..core.score_calculator import ComplianceScoreCalculator

logger = logging.getLogger(__name__)


class BaseFrameworkIntelligence(ABC):
    """
    Abstract base class for framework-specific compliance intelligence.

    Each compliance framework (NIST 800-53, CIS, STIG) implements this interface
    to provide framework-specific analysis and reporting.

    Design Pattern: Strategy pattern - different frameworks use different strategies
    for calculating compliance scores and generating intelligence.

    Security: All implementations must use parameterized queries via QueryBuilder
    to prevent SQL injection attacks.
    """

    def __init__(self, db: Session, score_calculator: ComplianceScoreCalculator):
        """
        Initialize framework intelligence.

        Args:
            db: SQLAlchemy database session for query execution
            score_calculator: OWCA score calculator for canonical score calculations
        """
        self.db = db
        self.score_calculator = score_calculator
        self._framework_name = self._get_framework_name()
        logger.debug(f"Initialized {self._framework_name} framework intelligence")

    @abstractmethod
    def _get_framework_name(self) -> str:
        """
        Get framework name identifier.

        Returns:
            Framework name (e.g., "NIST_800_53", "CIS", "STIG")
        """
        pass

    @abstractmethod
    async def analyze_host_compliance(self, host_id: str, scan_results: Optional[Dict] = None) -> Dict:
        """
        Analyze host compliance using framework-specific intelligence.

        This is the main entry point for framework-specific analysis.
        Each framework implementation provides its own analysis logic.

        Args:
            host_id: UUID of the host to analyze
            scan_results: Optional pre-fetched scan results (avoids duplicate queries)

        Returns:
            Framework-specific intelligence dictionary with detailed compliance analysis

        Example:
            For NIST 800-53:
            {
                "framework": "NIST_800_53",
                "overall_score": 85.5,
                "control_families": [...],
                "baseline_scores": [...]
            }
        """
        pass

    @abstractmethod
    async def get_framework_summary(self, scan_results: Dict) -> Dict:
        """
        Generate framework-specific summary from scan results.

        Provides high-level overview of framework compliance without
        requiring database queries. Used for quick summaries.

        Args:
            scan_results: Scan results dictionary with rule findings

        Returns:
            Framework summary dictionary with key metrics
        """
        pass

    def _extract_framework_rules(self, scan_results: Dict, framework_identifier: str) -> List[Dict]:
        """
        Extract rules that map to this framework from scan results.

        Filters scan results to include only rules that have mappings
        to the specified framework.

        Args:
            scan_results: Complete scan results from database
            framework_identifier: Framework identifier (e.g., "nist_800_53", "cis")

        Returns:
            List of rules mapped to this framework with their results

        Example:
            >>> rules = self._extract_framework_rules(scan_results, "nist_800_53")
            >>> # Returns only rules with NIST 800-53 control mappings
        """
        framework_rules = []

        # Scan results contain enriched_rules with framework mappings
        for rule_id, rule_data in scan_results.get("enriched_rules", {}).items():
            # Check if rule has framework mapping in MongoDB intelligence data
            frameworks = rule_data.get("frameworks", {})
            if framework_identifier in frameworks:
                framework_rules.append(
                    {
                        "rule_id": rule_id,
                        "result": rule_data.get("result", "unknown"),
                        "severity": rule_data.get("severity", "medium"),
                        "framework_controls": frameworks[framework_identifier],
                    }
                )

        logger.debug(f"Extracted {len(framework_rules)} rules for framework {framework_identifier}")
        return framework_rules

    def _calculate_framework_score(self, framework_rules: List[Dict]) -> float:
        """
        Calculate overall framework compliance score using OWCA.

        Uses OWCA's canonical score calculation to ensure consistency
        with platform-wide compliance scoring.

        Args:
            framework_rules: List of rules mapped to this framework

        Returns:
            Framework compliance score (0-100)

        Security Note: Uses OWCA score calculator (single source of truth)
        instead of implementing custom scoring logic.
        """
        if not framework_rules:
            logger.warning("No rules found for framework score calculation")
            return 0.0

        total_rules = len(framework_rules)
        passed_rules = sum(1 for rule in framework_rules if rule["result"] == "pass")

        # Use OWCA's canonical score calculation
        score = self.score_calculator.calculate_score(passed_rules, total_rules)

        logger.debug(f"Framework score: {score}% ({passed_rules}/{total_rules} rules passed)")
        return score

    def _get_compliance_tier(self, score: float) -> str:
        """
        Get OWCA compliance tier for a score.

        Delegates to OWCA score calculator to ensure consistent tier
        classification across the platform.

        Args:
            score: Compliance score (0-100)

        Returns:
            OWCA tier: "excellent", "good", "fair", or "poor"
        """
        tier_enum = self.score_calculator.get_compliance_tier(score)
        return tier_enum.value

    async def get_framework_name(self) -> str:
        """
        Get framework name identifier.

        Returns:
            Framework name string
        """
        return self._framework_name
