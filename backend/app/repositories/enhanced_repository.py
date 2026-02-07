"""
Enhanced Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides enhanced model-specific query methods for UnifiedComplianceRule
and FrameworkControlDefinition collections.
Centralizes all enhanced compliance model query logic in one place.
"""

import logging
from typing import Any, Dict, List, Optional

from ..models.enhanced_mongo_models import FrameworkControlDefinition, UnifiedComplianceRule
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class UnifiedComplianceRuleRepository(BaseRepository[UnifiedComplianceRule]):
    """
    Repository for UnifiedComplianceRule operations.

    Provides unified compliance rule-specific query methods:
    - Find by rule_id
    - Find by framework controls
    - Cross-framework queries
    - Intelligence-based queries

    Example:
        repo = UnifiedComplianceRuleRepository()
        rule = await repo.find_by_rule_id("ow-password-complexity")
    """

    def __init__(self) -> None:
        """Initialize the unified compliance rule repository."""
        super().__init__(UnifiedComplianceRule)

    async def find_by_rule_id(self, rule_id: str) -> Optional[UnifiedComplianceRule]:
        """
        Find rule by unique rule_id.

        Args:
            rule_id: Unique rule identifier (e.g., "ow-password-complexity")

        Returns:
            UnifiedComplianceRule if found, None otherwise

        Example:
            rule = await repo.find_by_rule_id("ow-password-complexity")
        """
        query = {"rule_id": rule_id}
        return await self.find_one(query)

    async def find_by_scap_rule_id(self, scap_rule_id: str) -> Optional[UnifiedComplianceRule]:
        """
        Find rule by original SCAP rule ID.

        Args:
            scap_rule_id: Original SCAP rule identifier

        Returns:
            UnifiedComplianceRule if found, None otherwise

        Example:
            rule = await repo.find_by_scap_rule_id(
                "xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs"
            )
        """
        query = {"scap_rule_id": scap_rule_id}
        return await self.find_one(query)

    async def find_by_framework_controls(
        self,
        framework: str,
        controls: List[str],
    ) -> List[UnifiedComplianceRule]:
        """
        Find rules that implement specific framework controls.

        Args:
            framework: Framework identifier (e.g., "nist_800_53_r5")
            controls: List of control IDs to match

        Returns:
            List of UnifiedComplianceRule documents

        Example:
            rules = await repo.find_by_framework_controls(
                "nist_800_53_r5",
                ["AC-2", "AC-3"]
            )
        """
        query = {f"frameworks.{framework}.controls": {"$in": controls}}
        return await self.find_many(query)

    async def find_by_severity(self, severity: str) -> List[UnifiedComplianceRule]:
        """
        Find rules by severity level.

        Args:
            severity: Severity level (info, low, medium, high, critical)

        Returns:
            List of UnifiedComplianceRule documents

        Example:
            critical = await repo.find_by_severity("critical")
        """
        query = {"severity": severity}
        return await self.find_many(query)

    async def find_by_category(self, category: str) -> List[UnifiedComplianceRule]:
        """
        Find rules by category.

        Args:
            category: Rule category (authentication, access_control, etc.)

        Returns:
            List of UnifiedComplianceRule documents

        Example:
            auth_rules = await repo.find_by_category("authentication")
        """
        query = {"category": category}
        return await self.find_many(query)

    async def find_by_security_domain(self, domain: str) -> List[UnifiedComplianceRule]:
        """
        Find rules by security domain.

        Args:
            domain: Security domain (access_control, crypto, audit, network, etc.)

        Returns:
            List of UnifiedComplianceRule documents

        Example:
            crypto_rules = await repo.find_by_security_domain("crypto")
        """
        query = {"security_domain": domain}
        return await self.find_many(query)

    async def find_by_platform(
        self,
        platform: str,
        version: Optional[str] = None,
    ) -> List[UnifiedComplianceRule]:
        """
        Find rules by platform and optional version.

        Args:
            platform: Platform identifier (rhel, ubuntu, windows, etc.)
            version: Optional version pattern to match

        Returns:
            List of UnifiedComplianceRule documents

        Example:
            rhel_rules = await repo.find_by_platform("rhel")
            rhel9_rules = await repo.find_by_platform("rhel", version="9")
        """
        query: Dict[str, Any] = {f"platform_implementations.{platform}": {"$exists": True}}

        if version:
            query[f"platform_implementations.{platform}.version_ranges"] = {"$elemMatch": {"$regex": version}}

        return await self.find_many(query)

    async def find_abstract_rules(self) -> List[UnifiedComplianceRule]:
        """
        Find abstract (base) rules.

        Returns:
            List of abstract UnifiedComplianceRule documents

        Example:
            abstract = await repo.find_abstract_rules()
        """
        query = {"abstract": True}
        return await self.find_many(query)

    async def find_derived_rules(self, parent_rule_id: str) -> List[UnifiedComplianceRule]:
        """
        Find rules that inherit from a parent rule.

        Args:
            parent_rule_id: Parent rule identifier

        Returns:
            List of derived UnifiedComplianceRule documents

        Example:
            derived = await repo.find_derived_rules("ow-password-base")
        """
        query = {"inherits_from": parent_rule_id}
        return await self.find_many(query)

    async def find_with_remediation(self) -> List[UnifiedComplianceRule]:
        """
        Find rules with automated remediation available.

        Returns:
            List of UnifiedComplianceRule documents with fix_available=True

        Example:
            with_fix = await repo.find_with_remediation()
        """
        query = {"fix_available": True}
        return await self.find_many(query)

    async def find_by_business_impact(self, impact: str) -> List[UnifiedComplianceRule]:
        """
        Find rules by business impact level.

        Args:
            impact: Business impact (low, medium, high, critical)

        Returns:
            List of UnifiedComplianceRule documents

        Example:
            high_impact = await repo.find_by_business_impact("high")
        """
        query = {"rule_intelligence.business_impact": impact}
        return await self.find_many(query)

    async def find_high_coverage_rules(self, min_coverage: float = 0.5) -> List[UnifiedComplianceRule]:
        """
        Find rules with high cross-framework coverage.

        Args:
            min_coverage: Minimum coverage percentage (0.0-1.0)

        Returns:
            List of UnifiedComplianceRule documents

        Example:
            high_coverage = await repo.find_high_coverage_rules(0.7)
        """
        query = {"rule_intelligence.cross_framework_coverage": {"$gte": min_coverage}}
        return await self.find_many(
            query,
            sort=[("rule_intelligence.cross_framework_coverage", -1)],
        )

    async def search_by_text(self, search_term: str) -> List[UnifiedComplianceRule]:
        """
        Full-text search on rule name, description, and tags.

        Args:
            search_term: Text to search for

        Returns:
            List of matching UnifiedComplianceRule documents

        Example:
            results = await repo.search_by_text("password policy")
        """
        query = {"$text": {"$search": search_term}}
        return await self.find_many(query)

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get unified compliance rule statistics.

        Returns:
            Dictionary with statistics

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()
            with_fix = await self.count({"fix_available": True})

            # Count by severity
            severity_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            severity_results = await self.aggregate(severity_pipeline)
            severity_counts = {item["_id"]: item["count"] for item in severity_results}

            # Count by category
            category_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$category", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            category_results = await self.aggregate(category_pipeline)
            category_counts = {item["_id"]: item["count"] for item in category_results}

            # Count by security domain
            domain_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$security_domain", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            domain_results = await self.aggregate(domain_pipeline)
            domain_counts = {item["_id"]: item["count"] for item in domain_results}

            return {
                "total_rules": total,
                "with_remediation": with_fix,
                "by_severity": severity_counts,
                "by_category": category_counts,
                "by_security_domain": domain_counts,
            }

        except Exception as e:
            logger.error(f"Error getting unified rule statistics: {e}")
            raise


class FrameworkControlRepository(BaseRepository[FrameworkControlDefinition]):
    """
    Repository for FrameworkControlDefinition operations.

    Provides framework control-specific query methods:
    - Find by framework
    - Find by control_id
    - Search controls
    - Get control families

    Example:
        repo = FrameworkControlRepository()
        controls = await repo.find_by_framework("nist_800_53_r5")
    """

    def __init__(self) -> None:
        """Initialize the framework control repository."""
        super().__init__(FrameworkControlDefinition)

    async def find_by_framework(self, framework_id: str) -> List[FrameworkControlDefinition]:
        """
        Find all controls for a framework.

        Args:
            framework_id: Framework identifier (e.g., "nist_800_53_r5")

        Returns:
            List of FrameworkControlDefinition documents

        Example:
            nist_controls = await repo.find_by_framework("nist_800_53_r5")
        """
        query = {"framework_id": framework_id}
        return await self.find_many(query, sort=[("control_id", 1)])

    async def find_by_control_id(
        self,
        control_id: str,
        framework_id: Optional[str] = None,
    ) -> Optional[FrameworkControlDefinition]:
        """
        Find control by control_id and optional framework.

        Args:
            control_id: Control identifier (e.g., "AC-2")
            framework_id: Optional framework to filter

        Returns:
            FrameworkControlDefinition if found, None otherwise

        Example:
            control = await repo.find_by_control_id("AC-2", "nist_800_53_r5")
        """
        query: Dict[str, str] = {"control_id": control_id}
        if framework_id:
            query["framework_id"] = framework_id
        return await self.find_one(query)

    async def find_by_family(
        self,
        family: str,
        framework_id: Optional[str] = None,
    ) -> List[FrameworkControlDefinition]:
        """
        Find controls by family/category.

        Args:
            family: Control family (e.g., "Access Control")
            framework_id: Optional framework to filter

        Returns:
            List of FrameworkControlDefinition documents

        Example:
            ac_controls = await repo.find_by_family("Access Control", "nist_800_53_r5")
        """
        query: Dict[str, str] = {"family": family}
        if framework_id:
            query["framework_id"] = framework_id
        return await self.find_many(query, sort=[("control_id", 1)])

    async def find_by_priority(
        self,
        priority: str,
        framework_id: Optional[str] = None,
    ) -> List[FrameworkControlDefinition]:
        """
        Find controls by priority/baseline.

        Args:
            priority: Control priority (e.g., "P1", "High")
            framework_id: Optional framework to filter

        Returns:
            List of FrameworkControlDefinition documents

        Example:
            high_priority = await repo.find_by_priority("P1", "nist_800_53_r5")
        """
        query: Dict[str, str] = {"priority": priority}
        if framework_id:
            query["framework_id"] = framework_id
        return await self.find_many(query, sort=[("control_id", 1)])

    async def find_related_controls(self, control_id: str, framework_id: str) -> List[FrameworkControlDefinition]:
        """
        Find controls related to a specific control.

        Args:
            control_id: Control identifier
            framework_id: Framework identifier

        Returns:
            List of related FrameworkControlDefinition documents

        Example:
            related = await repo.find_related_controls("AC-2", "nist_800_53_r5")
        """
        # First find the control to get its related controls
        control = await self.find_by_control_id(control_id, framework_id)
        if not control or not control.related_controls:
            return []

        query = {
            "framework_id": framework_id,
            "control_id": {"$in": control.related_controls},
        }
        return await self.find_many(query, sort=[("control_id", 1)])

    async def search_by_text(self, search_term: str) -> List[FrameworkControlDefinition]:
        """
        Full-text search on control title and description.

        Args:
            search_term: Text to search for

        Returns:
            List of matching FrameworkControlDefinition documents

        Example:
            results = await repo.search_by_text("access control")
        """
        query = {"$text": {"$search": search_term}}
        return await self.find_many(query)

    async def get_families_for_framework(self, framework_id: str) -> List[str]:
        """
        Get all unique families for a framework.

        Args:
            framework_id: Framework identifier

        Returns:
            List of family names

        Example:
            families = await repo.get_families_for_framework("nist_800_53_r5")
        """
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"framework_id": framework_id}},
            {"$group": {"_id": "$family"}},
            {"$sort": {"_id": 1}},
        ]
        results = await self.aggregate(pipeline)
        return [item["_id"] for item in results if item["_id"]]

    async def upsert_control(
        self,
        framework_id: str,
        control_id: str,
        data: Dict[str, Any],
    ) -> FrameworkControlDefinition:
        """
        Upsert a framework control definition.

        Args:
            framework_id: Framework identifier
            control_id: Control identifier
            data: Control data

        Returns:
            Created or updated FrameworkControlDefinition

        Example:
            control = await repo.upsert_control(
                "nist_800_53_r5",
                "AC-2",
                {
                    "title": "Account Management",
                    "description": "...",
                    "family": "Access Control",
                }
            )
        """
        existing = await self.find_by_control_id(control_id, framework_id)

        if existing:
            # Update existing
            await self.update_one(
                {"framework_id": framework_id, "control_id": control_id},
                {"$set": data},
            )
            updated = await self.find_by_control_id(control_id, framework_id)
            if updated:
                return updated
            raise ValueError(f"Failed to fetch updated control {framework_id}/{control_id}")
        else:
            # Create new
            data["framework_id"] = framework_id
            data["control_id"] = control_id
            control = FrameworkControlDefinition(**data)
            return await self.create(control)

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get framework control statistics.

        Returns:
            Dictionary with statistics

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()

            # Count by framework
            framework_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$framework_id", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            framework_results = await self.aggregate(framework_pipeline)
            framework_counts = {item["_id"]: item["count"] for item in framework_results}

            # Count by family
            family_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$family", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            family_results = await self.aggregate(family_pipeline)
            family_counts = {item["_id"]: item["count"] for item in family_results}

            return {
                "total_controls": total,
                "by_framework": framework_counts,
                "by_family": family_counts,
            }

        except Exception as e:
            logger.error(f"Error getting framework control statistics: {e}")
            raise
