"""
Compliance Rule Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides compliance-specific query methods for ComplianceRule collection.
Centralizes all compliance rule query logic in one place.
"""

from typing import List, Dict, Any, Optional
from .base_repository import BaseRepository
from ..models.mongo_models import ComplianceRule
import logging

logger = logging.getLogger(__name__)


class ComplianceRuleRepository(BaseRepository[ComplianceRule]):
    """
    Repository for ComplianceRule operations.

    Provides compliance-specific query methods:
    - Find by framework and version
    - Find by platform and version
    - Search by title or description
    - Filter by severity
    - Get statistics

    Example:
        repo = ComplianceRuleRepository()
        rules = await repo.find_by_framework("CIS", version="2.0.0")
    """

    def __init__(self):
        super().__init__(ComplianceRule)

    async def find_by_framework(
        self, framework: str, version: Optional[str] = None
    ) -> List[ComplianceRule]:
        """
        Find rules by framework and optional version.

        Args:
            framework: Framework ID (e.g., "CIS", "NIST", "PCI_DSS")
            version: Optional framework version (e.g., "2.0.0")

        Returns:
            List of compliance rules for the framework

        Example:
            # All CIS rules
            rules = await repo.find_by_framework("CIS")

            # CIS 2.0.0 rules only
            rules = await repo.find_by_framework("CIS", version="2.0.0")
        """
        query = {f"frameworks.{framework}": {"$exists": True}}

        if version:
            query[f"frameworks.{framework}.versions.{version}"] = {"$exists": True}

        return await self.find_many(query)

    async def find_by_platform(
        self, platform: str, version: Optional[str] = None
    ) -> List[ComplianceRule]:
        """
        Find rules by platform and optional version.

        Args:
            platform: Platform ID (e.g., "RHEL", "Ubuntu", "Windows")
            version: Optional platform version (e.g., "8", "22.04")

        Returns:
            List of compliance rules for the platform

        Example:
            # All RHEL rules
            rules = await repo.find_by_platform("RHEL")

            # RHEL 8 rules only
            rules = await repo.find_by_platform("RHEL", version="8")
        """
        query = {f"platforms.{platform}": {"$exists": True}}

        if version:
            query[f"platforms.{platform}.versions"] = version

        return await self.find_many(query)

    async def search_by_title(
        self, search_term: str, case_sensitive: bool = False
    ) -> List[ComplianceRule]:
        """
        Search rules by title (supports regex).

        Args:
            search_term: Search term to find in title
            case_sensitive: Whether search is case-sensitive (default: False)

        Returns:
            List of matching compliance rules

        Example:
            # Case-insensitive search
            rules = await repo.search_by_title("password")

            # Case-sensitive search
            rules = await repo.search_by_title("SSH", case_sensitive=True)
        """
        options = "" if case_sensitive else "i"
        query = {"title": {"$regex": search_term, "$options": options}}
        return await self.find_many(query)

    async def search_by_description(
        self, search_term: str, case_sensitive: bool = False
    ) -> List[ComplianceRule]:
        """
        Search rules by description (supports regex).

        Args:
            search_term: Search term to find in description
            case_sensitive: Whether search is case-sensitive (default: False)

        Returns:
            List of matching compliance rules

        Example:
            rules = await repo.search_by_description("authentication")
        """
        options = "" if case_sensitive else "i"
        query = {"description": {"$regex": search_term, "$options": options}}
        return await self.find_many(query)

    async def find_by_severity(self, severity: str) -> List[ComplianceRule]:
        """
        Find rules by severity level.

        Args:
            severity: Severity level ("critical", "high", "medium", "low")

        Returns:
            List of rules with specified severity

        Example:
            critical_rules = await repo.find_by_severity("critical")
        """
        query = {"severity": severity}
        return await self.find_many(query)

    async def find_by_rule_id(self, rule_id: str) -> Optional[ComplianceRule]:
        """
        Find rule by unique rule_id.

        Args:
            rule_id: Unique rule identifier

        Returns:
            ComplianceRule if found, None otherwise

        Example:
            rule = await repo.find_by_rule_id("xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs")
        """
        query = {"rule_id": rule_id}
        return await self.find_one(query)

    async def find_by_multiple_frameworks(
        self, frameworks: List[str]
    ) -> List[ComplianceRule]:
        """
        Find rules that apply to any of the specified frameworks.

        Args:
            frameworks: List of framework IDs

        Returns:
            List of rules matching any framework

        Example:
            rules = await repo.find_by_multiple_frameworks(["CIS", "NIST", "PCI_DSS"])
        """
        # Build OR query for multiple frameworks
        or_conditions = []
        for framework in frameworks:
            or_conditions.append({f"frameworks.{framework}": {"$exists": True}})

        query = {"$or": or_conditions}
        return await self.find_many(query)

    async def find_by_framework_and_platform(
        self, framework: str, platform: str
    ) -> List[ComplianceRule]:
        """
        Find rules that apply to both a framework and platform.

        Args:
            framework: Framework ID
            platform: Platform ID

        Returns:
            List of rules matching both framework and platform

        Example:
            rules = await repo.find_by_framework_and_platform("CIS", "RHEL")
        """
        query = {
            f"frameworks.{framework}": {"$exists": True},
            f"platforms.{platform}": {"$exists": True},
        }
        return await self.find_many(query)

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about compliance rules.

        Returns:
            Dictionary with statistics:
            - total_rules: Total number of rules
            - by_severity: Count by severity level
            - by_framework: Count by framework
            - by_platform: Count by platform

        Example:
            stats = await repo.get_statistics()
            print(f"Total rules: {stats['total_rules']}")
            print(f"Critical: {stats['by_severity']['critical']}")
        """
        try:
            # Get total count
            total = await self.count()

            # Count by severity
            severity_counts = {}
            for severity in ["critical", "high", "medium", "low", "unknown"]:
                count = await self.count({"severity": severity})
                if count > 0:
                    severity_counts[severity] = count

            # Count by framework using aggregation
            framework_pipeline = [
                {"$project": {"frameworks": {"$objectToArray": "$frameworks"}}},
                {"$unwind": "$frameworks"},
                {"$group": {"_id": "$frameworks.k", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            framework_results = await self.aggregate(framework_pipeline)
            framework_counts = {
                item["_id"]: item["count"] for item in framework_results
            }

            # Count by platform using aggregation
            platform_pipeline = [
                {"$project": {"platforms": {"$objectToArray": "$platforms"}}},
                {"$unwind": "$platforms"},
                {"$group": {"_id": "$platforms.k", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            platform_results = await self.aggregate(platform_pipeline)
            platform_counts = {item["_id"]: item["count"] for item in platform_results}

            return {
                "total_rules": total,
                "by_severity": severity_counts,
                "by_framework": framework_counts,
                "by_platform": platform_counts,
            }
        except Exception as e:
            logger.error(f"Error getting compliance statistics: {e}")
            raise

    async def get_framework_versions(self, framework: str) -> List[str]:
        """
        Get all available versions for a framework.

        Args:
            framework: Framework ID

        Returns:
            List of version strings

        Example:
            versions = await repo.get_framework_versions("CIS")
            # Returns: ["1.0.0", "2.0.0"]
        """
        try:
            pipeline = [
                {"$match": {f"frameworks.{framework}": {"$exists": True}}},
                {
                    "$project": {
                        "versions": {
                            "$objectToArray": f"$frameworks.{framework}.versions"
                        }
                    }
                },
                {"$unwind": "$versions"},
                {"$group": {"_id": "$versions.k"}},
                {"$sort": {"_id": 1}},
            ]

            results = await self.aggregate(pipeline)
            return [item["_id"] for item in results]
        except Exception as e:
            logger.error(f"Error getting framework versions for {framework}: {e}")
            raise

    async def get_platform_versions(self, platform: str) -> List[str]:
        """
        Get all available versions for a platform.

        Args:
            platform: Platform ID

        Returns:
            List of version strings

        Example:
            versions = await repo.get_platform_versions("RHEL")
            # Returns: ["7", "8", "9"]
        """
        try:
            pipeline = [
                {"$match": {f"platforms.{platform}": {"$exists": True}}},
                {"$project": {"versions": f"$platforms.{platform}.versions"}},
                {"$unwind": "$versions"},
                {"$group": {"_id": "$versions"}},
                {"$sort": {"_id": 1}},
            ]

            results = await self.aggregate(pipeline)
            return [item["_id"] for item in results if item["_id"]]
        except Exception as e:
            logger.error(f"Error getting platform versions for {platform}: {e}")
            raise
