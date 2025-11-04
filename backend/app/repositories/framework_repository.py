"""
Framework Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides framework-specific query methods for Framework collection.
Centralizes all framework query logic in one place.
"""

import logging
from typing import Any, Dict, List, Optional

from ..models.mongo_models import Framework
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class FrameworkRepository(BaseRepository[Framework]):
    """
    Repository for Framework operations.

    Provides framework-specific query methods:
    - Find by category (government/industry/custom)
    - Find active frameworks
    - Get framework with rule counts
    - Search by name or description
    - Get framework statistics

    Example:
        repo = FrameworkRepository()
        frameworks = await repo.find_by_category("government")
    """

    def __init__(self):
        super().__init__(Framework)

    async def find_by_category(self, category: str) -> List[Framework]:
        """
        Find frameworks by category.

        Args:
            category: Framework category (government/industry/custom)

        Returns:
            List of frameworks in the category

        Example:
            # Get all government frameworks
            frameworks = await repo.find_by_category("government")
        """
        query = {"category": category}
        return await self.find_many(query, sort=[("name", 1)])

    async def find_active_frameworks(self) -> List[Framework]:
        """
        Get all active frameworks sorted by name.

        Returns:
            List of active frameworks

        Example:
            active = await repo.find_active_frameworks()
        """
        query = {"is_active": True}
        return await self.find_many(query, sort=[("name", 1)])

    async def find_by_framework_id(self, framework_id: str) -> Optional[Framework]:
        """
        Find framework by unique framework_id.

        Args:
            framework_id: Unique framework identifier (e.g., "CIS", "NIST", "PCI_DSS")

        Returns:
            Framework if found, None otherwise

        Example:
            framework = await repo.find_by_framework_id("CIS")
        """
        query = {"framework_id": framework_id}
        return await self.find_one(query)

    async def search_by_name(
        self, search_term: str, case_sensitive: bool = False
    ) -> List[Framework]:
        """
        Search frameworks by name (supports regex).

        Args:
            search_term: Search term to find in name
            case_sensitive: Whether search is case-sensitive (default: False)

        Returns:
            List of matching frameworks

        Example:
            # Case-insensitive search
            frameworks = await repo.search_by_name("security")

            # Case-sensitive search
            frameworks = await repo.search_by_name("CIS", case_sensitive=True)
        """
        options = "" if case_sensitive else "i"
        query = {"name": {"$regex": search_term, "$options": options}}
        return await self.find_many(query, sort=[("name", 1)])

    async def search_by_description(
        self, search_term: str, case_sensitive: bool = False
    ) -> List[Framework]:
        """
        Search frameworks by description (supports regex).

        Args:
            search_term: Search term to find in description
            case_sensitive: Whether search is case-sensitive (default: False)

        Returns:
            List of matching frameworks

        Example:
            frameworks = await repo.search_by_description("compliance")
        """
        options = "" if case_sensitive else "i"
        query = {"description": {"$regex": search_term, "$options": options}}
        return await self.find_many(query, sort=[("name", 1)])

    async def get_framework_with_rules_count(self, framework_id: str) -> Optional[Dict[str, Any]]:
        """
        Get framework details with count of associated rules.

        Args:
            framework_id: Unique framework identifier

        Returns:
            Dictionary with framework data and rule_count, or None if not found

        Example:
            result = await repo.get_framework_with_rules_count("CIS")
            # Returns: {
            #     "framework_id": "CIS",
            #     "name": "CIS Benchmarks",
            #     "rule_count": 1234,
            #     ...
            # }
        """
        try:
            # Get framework
            framework = await self.find_by_framework_id(framework_id)
            if not framework:
                return None

            # Count associated rules using aggregation on ComplianceRule collection
            from ..models.mongo_models import ComplianceRule

            pipeline = [
                {"$match": {f"frameworks.{framework_id}": {"$exists": True}}},
                {"$count": "total"},
            ]

            result = await ComplianceRule.aggregate(pipeline).to_list()
            rule_count = result[0]["total"] if result else 0

            # Convert framework to dict and add rule count
            framework_dict = framework.dict()
            framework_dict["rule_count"] = rule_count

            return framework_dict

        except Exception as e:
            logger.error(f"Error getting framework with rule count for {framework_id}: {e}")
            raise

    async def get_frameworks_with_rules_counts(self) -> List[Dict[str, Any]]:
        """
        Get all frameworks with their associated rule counts.

        Returns:
            List of frameworks with rule counts

        Example:
            frameworks = await repo.get_frameworks_with_rules_counts()
            # Returns: [
            #     {"framework_id": "CIS", "name": "CIS Benchmarks", "rule_count": 1234},
            #     {"framework_id": "NIST", "name": "NIST SP 800-53", "rule_count": 567},
            #     ...
            # ]
        """
        try:
            # Get all frameworks
            frameworks = await self.find_many({}, sort=[("name", 1)])

            # For each framework, get rule count
            results = []
            for framework in frameworks:
                framework_dict = framework.dict()

                # Count rules for this framework
                from ..models.mongo_models import ComplianceRule

                pipeline = [
                    {"$match": {f"frameworks.{framework.framework_id}": {"$exists": True}}},
                    {"$count": "total"},
                ]

                count_result = await ComplianceRule.aggregate(pipeline).to_list()
                framework_dict["rule_count"] = count_result[0]["total"] if count_result else 0

                results.append(framework_dict)

            return results

        except Exception as e:
            logger.error(f"Error getting frameworks with rule counts: {e}")
            raise

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about frameworks.

        Returns:
            Dictionary with statistics:
            - total_frameworks: Total number of frameworks
            - by_category: Count by category
            - active_count: Number of active frameworks
            - inactive_count: Number of inactive frameworks

        Example:
            stats = await repo.get_statistics()
            print(f"Total frameworks: {stats['total_frameworks']}")
            print(f"Government: {stats['by_category']['government']}")
        """
        try:
            # Get total count
            total = await self.count()

            # Count by category using aggregation
            category_pipeline = [
                {"$group": {"_id": "$category", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            category_results = await self.aggregate(category_pipeline)
            category_counts = {item["_id"]: item["count"] for item in category_results}

            # Count active vs inactive
            active_count = await self.count({"is_active": True})
            inactive_count = total - active_count

            return {
                "total_frameworks": total,
                "by_category": category_counts,
                "active_count": active_count,
                "inactive_count": inactive_count,
            }

        except Exception as e:
            logger.error(f"Error getting framework statistics: {e}")
            raise

    async def get_available_versions(self, framework_id: str) -> List[str]:
        """
        Get all available versions for a framework by checking ComplianceRule collection.

        Args:
            framework_id: Framework identifier

        Returns:
            List of version strings

        Example:
            versions = await repo.get_available_versions("CIS")
            # Returns: ["1.0.0", "2.0.0"]
        """
        try:
            from ..models.mongo_models import ComplianceRule

            pipeline = [
                {"$match": {f"frameworks.{framework_id}": {"$exists": True}}},
                {
                    "$project": {
                        "versions": {"$objectToArray": f"$frameworks.{framework_id}.versions"}
                    }
                },
                {"$unwind": "$versions"},
                {"$group": {"_id": "$versions.k"}},
                {"$sort": {"_id": 1}},
            ]

            results = await ComplianceRule.aggregate(pipeline).to_list()
            return [item["_id"] for item in results]

        except Exception as e:
            logger.error(f"Error getting available versions for {framework_id}: {e}")
            raise

    async def find_by_multiple_categories(self, categories: List[str]) -> List[Framework]:
        """
        Find frameworks in any of the specified categories.

        Args:
            categories: List of category names

        Returns:
            List of frameworks matching any category

        Example:
            frameworks = await repo.find_by_multiple_categories(["government", "industry"])
        """
        query = {"category": {"$in": categories}}
        return await self.find_many(query, sort=[("category", 1), ("name", 1)])

    async def create_framework(
        self,
        framework_id: str,
        name: str,
        description: str,
        category: str,
        version: Optional[str] = None,
        is_active: bool = True,
    ) -> Framework:
        """
        Create a new framework.

        Args:
            framework_id: Unique framework identifier
            name: Framework name
            description: Framework description
            category: Category (government/industry/custom)
            version: Optional version string
            is_active: Whether framework is active (default: True)

        Returns:
            Created framework

        Example:
            framework = await repo.create_framework(
                framework_id="CUSTOM_FRAMEWORK",
                name="My Custom Framework",
                description="Custom compliance framework",
                category="custom"
            )
        """
        try:
            # Check if framework_id already exists
            existing = await self.find_by_framework_id(framework_id)
            if existing:
                raise ValueError(f"Framework with ID '{framework_id}' already exists")

            # Create framework instance
            framework = Framework(
                framework_id=framework_id,
                name=name,
                description=description,
                category=category,
                version=version,
                is_active=is_active,
            )

            # Save to database
            created = await self.create(framework)

            logger.info(f"Created new framework: {framework_id} ({name})")
            return created

        except Exception as e:
            logger.error(f"Error creating framework {framework_id}: {e}")
            raise

    async def update_framework_status(
        self, framework_id: str, is_active: bool
    ) -> Optional[Framework]:
        """
        Update framework active status.

        Args:
            framework_id: Framework identifier
            is_active: New active status

        Returns:
            Updated framework if found, None otherwise

        Example:
            # Deactivate a framework
            framework = await repo.update_framework_status("OLD_FRAMEWORK", False)
        """
        query = {"framework_id": framework_id}
        update = {"$set": {"is_active": is_active}}

        updated = await self.update_one(query, update)

        if updated:
            status = "activated" if is_active else "deactivated"
            logger.info(f"Framework {framework_id} {status}")

        return updated
