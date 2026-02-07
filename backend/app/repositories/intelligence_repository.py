"""
Intelligence Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides intelligence-specific query methods for RuleIntelligence and UploadHistory collections.
Centralizes all intelligence and upload history query logic in one place.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models.mongo_models import RuleIntelligence, UploadHistory
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class RuleIntelligenceRepository(BaseRepository[RuleIntelligence]):
    """
    Repository for RuleIntelligence operations.

    Provides intelligence-specific query methods:
    - Find by rule_id
    - Find latest intelligence for multiple rules
    - Upsert intelligence data
    - Find by business impact or false positive rate

    Example:
        repo = RuleIntelligenceRepository()
        intel = await repo.find_by_rule_id("ow-password-complexity")
    """

    def __init__(self) -> None:
        """Initialize the rule intelligence repository."""
        super().__init__(RuleIntelligence)

    async def find_by_rule_id(self, rule_id: str) -> Optional[RuleIntelligence]:
        """
        Find intelligence by rule_id.

        Args:
            rule_id: Unique rule identifier

        Returns:
            RuleIntelligence if found, None otherwise

        Example:
            intel = await repo.find_by_rule_id("ow-password-complexity")
        """
        query = {"rule_id": rule_id}
        return await self.find_one(query)

    async def find_latest_for_rules(self, rule_ids: List[str]) -> List[RuleIntelligence]:
        """
        Find intelligence for multiple rules.

        Args:
            rule_ids: List of rule identifiers

        Returns:
            List of RuleIntelligence documents for the specified rules

        Example:
            intel_list = await repo.find_latest_for_rules(["ow-rule-1", "ow-rule-2"])
        """
        query = {"rule_id": {"$in": rule_ids}}
        return await self.find_many(query, limit=len(rule_ids))

    async def upsert_intelligence(self, rule_id: str, data: Dict[str, Any]) -> RuleIntelligence:
        """
        Upsert intelligence data for a rule.

        Creates new intelligence if not exists, updates if exists.

        Args:
            rule_id: Rule identifier
            data: Intelligence data to upsert

        Returns:
            Updated or created RuleIntelligence document

        Example:
            intel = await repo.upsert_intelligence(
                "ow-password-complexity",
                {"business_impact": "high", "false_positive_rate": 0.05}
            )
        """
        existing = await self.find_by_rule_id(rule_id)

        if existing:
            # Update existing
            data["last_validation"] = datetime.utcnow()
            await self.update_one({"rule_id": rule_id}, {"$set": data})
            # Fetch updated document
            updated = await self.find_by_rule_id(rule_id)
            if updated:
                return updated
            raise ValueError(f"Failed to fetch updated intelligence for {rule_id}")
        else:
            # Create new
            data["rule_id"] = rule_id
            data["last_validation"] = datetime.utcnow()
            intel = RuleIntelligence(**data)
            return await self.create(intel)

    async def find_by_business_impact(self, impact: str) -> List[RuleIntelligence]:
        """
        Find intelligence by business impact level.

        Args:
            impact: Business impact level (low/medium/high/critical)

        Returns:
            List of RuleIntelligence with specified impact

        Example:
            high_impact = await repo.find_by_business_impact("high")
        """
        query = {"business_impact": impact}
        return await self.find_many(query)

    async def find_high_false_positive_rules(self, threshold: float = 0.1) -> List[RuleIntelligence]:
        """
        Find rules with false positive rate above threshold.

        Args:
            threshold: False positive rate threshold (default: 0.1 = 10%)

        Returns:
            List of RuleIntelligence with high false positive rates

        Example:
            problematic = await repo.find_high_false_positive_rules(0.15)
        """
        query = {"false_positive_rate": {"$gte": threshold}}
        return await self.find_many(query, sort=[("false_positive_rate", -1)])

    async def increment_usage_count(self, rule_id: str) -> Optional[RuleIntelligence]:
        """
        Increment usage count for a rule.

        Args:
            rule_id: Rule identifier

        Returns:
            Updated RuleIntelligence if found, None otherwise

        Example:
            updated = await repo.increment_usage_count("ow-password-complexity")
        """
        return await self.update_one(
            {"rule_id": rule_id},
            {"$inc": {"usage_count": 1}},
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get intelligence statistics.

        Returns:
            Dictionary with statistics:
            - total_rules: Total rules with intelligence
            - by_business_impact: Count by business impact
            - avg_false_positive_rate: Average false positive rate
            - avg_success_rate: Average remediation success rate

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()

            # Count by business impact
            impact_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$business_impact", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            impact_results = await self.aggregate(impact_pipeline)
            impact_counts = {item["_id"]: item["count"] for item in impact_results}

            # Calculate averages
            avg_pipeline: List[Dict[str, Any]] = [
                {
                    "$group": {
                        "_id": None,
                        "avg_false_positive": {"$avg": "$false_positive_rate"},
                        "avg_success_rate": {"$avg": "$success_rate"},
                    }
                }
            ]
            avg_results = await self.aggregate(avg_pipeline)
            avgs = avg_results[0] if avg_results else {}

            return {
                "total_rules": total,
                "by_business_impact": impact_counts,
                "avg_false_positive_rate": avgs.get("avg_false_positive", 0.0),
                "avg_success_rate": avgs.get("avg_success_rate", 1.0),
            }

        except Exception as e:
            logger.error(f"Error getting intelligence statistics: {e}")
            raise


class UploadHistoryRepository(BaseRepository[UploadHistory]):
    """
    Repository for UploadHistory operations.

    Provides upload history-specific query methods:
    - Find recent uploads
    - Find by upload source/user
    - Create upload records
    - Get upload statistics

    Example:
        repo = UploadHistoryRepository()
        recent = await repo.find_recent(limit=10)
    """

    def __init__(self) -> None:
        """Initialize the upload history repository."""
        super().__init__(UploadHistory)

    async def find_recent(self, limit: int = 10) -> List[UploadHistory]:
        """
        Find most recent uploads.

        Args:
            limit: Maximum number of uploads to return (default: 10)

        Returns:
            List of recent UploadHistory records

        Example:
            recent = await repo.find_recent(limit=5)
        """
        return await self.find_many(
            query={},
            skip=0,
            limit=limit,
            sort=[("uploaded_at", -1)],
        )

    async def find_by_source(self, source: str) -> List[UploadHistory]:
        """
        Find uploads by source filename pattern.

        Args:
            source: Source filename or pattern to search

        Returns:
            List of matching UploadHistory records

        Example:
            rhel_uploads = await repo.find_by_source("rhel8")
        """
        query = {"filename": {"$regex": source, "$options": "i"}}
        return await self.find_many(query, sort=[("uploaded_at", -1)])

    async def find_by_user(self, username: str) -> List[UploadHistory]:
        """
        Find uploads by username.

        Args:
            username: Username who uploaded

        Returns:
            List of uploads by the user

        Example:
            user_uploads = await repo.find_by_user("admin")
        """
        query = {"uploaded_by": username}
        return await self.find_many(query, sort=[("uploaded_at", -1)])

    async def find_by_upload_id(self, upload_id: str) -> Optional[UploadHistory]:
        """
        Find upload by unique upload_id.

        Args:
            upload_id: Unique upload identifier (UUID)

        Returns:
            UploadHistory if found, None otherwise

        Example:
            upload = await repo.find_by_upload_id("550e8400-e29b-41d4-a716-446655440000")
        """
        query = {"upload_id": upload_id}
        return await self.find_one(query)

    async def create_upload_record(self, data: Dict[str, Any]) -> UploadHistory:
        """
        Create a new upload history record.

        Args:
            data: Upload record data

        Returns:
            Created UploadHistory document

        Example:
            record = await repo.create_upload_record({
                "upload_id": str(uuid4()),
                "filename": "bundle.tar.gz",
                "file_hash": "sha512_hash_here",
                "uploaded_at": datetime.utcnow(),
                "uploaded_by": "admin",
                "success": True,
                "phase": "completed",
            })
        """
        upload = UploadHistory(**data)
        return await self.create(upload)

    async def find_failed_uploads(self, limit: int = 20) -> List[UploadHistory]:
        """
        Find recent failed uploads.

        Args:
            limit: Maximum number of failed uploads to return

        Returns:
            List of failed UploadHistory records

        Example:
            failed = await repo.find_failed_uploads(limit=10)
        """
        query = {"success": False}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("uploaded_at", -1)],
        )

    async def find_successful_uploads(self, limit: int = 20) -> List[UploadHistory]:
        """
        Find recent successful uploads.

        Args:
            limit: Maximum number of successful uploads to return

        Returns:
            List of successful UploadHistory records

        Example:
            successful = await repo.find_successful_uploads(limit=10)
        """
        query = {"success": True}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("uploaded_at", -1)],
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get upload statistics.

        Returns:
            Dictionary with statistics:
            - total_uploads: Total upload count
            - successful: Count of successful uploads
            - failed: Count of failed uploads
            - by_user: Upload count by user

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()
            successful = await self.count({"success": True})
            failed = await self.count({"success": False})

            # Count by user
            user_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$uploaded_by", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            user_results = await self.aggregate(user_pipeline)
            user_counts = {item["_id"]: item["count"] for item in user_results}

            return {
                "total_uploads": total,
                "successful": successful,
                "failed": failed,
                "by_user": user_counts,
            }

        except Exception as e:
            logger.error(f"Error getting upload statistics: {e}")
            raise
