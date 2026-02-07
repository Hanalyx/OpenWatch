"""
Health Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides health-specific query methods for ServiceHealthDocument,
ContentHealthDocument, and HealthSummaryDocument collections.
Centralizes all health monitoring query logic in one place.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models.health_models import ContentHealthDocument, HealthStatus, HealthSummaryDocument, ServiceHealthDocument
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class ServiceHealthRepository(BaseRepository[ServiceHealthDocument]):
    """
    Repository for ServiceHealthDocument operations.

    Provides service health-specific query methods:
    - Find latest health check
    - Find by scanner ID
    - Find by overall status
    - Get health history

    Example:
        repo = ServiceHealthRepository()
        latest = await repo.find_latest()
    """

    def __init__(self) -> None:
        """Initialize the service health repository."""
        super().__init__(ServiceHealthDocument)

    async def find_latest(self, scanner_id: Optional[str] = None) -> Optional[ServiceHealthDocument]:
        """
        Find the most recent health check.

        Args:
            scanner_id: Optional scanner ID filter

        Returns:
            Most recent ServiceHealthDocument if found, None otherwise

        Example:
            latest = await repo.find_latest()
            scanner_latest = await repo.find_latest("scanner-001")
        """
        query: Dict[str, Any] = {}
        if scanner_id:
            query["scanner_id"] = scanner_id

        results = await self.find_many(
            query,
            skip=0,
            limit=1,
            sort=[("health_check_timestamp", -1)],
        )
        return results[0] if results else None

    async def find_by_service(self, service_name: str, limit: int = 10) -> List[ServiceHealthDocument]:
        """
        Find health documents that include a specific service.

        Args:
            service_name: Name of the core service to filter by
            limit: Maximum number of documents to return

        Returns:
            List of ServiceHealthDocument containing the service

        Example:
            api_health = await repo.find_by_service("api")
        """
        query = {f"core_services.{service_name}": {"$exists": True}}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("health_check_timestamp", -1)],
        )

    async def find_by_status(self, status: str, limit: int = 20) -> List[ServiceHealthDocument]:
        """
        Find health documents by overall status.

        Args:
            status: Health status (healthy, warning, degraded, unhealthy, unknown)
            limit: Maximum number of documents to return

        Returns:
            List of ServiceHealthDocument with specified status

        Example:
            degraded = await repo.find_by_status("degraded")
        """
        query = {"overall_status": status}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("health_check_timestamp", -1)],
        )

    async def find_with_alerts(self, limit: int = 20) -> List[ServiceHealthDocument]:
        """
        Find health documents that have active alerts.

        Args:
            limit: Maximum number of documents to return

        Returns:
            List of ServiceHealthDocument with alerts

        Example:
            with_alerts = await repo.find_with_alerts()
        """
        query = {"alerts": {"$ne": []}}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("health_check_timestamp", -1)],
        )

    async def get_health_history(
        self,
        scanner_id: str,
        hours: int = 24,
    ) -> List[ServiceHealthDocument]:
        """
        Get health history for a scanner over specified hours.

        Args:
            scanner_id: Scanner identifier
            hours: Number of hours of history to retrieve

        Returns:
            List of ServiceHealthDocument ordered by timestamp

        Example:
            history = await repo.get_health_history("scanner-001", hours=48)
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(hours=hours)
        query = {
            "scanner_id": scanner_id,
            "health_check_timestamp": {"$gte": cutoff},
        }
        return await self.find_many(
            query,
            skip=0,
            limit=1000,  # Reasonable limit for time series data
            sort=[("health_check_timestamp", 1)],
        )


class ContentHealthRepository(BaseRepository[ContentHealthDocument]):
    """
    Repository for ContentHealthDocument operations.

    Provides content health-specific query methods:
    - Find latest health check
    - Find by scanner ID
    - Get framework/benchmark health

    Example:
        repo = ContentHealthRepository()
        latest = await repo.find_latest()
    """

    def __init__(self) -> None:
        """Initialize the content health repository."""
        super().__init__(ContentHealthDocument)

    async def find_latest(self, scanner_id: Optional[str] = None) -> Optional[ContentHealthDocument]:
        """
        Find the most recent content health check.

        Args:
            scanner_id: Optional scanner ID filter

        Returns:
            Most recent ContentHealthDocument if found, None otherwise

        Example:
            latest = await repo.find_latest()
        """
        query: Dict[str, Any] = {}
        if scanner_id:
            query["scanner_id"] = scanner_id

        results = await self.find_many(
            query,
            skip=0,
            limit=1,
            sort=[("health_check_timestamp", -1)],
        )
        return results[0] if results else None

    async def find_by_scanner(self, scanner_id: str, limit: int = 10) -> List[ContentHealthDocument]:
        """
        Find content health documents for a scanner.

        Args:
            scanner_id: Scanner identifier
            limit: Maximum number of documents to return

        Returns:
            List of ContentHealthDocument for the scanner

        Example:
            scanner_health = await repo.find_by_scanner("scanner-001")
        """
        query = {"scanner_id": scanner_id}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("health_check_timestamp", -1)],
        )

    async def find_with_alerts(self, limit: int = 20) -> List[ContentHealthDocument]:
        """
        Find content health documents that have alerts/recommendations.

        Args:
            limit: Maximum number of documents to return

        Returns:
            List of ContentHealthDocument with alerts

        Example:
            with_alerts = await repo.find_with_alerts()
        """
        query = {"alerts_and_recommendations": {"$ne": []}}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("health_check_timestamp", -1)],
        )

    async def get_content_history(
        self,
        scanner_id: str,
        hours: int = 24,
    ) -> List[ContentHealthDocument]:
        """
        Get content health history for a scanner.

        Args:
            scanner_id: Scanner identifier
            hours: Number of hours of history to retrieve

        Returns:
            List of ContentHealthDocument ordered by timestamp

        Example:
            history = await repo.get_content_history("scanner-001", hours=48)
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(hours=hours)
        query = {
            "scanner_id": scanner_id,
            "health_check_timestamp": {"$gte": cutoff},
        }
        return await self.find_many(
            query,
            skip=0,
            limit=1000,
            sort=[("health_check_timestamp", 1)],
        )


class HealthSummaryRepository(BaseRepository[HealthSummaryDocument]):
    """
    Repository for HealthSummaryDocument operations.

    Provides health summary-specific query methods:
    - Find latest summary
    - Upsert summary
    - Find by overall status

    Example:
        repo = HealthSummaryRepository()
        summary = await repo.find_latest()
    """

    def __init__(self) -> None:
        """Initialize the health summary repository."""
        super().__init__(HealthSummaryDocument)

    async def find_latest(self, scanner_id: Optional[str] = None) -> Optional[HealthSummaryDocument]:
        """
        Find the most recent health summary.

        Args:
            scanner_id: Optional scanner ID filter

        Returns:
            Most recent HealthSummaryDocument if found, None otherwise

        Example:
            latest = await repo.find_latest()
        """
        query: Dict[str, Any] = {}
        if scanner_id:
            query["scanner_id"] = scanner_id

        results = await self.find_many(
            query,
            skip=0,
            limit=1,
            sort=[("last_updated", -1)],
        )
        return results[0] if results else None

    async def find_by_scanner(self, scanner_id: str) -> Optional[HealthSummaryDocument]:
        """
        Find health summary for a specific scanner.

        Args:
            scanner_id: Scanner identifier

        Returns:
            HealthSummaryDocument if found, None otherwise

        Example:
            summary = await repo.find_by_scanner("scanner-001")
        """
        query = {"scanner_id": scanner_id}
        return await self.find_one(query)

    async def upsert_summary(self, data: Dict[str, Any]) -> HealthSummaryDocument:
        """
        Upsert health summary.

        Creates new summary if not exists, updates if exists (by scanner_id).

        Args:
            data: Summary data including scanner_id

        Returns:
            Created or updated HealthSummaryDocument

        Example:
            summary = await repo.upsert_summary({
                "scanner_id": "scanner-001",
                "service_health_status": "healthy",
                "content_health_status": "healthy",
                "overall_health_status": "healthy",
                "key_metrics": {"uptime": 99.9},
                "active_issues_count": 0,
            })
        """
        scanner_id = data.get("scanner_id")
        if not scanner_id:
            raise ValueError("scanner_id is required for upsert")

        existing = await self.find_by_scanner(scanner_id)
        data["last_updated"] = datetime.utcnow()

        if existing:
            # Update existing
            await self.update_one(
                {"scanner_id": scanner_id},
                {"$set": data},
            )
            updated = await self.find_by_scanner(scanner_id)
            if updated:
                return updated
            raise ValueError(f"Failed to fetch updated summary for {scanner_id}")
        else:
            # Create new
            summary = HealthSummaryDocument(**data)
            return await self.create(summary)

    async def find_unhealthy(self) -> List[HealthSummaryDocument]:
        """
        Find all unhealthy summaries.

        Returns:
            List of HealthSummaryDocument with unhealthy status

        Example:
            unhealthy = await repo.find_unhealthy()
        """
        query = {
            "overall_health_status": {
                "$in": [
                    HealthStatus.UNHEALTHY.value,
                    HealthStatus.DEGRADED.value,
                ]
            }
        }
        return await self.find_many(query)

    async def find_with_critical_alerts(self) -> List[HealthSummaryDocument]:
        """
        Find summaries with critical alerts.

        Returns:
            List of HealthSummaryDocument with critical alerts

        Example:
            critical = await repo.find_with_critical_alerts()
        """
        query = {"critical_alerts": {"$ne": []}}
        return await self.find_many(query)

    async def get_all_summaries(self) -> List[HealthSummaryDocument]:
        """
        Get all health summaries (one per scanner).

        Returns:
            List of all HealthSummaryDocument records

        Example:
            all_summaries = await repo.get_all_summaries()
        """
        return await self.find_many(
            query={},
            skip=0,
            limit=1000,
            sort=[("scanner_id", 1)],
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get health summary statistics across all scanners.

        Returns:
            Dictionary with statistics:
            - total_scanners: Total scanner count
            - by_status: Count by overall health status
            - total_issues: Sum of active issues

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()

            # Count by status
            status_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$overall_health_status", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            status_results = await self.aggregate(status_pipeline)
            status_counts = {item["_id"]: item["count"] for item in status_results}

            # Sum of active issues
            issues_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": None, "total_issues": {"$sum": "$active_issues_count"}}}
            ]
            issues_results = await self.aggregate(issues_pipeline)
            total_issues = issues_results[0]["total_issues"] if issues_results else 0

            return {
                "total_scanners": total,
                "by_status": status_counts,
                "total_issues": total_issues,
            }

        except Exception as e:
            logger.error(f"Error getting health statistics: {e}")
            raise
