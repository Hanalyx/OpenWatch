"""
Scan Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides scan-specific query methods for ScanTemplate, ScanResult,
and ScanSchedule collections.
Centralizes all scan-related query logic in one place.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models.scan_config_models import ScanTemplate
from ..models.scan_models import ScanResult, ScanSchedule, ScanStatus
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class ScanTemplateRepository(BaseRepository[ScanTemplate]):
    """
    Repository for ScanTemplate operations.

    Provides template-specific query methods:
    - Find by name or template_id
    - Find active templates
    - Find by framework or user
    - Template management

    Example:
        repo = ScanTemplateRepository()
        templates = await repo.find_active()
    """

    def __init__(self) -> None:
        """Initialize the scan template repository."""
        super().__init__(ScanTemplate)

    async def find_by_template_id(self, template_id: str) -> Optional[ScanTemplate]:
        """
        Find template by unique template_id.

        Args:
            template_id: Unique template identifier (UUID)

        Returns:
            ScanTemplate if found, None otherwise

        Example:
            template = await repo.find_by_template_id("550e8400-e29b-41d4-a716-446655440000")
        """
        query = {"template_id": template_id}
        return await self.find_one(query)

    async def find_by_name(self, name: str) -> Optional[ScanTemplate]:
        """
        Find template by name.

        Args:
            name: Template name

        Returns:
            ScanTemplate if found, None otherwise

        Example:
            template = await repo.find_by_name("RHEL 9 CIS Scan")
        """
        query = {"name": name}
        return await self.find_one(query)

    async def find_active(self) -> List[ScanTemplate]:
        """
        Find all templates (templates don't have an active/inactive status
        but we filter out default templates for active list).

        Returns:
            List of ScanTemplate documents

        Example:
            templates = await repo.find_active()
        """
        # Return all templates sorted by name
        return await self.find_many(
            query={},
            skip=0,
            limit=1000,
            sort=[("name", 1)],
        )

    async def find_by_framework(self, framework: str) -> List[ScanTemplate]:
        """
        Find templates by framework.

        Args:
            framework: Framework identifier (e.g., "nist", "cis")

        Returns:
            List of ScanTemplate documents for the framework

        Example:
            cis_templates = await repo.find_by_framework("cis")
        """
        query = {"framework": framework}
        return await self.find_many(query, sort=[("name", 1)])

    async def find_by_user(self, username: str) -> List[ScanTemplate]:
        """
        Find templates created by a user.

        Args:
            username: Username who created the templates

        Returns:
            List of ScanTemplate documents by the user

        Example:
            user_templates = await repo.find_by_user("admin")
        """
        query = {"created_by": username}
        return await self.find_many(query, sort=[("created_at", -1)])

    async def find_public(self) -> List[ScanTemplate]:
        """
        Find all public templates.

        Returns:
            List of public ScanTemplate documents

        Example:
            public = await repo.find_public()
        """
        query = {"is_public": True}
        return await self.find_many(query, sort=[("name", 1)])

    async def find_default_for_framework(self, framework: str, username: str) -> Optional[ScanTemplate]:
        """
        Find default template for a framework and user.

        Args:
            framework: Framework identifier
            username: Username

        Returns:
            Default ScanTemplate if found, None otherwise

        Example:
            default = await repo.find_default_for_framework("cis", "admin")
        """
        query = {
            "framework": framework,
            "created_by": username,
            "is_default": True,
        }
        return await self.find_one(query)

    async def find_shared_with_user(self, username: str) -> List[ScanTemplate]:
        """
        Find templates shared with a user.

        Args:
            username: Username to check sharing

        Returns:
            List of ScanTemplate documents shared with the user

        Example:
            shared = await repo.find_shared_with_user("analyst")
        """
        query = {"shared_with": username}
        return await self.find_many(query, sort=[("name", 1)])

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get template statistics.

        Returns:
            Dictionary with statistics

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()
            public = await self.count({"is_public": True})

            # Count by framework
            framework_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$framework", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            framework_results = await self.aggregate(framework_pipeline)
            framework_counts = {item["_id"]: item["count"] for item in framework_results}

            # Count by user
            user_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$created_by", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            user_results = await self.aggregate(user_pipeline)
            user_counts = {item["_id"]: item["count"] for item in user_results}

            return {
                "total_templates": total,
                "public_templates": public,
                "by_framework": framework_counts,
                "by_user": user_counts,
            }

        except Exception as e:
            logger.error(f"Error getting template statistics: {e}")
            raise


class ScanResultRepository(BaseRepository[ScanResult]):
    """
    Repository for ScanResult operations.

    Provides result-specific query methods:
    - Find by scan_id
    - Find by host
    - Find by status
    - Get compliance scores

    Example:
        repo = ScanResultRepository()
        result = await repo.find_by_scan_id("scan-123")
    """

    def __init__(self) -> None:
        """Initialize the scan result repository."""
        super().__init__(ScanResult)

    async def find_by_scan_id(self, scan_id: str) -> Optional[ScanResult]:
        """
        Find result by scan_id.

        Args:
            scan_id: Unique scan identifier

        Returns:
            ScanResult if found, None otherwise

        Example:
            result = await repo.find_by_scan_id("550e8400-e29b-41d4-a716-446655440000")
        """
        query = {"scan_id": scan_id}
        return await self.find_one(query)

    async def find_by_host(self, host_identifier: str, limit: int = 10) -> List[ScanResult]:
        """
        Find results for a host.

        Args:
            host_identifier: Host address or identifier
            limit: Maximum number of results to return

        Returns:
            List of ScanResult documents for the host

        Example:
            host_results = await repo.find_by_host("192.168.1.100")
        """
        query = {"config.target.identifier": host_identifier}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_by_status(self, status: str, limit: int = 20) -> List[ScanResult]:
        """
        Find results by status.

        Args:
            status: Scan status (pending, running, completed, failed, cancelled)
            limit: Maximum number of results to return

        Returns:
            List of ScanResult documents with specified status

        Example:
            completed = await repo.find_by_status("completed")
        """
        query = {"status": status}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_by_framework(self, framework: str, limit: int = 20) -> List[ScanResult]:
        """
        Find results by framework.

        Args:
            framework: Framework identifier
            limit: Maximum number of results to return

        Returns:
            List of ScanResult documents for the framework

        Example:
            cis_results = await repo.find_by_framework("cis")
        """
        query = {"config.framework": framework}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_by_user(self, username: str, limit: int = 20) -> List[ScanResult]:
        """
        Find results started by a user.

        Args:
            username: Username who started the scans
            limit: Maximum number of results to return

        Returns:
            List of ScanResult documents by the user

        Example:
            user_results = await repo.find_by_user("admin")
        """
        query = {"started_by": username}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_recent(self, limit: int = 10) -> List[ScanResult]:
        """
        Find most recent scan results.

        Args:
            limit: Maximum number of results to return

        Returns:
            List of recent ScanResult documents

        Example:
            recent = await repo.find_recent()
        """
        return await self.find_many(
            query={},
            skip=0,
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_failed(self, limit: int = 20) -> List[ScanResult]:
        """
        Find recent failed scans.

        Args:
            limit: Maximum number of failed results to return

        Returns:
            List of failed ScanResult documents

        Example:
            failed = await repo.find_failed()
        """
        query = {"status": ScanStatus.FAILED.value}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def get_compliance_trend(
        self,
        host_identifier: str,
        limit: int = 30,
    ) -> List[Dict[str, Any]]:
        """
        Get compliance score trend for a host.

        Args:
            host_identifier: Host address or identifier
            limit: Number of data points to return

        Returns:
            List of dicts with timestamp and compliance_percentage

        Example:
            trend = await repo.get_compliance_trend("192.168.1.100")
        """
        pipeline: List[Dict[str, Any]] = [
            {
                "$match": {
                    "config.target.identifier": host_identifier,
                    "status": ScanStatus.COMPLETED.value,
                }
            },
            {"$sort": {"started_at": -1}},
            {"$limit": limit},
            {
                "$project": {
                    "timestamp": "$started_at",
                    "compliance_percentage": "$summary.compliance_percentage",
                    "passed": "$summary.passed",
                    "failed": "$summary.failed",
                }
            },
        ]
        return await self.aggregate(pipeline)

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get scan result statistics.

        Returns:
            Dictionary with statistics

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()

            # Count by status
            status_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$status", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            status_results = await self.aggregate(status_pipeline)
            status_counts = {item["_id"]: item["count"] for item in status_results}

            # Average compliance percentage
            avg_pipeline: List[Dict[str, Any]] = [
                {"$match": {"status": ScanStatus.COMPLETED.value}},
                {
                    "$group": {
                        "_id": None,
                        "avg_compliance": {"$avg": "$summary.compliance_percentage"},
                    }
                },
            ]
            avg_results = await self.aggregate(avg_pipeline)
            avg_compliance = avg_results[0]["avg_compliance"] if avg_results else 0.0

            return {
                "total_scans": total,
                "by_status": status_counts,
                "avg_compliance_percentage": avg_compliance,
            }

        except Exception as e:
            logger.error(f"Error getting scan statistics: {e}")
            raise


class ScanScheduleRepository(BaseRepository[ScanSchedule]):
    """
    Repository for ScanSchedule operations.

    Provides schedule-specific query methods:
    - Find active schedules
    - Find due schedules
    - Find by user

    Example:
        repo = ScanScheduleRepository()
        active = await repo.find_active()
    """

    def __init__(self) -> None:
        """Initialize the scan schedule repository."""
        super().__init__(ScanSchedule)

    async def find_by_schedule_id(self, schedule_id: str) -> Optional[ScanSchedule]:
        """
        Find schedule by unique schedule_id.

        Args:
            schedule_id: Unique schedule identifier

        Returns:
            ScanSchedule if found, None otherwise

        Example:
            schedule = await repo.find_by_schedule_id("schedule-123")
        """
        query = {"schedule_id": schedule_id}
        return await self.find_one(query)

    async def find_active(self) -> List[ScanSchedule]:
        """
        Find all active (enabled) schedules.

        Returns:
            List of active ScanSchedule documents

        Example:
            active = await repo.find_active()
        """
        query = {"enabled": True}
        return await self.find_many(query, sort=[("next_run_at", 1)])

    async def find_due(self) -> List[ScanSchedule]:
        """
        Find schedules that are due to run.

        Returns:
            List of ScanSchedule documents due for execution

        Example:
            due = await repo.find_due()
        """
        query = {
            "enabled": True,
            "next_run_at": {"$lte": datetime.utcnow()},
        }
        return await self.find_many(query, sort=[("next_run_at", 1)])

    async def find_by_user(self, username: str) -> List[ScanSchedule]:
        """
        Find schedules created by a user.

        Args:
            username: Username who created the schedules

        Returns:
            List of ScanSchedule documents by the user

        Example:
            user_schedules = await repo.find_by_user("admin")
        """
        query = {"created_by": username}
        return await self.find_many(query, sort=[("name", 1)])

    async def find_disabled(self) -> List[ScanSchedule]:
        """
        Find all disabled schedules.

        Returns:
            List of disabled ScanSchedule documents

        Example:
            disabled = await repo.find_disabled()
        """
        query = {"enabled": False}
        return await self.find_many(query, sort=[("name", 1)])

    async def update_last_run(
        self,
        schedule_id: str,
        scan_id: str,
        next_run_at: datetime,
    ) -> Optional[ScanSchedule]:
        """
        Update schedule after a run completes.

        Args:
            schedule_id: Schedule identifier
            scan_id: ID of the scan that ran
            next_run_at: Next scheduled run time

        Returns:
            Updated ScanSchedule if found, None otherwise

        Example:
            updated = await repo.update_last_run(
                "schedule-123",
                "scan-456",
                datetime.utcnow() + timedelta(days=1),
            )
        """
        update = {
            "$set": {
                "last_run_at": datetime.utcnow(),
                "last_scan_id": scan_id,
                "next_run_at": next_run_at,
                "updated_at": datetime.utcnow(),
            }
        }
        return await self.update_one({"schedule_id": schedule_id}, update)

    async def enable(self, schedule_id: str) -> bool:
        """
        Enable a schedule.

        Args:
            schedule_id: Schedule identifier to enable

        Returns:
            True if schedule was enabled, False if not found

        Example:
            success = await repo.enable("schedule-123")
        """
        result = await self.update_one(
            {"schedule_id": schedule_id},
            {"$set": {"enabled": True, "updated_at": datetime.utcnow()}},
        )
        return result is not None

    async def disable(self, schedule_id: str) -> bool:
        """
        Disable a schedule.

        Args:
            schedule_id: Schedule identifier to disable

        Returns:
            True if schedule was disabled, False if not found

        Example:
            success = await repo.disable("schedule-123")
        """
        result = await self.update_one(
            {"schedule_id": schedule_id},
            {"$set": {"enabled": False, "updated_at": datetime.utcnow()}},
        )
        return result is not None

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get schedule statistics.

        Returns:
            Dictionary with statistics

        Example:
            stats = await repo.get_statistics()
        """
        try:
            total = await self.count()
            active = await self.count({"enabled": True})
            disabled = await self.count({"enabled": False})

            # Count by user
            user_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$created_by", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            user_results = await self.aggregate(user_pipeline)
            user_counts = {item["_id"]: item["count"] for item in user_results}

            return {
                "total_schedules": total,
                "active": active,
                "disabled": disabled,
                "by_user": user_counts,
            }

        except Exception as e:
            logger.error(f"Error getting schedule statistics: {e}")
            raise
