"""
Remediation Job Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides remediation job-specific query methods for RemediationResult
and BulkRemediationJob collections.
Centralizes all remediation job query logic in one place.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models.remediation_models import BulkRemediationJob, RemediationResult, RemediationStatus
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class RemediationResultRepository(BaseRepository[RemediationResult]):
    """
    Repository for RemediationResult operations.

    Provides remediation result-specific query methods:
    - Find by scan_id
    - Find by host
    - Find by rule_id
    - Find by status

    Example:
        repo = RemediationResultRepository()
        results = await repo.find_by_scan_id("scan-123")
    """

    def __init__(self) -> None:
        """Initialize the remediation result repository."""
        super().__init__(RemediationResult)

    async def find_by_remediation_id(self, remediation_id: str) -> Optional[RemediationResult]:
        """
        Find result by unique remediation_id.

        Args:
            remediation_id: Unique remediation identifier

        Returns:
            RemediationResult if found, None otherwise

        Example:
            result = await repo.find_by_remediation_id("rem-123")
        """
        query = {"remediation_id": remediation_id}
        return await self.find_one(query)

    async def find_by_scan_id(self, scan_id: str) -> List[RemediationResult]:
        """
        Find all remediation results for a scan.

        Args:
            scan_id: Scan identifier

        Returns:
            List of RemediationResult documents for the scan

        Example:
            results = await repo.find_by_scan_id("scan-123")
        """
        query = {"scan_id": scan_id}
        return await self.find_many(query, sort=[("created_at", -1)])

    async def find_by_host(self, host_identifier: str, limit: int = 20) -> List[RemediationResult]:
        """
        Find remediation results for a host.

        Args:
            host_identifier: Host address or identifier
            limit: Maximum number of results to return

        Returns:
            List of RemediationResult documents for the host

        Example:
            results = await repo.find_by_host("192.168.1.100")
        """
        query = {"target.identifier": host_identifier}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("created_at", -1)],
        )

    async def find_by_rule_id(self, rule_id: str, limit: int = 20) -> List[RemediationResult]:
        """
        Find remediation results for a rule.

        Args:
            rule_id: Rule identifier
            limit: Maximum number of results to return

        Returns:
            List of RemediationResult documents for the rule

        Example:
            results = await repo.find_by_rule_id("ow-ssh-disable-root")
        """
        query = {"rule_id": rule_id}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("created_at", -1)],
        )

    async def find_by_status(self, status: str, limit: int = 20) -> List[RemediationResult]:
        """
        Find remediation results by status.

        Args:
            status: Remediation status (pending, running, completed, failed, rolled_back)
            limit: Maximum number of results to return

        Returns:
            List of RemediationResult documents with specified status

        Example:
            completed = await repo.find_by_status("completed")
        """
        query = {"status": status}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("created_at", -1)],
        )

    async def find_by_user(self, username: str, limit: int = 20) -> List[RemediationResult]:
        """
        Find remediation results by user.

        Args:
            username: Username who executed the remediations
            limit: Maximum number of results to return

        Returns:
            List of RemediationResult documents by the user

        Example:
            user_results = await repo.find_by_user("admin")
        """
        query = {"executed_by": username}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("created_at", -1)],
        )

    async def find_pending(self) -> List[RemediationResult]:
        """
        Find pending remediations.

        Returns:
            List of pending RemediationResult documents

        Example:
            pending = await repo.find_pending()
        """
        query = {"status": RemediationStatus.PENDING.value}
        return await self.find_many(query, sort=[("created_at", 1)])

    async def find_running(self) -> List[RemediationResult]:
        """
        Find currently running remediations.

        Returns:
            List of running RemediationResult documents

        Example:
            running = await repo.find_running()
        """
        query = {"status": RemediationStatus.RUNNING.value}
        return await self.find_many(query, sort=[("started_at", 1)])

    async def find_with_rollback_available(self, limit: int = 20) -> List[RemediationResult]:
        """
        Find completed remediations that can be rolled back.

        Args:
            limit: Maximum number of results to return

        Returns:
            List of RemediationResult documents with rollback available

        Example:
            rollbackable = await repo.find_with_rollback_available()
        """
        query = {
            "status": RemediationStatus.COMPLETED.value,
            "rollback_available": True,
            "rollback_executed": False,
        }
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("completed_at", -1)],
        )

    async def update_status(
        self,
        remediation_id: str,
        status: str,
        **kwargs: Any,
    ) -> Optional[RemediationResult]:
        """
        Update remediation status.

        Args:
            remediation_id: Remediation identifier
            status: New status
            **kwargs: Additional fields to update

        Returns:
            Updated RemediationResult if found, None otherwise

        Example:
            updated = await repo.update_status(
                "rem-123",
                "completed",
                completed_at=datetime.utcnow(),
            )
        """
        update_data: Dict[str, Any] = {"status": status, **kwargs}

        # Set timing fields based on status
        if status == RemediationStatus.RUNNING.value:
            update_data.setdefault("started_at", datetime.utcnow())
        elif status in [
            RemediationStatus.COMPLETED.value,
            RemediationStatus.FAILED.value,
            RemediationStatus.ROLLED_BACK.value,
        ]:
            update_data.setdefault("completed_at", datetime.utcnow())

        return await self.update_one(
            {"remediation_id": remediation_id},
            {"$set": update_data},
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get remediation result statistics.

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

            # Count by executor type
            executor_pipeline: List[Dict[str, Any]] = [
                {"$group": {"_id": "$executor_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            executor_results = await self.aggregate(executor_pipeline)
            executor_counts = {item["_id"]: item["count"] for item in executor_results}

            # Success rate
            completed = status_counts.get(RemediationStatus.COMPLETED.value, 0)
            failed = status_counts.get(RemediationStatus.FAILED.value, 0)
            success_rate = (completed / (completed + failed) * 100) if (completed + failed) > 0 else 0.0

            return {
                "total_remediations": total,
                "by_status": status_counts,
                "by_executor": executor_counts,
                "success_rate": success_rate,
            }

        except Exception as e:
            logger.error(f"Error getting remediation statistics: {e}")
            raise


class BulkRemediationJobRepository(BaseRepository[BulkRemediationJob]):
    """
    Repository for BulkRemediationJob operations.

    Provides bulk job-specific query methods:
    - Find pending jobs
    - Find by status
    - Find by scan_id
    - Update job progress

    Example:
        repo = BulkRemediationJobRepository()
        pending = await repo.find_pending()
    """

    def __init__(self) -> None:
        """Initialize the bulk remediation job repository."""
        super().__init__(BulkRemediationJob)

    async def find_by_job_id(self, job_id: str) -> Optional[BulkRemediationJob]:
        """
        Find job by unique job_id.

        Args:
            job_id: Unique job identifier

        Returns:
            BulkRemediationJob if found, None otherwise

        Example:
            job = await repo.find_by_job_id("job-123")
        """
        query = {"job_id": job_id}
        return await self.find_one(query)

    async def find_by_scan_id(self, scan_id: str) -> List[BulkRemediationJob]:
        """
        Find bulk jobs for a scan.

        Args:
            scan_id: Scan identifier

        Returns:
            List of BulkRemediationJob documents for the scan

        Example:
            jobs = await repo.find_by_scan_id("scan-123")
        """
        query = {"scan_id": scan_id}
        return await self.find_many(query, sort=[("created_at", -1)])

    async def find_pending(self) -> List[BulkRemediationJob]:
        """
        Find pending bulk jobs.

        Returns:
            List of pending BulkRemediationJob documents

        Example:
            pending = await repo.find_pending()
        """
        query = {"status": RemediationStatus.PENDING.value}
        return await self.find_many(query, sort=[("created_at", 1)])

    async def find_running(self) -> List[BulkRemediationJob]:
        """
        Find currently running bulk jobs.

        Returns:
            List of running BulkRemediationJob documents

        Example:
            running = await repo.find_running()
        """
        query = {"status": RemediationStatus.RUNNING.value}
        return await self.find_many(query, sort=[("started_at", 1)])

    async def find_by_status(self, status: str) -> List[BulkRemediationJob]:
        """
        Find bulk jobs by status.

        Args:
            status: Job status (pending, running, completed, failed, rolled_back)

        Returns:
            List of BulkRemediationJob documents with specified status

        Example:
            completed = await repo.find_by_status("completed")
        """
        query = {"status": status}
        return await self.find_many(query, sort=[("created_at", -1)])

    async def find_by_user(self, username: str, limit: int = 20) -> List[BulkRemediationJob]:
        """
        Find bulk jobs by user.

        Args:
            username: Username who executed the jobs
            limit: Maximum number of results to return

        Returns:
            List of BulkRemediationJob documents by the user

        Example:
            user_jobs = await repo.find_by_user("admin")
        """
        query = {"executed_by": username}
        return await self.find_many(
            query,
            skip=0,
            limit=limit,
            sort=[("created_at", -1)],
        )

    async def update_progress(
        self,
        job_id: str,
        completed: int,
        failed: int,
    ) -> Optional[BulkRemediationJob]:
        """
        Update job progress.

        Args:
            job_id: Job identifier
            completed: Number of completed remediations
            failed: Number of failed remediations

        Returns:
            Updated BulkRemediationJob if found, None otherwise

        Example:
            updated = await repo.update_progress("job-123", 5, 1)
        """
        return await self.update_one(
            {"job_id": job_id},
            {
                "$set": {
                    "completed_remediations": completed,
                    "failed_remediations": failed,
                }
            },
        )

    async def update_status(
        self,
        job_id: str,
        status: str,
        **kwargs: Any,
    ) -> Optional[BulkRemediationJob]:
        """
        Update job status.

        Args:
            job_id: Job identifier
            status: New status
            **kwargs: Additional fields to update

        Returns:
            Updated BulkRemediationJob if found, None otherwise

        Example:
            updated = await repo.update_status("job-123", "completed")
        """
        update_data: Dict[str, Any] = {"status": status, **kwargs}

        # Set timing fields based on status
        if status == RemediationStatus.RUNNING.value:
            update_data.setdefault("started_at", datetime.utcnow())
        elif status in [
            RemediationStatus.COMPLETED.value,
            RemediationStatus.FAILED.value,
        ]:
            update_data.setdefault("completed_at", datetime.utcnow())

        return await self.update_one(
            {"job_id": job_id},
            {"$set": update_data},
        )

    async def add_remediation(self, job_id: str, remediation_id: str) -> Optional[BulkRemediationJob]:
        """
        Add a remediation ID to the job.

        Args:
            job_id: Job identifier
            remediation_id: Remediation ID to add

        Returns:
            Updated BulkRemediationJob if found, None otherwise

        Example:
            updated = await repo.add_remediation("job-123", "rem-456")
        """
        return await self.update_one(
            {"job_id": job_id},
            {
                "$push": {"remediation_ids": remediation_id},
                "$inc": {"total_remediations": 1},
            },
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get bulk job statistics.

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

            # Average success rate
            avg_pipeline: List[Dict[str, Any]] = [
                {"$match": {"status": RemediationStatus.COMPLETED.value}},
                {
                    "$project": {
                        "success_rate": {
                            "$cond": {
                                "if": {"$gt": ["$total_remediations", 0]},
                                "then": {
                                    "$multiply": [
                                        {
                                            "$divide": [
                                                "$completed_remediations",
                                                "$total_remediations",
                                            ]
                                        },
                                        100,
                                    ]
                                },
                                "else": 0,
                            }
                        }
                    }
                },
                {"$group": {"_id": None, "avg_success_rate": {"$avg": "$success_rate"}}},
            ]
            avg_results = await self.aggregate(avg_pipeline)
            avg_success_rate = avg_results[0]["avg_success_rate"] if avg_results else 0.0

            return {
                "total_jobs": total,
                "by_status": status_counts,
                "avg_success_rate": avg_success_rate,
            }

        except Exception as e:
            logger.error(f"Error getting bulk job statistics: {e}")
            raise
