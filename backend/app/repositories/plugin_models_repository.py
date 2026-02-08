"""
Plugin Models Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides repositories for plugin-specific MongoDB Document models:
- PluginUpdateExecution (lifecycle)
- SystemWideAnalytics (analytics)
- OptimizationJob (orchestration)
- AuditEvent (governance)
- PluginInstallationResult (marketplace)
- TestSuite, TestExecution (development)
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class PluginUpdateExecutionRepository(BaseRepository):
    """
    Repository for PluginUpdateExecution operations.

    Provides update execution-specific query methods:
    - Find by execution_id
    - Find by plugin_id
    - Find by status
    - Find recent executions

    Example:
        repo = PluginUpdateExecutionRepository()
        executions = await repo.find_by_status("in_progress")
    """

    def __init__(self) -> None:
        """Initialize the plugin update execution repository."""
        from ..services.plugins.lifecycle.models import PluginUpdateExecution

        super().__init__(PluginUpdateExecution)

    async def find_by_execution_id(self, execution_id: str) -> Optional[Any]:
        """Find execution by unique execution_id."""
        return await self.find_one({"execution_id": execution_id})

    async def find_by_plugin_id(self, plugin_id: str, limit: int = 20) -> List[Any]:
        """Find executions for a plugin."""
        return await self.find_many(
            {"update_plan.plugin_id": plugin_id},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_by_status(self, status: str, limit: int = 100) -> List[Any]:
        """Find executions by status."""
        return await self.find_many(
            {"status": status},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_in_progress(self) -> List[Any]:
        """Find currently running executions."""
        return await self.find_many({"status": "in_progress"})

    async def find_recent(self, hours: int = 24, limit: int = 100) -> List[Any]:
        """Find recent executions within specified hours."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return await self.find_many(
            {"started_at": {"$gte": cutoff}},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics."""
        total = await self.count()

        status_pipeline: List[Dict[str, Any]] = [
            {"$group": {"_id": "$status", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        status_results = await self.aggregate(status_pipeline)
        status_counts = {item["_id"]: item["count"] for item in status_results}

        return {
            "total_executions": total,
            "by_status": status_counts,
        }


class SystemWideAnalyticsRepository(BaseRepository):
    """
    Repository for SystemWideAnalytics operations.

    Provides analytics-specific query methods:
    - Find latest snapshot
    - Find snapshots in time range

    Example:
        repo = SystemWideAnalyticsRepository()
        latest = await repo.find_latest()
    """

    def __init__(self) -> None:
        """Initialize the system wide analytics repository."""
        from ..services.plugins.analytics.models import SystemWideAnalytics

        super().__init__(SystemWideAnalytics)

    async def find_by_snapshot_id(self, snapshot_id: str) -> Optional[Any]:
        """Find analytics by snapshot_id."""
        return await self.find_one({"snapshot_id": snapshot_id})

    async def find_latest(self) -> Optional[Any]:
        """Find the most recent analytics snapshot."""
        results = await self.find_many({}, limit=1, sort=[("snapshot_time", -1)])
        return results[0] if results else None

    async def find_in_range(
        self,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Any]:
        """Find analytics snapshots in time range."""
        query: Dict[str, Any] = {"snapshot_time": {"$gte": start_time}}
        if end_time:
            query["snapshot_time"]["$lte"] = end_time
        return await self.find_many(query, limit=limit, sort=[("snapshot_time", 1)])

    async def find_recent(self, hours: int = 24) -> List[Any]:
        """Find recent analytics snapshots."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return await self.find_in_range(cutoff)


class OptimizationJobRepository(BaseRepository):
    """
    Repository for OptimizationJob operations.

    Provides job-specific query methods:
    - Find by job_id
    - Find by plugin_id
    - Find pending/running jobs

    Example:
        repo = OptimizationJobRepository()
        pending = await repo.find_pending()
    """

    def __init__(self) -> None:
        """Initialize the optimization job repository."""
        from ..services.plugins.orchestration.models import OptimizationJob

        super().__init__(OptimizationJob)

    async def find_by_job_id(self, job_id: str) -> Optional[Any]:
        """Find job by unique job_id."""
        return await self.find_one({"job_id": job_id})

    async def find_by_plugin_id(self, plugin_id: str, limit: int = 20) -> List[Any]:
        """Find jobs for a plugin."""
        return await self.find_many(
            {"plugin_id": plugin_id},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_pending(self) -> List[Any]:
        """Find pending optimization jobs."""
        return await self.find_many({"status": "pending"})

    async def find_running(self) -> List[Any]:
        """Find running optimization jobs."""
        return await self.find_many({"status": "running"})

    async def find_by_status(self, status: str, limit: int = 100) -> List[Any]:
        """Find jobs by status."""
        return await self.find_many(
            {"status": status},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def update_progress(self, job_id: str, progress: float) -> Optional[Any]:
        """Update job progress."""
        return await self.update_one(
            {"job_id": job_id},
            {"$set": {"progress": progress}},
        )

    async def update_status(
        self,
        job_id: str,
        status: str,
        **kwargs: Any,
    ) -> Optional[Any]:
        """Update job status with optional fields."""
        update_data: Dict[str, Any] = {"status": status, **kwargs}

        if status == "running":
            update_data.setdefault("started_at", datetime.utcnow())
        elif status in ["completed", "failed"]:
            update_data.setdefault("completed_at", datetime.utcnow())

        return await self.update_one({"job_id": job_id}, {"$set": update_data})

    async def get_statistics(self) -> Dict[str, Any]:
        """Get job statistics."""
        total = await self.count()

        status_pipeline: List[Dict[str, Any]] = [
            {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        ]
        status_results = await self.aggregate(status_pipeline)
        status_counts = {item["_id"]: item["count"] for item in status_results}

        return {
            "total_jobs": total,
            "by_status": status_counts,
        }


class AuditEventRepository(BaseRepository):
    """
    Repository for AuditEvent operations.

    Provides audit-specific query methods:
    - Find by event_id
    - Find by plugin_id
    - Find by actor
    - Find by event type
    - Find in time range

    Example:
        repo = AuditEventRepository()
        events = await repo.find_by_plugin_id("my-plugin@1.0.0")
    """

    def __init__(self) -> None:
        """Initialize the audit event repository."""
        from ..services.plugins.governance.models import AuditEvent

        super().__init__(AuditEvent)

    async def find_by_event_id(self, event_id: str) -> Optional[Any]:
        """Find event by unique event_id."""
        return await self.find_one({"event_id": event_id})

    async def find_by_plugin_id(self, plugin_id: str, limit: int = 100) -> List[Any]:
        """Find events for a plugin."""
        return await self.find_many(
            {"plugin_id": plugin_id},
            limit=limit,
            sort=[("timestamp", -1)],
        )

    async def find_by_actor(self, actor: str, limit: int = 100) -> List[Any]:
        """Find events by actor."""
        return await self.find_many(
            {"actor": actor},
            limit=limit,
            sort=[("timestamp", -1)],
        )

    async def find_by_event_type(self, event_type: str, limit: int = 100) -> List[Any]:
        """Find events by type."""
        return await self.find_many(
            {"event_type": event_type},
            limit=limit,
            sort=[("timestamp", -1)],
        )

    async def find_recent(self, hours: int = 24, limit: int = 100) -> List[Any]:
        """Find recent events within specified hours."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return await self.find_many(
            {"timestamp": {"$gte": cutoff}},
            limit=limit,
            sort=[("timestamp", -1)],
        )

    async def find_by_correlation_id(self, correlation_id: str) -> List[Any]:
        """Find related events by correlation ID."""
        return await self.find_many(
            {"correlation_id": correlation_id},
            sort=[("timestamp", 1)],
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """Get audit event statistics."""
        total = await self.count()

        type_pipeline: List[Dict[str, Any]] = [
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        type_results = await self.aggregate(type_pipeline)
        type_counts = {item["_id"]: item["count"] for item in type_results}

        outcome_pipeline: List[Dict[str, Any]] = [
            {"$group": {"_id": "$outcome", "count": {"$sum": 1}}},
        ]
        outcome_results = await self.aggregate(outcome_pipeline)
        outcome_counts = {item["_id"]: item["count"] for item in outcome_results}

        return {
            "total_events": total,
            "by_event_type": type_counts,
            "by_outcome": outcome_counts,
        }


class PluginInstallationResultRepository(BaseRepository):
    """
    Repository for PluginInstallationResult operations.

    Provides installation result-specific query methods:
    - Find by installation_id
    - Find by plugin_id
    - Find by status

    Example:
        repo = PluginInstallationResultRepository()
        results = await repo.find_by_plugin_id("my-plugin")
    """

    def __init__(self) -> None:
        """Initialize the plugin installation result repository."""
        from ..services.plugins.marketplace.models import PluginInstallationResult

        super().__init__(PluginInstallationResult)

    async def find_by_installation_id(self, installation_id: str) -> Optional[Any]:
        """Find result by unique installation_id."""
        return await self.find_one({"installation_id": installation_id})

    async def find_by_plugin_id(self, plugin_id: str, limit: int = 20) -> List[Any]:
        """Find results for a plugin."""
        return await self.find_many(
            {"plugin_id": plugin_id},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_by_status(self, status: str, limit: int = 100) -> List[Any]:
        """Find results by status."""
        return await self.find_many(
            {"status": status},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_in_progress(self) -> List[Any]:
        """Find in-progress installations."""
        return await self.find_many({"status": "in_progress"})

    async def find_recent(self, hours: int = 24, limit: int = 100) -> List[Any]:
        """Find recent installation results."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return await self.find_many(
            {"started_at": {"$gte": cutoff}},
            limit=limit,
            sort=[("started_at", -1)],
        )


class TestSuiteRepository(BaseRepository):
    """
    Repository for TestSuite operations.

    Provides test suite-specific query methods:
    - Find by suite_id
    - Find by plugin_id
    - Find active suites

    Example:
        repo = TestSuiteRepository()
        suites = await repo.find_by_plugin_id("my-plugin@1.0.0")
    """

    def __init__(self) -> None:
        """Initialize the test suite repository."""
        from ..services.plugins.development.models import TestSuite

        super().__init__(TestSuite)

    async def find_by_suite_id(self, suite_id: str) -> Optional[Any]:
        """Find suite by unique suite_id."""
        return await self.find_one({"suite_id": suite_id})

    async def find_by_plugin_id(self, plugin_id: str) -> List[Any]:
        """Find test suites for a plugin."""
        return await self.find_many(
            {"plugin_id": plugin_id},
            sort=[("created_at", -1)],
        )

    async def find_active(self) -> List[Any]:
        """Find active test suites."""
        return await self.find_many({"is_active": True})


class TestExecutionRepository(BaseRepository):
    """
    Repository for TestExecution operations.

    Provides test execution-specific query methods:
    - Find by execution_id
    - Find by suite_id
    - Find by status
    - Find recent executions

    Example:
        repo = TestExecutionRepository()
        executions = await repo.find_by_suite_id("suite-123")
    """

    def __init__(self) -> None:
        """Initialize the test execution repository."""
        from ..services.plugins.development.models import TestExecution

        super().__init__(TestExecution)

    async def find_by_execution_id(self, execution_id: str) -> Optional[Any]:
        """Find execution by unique execution_id."""
        return await self.find_one({"execution_id": execution_id})

    async def find_by_suite_id(self, suite_id: str, limit: int = 50) -> List[Any]:
        """Find executions for a suite."""
        return await self.find_many(
            {"suite_id": suite_id},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_by_status(self, status: str, limit: int = 100) -> List[Any]:
        """Find executions by status."""
        return await self.find_many(
            {"status": status},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def find_running(self) -> List[Any]:
        """Find running test executions."""
        return await self.find_many({"status": "running"})

    async def find_recent(self, hours: int = 24, limit: int = 100) -> List[Any]:
        """Find recent test executions."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return await self.find_many(
            {"started_at": {"$gte": cutoff}},
            limit=limit,
            sort=[("started_at", -1)],
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """Get test execution statistics."""
        total = await self.count()

        status_pipeline: List[Dict[str, Any]] = [
            {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        ]
        status_results = await self.aggregate(status_pipeline)
        status_counts = {item["_id"]: item["count"] for item in status_results}

        return {
            "total_executions": total,
            "by_status": status_counts,
        }


class RulePluginMappingRepository(BaseRepository):
    """
    Repository for RulePluginMapping operations.

    Provides rule-plugin mapping-specific query methods:
    - Find by mapping_id
    - Find by rule_id
    - Find by plugin_id
    - Find by platform
    - Get mapping statistics

    Example:
        repo = RulePluginMappingRepository()
        mappings = await repo.find_by_rule_id("xccdf_rule_123")
    """

    def __init__(self) -> None:
        """Initialize the rule plugin mapping repository."""
        from ..services.rules.association import RulePluginMapping

        super().__init__(RulePluginMapping)

    async def find_by_mapping_id(self, mapping_id: str) -> Optional[Any]:
        """Find mapping by unique mapping_id."""
        return await self.find_one({"mapping_id": mapping_id})

    async def find_by_rule_id(
        self,
        rule_id: str,
        platform: Optional[str] = None,
        framework: Optional[str] = None,
        min_confidence_score: float = 0.0,
        limit: int = 100,
    ) -> List[Any]:
        """Find mappings for a rule with optional filters."""
        query: Dict[str, Any] = {"openwatch_rule_id": rule_id}

        if platform:
            query["platform"] = platform
        if framework:
            query["framework"] = framework
        if min_confidence_score > 0:
            query["confidence_score"] = {"$gte": min_confidence_score}

        return await self.find_many(
            query,
            limit=limit,
            sort=[("confidence_score", -1)],
        )

    async def find_by_plugin_id(
        self,
        plugin_id: str,
        platform: Optional[str] = None,
        min_confidence_score: float = 0.0,
        limit: int = 100,
    ) -> List[Any]:
        """Find mappings for a plugin."""
        query: Dict[str, Any] = {"plugin_id": plugin_id}

        if platform:
            query["platform"] = platform
        if min_confidence_score > 0:
            query["confidence_score"] = {"$gte": min_confidence_score}

        return await self.find_many(
            query,
            limit=limit,
            sort=[("confidence_score", -1)],
        )

    async def find_validated(self, limit: int = 100) -> List[Any]:
        """Find validated mappings."""
        return await self.find_many(
            {"is_validated": True},
            limit=limit,
            sort=[("effectiveness_score", -1)],
        )

    async def find_top_performing(self, min_executions: int = 1, limit: int = 10) -> List[Any]:
        """Find top performing mappings by effectiveness."""
        return await self.find_many(
            {"execution_count": {"$gte": min_executions}},
            limit=limit,
            sort=[("effectiveness_score", -1)],
        )

    async def find_by_confidence(self, confidence: str, limit: int = 100) -> List[Any]:
        """Find mappings by confidence level."""
        return await self.find_many(
            {"confidence": confidence},
            limit=limit,
            sort=[("confidence_score", -1)],
        )

    async def find_by_source(self, source: str, limit: int = 100) -> List[Any]:
        """Find mappings by mapping source."""
        return await self.find_many(
            {"mapping_source": source},
            limit=limit,
            sort=[("created_at", -1)],
        )

    async def find_for_rule_plugin_platform(
        self,
        rule_id: str,
        plugin_id: str,
        platform: str,
    ) -> List[Any]:
        """Find mappings for specific rule-plugin-platform combination."""
        return await self.find_many(
            {
                "openwatch_rule_id": rule_id,
                "plugin_id": plugin_id,
                "platform": platform,
            }
        )

    async def get_statistics(self) -> Dict[str, Any]:
        """Get mapping statistics."""
        total = await self.count()

        # By confidence
        confidence_pipeline: List[Dict[str, Any]] = [
            {"$group": {"_id": "$confidence", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        confidence_results = await self.aggregate(confidence_pipeline)
        confidence_counts = {item["_id"]: item["count"] for item in confidence_results}

        # By source
        source_pipeline: List[Dict[str, Any]] = [
            {"$group": {"_id": "$mapping_source", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        source_results = await self.aggregate(source_pipeline)
        source_counts = {item["_id"]: item["count"] for item in source_results}

        # Validated count
        validated_count = await self.count({"is_validated": True})

        return {
            "total_mappings": total,
            "by_confidence": confidence_counts,
            "by_source": source_counts,
            "validated_count": validated_count,
        }
