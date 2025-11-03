"""
Bulk Remediation Service
Handles bulk remediation execution across multiple hosts with parallel processing,
batching, and comprehensive tracking.
"""

import asyncio
import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from beanie import Document
from pydantic import BaseModel, Field

from ..database import Host
from ..models.plugin_models import InstalledPlugin, PluginExecutionRequest, PluginExecutionResult, PluginStatus
from .plugin_execution_service import PluginExecutionService
from .plugin_registry_service import PluginRegistryService

logger = logging.getLogger(__name__)


class BulkExecutionStrategy(str, Enum):
    """Bulk execution strategies"""

    PARALLEL = "parallel"  # Execute all hosts simultaneously
    SEQUENTIAL = "sequential"  # Execute hosts one by one
    BATCHED = "batched"  # Execute in batches
    ROLLING = "rolling"  # Rolling deployment style
    STAGED = "staged"  # Execute by priority/stage


class BulkExecutionStatus(str, Enum):
    """Bulk execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIAL_SUCCESS = "partial_success"


class HostExecutionResult(BaseModel):
    """Result for individual host in bulk execution"""

    host_id: str
    platform: str
    status: str = Field(..., description="success, failed, timeout, cancelled")

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Results
    rules_executed: int = 0
    rules_successful: int = 0
    rules_failed: int = 0

    # Plugin results
    plugin_results: List[PluginExecutionResult] = Field(default_factory=list)

    # Error info
    error_message: Optional[str] = None
    last_error: Optional[str] = None

    # System impact
    changes_made: bool = False
    requires_reboot: bool = False


class BulkRemediationRequest(BaseModel):
    """Request for bulk remediation across multiple hosts"""

    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # Target specification
    host_ids: List[str] = Field(..., min_items=1, max_items=1000)
    rule_ids: List[str] = Field(..., min_items=1)

    # Execution configuration
    strategy: BulkExecutionStrategy = BulkExecutionStrategy.BATCHED
    batch_size: int = Field(default=10, ge=1, le=100)
    max_parallel: int = Field(default=20, ge=1, le=100)

    # Execution options
    dry_run: bool = Field(default=False)
    timeout_per_host: int = Field(default=1800, ge=60, le=7200)
    continue_on_failure: bool = Field(default=True)

    # Failure handling
    max_failure_rate: float = Field(default=0.2, ge=0.0, le=1.0)  # Stop if >20% fail
    rollback_on_high_failure: bool = Field(default=False)

    # Scheduling (optional)
    scheduled_at: Optional[datetime] = None
    maintenance_window: Optional[Dict[str, Any]] = None

    # Context
    execution_context: Dict[str, Any] = Field(default_factory=dict)
    user: str = Field(..., description="User requesting bulk remediation")


class BulkRemediationResult(Document):
    """Complete bulk remediation execution result"""

    job_id: str = Field(..., unique=True)

    # Request info
    request: BulkRemediationRequest

    # Execution status
    status: BulkExecutionStatus = BulkExecutionStatus.PENDING

    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Progress tracking
    total_hosts: int = 0
    completed_hosts: int = 0
    successful_hosts: int = 0
    failed_hosts: int = 0
    cancelled_hosts: int = 0

    # Detailed results
    host_results: List[HostExecutionResult] = Field(default_factory=list)

    # Summary statistics
    total_rules_executed: int = 0
    total_rules_successful: int = 0
    total_rules_failed: int = 0

    # System impact
    hosts_with_changes: int = 0
    hosts_requiring_reboot: int = 0

    # Error tracking
    execution_errors: List[str] = Field(default_factory=list)
    stopped_reason: Optional[str] = None

    class Settings:
        collection = "bulk_remediation_results"
        indexes = ["job_id", "status", "created_at", "request.user"]


@dataclass
class ExecutionBatch:
    """Represents a batch of hosts for execution"""

    batch_id: int
    host_ids: List[str]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"


class BulkRemediationService:
    """
    Service for executing remediation across multiple hosts

    Supports various execution strategies, failure handling, and comprehensive
    progress tracking for large-scale remediation operations.
    """

    def __init__(self):
        self.plugin_execution_service = PluginExecutionService()
        self.plugin_registry_service = PluginRegistryService()
        self.active_jobs: Dict[str, BulkRemediationResult] = {}
        self.executor = ThreadPoolExecutor(max_workers=50)

    async def submit_bulk_remediation(self, request: BulkRemediationRequest) -> BulkRemediationResult:
        """
        Submit bulk remediation job

        Args:
            request: Bulk remediation request

        Returns:
            Bulk remediation result (initially in pending state)
        """
        try:
            # Validate request
            await self._validate_bulk_request(request)

            # Create result document
            result = BulkRemediationResult(
                job_id=request.job_id,
                request=request,
                total_hosts=len(request.host_ids),
                host_results=[],
            )

            # Save initial state
            await result.save()
            self.active_jobs[request.job_id] = result

            # Start execution asynchronously
            if request.scheduled_at:
                # Schedule for later execution
                await self._schedule_execution(request, result)
            else:
                # Execute immediately
                asyncio.create_task(self._execute_bulk_remediation(request, result))

            logger.info(
                f"Bulk remediation job submitted: {request.job_id} ({request.strategy.value}, {len(request.host_ids)} hosts)"
            )

            return result

        except Exception as e:
            logger.error(f"Failed to submit bulk remediation: {e}")
            raise

    async def get_bulk_job_status(self, job_id: str) -> Optional[BulkRemediationResult]:
        """Get current status of bulk remediation job"""
        # Check active jobs first
        if job_id in self.active_jobs:
            return self.active_jobs[job_id]

        # Query database
        return await BulkRemediationResult.find_one(BulkRemediationResult.job_id == job_id)

    async def cancel_bulk_job(self, job_id: str, reason: str = "User cancelled") -> bool:
        """Cancel running bulk remediation job"""
        try:
            result = await self.get_bulk_job_status(job_id)
            if not result:
                return False

            if result.status in [
                BulkExecutionStatus.COMPLETED,
                BulkExecutionStatus.FAILED,
                BulkExecutionStatus.CANCELLED,
            ]:
                return False  # Already finished

            # Mark as cancelled
            result.status = BulkExecutionStatus.CANCELLED
            result.stopped_reason = reason
            result.completed_at = datetime.utcnow()

            if result.started_at:
                result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

            await result.save()

            # Remove from active jobs
            self.active_jobs.pop(job_id, None)

            logger.info(f"Cancelled bulk remediation job: {job_id} - {reason}")
            return True

        except Exception as e:
            logger.error(f"Failed to cancel bulk job {job_id}: {e}")
            return False

    async def list_bulk_jobs(
        self,
        user: Optional[str] = None,
        status: Optional[BulkExecutionStatus] = None,
        limit: int = 50,
    ) -> List[BulkRemediationResult]:
        """List bulk remediation jobs with filtering"""
        query = {}

        if user:
            query["request.user"] = user

        if status:
            query["status"] = status

        return await BulkRemediationResult.find(query).sort(-BulkRemediationResult.created_at).limit(limit).to_list()

    async def _validate_bulk_request(self, request: BulkRemediationRequest):
        """Validate bulk remediation request"""
        # Check host existence and get platforms
        host_platforms = {}
        for host_id in request.host_ids:
            host = await Host.find_one(Host.id == host_id)
            if not host:
                raise ValueError(f"Host not found: {host_id}")
            host_platforms[host_id] = host.platform

        # Validate rules exist and are applicable
        for rule_id in request.rule_ids:
            # Check if any plugins can handle this rule
            plugins = await self.plugin_registry_service.find_plugins({"status": PluginStatus.ACTIVE})

            rule_supported = False
            for plugin in plugins:
                # Simple check - in production would be more sophisticated
                if any(rule_id in plugin.applied_to_rules for plugin in plugins):
                    rule_supported = True
                    break

            if not rule_supported:
                logger.warning(f"Rule {rule_id} may not have available remediation plugins")

        # Validate batch configuration
        if request.batch_size > len(request.host_ids):
            request.batch_size = len(request.host_ids)

        if request.max_parallel > len(request.host_ids):
            request.max_parallel = len(request.host_ids)

    async def _execute_bulk_remediation(self, request: BulkRemediationRequest, result: BulkRemediationResult):
        """Execute bulk remediation based on strategy"""
        try:
            # Mark as started
            result.status = BulkExecutionStatus.RUNNING
            result.started_at = datetime.utcnow()
            await result.save()

            logger.info(f"Starting bulk remediation execution: {request.job_id}")

            # Execute based on strategy
            if request.strategy == BulkExecutionStrategy.PARALLEL:
                await self._execute_parallel(request, result)
            elif request.strategy == BulkExecutionStrategy.SEQUENTIAL:
                await self._execute_sequential(request, result)
            elif request.strategy == BulkExecutionStrategy.BATCHED:
                await self._execute_batched(request, result)
            elif request.strategy == BulkExecutionStrategy.ROLLING:
                await self._execute_rolling(request, result)
            elif request.strategy == BulkExecutionStrategy.STAGED:
                await self._execute_staged(request, result)

            # Finalize results
            await self._finalize_bulk_execution(request, result)

        except Exception as e:
            logger.error(f"Bulk remediation execution failed: {e}")
            result.status = BulkExecutionStatus.FAILED
            result.execution_errors.append(str(e))
            result.completed_at = datetime.utcnow()

            if result.started_at:
                result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

            await result.save()

        finally:
            # Remove from active jobs
            self.active_jobs.pop(request.job_id, None)

    async def _execute_parallel(self, request: BulkRemediationRequest, result: BulkRemediationResult):
        """Execute all hosts in parallel with concurrency control"""
        semaphore = asyncio.Semaphore(request.max_parallel)

        async def execute_host(host_id: str) -> HostExecutionResult:
            async with semaphore:
                return await self._execute_host_remediation(host_id, request, result)

        # Execute all hosts concurrently
        tasks = [execute_host(host_id) for host_id in request.host_ids]
        host_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for i, host_result in enumerate(host_results):
            if isinstance(host_result, Exception):
                # Create error result
                result.host_results.append(
                    HostExecutionResult(
                        host_id=request.host_ids[i],
                        platform="unknown",
                        status="failed",
                        error_message=str(host_result),
                    )
                )
            else:
                result.host_results.append(host_result)

    async def _execute_sequential(self, request: BulkRemediationRequest, result: BulkRemediationResult):
        """Execute hosts one by one"""
        for host_id in request.host_ids:
            if result.status == BulkExecutionStatus.CANCELLED:
                break

            host_result = await self._execute_host_remediation(host_id, request, result)
            result.host_results.append(host_result)

            # Update progress
            await self._update_progress(result)

            # Check failure rate
            if await self._should_stop_on_failure(request, result):
                break

    async def _execute_batched(self, request: BulkRemediationRequest, result: BulkRemediationResult):
        """Execute hosts in batches"""
        # Create batches
        batches = []
        for i in range(0, len(request.host_ids), request.batch_size):
            batch_hosts = request.host_ids[i : i + request.batch_size]
            batches.append(ExecutionBatch(batch_id=len(batches), host_ids=batch_hosts))

        # Execute each batch
        for batch in batches:
            if result.status == BulkExecutionStatus.CANCELLED:
                break

            logger.info(f"Executing batch {batch.batch_id + 1}/{len(batches)} with {len(batch.host_ids)} hosts")

            batch.started_at = datetime.utcnow()
            batch.status = "running"

            # Execute batch in parallel
            semaphore = asyncio.Semaphore(min(request.max_parallel, len(batch.host_ids)))

            async def execute_host(host_id: str) -> HostExecutionResult:
                async with semaphore:
                    return await self._execute_host_remediation(host_id, request, result)

            tasks = [execute_host(host_id) for host_id in batch.host_ids]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process batch results
            for i, host_result in enumerate(batch_results):
                if isinstance(host_result, Exception):
                    result.host_results.append(
                        HostExecutionResult(
                            host_id=batch.host_ids[i],
                            platform="unknown",
                            status="failed",
                            error_message=str(host_result),
                        )
                    )
                else:
                    result.host_results.append(host_result)

            batch.completed_at = datetime.utcnow()
            batch.status = "completed"

            # Update progress
            await self._update_progress(result)

            # Check failure rate
            if await self._should_stop_on_failure(request, result):
                result.stopped_reason = "High failure rate detected"
                break

            # Brief pause between batches
            if batch.batch_id < len(batches) - 1:
                await asyncio.sleep(2)

    async def _execute_rolling(self, request: BulkRemediationRequest, result: BulkRemediationResult):
        """Execute hosts in rolling deployment style"""
        # Start with small batch, increase on success
        current_batch_size = min(2, len(request.host_ids))
        processed = 0

        while processed < len(request.host_ids) and result.status != BulkExecutionStatus.CANCELLED:
            # Get next batch
            batch_hosts = request.host_ids[processed : processed + current_batch_size]

            logger.info(
                f"Rolling execution: batch size {current_batch_size}, hosts {processed + 1}-{processed + len(batch_hosts)}"
            )

            # Execute batch
            semaphore = asyncio.Semaphore(current_batch_size)

            async def execute_host(host_id: str) -> HostExecutionResult:
                async with semaphore:
                    return await self._execute_host_remediation(host_id, request, result)

            tasks = [execute_host(host_id) for host_id in batch_hosts]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            batch_success_rate = 0
            for i, host_result in enumerate(batch_results):
                if isinstance(host_result, Exception):
                    result.host_results.append(
                        HostExecutionResult(
                            host_id=batch_hosts[i],
                            platform="unknown",
                            status="failed",
                            error_message=str(host_result),
                        )
                    )
                else:
                    result.host_results.append(host_result)
                    if host_result.status == "success":
                        batch_success_rate += 1

            batch_success_rate = batch_success_rate / len(batch_hosts)

            # Adjust batch size based on success rate
            if batch_success_rate >= 0.9:
                # High success rate - can increase batch size
                current_batch_size = min(current_batch_size * 2, request.batch_size)
            elif batch_success_rate < 0.7:
                # Low success rate - decrease batch size
                current_batch_size = max(1, current_batch_size // 2)

            processed += len(batch_hosts)

            # Update progress
            await self._update_progress(result)

            # Check if should stop
            if await self._should_stop_on_failure(request, result):
                break

    async def _execute_staged(self, request: BulkRemediationRequest, result: BulkRemediationResult):
        """Execute hosts by priority/stage"""
        # Group hosts by priority (simplified - would use host metadata)
        stages = {"high_priority": [], "medium_priority": [], "low_priority": []}

        # Simple staging based on host naming or would use actual host metadata
        for host_id in request.host_ids:
            if "prod" in host_id or "critical" in host_id:
                stages["high_priority"].append(host_id)
            elif "staging" in host_id or "test" in host_id:
                stages["low_priority"].append(host_id)
            else:
                stages["medium_priority"].append(host_id)

        # Execute each stage
        for stage_name, host_ids in stages.items():
            if not host_ids or result.status == BulkExecutionStatus.CANCELLED:
                continue

            logger.info(f"Executing stage '{stage_name}' with {len(host_ids)} hosts")

            # Execute stage hosts with limited parallelism
            stage_parallel = min(5, len(host_ids))  # Conservative for staged approach
            semaphore = asyncio.Semaphore(stage_parallel)

            async def execute_host(host_id: str) -> HostExecutionResult:
                async with semaphore:
                    return await self._execute_host_remediation(host_id, request, result)

            tasks = [execute_host(host_id) for host_id in host_ids]
            stage_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process stage results
            for i, host_result in enumerate(stage_results):
                if isinstance(host_result, Exception):
                    result.host_results.append(
                        HostExecutionResult(
                            host_id=host_ids[i],
                            platform="unknown",
                            status="failed",
                            error_message=str(host_result),
                        )
                    )
                else:
                    result.host_results.append(host_result)

            # Update progress
            await self._update_progress(result)

            # For staged execution, be more conservative about failures
            current_failure_rate = result.failed_hosts / max(result.completed_hosts, 1)
            if current_failure_rate > 0.1:  # Stop at 10% failure for staged
                result.stopped_reason = f"High failure rate in {stage_name} stage"
                break

            # Pause between stages
            if stage_name != "low_priority":
                await asyncio.sleep(5)

    async def _execute_host_remediation(
        self,
        host_id: str,
        request: BulkRemediationRequest,
        bulk_result: BulkRemediationResult,
    ) -> HostExecutionResult:
        """Execute remediation for a single host"""
        started_at = datetime.utcnow()

        try:
            # Get host information
            host = await Host.find_one(Host.id == host_id)
            if not host:
                return HostExecutionResult(
                    host_id=host_id,
                    platform="unknown",
                    status="failed",
                    error_message="Host not found",
                    started_at=started_at,
                    completed_at=datetime.utcnow(),
                )

            # Find available plugins for rules
            plugin_results = []
            rules_successful = 0
            rules_failed = 0
            changes_made = False
            requires_reboot = False

            for rule_id in request.rule_ids:
                try:
                    # Find plugins that can remediate this rule
                    plugins = await self._find_plugins_for_rule(rule_id, host.platform)

                    if not plugins:
                        logger.warning(f"No plugins found for rule {rule_id} on platform {host.platform}")
                        rules_failed += 1
                        continue

                    # Use first available plugin (could be smarter selection)
                    plugin = plugins[0]

                    # Create execution request
                    execution_request = PluginExecutionRequest(
                        plugin_id=plugin.plugin_id,
                        rule_id=rule_id,
                        host_id=host_id,
                        platform=host.platform,
                        dry_run=request.dry_run,
                        timeout_override=request.timeout_per_host,
                        execution_context={
                            **request.execution_context,
                            "bulk_job_id": request.job_id,
                            "bulk_strategy": request.strategy.value,
                        },
                        user=request.user,
                    )

                    # Execute plugin
                    result = await self.plugin_execution_service.execute_plugin(execution_request)
                    plugin_results.append(result)

                    if result.status == "success":
                        rules_successful += 1
                        if result.changes_made:
                            changes_made = True
                    else:
                        rules_failed += 1

                    # Check for reboot requirement
                    if hasattr(result, "rollback_data") and result.rollback_data:
                        if result.rollback_data.get("requires_reboot"):
                            requires_reboot = True

                except Exception as e:
                    logger.error(f"Failed to execute rule {rule_id} on host {host_id}: {e}")
                    rules_failed += 1

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            # Determine overall host status
            if rules_failed == 0:
                status = "success"
            elif rules_successful == 0:
                status = "failed"
            else:
                status = "partial_success"

            return HostExecutionResult(
                host_id=host_id,
                platform=host.platform,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                rules_executed=len(request.rule_ids),
                rules_successful=rules_successful,
                rules_failed=rules_failed,
                plugin_results=plugin_results,
                changes_made=changes_made,
                requires_reboot=requires_reboot,
            )

        except Exception as e:
            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            logger.error(f"Host remediation failed for {host_id}: {e}")

            return HostExecutionResult(
                host_id=host_id,
                platform="unknown",
                status="failed",
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                error_message=str(e),
            )

    async def _find_plugins_for_rule(self, rule_id: str, platform: str) -> List[InstalledPlugin]:
        """Find plugins that can remediate a specific rule on a platform"""
        plugins = await self.plugin_registry_service.find_plugins({"status": PluginStatus.ACTIVE, "platform": platform})

        # Simple matching - in production would be more sophisticated
        matching_plugins = []
        for plugin in plugins:
            if rule_id in plugin.applied_to_rules or platform in plugin.enabled_platforms:
                matching_plugins.append(plugin)

        return matching_plugins

    async def _update_progress(self, result: BulkRemediationResult):
        """Update execution progress and statistics"""
        result.completed_hosts = len(result.host_results)
        result.successful_hosts = len([r for r in result.host_results if r.status == "success"])
        result.failed_hosts = len([r for r in result.host_results if r.status == "failed"])

        # Calculate totals
        result.total_rules_executed = sum(r.rules_executed for r in result.host_results)
        result.total_rules_successful = sum(r.rules_successful for r in result.host_results)
        result.total_rules_failed = sum(r.rules_failed for r in result.host_results)

        # System impact
        result.hosts_with_changes = len([r for r in result.host_results if r.changes_made])
        result.hosts_requiring_reboot = len([r for r in result.host_results if r.requires_reboot])

        await result.save()

    async def _should_stop_on_failure(self, request: BulkRemediationRequest, result: BulkRemediationResult) -> bool:
        """Check if execution should stop due to high failure rate"""
        if not request.continue_on_failure:
            return result.failed_hosts > 0

        if result.completed_hosts == 0:
            return False

        failure_rate = result.failed_hosts / result.completed_hosts
        return failure_rate > request.max_failure_rate

    async def _finalize_bulk_execution(self, request: BulkRemediationRequest, result: BulkRemediationResult):
        """Finalize bulk execution results"""
        result.completed_at = datetime.utcnow()

        if result.started_at:
            result.duration_seconds = (result.completed_at - result.started_at).total_seconds()

        # Determine final status
        if result.status == BulkExecutionStatus.CANCELLED:
            # Already set
            pass
        elif result.failed_hosts == 0:
            result.status = BulkExecutionStatus.COMPLETED
        elif result.successful_hosts == 0:
            result.status = BulkExecutionStatus.FAILED
        else:
            result.status = BulkExecutionStatus.PARTIAL_SUCCESS

        await result.save()

        logger.info(
            f"Bulk remediation completed: {request.job_id} - "
            f"Status: {result.status.value}, "
            f"Hosts: {result.successful_hosts}/{result.total_hosts} successful, "
            f"Duration: {result.duration_seconds:.1f}s"
        )

    async def _schedule_execution(self, request: BulkRemediationRequest, result: BulkRemediationResult):
        """Schedule bulk execution for later (placeholder implementation)"""
        # In production, would integrate with a job scheduler like Celery
        # For now, just log the scheduled time
        logger.info(f"Bulk remediation scheduled for {request.scheduled_at}: {request.job_id}")

        # Could use asyncio to delay execution
        if request.scheduled_at:
            delay = (request.scheduled_at - datetime.utcnow()).total_seconds()
            if delay > 0:
                await asyncio.sleep(delay)
                await self._execute_bulk_remediation(request, result)
