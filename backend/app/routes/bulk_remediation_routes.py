"""
Bulk Remediation API Routes
Provides endpoints for executing remediation across multiple hosts with various strategies.
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, ValidationError

from ..auth import get_current_user
from ..database import User
from ..services.bulk_remediation_service import (
    BulkExecutionStatus,
    BulkExecutionStrategy,
    BulkRemediationRequest,
    BulkRemediationService,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bulk-remediation", tags=["bulk-remediation"])

# Service instance
bulk_remediation_service = BulkRemediationService()


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================


class BulkRemediationJobRequest(BaseModel):
    """Request to submit bulk remediation job"""

    host_ids: List[str] = Field(..., min_items=1, max_items=1000, description="Target host IDs")
    rule_ids: List[str] = Field(..., min_items=1, description="Rules to remediate")
    strategy: BulkExecutionStrategy = Field(
        default=BulkExecutionStrategy.BATCHED, description="Execution strategy"
    )
    batch_size: int = Field(
        default=10, ge=1, le=100, description="Batch size for batched execution"
    )
    max_parallel: int = Field(default=20, ge=1, le=100, description="Maximum parallel executions")
    dry_run: bool = Field(default=False, description="Execute in dry-run mode")
    timeout_per_host: int = Field(
        default=1800, ge=60, le=7200, description="Timeout per host in seconds"
    )
    continue_on_failure: bool = Field(
        default=True, description="Continue execution when individual hosts fail"
    )
    max_failure_rate: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description="Stop if failure rate exceeds this threshold",
    )
    rollback_on_high_failure: bool = Field(
        default=False, description="Rollback changes if failure rate is high"
    )
    scheduled_at: Optional[datetime] = Field(
        default=None, description="Schedule execution for later"
    )
    execution_context: dict = Field(
        default_factory=dict, description="Additional execution context"
    )


class BulkRemediationJobResponse(BaseModel):
    """Response for bulk remediation job submission"""

    job_id: str
    status: BulkExecutionStatus
    total_hosts: int
    strategy: BulkExecutionStrategy
    created_at: datetime
    scheduled_at: Optional[datetime] = None
    estimated_duration_minutes: Optional[int] = None


class BulkRemediationStatusResponse(BaseModel):
    """Response for bulk remediation status check"""

    job_id: str
    status: BulkExecutionStatus
    total_hosts: int
    completed_hosts: int
    successful_hosts: int
    failed_hosts: int
    cancelled_hosts: int
    progress_percentage: float
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    execution_errors: List[str] = Field(default_factory=list)
    stopped_reason: Optional[str] = None

    # Summary statistics
    total_rules_executed: int = 0
    total_rules_successful: int = 0
    total_rules_failed: int = 0
    hosts_with_changes: int = 0
    hosts_requiring_reboot: int = 0


class BulkRemediationListResponse(BaseModel):
    """Response for listing bulk remediation jobs"""

    jobs: List[BulkRemediationStatusResponse]
    total_count: int
    page: int
    page_size: int


class HostExecutionSummary(BaseModel):
    """Summary of host execution for detailed results"""

    host_id: str
    platform: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    rules_executed: int = 0
    rules_successful: int = 0
    rules_failed: int = 0
    changes_made: bool = False
    requires_reboot: bool = False
    error_message: Optional[str] = None


class DetailedBulkRemediationResponse(BaseModel):
    """Detailed response including host-level results"""

    job_id: str
    status: BulkExecutionStatus
    request: BulkRemediationJobRequest

    # Timing and progress
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Progress tracking
    total_hosts: int
    completed_hosts: int
    successful_hosts: int
    failed_hosts: int
    cancelled_hosts: int

    # Host results
    host_results: List[HostExecutionSummary] = Field(default_factory=list)

    # Summary statistics
    total_rules_executed: int = 0
    total_rules_successful: int = 0
    total_rules_failed: int = 0
    hosts_with_changes: int = 0
    hosts_requiring_reboot: int = 0

    # Error tracking
    execution_errors: List[str] = Field(default_factory=list)
    stopped_reason: Optional[str] = None


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post(
    "/submit",
    response_model=BulkRemediationJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_bulk_remediation_job(
    request: BulkRemediationJobRequest, current_user: User = Depends(get_current_user)
):
    """
    Submit a bulk remediation job for execution across multiple hosts.

    The job will be executed according to the specified strategy:
    - **parallel**: Execute all hosts simultaneously (limited by max_parallel)
    - **sequential**: Execute hosts one by one
    - **batched**: Execute hosts in batches of specified size
    - **rolling**: Start with small batches, increase size on success
    - **staged**: Execute by priority/stage (prod, staging, dev)

    Returns job details that can be used to monitor execution progress.
    """
    try:
        # Convert to internal request model
        bulk_request = BulkRemediationRequest(
            host_ids=request.host_ids,
            rule_ids=request.rule_ids,
            strategy=request.strategy,
            batch_size=request.batch_size,
            max_parallel=request.max_parallel,
            dry_run=request.dry_run,
            timeout_per_host=request.timeout_per_host,
            continue_on_failure=request.continue_on_failure,
            max_failure_rate=request.max_failure_rate,
            rollback_on_high_failure=request.rollback_on_high_failure,
            scheduled_at=request.scheduled_at,
            execution_context=request.execution_context,
            user=current_user.username,
        )

        # Submit job
        result = await bulk_remediation_service.submit_bulk_remediation(bulk_request)

        # Calculate estimated duration
        estimated_duration = None
        if not request.scheduled_at:
            # Simple estimation based on strategy and host count
            base_time_per_host = 30  # seconds
            if request.strategy == BulkExecutionStrategy.PARALLEL:
                estimated_duration = max(1, base_time_per_host // request.max_parallel) * len(
                    request.host_ids
                )
            elif request.strategy == BulkExecutionStrategy.SEQUENTIAL:
                estimated_duration = base_time_per_host * len(request.host_ids)
            elif request.strategy == BulkExecutionStrategy.BATCHED:
                batches = (len(request.host_ids) + request.batch_size - 1) // request.batch_size
                estimated_duration = base_time_per_host * batches
            else:
                estimated_duration = base_time_per_host * len(request.host_ids) // 2

            estimated_duration = estimated_duration // 60  # Convert to minutes

        return BulkRemediationJobResponse(
            job_id=result.job_id,
            status=result.status,
            total_hosts=result.total_hosts,
            strategy=request.strategy,
            created_at=result.created_at,
            scheduled_at=request.scheduled_at,
            estimated_duration_minutes=estimated_duration,
        )

    except ValidationError as e:
        logger.error(f"Validation error in bulk remediation request: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid request: {str(e)}",
        )
    except ValueError as e:
        logger.error(f"Value error in bulk remediation: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to submit bulk remediation job: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit bulk remediation job",
        )


@router.get("/jobs/{job_id}/status", response_model=BulkRemediationStatusResponse)
async def get_bulk_job_status(job_id: str, current_user: User = Depends(get_current_user)):
    """
    Get the current status of a bulk remediation job.

    Returns detailed execution progress including:
    - Overall job status and progress
    - Host-level completion counts
    - Execution timing and duration
    - Error information if applicable
    """
    try:
        result = await bulk_remediation_service.get_bulk_job_status(job_id)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Bulk remediation job not found: {job_id}",
            )

        # Calculate progress percentage
        progress_percentage = 0.0
        if result.total_hosts > 0:
            progress_percentage = (result.completed_hosts / result.total_hosts) * 100

        return BulkRemediationStatusResponse(
            job_id=result.job_id,
            status=result.status,
            total_hosts=result.total_hosts,
            completed_hosts=result.completed_hosts,
            successful_hosts=result.successful_hosts,
            failed_hosts=result.failed_hosts,
            cancelled_hosts=result.cancelled_hosts,
            progress_percentage=progress_percentage,
            started_at=result.started_at,
            completed_at=result.completed_at,
            duration_seconds=result.duration_seconds,
            execution_errors=result.execution_errors,
            stopped_reason=result.stopped_reason,
            total_rules_executed=result.total_rules_executed,
            total_rules_successful=result.total_rules_successful,
            total_rules_failed=result.total_rules_failed,
            hosts_with_changes=result.hosts_with_changes,
            hosts_requiring_reboot=result.hosts_requiring_reboot,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get bulk job status for {job_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve job status",
        )


@router.get("/jobs/{job_id}/details", response_model=DetailedBulkRemediationResponse)
async def get_detailed_bulk_job_results(
    job_id: str, current_user: User = Depends(get_current_user)
):
    """
    Get detailed results of a bulk remediation job including host-level results.

    This endpoint provides comprehensive job information including:
    - Original request parameters
    - Execution timing and progress
    - Individual host execution results
    - Detailed error information
    """
    try:
        result = await bulk_remediation_service.get_bulk_job_status(job_id)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Bulk remediation job not found: {job_id}",
            )

        # Convert host results to summary format
        host_summaries = []
        for host_result in result.host_results:
            host_summaries.append(
                HostExecutionSummary(
                    host_id=host_result.host_id,
                    platform=host_result.platform,
                    status=host_result.status,
                    started_at=host_result.started_at,
                    completed_at=host_result.completed_at,
                    duration_seconds=host_result.duration_seconds,
                    rules_executed=host_result.rules_executed,
                    rules_successful=host_result.rules_successful,
                    rules_failed=host_result.rules_failed,
                    changes_made=host_result.changes_made,
                    requires_reboot=host_result.requires_reboot,
                    error_message=host_result.error_message,
                )
            )

        # Convert request to response format
        request_response = BulkRemediationJobRequest(
            host_ids=result.request.host_ids,
            rule_ids=result.request.rule_ids,
            strategy=result.request.strategy,
            batch_size=result.request.batch_size,
            max_parallel=result.request.max_parallel,
            dry_run=result.request.dry_run,
            timeout_per_host=result.request.timeout_per_host,
            continue_on_failure=result.request.continue_on_failure,
            max_failure_rate=result.request.max_failure_rate,
            rollback_on_high_failure=result.request.rollback_on_high_failure,
            scheduled_at=result.request.scheduled_at,
            execution_context=result.request.execution_context,
        )

        return DetailedBulkRemediationResponse(
            job_id=result.job_id,
            status=result.status,
            request=request_response,
            created_at=result.created_at,
            started_at=result.started_at,
            completed_at=result.completed_at,
            duration_seconds=result.duration_seconds,
            total_hosts=result.total_hosts,
            completed_hosts=result.completed_hosts,
            successful_hosts=result.successful_hosts,
            failed_hosts=result.failed_hosts,
            cancelled_hosts=result.cancelled_hosts,
            host_results=host_summaries,
            total_rules_executed=result.total_rules_executed,
            total_rules_successful=result.total_rules_successful,
            total_rules_failed=result.total_rules_failed,
            hosts_with_changes=result.hosts_with_changes,
            hosts_requiring_reboot=result.hosts_requiring_reboot,
            execution_errors=result.execution_errors,
            stopped_reason=result.stopped_reason,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get detailed bulk job results for {job_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve detailed job results",
        )


@router.post("/jobs/{job_id}/cancel")
async def cancel_bulk_job(
    job_id: str,
    reason: str = Query(default="User cancelled", description="Reason for cancellation"),
    current_user: User = Depends(get_current_user),
):
    """
    Cancel a running bulk remediation job.

    This will attempt to gracefully stop the job execution:
    - Currently running host remediations will complete
    - Pending host executions will be cancelled
    - Job status will be marked as cancelled
    """
    try:
        success = await bulk_remediation_service.cancel_bulk_job(job_id, reason)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Bulk remediation job not found or cannot be cancelled: {job_id}",
            )

        return {"success": True, "message": f"Job {job_id} cancelled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel bulk job {job_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel job",
        )


@router.get("/jobs", response_model=BulkRemediationListResponse)
async def list_bulk_jobs(
    user: Optional[str] = Query(default=None, description="Filter by user"),
    status_filter: Optional[BulkExecutionStatus] = Query(
        default=None, alias="status", description="Filter by status"
    ),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Page size"),
    current_user: User = Depends(get_current_user),
):
    """
    List bulk remediation jobs with filtering and pagination.

    Supports filtering by:
    - User who submitted the job
    - Job execution status
    - Pagination for large result sets
    """
    try:
        # If no user specified and current user is not admin, filter to their jobs
        if not user and not current_user.is_admin:
            user = current_user.username

        # Get jobs with filtering
        jobs = await bulk_remediation_service.list_bulk_jobs(
            user=user, status=status_filter, limit=page_size * page  # Simple pagination
        )

        # Apply pagination
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_jobs = jobs[start_idx:end_idx]

        # Convert to response format
        job_responses = []
        for job in page_jobs:
            progress_percentage = 0.0
            if job.total_hosts > 0:
                progress_percentage = (job.completed_hosts / job.total_hosts) * 100

            job_responses.append(
                BulkRemediationStatusResponse(
                    job_id=job.job_id,
                    status=job.status,
                    total_hosts=job.total_hosts,
                    completed_hosts=job.completed_hosts,
                    successful_hosts=job.successful_hosts,
                    failed_hosts=job.failed_hosts,
                    cancelled_hosts=job.cancelled_hosts,
                    progress_percentage=progress_percentage,
                    started_at=job.started_at,
                    completed_at=job.completed_at,
                    duration_seconds=job.duration_seconds,
                    execution_errors=job.execution_errors,
                    stopped_reason=job.stopped_reason,
                    total_rules_executed=job.total_rules_executed,
                    total_rules_successful=job.total_rules_successful,
                    total_rules_failed=job.total_rules_failed,
                    hosts_with_changes=job.hosts_with_changes,
                    hosts_requiring_reboot=job.hosts_requiring_reboot,
                )
            )

        return BulkRemediationListResponse(
            jobs=job_responses, total_count=len(jobs), page=page, page_size=page_size
        )

    except Exception as e:
        logger.error(f"Failed to list bulk jobs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve job list",
        )


@router.get("/strategies", response_model=List[dict])
async def get_execution_strategies():
    """
    Get available bulk execution strategies with descriptions.

    Returns information about each execution strategy including:
    - Strategy name and description
    - Use cases and recommendations
    - Configuration parameters
    """
    strategies = [
        {
            "strategy": BulkExecutionStrategy.PARALLEL,
            "name": "Parallel Execution",
            "description": "Execute remediation on all hosts simultaneously",
            "use_cases": [
                "Fast execution when hosts are homogeneous",
                "Low-risk changes",
                "Development environments",
            ],
            "parameters": ["max_parallel"],
            "risk_level": "medium",
            "recommended_for": ["development", "testing"],
        },
        {
            "strategy": BulkExecutionStrategy.SEQUENTIAL,
            "name": "Sequential Execution",
            "description": "Execute remediation on hosts one by one",
            "use_cases": [
                "High-risk changes",
                "Resource-constrained environments",
                "Careful rollouts",
            ],
            "parameters": [],
            "risk_level": "low",
            "recommended_for": ["production", "critical_systems"],
        },
        {
            "strategy": BulkExecutionStrategy.BATCHED,
            "name": "Batched Execution",
            "description": "Execute remediation in configurable batches",
            "use_cases": [
                "Balanced speed and safety",
                "Most production environments",
                "Large host groups",
            ],
            "parameters": ["batch_size", "max_parallel"],
            "risk_level": "low",
            "recommended_for": ["production", "staging"],
        },
        {
            "strategy": BulkExecutionStrategy.ROLLING,
            "name": "Rolling Deployment",
            "description": "Start with small batches, increase size on success",
            "use_cases": [
                "Gradual rollouts",
                "Testing remediation effectiveness",
                "Mixed environments",
            ],
            "parameters": ["max_parallel"],
            "risk_level": "very_low",
            "recommended_for": ["production", "mixed_environments"],
        },
        {
            "strategy": BulkExecutionStrategy.STAGED,
            "name": "Staged Execution",
            "description": "Execute by priority/environment (dev → staging → prod)",
            "use_cases": [
                "Multi-environment rollouts",
                "Priority-based execution",
                "Enterprise environments",
            ],
            "parameters": [],
            "risk_level": "very_low",
            "recommended_for": ["enterprise", "multi_environment"],
        },
    ]

    return strategies


@router.get("/statistics", response_model=dict)
async def get_bulk_remediation_statistics(
    days: int = Query(default=30, ge=1, le=365, description="Days to include in statistics"),
    current_user: User = Depends(get_current_user),
):
    """
    Get bulk remediation execution statistics.

    Returns aggregate statistics for bulk remediation jobs including:
    - Success rates by strategy
    - Average execution times
    - Most common failures
    - Host and rule statistics
    """
    try:
        # In a real implementation, this would query the database for statistics
        # For now, return mock data structure

        statistics = {
            "summary": {
                "total_jobs": 145,
                "successful_jobs": 132,
                "failed_jobs": 8,
                "cancelled_jobs": 5,
                "success_rate": 0.91,
                "average_duration_minutes": 15.7,
                "total_hosts_processed": 2840,
                "total_rules_executed": 8520,
            },
            "by_strategy": {
                "parallel": {"jobs": 45, "success_rate": 0.89, "avg_duration": 8.2},
                "sequential": {"jobs": 20, "success_rate": 0.95, "avg_duration": 28.5},
                "batched": {"jobs": 65, "success_rate": 0.92, "avg_duration": 18.1},
                "rolling": {"jobs": 10, "success_rate": 0.90, "avg_duration": 22.3},
                "staged": {"jobs": 5, "success_rate": 1.0, "avg_duration": 35.7},
            },
            "common_failures": [
                {"rule_id": "ssh-hardening", "failure_count": 12, "failure_rate": 0.08},
                {
                    "rule_id": "firewall-config",
                    "failure_count": 8,
                    "failure_rate": 0.05,
                },
                {
                    "rule_id": "package-updates",
                    "failure_count": 5,
                    "failure_rate": 0.03,
                },
            ],
            "platform_distribution": {
                "rhel": 45,
                "ubuntu": 38,
                "centos": 12,
                "debian": 5,
            },
            "time_range": {
                "start_date": datetime.utcnow().replace(day=1).isoformat(),
                "end_date": datetime.utcnow().isoformat(),
                "days": days,
            },
        }

        return statistics

    except Exception as e:
        logger.error(f"Failed to get bulk remediation statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve statistics",
        )
