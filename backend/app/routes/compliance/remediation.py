"""
Remediation API Routes for Phase 4

Endpoints for managing remediation jobs with license enforcement.

Part of Phase 4: Remediation + Subscription (Kensa Integration Plan)
"""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.remediation_schemas import (
    RemediationJobCreate,
    RemediationJobDetailResponse,
    RemediationJobListResponse,
    RemediationJobResponse,
    RemediationPlanResponse,
    RemediationStepResponse,
    RemediationSummary,
    RollbackRequest,
    RollbackResponse,
)
from app.services.compliance.remediation import RemediationService
from app.services.licensing.service import LicenseRequiredError
from app.tasks.remediation_tasks import execute_remediation_job, execute_rollback_job

from ...auth import get_current_user
from ...rbac import UserRole, require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/remediation", tags=["remediation"])


@router.post(
    "",
    response_model=RemediationJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create remediation job",
    description="Create a new remediation job. Requires OpenWatch+ license.",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def create_remediation_job(
    request: RemediationJobCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Create a new remediation job for a host.

    This endpoint requires an OpenWatch+ subscription for the remediation feature.
    The job will be queued for async execution via Celery.

    Args:
        request: Remediation job configuration
        db: Database session
        current_user: Authenticated user

    Returns:
        Created job with pending status

    Raises:
        402: OpenWatch+ license required
        404: Host not found
        400: Invalid rules
    """
    service = RemediationService(db)

    try:
        job = service.create_job(request, current_user["id"])

        # Queue for async execution
        execute_remediation_job.delay(str(job.id))

        logger.info(f"User {current_user['username']} created remediation job {job.id} " f"for host {request.host_id}")

        return job

    except LicenseRequiredError as e:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "license_required",
                "feature": e.feature,
                "message": str(e),
                "upgrade_url": "/settings/license/upgrade",
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "",
    response_model=RemediationJobListResponse,
    summary="List remediation jobs",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def list_remediation_jobs(
    host_id: Optional[UUID] = Query(None, description="Filter by host"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List remediation jobs with optional filters."""
    service = RemediationService(db)
    jobs, total = service.list_jobs(
        host_id=host_id,
        status=status_filter,
        page=page,
        per_page=per_page,
    )

    total_pages = (total + per_page - 1) // per_page

    return RemediationJobListResponse(
        items=jobs,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
    )


@router.get(
    "/summary",
    response_model=RemediationSummary,
    summary="Get remediation summary",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_remediation_summary(
    host_id: Optional[UUID] = Query(None, description="Filter by host"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get remediation summary statistics."""
    service = RemediationService(db)
    return service.get_summary(host_id)


@router.post(
    "/check-rules",
    summary="Check which rules support auto-remediation",
    description="Returns remediation availability for a list of rule IDs.",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def check_rules_remediation(
    rule_ids: List[str],
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Check which rules have auto-remediation steps defined."""
    from sqlalchemy import text

    query = """
        SELECT rule_id, has_remediation
        FROM kensa_rules
        WHERE rule_id = ANY(:rule_ids)
    """
    result = db.execute(text(query), {"rule_ids": rule_ids})
    rows = result.fetchall()
    lookup = {row.rule_id: row.has_remediation for row in rows}

    return {rule_id: lookup.get(rule_id, False) for rule_id in rule_ids}


@router.post(
    "/plan",
    response_model=RemediationPlanResponse,
    summary="Get remediation plan",
    description="Preview a remediation plan with real Kensa dry-run data.",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_remediation_plan(
    request: RemediationJobCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get a remediation plan preview.

    Connects to the host via SSH and runs each rule in dry-run mode to
    generate real step-level preview data with risk classification.
    """
    service = RemediationService(db)

    try:
        return service.get_remediation_plan(request.host_id, request.rule_ids)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/{job_id}",
    response_model=RemediationJobDetailResponse,
    summary="Get remediation job details",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_remediation_job(
    job_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get detailed information about a remediation job including all results."""
    service = RemediationService(db)

    job = service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    results = service.get_job_results(job_id)

    return RemediationJobDetailResponse(job=job, results=results)


@router.get(
    "/{job_id}/results/{result_id}/steps",
    response_model=List[RemediationStepResponse],
    summary="Get step-level remediation results",
    description="Returns per-step detail for a specific rule remediation result.",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def get_remediation_steps(
    job_id: UUID,
    result_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get step-level results for a specific rule remediation.

    Each step shows the mechanism used, success/failure, pre-state data
    for rollback, verification status, and risk classification.
    """
    service = RemediationService(db)

    # Verify the job exists
    job = service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    steps = service.get_step_results(result_id)
    return steps


@router.post(
    "/{job_id}/cancel",
    response_model=RemediationJobResponse,
    summary="Cancel remediation job",
)
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def cancel_remediation_job(
    job_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Cancel a pending or running remediation job."""
    service = RemediationService(db)

    if not service.cancel_job(job_id, current_user["id"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Job cannot be cancelled (not pending/running or not found)",
        )

    job = service.get_job(job_id)
    return job


@router.post(
    "/rollback",
    response_model=RollbackResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Rollback remediation",
    description="Rollback a completed remediation job. Requires OpenWatch+ license.",
)
@require_role([UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def rollback_remediation(
    request: RollbackRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Rollback a remediation job.

    Restores the system to its pre-remediation state.
    Requires OpenWatch+ license for the rollback feature.
    """
    service = RemediationService(db)

    try:
        response = service.rollback_job(
            request.job_id,
            current_user["id"],
            request.rule_ids,
        )

        # Queue for async execution
        execute_rollback_job.delay(str(response.rollback_job_id))

        logger.info(
            f"User {current_user['username']} initiated rollback {response.rollback_job_id} "
            f"for job {request.job_id}"
        )

        return response

    except LicenseRequiredError as e:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "license_required",
                "feature": e.feature,
                "message": str(e),
                "upgrade_url": "/settings/license/upgrade",
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
