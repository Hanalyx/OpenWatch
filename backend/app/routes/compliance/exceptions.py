"""
Compliance Exception API Endpoints

Endpoints for managing structured compliance exceptions with approval workflows.

Part of Phase 3: Governance Primitives (Aegis Integration Plan)

Endpoint Structure:
    GET    /exceptions                  - List exceptions (paginated)
    GET    /exceptions/summary          - Get exception statistics
    POST   /exceptions                  - Request new exception
    GET    /exceptions/{id}             - Get exception by ID
    POST   /exceptions/{id}/approve     - Approve pending exception
    POST   /exceptions/{id}/reject      - Reject pending exception
    POST   /exceptions/{id}/revoke      - Revoke approved exception
    POST   /exceptions/check            - Check if rule is excepted for host
"""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import User, get_db
from ...schemas.exception_schemas import (
    ExceptionApproveRequest,
    ExceptionCheckRequest,
    ExceptionCheckResponse,
    ExceptionListResponse,
    ExceptionRejectRequest,
    ExceptionRequestCreate,
    ExceptionResponse,
    ExceptionRevokeRequest,
    ExceptionSummary,
)
from ...services.compliance import ExceptionService
from ...services.licensing import LicenseService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/exceptions", tags=["Compliance Exceptions"])


# =============================================================================
# API ENDPOINTS
# =============================================================================


@router.get("", response_model=ExceptionListResponse)
async def list_exceptions(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    host_id: Optional[UUID] = Query(None, description="Filter by host ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExceptionListResponse:
    """
    List compliance exceptions with pagination and filtering.

    Args:
        page: Page number (1-indexed)
        per_page: Items per page (max 100)
        status: Filter by status (pending, approved, rejected, expired, revoked)
        rule_id: Filter by rule ID
        host_id: Filter by host ID
        db: Database session
        current_user: Authenticated user

    Returns:
        Paginated list of exceptions
    """
    service = ExceptionService(db)
    return service.list_exceptions(
        page=page,
        per_page=per_page,
        status=status,
        rule_id=rule_id,
        host_id=host_id,
    )


@router.get("/summary", response_model=ExceptionSummary)
async def get_exception_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExceptionSummary:
    """
    Get exception statistics summary.

    Returns:
        Summary with counts by status and expiring soon count
    """
    service = ExceptionService(db)
    return service.get_summary()


@router.post("", response_model=ExceptionResponse)
async def request_exception(
    request: ExceptionRequestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExceptionResponse:
    """
    Request a new compliance exception.

    Creates an exception in 'pending' status awaiting approval.
    Requires OpenWatch+ subscription for exception management.

    Args:
        request: Exception request details
        db: Database session
        current_user: Authenticated user

    Returns:
        Created exception

    Raises:
        HTTPException: 400 if validation fails
        HTTPException: 403 if no subscription
        HTTPException: 409 if active exception already exists
    """
    # Exception management requires OpenWatch+ subscription
    license_service = LicenseService()
    if not await license_service.has_feature("structured_exceptions"):
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Structured exceptions require OpenWatch+ subscription",
        )

    # Validate scope
    if not request.host_id and not request.host_group_id:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Either host_id or host_group_id must be provided",
        )

    service = ExceptionService(db)
    exception = service.request_exception(
        rule_id=request.rule_id,
        host_id=request.host_id,
        host_group_id=request.host_group_id,
        justification=request.justification,
        duration_days=request.duration_days,
        requested_by=int(current_user.id),
        risk_acceptance=request.risk_acceptance,
        compensating_controls=request.compensating_controls,
        business_impact=request.business_impact,
    )

    if not exception:
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail="Active exception already exists for this rule and scope",
        )

    return service._row_to_response(exception)


@router.get("/{exception_id}", response_model=ExceptionResponse)
async def get_exception(
    exception_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExceptionResponse:
    """
    Get exception by ID.

    Args:
        exception_id: Exception UUID
        db: Database session
        current_user: Authenticated user

    Returns:
        Exception details

    Raises:
        HTTPException: 404 if not found
    """
    service = ExceptionService(db)
    exception = service.get_exception(exception_id)

    if not exception:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Exception {exception_id} not found",
        )

    return service._row_to_response(exception)


@router.post("/{exception_id}/approve", response_model=ExceptionResponse)
async def approve_exception(
    exception_id: UUID,
    request: ExceptionApproveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExceptionResponse:
    """
    Approve a pending exception.

    Requires ADMIN role or higher.

    Args:
        exception_id: Exception UUID to approve
        request: Approval details
        db: Database session
        current_user: Authenticated user (must be ADMIN+)

    Returns:
        Updated exception

    Raises:
        HTTPException: 400 if exception is not pending
        HTTPException: 403 if user lacks permission
        HTTPException: 404 if not found
    """
    # Check admin permission
    if current_user.role not in ("super_admin", "security_admin", "compliance_officer"):
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Only admins and compliance officers can approve exceptions",
        )

    service = ExceptionService(db)
    exception = service.approve_exception(exception_id, int(current_user.id))

    if not exception:
        # Check if it exists first
        existing = service.get_exception(exception_id)
        if not existing:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Exception {exception_id} not found",
            )
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve exception: status is '{existing.status}', not 'pending'",
        )

    return service._row_to_response(exception)


@router.post("/{exception_id}/reject", response_model=ExceptionResponse)
async def reject_exception(
    exception_id: UUID,
    request: ExceptionRejectRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExceptionResponse:
    """
    Reject a pending exception.

    Requires ADMIN role or higher.

    Args:
        exception_id: Exception UUID to reject
        request: Rejection details (includes reason)
        db: Database session
        current_user: Authenticated user (must be ADMIN+)

    Returns:
        Updated exception

    Raises:
        HTTPException: 400 if exception is not pending
        HTTPException: 403 if user lacks permission
        HTTPException: 404 if not found
    """
    # Check admin permission
    if current_user.role not in ("super_admin", "security_admin", "compliance_officer"):
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Only admins and compliance officers can reject exceptions",
        )

    service = ExceptionService(db)
    exception = service.reject_exception(exception_id, int(current_user.id), request.reason)

    if not exception:
        existing = service.get_exception(exception_id)
        if not existing:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Exception {exception_id} not found",
            )
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reject exception: status is '{existing.status}', not 'pending'",
        )

    return service._row_to_response(exception)


@router.post("/{exception_id}/revoke", response_model=ExceptionResponse)
async def revoke_exception(
    exception_id: UUID,
    request: ExceptionRevokeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExceptionResponse:
    """
    Revoke an approved exception.

    Requires ADMIN role or higher.

    Args:
        exception_id: Exception UUID to revoke
        request: Revocation details (includes reason)
        db: Database session
        current_user: Authenticated user (must be ADMIN+)

    Returns:
        Updated exception

    Raises:
        HTTPException: 400 if exception is not approved
        HTTPException: 403 if user lacks permission
        HTTPException: 404 if not found
    """
    # Check admin permission
    if current_user.role not in ("super_admin", "security_admin", "compliance_officer"):
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Only admins and compliance officers can revoke exceptions",
        )

    service = ExceptionService(db)
    exception = service.revoke_exception(exception_id, int(current_user.id), request.reason)

    if not exception:
        existing = service.get_exception(exception_id)
        if not existing:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Exception {exception_id} not found",
            )
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot revoke exception: status is '{existing.status}', not 'approved'",
        )

    return service._row_to_response(exception)


@router.post("/check", response_model=ExceptionCheckResponse)
async def check_exception(
    request: ExceptionCheckRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExceptionCheckResponse:
    """
    Check if a rule is currently excepted for a host.

    Checks both direct host exceptions and host group exceptions.

    Args:
        request: Check request with rule_id and host_id
        db: Database session
        current_user: Authenticated user

    Returns:
        ExceptionCheckResponse with exception status
    """
    service = ExceptionService(db)
    return service.is_excepted(request.rule_id, request.host_id)


__all__ = ["router"]
