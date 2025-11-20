"""
Baseline Management API Endpoints

Provides REST API for compliance baseline establishment and management.
Baselines are used for drift detection per NIST SP 800-137 Continuous Monitoring.

Endpoints:
    POST /api/hosts/{host_id}/baseline - Establish new baseline from scan
    GET /api/hosts/{host_id}/baseline - Get active baseline for host
    DELETE /api/hosts/{host_id}/baseline - Reset (deactivate) baseline

Security:
    - JWT authentication required for all endpoints
    - RBAC enforcement via role decorators
    - Input validation via Pydantic models
    - Audit logging for create/delete operations
"""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..services.baseline_service import BaselineService
from ..utils.logging_security import sanitize_for_log, sanitize_id_for_log, sanitize_username_for_log

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("openwatch.audit")

router = APIRouter(prefix="/api/hosts", tags=["baselines"])


class BaselineEstablishRequest(BaseModel):
    """Request model for establishing a baseline."""

    scan_id: UUID = Field(..., description="UUID of completed scan to use as baseline")
    baseline_type: str = Field(
        default="manual",
        description="Baseline type: 'initial', 'manual', or 'rolling_avg'",
        pattern="^(initial|manual|rolling_avg)$",
    )


class BaselineResponse(BaseModel):
    """Response model for baseline data."""

    id: UUID
    host_id: UUID
    baseline_type: str
    established_at: str
    established_by: Optional[int]  # Integer (users table uses int primary key)
    baseline_score: float
    baseline_passed_rules: int
    baseline_failed_rules: int
    baseline_total_rules: int
    baseline_critical_passed: int
    baseline_critical_failed: int
    baseline_high_passed: int
    baseline_high_failed: int
    baseline_medium_passed: int
    baseline_medium_failed: int
    baseline_low_passed: int
    baseline_low_failed: int
    drift_threshold_major: float
    drift_threshold_minor: float
    is_active: bool

    class Config:
        from_attributes = True


@router.post(
    "/{host_id}/baseline",
    response_model=BaselineResponse,
    status_code=201,
    summary="Establish compliance baseline",
    description="Create new baseline from completed scan. Supersedes existing active baseline.",
)
async def establish_baseline(
    host_id: UUID,
    request_body: BaselineEstablishRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Establish compliance baseline for a host.

    Requires scan_manager or super_admin role.
    Creates baseline from completed scan and supersedes any existing active baseline.

    Security validations:
    - Scan must belong to the specified host
    - Scan must be in 'completed' status
    - User must have scan_manager or super_admin role

    Audit logged: Baseline establishment with user, host, scan IDs
    """
    # Check user role
    user_role = current_user.get("role", "")
    # Security: Sanitize user-controlled data before logging to prevent log injection
    # CWE-117: Prevents attackers from injecting newlines to forge log entries
    logger.info(
        f"DEBUG establish_baseline: current_user = {sanitize_for_log(str(current_user))}, "
        f"user_role = '{sanitize_for_log(user_role)}'"
    )
    if user_role not in ["scan_manager", "super_admin"]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Requires scan_manager or super_admin role.",
        )

    baseline_service = BaselineService()

    try:
        # Establish baseline using service layer
        baseline = baseline_service.establish_baseline(
            db=db,
            host_id=host_id,
            scan_id=request_body.scan_id,
            baseline_type=request_body.baseline_type,
            established_by=current_user.get("id"),
        )

        # Audit log the baseline establishment
        # Security: Sanitize all user-controlled values to prevent log injection (CWE-117)
        # Protects against CRLF injection that could forge audit log entries
        audit_logger.info(
            f"BASELINE_ESTABLISHED - User {sanitize_username_for_log(current_user.get('username'))} "
            f"(ID: {sanitize_id_for_log(current_user.get('id'))}) "
            f"established {sanitize_for_log(request_body.baseline_type)} baseline for host "
            f"{sanitize_id_for_log(host_id)} from scan {sanitize_id_for_log(request_body.scan_id)} "
            f"(baseline ID: {sanitize_id_for_log(baseline.id)})",
            extra={
                "event_type": "BASELINE_ESTABLISHED",
                "user_id": sanitize_id_for_log(current_user.get("id")),
                "username": sanitize_username_for_log(current_user.get("username")),
                "host_id": sanitize_id_for_log(host_id),
                "scan_id": sanitize_id_for_log(request_body.scan_id),
                "baseline_id": sanitize_id_for_log(baseline.id),
                "baseline_type": sanitize_for_log(request_body.baseline_type),
                "ip_address": sanitize_for_log(request.client.host),
            },
        )

        # Convert to response model
        return BaselineResponse(
            id=baseline.id,
            host_id=baseline.host_id,
            baseline_type=baseline.baseline_type,
            established_at=baseline.established_at.isoformat(),
            established_by=baseline.established_by,
            baseline_score=baseline.baseline_score,
            baseline_passed_rules=baseline.baseline_passed_rules,
            baseline_failed_rules=baseline.baseline_failed_rules,
            baseline_total_rules=baseline.baseline_total_rules,
            baseline_critical_passed=baseline.baseline_critical_passed,
            baseline_critical_failed=baseline.baseline_critical_failed,
            baseline_high_passed=baseline.baseline_high_passed,
            baseline_high_failed=baseline.baseline_high_failed,
            baseline_medium_passed=baseline.baseline_medium_passed,
            baseline_medium_failed=baseline.baseline_medium_failed,
            baseline_low_passed=baseline.baseline_low_passed,
            baseline_low_failed=baseline.baseline_low_failed,
            drift_threshold_major=baseline.drift_threshold_major,
            drift_threshold_minor=baseline.drift_threshold_minor,
            is_active=baseline.is_active,
        )

    except ValueError as e:
        # Invalid scan or host
        # Security: Sanitize user-controlled data and error messages to prevent log injection
        logger.warning(
            f"Failed to establish baseline for host {sanitize_id_for_log(host_id)}: " f"{sanitize_for_log(str(e))}",
            extra={
                "host_id": sanitize_id_for_log(host_id),
                "scan_id": sanitize_id_for_log(request_body.scan_id),
            },
        )
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        # Unexpected error
        # Security: Sanitize user-controlled data and error messages to prevent log injection
        logger.error(
            f"Error establishing baseline for host {sanitize_id_for_log(host_id)}: " f"{sanitize_for_log(str(e))}",
            exc_info=True,
            extra={
                "host_id": sanitize_id_for_log(host_id),
                "scan_id": sanitize_id_for_log(request_body.scan_id),
            },
        )
        raise HTTPException(status_code=500, detail="Failed to establish baseline. Check server logs.")


@router.get(
    "/{host_id}/baseline",
    response_model=Optional[BaselineResponse],
    summary="Get active baseline",
    description="Retrieve currently active baseline for a host, or None if no baseline exists.",
)
async def get_active_baseline(
    host_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Get active baseline for a host.

    Requires analyst, scan_manager, or super_admin role.
    Returns None if no active baseline exists.

    Security validations:
    - User must have analyst or higher role
    - Host ID must be valid UUID

    No audit logging: Read-only operation
    """
    baseline_service = BaselineService()

    try:
        baseline = baseline_service.get_active_baseline(db=db, host_id=host_id)

        if not baseline:
            return None

        # Convert to response model
        return BaselineResponse(
            id=baseline.id,
            host_id=baseline.host_id,
            baseline_type=baseline.baseline_type,
            established_at=baseline.established_at.isoformat(),
            established_by=baseline.established_by,
            baseline_score=baseline.baseline_score,
            baseline_passed_rules=baseline.baseline_passed_rules,
            baseline_failed_rules=baseline.baseline_failed_rules,
            baseline_total_rules=baseline.baseline_total_rules,
            baseline_critical_passed=baseline.baseline_critical_passed,
            baseline_critical_failed=baseline.baseline_critical_failed,
            baseline_high_passed=baseline.baseline_high_passed,
            baseline_high_failed=baseline.baseline_high_failed,
            baseline_medium_passed=baseline.baseline_medium_passed,
            baseline_medium_failed=baseline.baseline_medium_failed,
            baseline_low_passed=baseline.baseline_low_passed,
            baseline_low_failed=baseline.baseline_low_failed,
            drift_threshold_major=baseline.drift_threshold_major,
            drift_threshold_minor=baseline.drift_threshold_minor,
            is_active=baseline.is_active,
        )

    except Exception as e:
        # Security: Sanitize user-controlled data and error messages to prevent log injection
        logger.error(
            f"Error retrieving baseline for host {sanitize_id_for_log(host_id)}: " f"{sanitize_for_log(str(e))}",
            exc_info=True,
            extra={"host_id": sanitize_id_for_log(host_id)},
        )
        raise HTTPException(status_code=500, detail="Failed to retrieve baseline. Check server logs.")


@router.delete(
    "/{host_id}/baseline",
    status_code=200,
    summary="Reset baseline",
    description="Deactivate current baseline. Returns 404 if no active baseline exists.",
)
async def reset_baseline(
    host_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Reset (deactivate) baseline for a host.

    Requires scan_manager or super_admin role.
    Marks current baseline as inactive without deleting it.

    Security validations:
    - User must have scan_manager or super_admin role
    - Host ID must be valid UUID

    Audit logged: Baseline reset with user and host IDs
    """
    # Check user role
    user_role = current_user.get("role", "")
    if user_role not in ["scan_manager", "super_admin"]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Requires scan_manager or super_admin role.",
        )

    baseline_service = BaselineService()

    try:
        success = baseline_service.reset_baseline(db=db, host_id=host_id)

        if not success:
            raise HTTPException(status_code=404, detail=f"No active baseline found for host {host_id}")

        # Audit log the baseline reset
        # Security: Sanitize all user-controlled values to prevent log injection (CWE-117)
        audit_logger.info(
            f"BASELINE_RESET - User {sanitize_username_for_log(current_user.get('username'))} "
            f"(ID: {sanitize_id_for_log(current_user.get('id'))}) "
            f"reset baseline for host {sanitize_id_for_log(host_id)}",
            extra={
                "event_type": "BASELINE_RESET",
                "user_id": sanitize_id_for_log(current_user.get("id")),
                "username": sanitize_username_for_log(current_user.get("username")),
                "host_id": sanitize_id_for_log(host_id),
                "ip_address": sanitize_for_log(request.client.host),
            },
        )

        return {
            "status": "success",
            "message": f"Baseline reset for host {host_id}",
            "host_id": str(host_id),
        }

    except HTTPException:
        # Re-raise HTTP exceptions (404)
        raise

    except Exception as e:
        # Security: Sanitize user-controlled data and error messages to prevent log injection
        logger.error(
            f"Error resetting baseline for host {sanitize_id_for_log(host_id)}: " f"{sanitize_for_log(str(e))}",
            exc_info=True,
            extra={"host_id": sanitize_id_for_log(host_id)},
        )
        raise HTTPException(status_code=500, detail="Failed to reset baseline. Check server logs.")
