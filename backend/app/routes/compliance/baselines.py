"""
Baseline Management API Routes

Endpoints for resetting, promoting, and retrieving compliance baselines.

Spec: specs/services/compliance/baseline-management.spec.yaml
AC-1: POST /api/hosts/{host_id}/baseline/reset
AC-2: POST /api/hosts/{host_id}/baseline/promote
AC-4: RBAC enforcement (SECURITY_ANALYST+)
AC-5: Audit logging on all mutations

Note: These routes use prefix /baselines under the compliance router,
but the reset/promote endpoints are mounted at /api/hosts/{host_id}/baseline/*
via a separate router registered at the app level.
"""

import logging
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import get_db
from ...rbac import UserRole, require_role
from ...routes.admin.audit import log_audit_event
from ...services.compliance.baseline_management import BaselineManagementService

logger = logging.getLogger(__name__)

# Router mounted at /api/hosts (registered at app level, not under /compliance)
router = APIRouter(prefix="/hosts", tags=["Baselines"])


# =============================================================================
# PYDANTIC MODELS
# =============================================================================


class BaselineResponse(BaseModel):
    """Response model for baseline data."""

    id: str
    host_id: str
    baseline_type: str
    established_at: str
    established_by: Optional[int] = None
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


def _baseline_to_response(baseline: Any) -> BaselineResponse:
    """Convert a ScanBaseline ORM object to a response dict."""
    return BaselineResponse(
        id=str(baseline.id),
        host_id=str(baseline.host_id),
        baseline_type=baseline.baseline_type,
        established_at=baseline.established_at.isoformat() + "Z",
        established_by=baseline.established_by,
        baseline_score=float(baseline.baseline_score),
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
        drift_threshold_major=float(baseline.drift_threshold_major),
        drift_threshold_minor=float(baseline.drift_threshold_minor),
        is_active=baseline.is_active,
    )


# =============================================================================
# ENDPOINTS
# =============================================================================


@router.post(
    "/{host_id}/baseline/reset",
    response_model=BaselineResponse,
    summary="Reset baseline from latest scan",
    description="Establish a new baseline from the most recent completed scan for this host.",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def reset_baseline(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> BaselineResponse:
    """
    Establish new baseline from the most recent scan for this host.

    Deactivates the current active baseline and creates a new one
    from the latest completed scan results.

    Requires SECURITY_ANALYST or higher role.
    """
    try:
        host_uuid = UUID(host_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid host ID format")

    service = BaselineManagementService()
    try:
        baseline = service.reset_baseline(
            db=db,
            host_id=host_uuid,
            user_id=current_user["id"],
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to reset baseline for host {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset baseline")

    # Write to audit_logs table
    log_audit_event(
        db=db,
        user_id=current_user.get("id"),
        action="BASELINE_RESET",
        resource_type="baseline",
        resource_id=str(baseline.id),
        ip_address="127.0.0.1",
        user_agent=None,
        details=f"Baseline reset for host {host_id}, score={baseline.baseline_score:.1f}%",
    )

    return _baseline_to_response(baseline)


@router.post(
    "/{host_id}/baseline/promote",
    response_model=BaselineResponse,
    summary="Promote current posture to baseline",
    description="Promote the current compliance posture to baseline after a known legitimate change.",
)
@require_role([UserRole.SECURITY_ANALYST, UserRole.SECURITY_ADMIN, UserRole.SUPER_ADMIN])
async def promote_baseline(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> BaselineResponse:
    """
    Promote current compliance posture to baseline.

    Uses host_rule_state data to establish a new baseline reflecting
    the current pass/fail state of all rules. Useful after a known
    legitimate configuration change.

    Requires SECURITY_ANALYST or higher role.
    """
    try:
        host_uuid = UUID(host_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid host ID format")

    service = BaselineManagementService()
    try:
        baseline = service.promote_baseline(
            db=db,
            host_id=host_uuid,
            user_id=current_user["id"],
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to promote baseline for host {host_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to promote baseline")

    # Write to audit_logs table
    log_audit_event(
        db=db,
        user_id=current_user.get("id"),
        action="BASELINE_PROMOTED",
        resource_type="baseline",
        resource_id=str(baseline.id),
        ip_address="127.0.0.1",
        user_agent=None,
        details=f"Baseline promoted for host {host_id}, score={baseline.baseline_score:.1f}%",
    )

    return _baseline_to_response(baseline)


@router.get(
    "/{host_id}/baseline",
    response_model=Optional[BaselineResponse],
    summary="Get active baseline",
    description="Get the current active baseline for a host.",
)
@require_role(
    [
        UserRole.GUEST,
        UserRole.AUDITOR,
        UserRole.SECURITY_ANALYST,
        UserRole.COMPLIANCE_OFFICER,
        UserRole.SECURITY_ADMIN,
        UserRole.SUPER_ADMIN,
    ]
)
async def get_baseline(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Optional[BaselineResponse]:
    """
    Get current active baseline for a host.

    Returns the active baseline with score and per-severity metrics,
    or null if no baseline has been established.

    Accessible to all authenticated roles.
    """
    try:
        host_uuid = UUID(host_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid host ID format")

    service = BaselineManagementService()
    baseline = service.get_active_baseline(db=db, host_id=host_uuid)

    if not baseline:
        return None

    return _baseline_to_response(baseline)
