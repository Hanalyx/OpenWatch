"""Admin endpoints for retention policy management.

Provides GET / PUT / POST endpoints under ``/admin/retention``
for listing, updating, and manually enforcing data retention policies.

All endpoints require SUPER_ADMIN role.

Spec: specs/services/compliance/retention-policy.spec.yaml (AC-5)
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.auth import get_current_user
from app.database import SessionLocal
from app.rbac import UserRole, require_role
from app.services.compliance.retention_policy import RetentionService

router = APIRouter(prefix="/admin/retention", tags=["admin"])


# ------------------------------------------------------------------ #
# Pydantic schemas
# ------------------------------------------------------------------ #


class RetentionPolicyRequest(BaseModel):
    """Request body for creating/updating a retention policy."""

    resource_type: str = Field(..., max_length=64, description="Resource type (e.g. 'transactions').")
    retention_days: int = Field(..., ge=1, description="Number of days to retain rows.")
    tenant_id: Optional[UUID] = Field(None, description="Optional tenant scope (null = global).")
    enabled: bool = Field(True, description="Whether enforcement is active.")


class RetentionPolicyResponse(BaseModel):
    """Single retention policy row."""

    id: UUID
    tenant_id: Optional[UUID] = None
    resource_type: str
    retention_days: int
    enabled: bool
    created_at: Any = None
    updated_at: Any = None


# ------------------------------------------------------------------ #
# Endpoints
# ------------------------------------------------------------------ #


@router.get("", response_model=List[RetentionPolicyResponse])
@require_role([UserRole.SUPER_ADMIN])
async def list_retention_policies(
    current_user: Dict = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List all retention policies.

    Returns:
        List of retention policy objects.
    """
    db = SessionLocal()
    try:
        service = RetentionService(db)
        return service.get_policies()
    finally:
        db.close()


@router.put("", response_model=RetentionPolicyResponse)
@require_role([UserRole.SUPER_ADMIN])
async def upsert_retention_policy(
    body: RetentionPolicyRequest,
    current_user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create or update a retention policy.

    If a policy for the given (tenant_id, resource_type) already exists
    the retention_days and enabled fields are updated.

    Args:
        body: Retention policy parameters.

    Returns:
        The upserted retention policy.
    """
    db = SessionLocal()
    try:
        service = RetentionService(db)
        return service.set_policy(
            resource_type=body.resource_type,
            retention_days=body.retention_days,
            tenant_id=body.tenant_id,
            enabled=body.enabled,
        )
    finally:
        db.close()


@router.post("/enforce")
@require_role([UserRole.SUPER_ADMIN])
async def enforce_retention(
    current_user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Manually trigger retention enforcement.

    Deletes expired rows for all enabled policies and returns
    per-resource deletion counts.

    Returns:
        Dict with resource_type -> deleted row count.
    """
    db = SessionLocal()
    try:
        service = RetentionService(db)
        counts = service.enforce()
        return {"status": "completed", "deleted": counts}
    finally:
        db.close()
