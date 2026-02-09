"""
Exception Schemas for Governance Primitives

Pydantic models for compliance exception requests and responses.

Part of Phase 3: Governance Primitives (Aegis Integration Plan)
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ExceptionRequestCreate(BaseModel):
    """Request model for creating a new exception.

    Note: Scope validation (host_id or host_group_id required) is performed
    at the service level since cross-field validation is complex in Pydantic.
    """

    rule_id: str = Field(..., description="Rule ID to except")
    host_id: Optional[UUID] = Field(None, description="Specific host (mutually exclusive with host_group_id)")
    host_group_id: Optional[int] = Field(None, description="Host group (mutually exclusive with host_id)")
    justification: str = Field(..., min_length=20, description="Business justification for exception")
    risk_acceptance: Optional[str] = Field(None, description="Risk acceptance statement")
    compensating_controls: Optional[str] = Field(None, description="Compensating controls in place")
    business_impact: Optional[str] = Field(None, description="Business impact of compliance")
    duration_days: int = Field(..., ge=1, le=365, description="Exception duration in days (max 1 year)")


class ExceptionApproveRequest(BaseModel):
    """Request model for approving an exception."""

    comments: Optional[str] = Field(None, description="Approval comments")


class ExceptionRejectRequest(BaseModel):
    """Request model for rejecting an exception."""

    reason: str = Field(..., min_length=10, description="Rejection reason")


class ExceptionRevokeRequest(BaseModel):
    """Request model for revoking an approved exception."""

    reason: str = Field(..., min_length=10, description="Revocation reason")


class ExceptionResponse(BaseModel):
    """Response model for a compliance exception."""

    id: UUID
    rule_id: str
    host_id: Optional[UUID] = None
    host_group_id: Optional[int] = None

    # Exception details
    justification: str
    risk_acceptance: Optional[str] = None
    compensating_controls: Optional[str] = None
    business_impact: Optional[str] = None

    # Lifecycle
    status: str
    requested_by: int
    requested_at: datetime
    approved_by: Optional[int] = None
    approved_at: Optional[datetime] = None
    rejected_by: Optional[int] = None
    rejected_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    expires_at: datetime
    revoked_by: Optional[int] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None

    # Audit
    created_at: datetime
    updated_at: datetime

    # Computed fields
    is_active: bool = Field(description="True if exception is currently active")
    days_until_expiry: Optional[int] = Field(None, description="Days until expiration (if active)")

    class Config:
        from_attributes = True


class ExceptionListResponse(BaseModel):
    """Response model for exception list queries."""

    items: List[ExceptionResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


class ExceptionSummary(BaseModel):
    """Summary of exception statistics."""

    total_pending: int = 0
    total_approved: int = 0
    total_rejected: int = 0
    total_expired: int = 0
    total_revoked: int = 0
    expiring_soon: int = Field(0, description="Approved exceptions expiring within 30 days")


class ExceptionCheckRequest(BaseModel):
    """Request to check if a rule is excepted for a host."""

    rule_id: str
    host_id: UUID


class ExceptionCheckResponse(BaseModel):
    """Response for exception check."""

    is_excepted: bool
    exception_id: Optional[UUID] = None
    expires_at: Optional[datetime] = None
    justification: Optional[str] = None


__all__ = [
    "ExceptionRequestCreate",
    "ExceptionApproveRequest",
    "ExceptionRejectRequest",
    "ExceptionRevokeRequest",
    "ExceptionResponse",
    "ExceptionListResponse",
    "ExceptionSummary",
    "ExceptionCheckRequest",
    "ExceptionCheckResponse",
]
