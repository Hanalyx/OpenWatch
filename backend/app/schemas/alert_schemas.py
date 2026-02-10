"""
Alert Schemas for Compliance Alert System

Pydantic models for compliance alert requests and responses.

Part of OpenWatch OS Transformation - Alert Thresholds (doc 03).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class AlertResponse(BaseModel):
    """Response model for a compliance alert."""

    id: UUID
    alert_type: str
    severity: str
    title: str
    message: Optional[str] = None

    # Context
    host_id: Optional[UUID] = None
    host_group_id: Optional[int] = None
    rule_id: Optional[str] = None
    scan_id: Optional[UUID] = None

    # State
    status: str
    acknowledged_by: Optional[int] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    # Additional data
    metadata: Optional[Dict[str, Any]] = None

    # Timestamps
    created_at: datetime

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    """Response model for alert list queries."""

    items: List[AlertResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


class AlertStats(BaseModel):
    """Alert statistics summary."""

    total_active: int = 0
    total_acknowledged: int = 0
    total_resolved: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_type: Dict[str, int] = Field(default_factory=dict)
    recent_24h: int = 0


class AlertAcknowledgeRequest(BaseModel):
    """Request model for acknowledging an alert."""

    comments: Optional[str] = Field(None, description="Optional acknowledgment comments")


class AlertResolveRequest(BaseModel):
    """Request model for resolving an alert."""

    comments: Optional[str] = Field(None, description="Optional resolution comments")


class AlertThresholds(BaseModel):
    """Alert threshold configuration."""

    compliance: Dict[str, Any] = Field(
        default_factory=lambda: {
            "critical_finding": True,
            "high_finding": True,
            "medium_finding": False,
            "score_drop_threshold": 20,
            "score_drop_window_hours": 24,
            "non_compliant_threshold": 80,
        },
        description="Compliance-related thresholds",
    )
    drift: Dict[str, Any] = Field(
        default_factory=lambda: {
            "mass_drift_threshold": 10,
        },
        description="Configuration drift thresholds",
    )
    operational: Dict[str, Any] = Field(
        default_factory=lambda: {
            "max_scan_age_hours": 48,
        },
        description="Operational thresholds",
    )


class AlertThresholdsUpdate(BaseModel):
    """Request model for updating alert thresholds."""

    compliance: Optional[Dict[str, Any]] = Field(None, description="Compliance thresholds")
    drift: Optional[Dict[str, Any]] = Field(None, description="Drift thresholds")
    operational: Optional[Dict[str, Any]] = Field(None, description="Operational thresholds")


class AlertSettingsResponse(BaseModel):
    """Response model for alert settings."""

    host_id: Optional[UUID] = None
    host_group_id: Optional[int] = None
    settings: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


__all__ = [
    "AlertResponse",
    "AlertListResponse",
    "AlertStats",
    "AlertAcknowledgeRequest",
    "AlertResolveRequest",
    "AlertThresholds",
    "AlertThresholdsUpdate",
    "AlertSettingsResponse",
]
