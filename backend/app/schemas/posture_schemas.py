"""
Posture Schemas for Temporal Compliance

Pydantic models for compliance posture queries and responses.

Part of Phase 2: Temporal Compliance (Kensa Integration Plan)
"""

from datetime import date, datetime
from typing import Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class SeverityBreakdown(BaseModel):
    """Severity-level pass/fail breakdown."""

    passed: int = 0
    failed: int = 0

    @property
    def total(self) -> int:
        """Total rules at this severity."""
        return self.passed + self.failed


class RuleState(BaseModel):
    """State of a single rule in a posture snapshot."""

    rule_id: str
    status: str  # pass, fail, error, notapplicable
    severity: str
    title: Optional[str] = None
    category: Optional[str] = None


class PostureResponse(BaseModel):
    """Response model for compliance posture query."""

    host_id: UUID
    snapshot_date: datetime
    is_current: bool = Field(description="True if this is current posture, False if historical")

    # Aggregate metrics
    total_rules: int
    passed: int
    failed: int
    error_count: int = 0
    not_applicable: int = 0
    compliance_score: float = Field(ge=0, le=100)

    # Per-severity breakdown
    severity_breakdown: Dict[str, SeverityBreakdown] = Field(default_factory=dict)

    # Rule-level details (optional, can be large)
    rule_states: Optional[Dict[str, RuleState]] = None

    # Source scan reference
    source_scan_id: Optional[UUID] = None


class PostureHistoryResponse(BaseModel):
    """Response model for posture history query."""

    host_id: UUID
    snapshots: List[PostureResponse]
    total_snapshots: int
    date_range: Dict[str, Optional[datetime]] = Field(default_factory=lambda: {"start": None, "end": None})


class DriftEvent(BaseModel):
    """A single compliance drift event."""

    rule_id: str
    rule_title: Optional[str] = None
    previous_status: str
    current_status: str
    severity: str
    detected_at: datetime
    direction: str = Field(description="improvement or regression")


class DriftAnalysisResponse(BaseModel):
    """Response model for drift analysis between two dates."""

    host_id: UUID
    start_date: datetime
    end_date: datetime

    # Overall drift metrics
    start_score: float
    end_score: float
    score_delta: float = Field(description="Positive = improvement, negative = regression")
    drift_magnitude: float = Field(description="Absolute value of score change")
    drift_type: str = Field(description="major, minor, improvement, stable")

    # Rule-level changes
    rules_improved: int = 0
    rules_regressed: int = 0
    rules_unchanged: int = 0

    # Detailed drift events
    drift_events: List[DriftEvent] = Field(default_factory=list)


class PostureQueryRequest(BaseModel):
    """Request model for posture query."""

    host_id: UUID
    as_of: Optional[date] = Field(None, description="Point-in-time query date (None = current)")
    include_rule_states: bool = Field(False, description="Include per-rule state details")


class PostureHistoryRequest(BaseModel):
    """Request model for posture history query."""

    host_id: UUID
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    limit: int = Field(30, ge=1, le=365)


class DriftAnalysisRequest(BaseModel):
    """Request model for drift analysis."""

    host_id: UUID
    start_date: date
    end_date: date


class SnapshotCreateRequest(BaseModel):
    """Request model for creating a manual snapshot."""

    host_id: UUID
    source_scan_id: Optional[UUID] = None


__all__ = [
    "SeverityBreakdown",
    "RuleState",
    "PostureResponse",
    "PostureHistoryResponse",
    "DriftEvent",
    "DriftAnalysisResponse",
    "PostureQueryRequest",
    "PostureHistoryRequest",
    "DriftAnalysisRequest",
    "SnapshotCreateRequest",
]
