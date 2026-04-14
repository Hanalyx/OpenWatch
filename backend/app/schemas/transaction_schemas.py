"""
Pydantic schemas for the Transactions API.

These schemas define the request/response models for querying the
transactions table, which stores compliance check results in a
four-phase transaction model (capture -> apply -> validate -> commit/rollback).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel


class TransactionResponse(BaseModel):
    """Summary response for a single transaction (list views)."""

    id: UUID
    host_id: UUID
    rule_id: Optional[str] = None
    scan_id: Optional[UUID] = None
    phase: str
    status: str
    severity: Optional[str] = None
    initiator_type: str
    initiator_id: Optional[str] = None
    evidence_envelope: Optional[Dict[str, Any]] = None
    framework_refs: Optional[Dict[str, Any]] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None


class TransactionDetailResponse(TransactionResponse):
    """Full detail response including phase state payloads."""

    pre_state: Optional[Dict[str, Any]] = None
    apply_plan: Optional[Dict[str, Any]] = None
    validate_result: Optional[Dict[str, Any]] = None
    post_state: Optional[Dict[str, Any]] = None
    baseline_id: Optional[UUID] = None
    remediation_job_id: Optional[UUID] = None


class TransactionListResponse(BaseModel):
    """Paginated list of transactions."""

    items: List[TransactionResponse]
    total: int
    page: int
    per_page: int


class RuleSummaryResponse(BaseModel):
    """Summary of a single rule's compliance state across all hosts."""

    rule_id: str
    severity: Optional[str] = None
    host_count: int
    hosts_passing: int
    hosts_failing: int
    hosts_skipped: int
    change_count: int
    last_checked_at: Optional[datetime] = None
    last_changed_at: Optional[datetime] = None
    total_checks: int


class RuleSummaryListResponse(BaseModel):
    """Paginated list of rule summaries."""

    items: List[RuleSummaryResponse]
    total: int
    page: int
    per_page: int
