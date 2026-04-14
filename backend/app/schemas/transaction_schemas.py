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


# ---------------------------------------------------------------------------
# POST /api/transactions/query — DSL + response (Q3 §6.1)
# ---------------------------------------------------------------------------
#
# Spec: specs/api/transactions/transaction-query.spec.yaml


# Columns available for the ``fields`` projection parameter. Kept as a
# module-level constant so the route handler, test, and OpenAPI docs share
# a single source of truth.
QUERY_PROJECTION_FIELDS = frozenset(
    {
        "id",
        "host_id",
        "rule_id",
        "scan_id",
        "phase",
        "status",
        "severity",
        "initiator_type",
        "initiator_id",
        "evidence_envelope",
        "framework_refs",
        "started_at",
        "completed_at",
        "duration_ms",
    }
)

# Default projection when the request omits ``fields``. Excludes heavy JSONB
# columns (evidence_envelope) to keep the payload small for the common case.
QUERY_DEFAULT_FIELDS = [
    "id",
    "host_id",
    "rule_id",
    "phase",
    "status",
    "severity",
    "initiator_type",
    "started_at",
    "completed_at",
    "duration_ms",
]


class TransactionQueryRequest(BaseModel):
    """Query DSL body for POST /api/transactions/query.

    Spec AC-2 (filters), AC-3 (pagination), AC-4 (projection).
    All filters combine with AND; list filters use IN clauses.
    """

    # ---- filters ----
    host_id: Optional[UUID] = None
    host_ids: Optional[List[UUID]] = None
    fleet_id: Optional[UUID] = None  # resolves via host_group_members
    rule_id: Optional[str] = None
    rule_ids: Optional[List[str]] = None
    status: Optional[List[str]] = None  # e.g. ["pass", "fail"]
    phase: Optional[List[str]] = None
    severity: Optional[List[str]] = None
    framework: Optional[str] = None  # JSONB key lookup on framework_refs
    initiator_type: Optional[List[str]] = None
    started_after: Optional[datetime] = None
    started_before: Optional[datetime] = None

    # ---- pagination ----
    cursor: Optional[str] = None
    limit: int = 50  # bounded 1..500 in validator

    # ---- projection ----
    fields: Optional[List[str]] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "fleet_id": "550e8400-e29b-41d4-a716-446655440000",
                    "status": ["fail"],
                    "started_after": "2026-03-01T00:00:00Z",
                    "limit": 100,
                    "fields": ["id", "rule_id", "status", "started_at"],
                }
            ]
        }
    }


class TransactionQueryResponse(BaseModel):
    """Paginated cursor-based result for POST /api/transactions/query.

    Spec AC-3: response includes next_cursor (null on last page) and
    total_count (stable across pages; not recomputed per request when the
    filter set matches a prior cursor).
    """

    items: List[Dict[str, Any]]  # dicts because projection is dynamic
    total_count: int
    next_cursor: Optional[str] = None
