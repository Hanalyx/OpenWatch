"""
Transaction CRUD Operations

Read-only endpoints for querying the transactions table, which stores
compliance check results in a four-phase transaction model
(capture -> apply -> validate -> commit/rollback).

Endpoints:
    GET  /api/transactions                     - List transactions (paginated)
    GET  /api/transactions/{transaction_id}    - Get single transaction detail
    GET  /api/hosts/{host_id}/transactions     - Per-host transaction timeline

Architecture Notes:
    - Uses QueryBuilder for all SELECT queries (SQL injection prevention)
    - Read-only: no INSERT/UPDATE/DELETE operations
    - All endpoints require GUEST or higher role (read-only access)

Security Notes:
    - All endpoints require JWT authentication
    - RBAC decorators on all endpoints
    - QueryBuilder prevents SQL injection
    - framework_refs JSONB queried via PostgreSQL ? operator
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.rbac import UserRole, require_role
from app.schemas.transaction_schemas import RuleSummaryListResponse, TransactionDetailResponse, TransactionListResponse
from app.utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/transactions", tags=["Transactions"])

# Separate router for host-scoped endpoints so the path is /api/hosts/{host_id}/transactions
host_transactions_router = APIRouter(tags=["Transactions"])

# Columns returned for list views (excludes large JSONB phase-state columns)
_LIST_COLUMNS = (
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
)

# All columns including phase-state payloads (detail view)
_DETAIL_COLUMNS = _LIST_COLUMNS + (
    "pre_state",
    "apply_plan",
    "validate_result",
    "post_state",
    "baseline_id",
    "remediation_job_id",
)


def _apply_common_filters(
    builder: QueryBuilder,
    status: Optional[str],
    severity: Optional[str],
    phase: Optional[str],
    rule_id: Optional[str],
    initiator_type: Optional[str],
    started_after: Optional[datetime],
    started_before: Optional[datetime],
) -> QueryBuilder:
    """Apply shared filter parameters to a QueryBuilder instance.

    Args:
        builder: QueryBuilder to add filters to.
        status: Filter by transaction status.
        severity: Filter by severity level.
        phase: Filter by transaction phase.
        rule_id: Filter by rule ID.
        initiator_type: Filter by initiator type (scheduler, user, etc.).
        started_after: Only transactions started after this timestamp.
        started_before: Only transactions started before this timestamp.

    Returns:
        The same QueryBuilder with filters applied (for chaining).
    """
    if status:
        builder.where("status = :status", status, "status")
    if severity:
        builder.where("severity = :severity", severity, "severity")
    if phase:
        builder.where("phase = :phase", phase, "phase")
    if rule_id:
        builder.where("rule_id = :rule_id", rule_id, "rule_id")
    if initiator_type:
        builder.where("initiator_type = :initiator_type", initiator_type, "initiator_type")
    if started_after:
        builder.where("started_at >= :started_after", started_after, "started_after")
    if started_before:
        builder.where("started_at <= :started_before", started_before, "started_before")
    return builder


def _parse_jsonb(val: Any) -> Optional[Dict]:
    """Parse a JSONB column value that may be a string or already a dict."""
    if val is None:
        return None
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        import json

        try:
            return json.loads(val)
        except (json.JSONDecodeError, ValueError):
            return None
    return None


def _row_to_transaction_response(row: Any) -> Dict[str, Any]:
    """Convert a database row to a dict suitable for TransactionResponse.

    Args:
        row: SQLAlchemy row result.

    Returns:
        Dictionary matching TransactionResponse fields.
    """
    return {
        "id": row.id,
        "host_id": row.host_id,
        "rule_id": row.rule_id,
        "scan_id": row.scan_id,
        "phase": row.phase,
        "status": row.status,
        "severity": row.severity,
        "initiator_type": row.initiator_type,
        "initiator_id": row.initiator_id,
        "evidence_envelope": _parse_jsonb(row.evidence_envelope),
        "framework_refs": _parse_jsonb(row.framework_refs),
        "started_at": row.started_at,
        "completed_at": row.completed_at,
        "duration_ms": row.duration_ms,
    }


# =============================================================================
# RULES SUMMARY (must be before /{transaction_id} to avoid path collision)
# =============================================================================

_ALL_ROLES = [
    UserRole.GUEST,
    UserRole.AUDITOR,
    UserRole.COMPLIANCE_OFFICER,
    UserRole.SECURITY_ANALYST,
    UserRole.SECURITY_ADMIN,
    UserRole.SUPER_ADMIN,
]


@require_role(_ALL_ROLES)
@router.get("/rules", response_model=RuleSummaryListResponse)
async def list_rules_summary(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None, description="Filter to rules with at least one host in this status"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """List unique rules with compliance state summary across all hosts."""
    try:
        offset = (page - 1) * per_page

        where_clauses = []
        params: Dict[str, Any] = {"lim": per_page, "off": offset}

        if severity:
            where_clauses.append("hrs.severity = :sev")
            params["sev"] = severity

        having_clause = ""
        if status == "fail":
            having_clause = "HAVING COUNT(*) FILTER (WHERE hrs.current_status = 'fail') > 0"
        elif status == "pass":
            having_clause = "HAVING COUNT(*) FILTER (WHERE hrs.current_status = 'pass') > 0"

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        data_sql = text(
            f"""
            SELECT
                hrs.rule_id,
                hrs.severity,
                COUNT(*) as host_count,
                COUNT(*) FILTER (WHERE hrs.current_status = 'pass') as hosts_passing,
                COUNT(*) FILTER (WHERE hrs.current_status = 'fail') as hosts_failing,
                COUNT(*) FILTER (WHERE hrs.current_status = 'skipped') as hosts_skipped,
                MAX(hrs.last_checked_at) as last_checked_at,
                MAX(hrs.last_changed_at) as last_changed_at,
                SUM(hrs.check_count) as total_checks,
                COALESCE(tc.change_count, 0) as change_count
            FROM host_rule_state hrs
            LEFT JOIN (
                SELECT rule_id, COUNT(*) as change_count
                FROM transactions
                GROUP BY rule_id
            ) tc ON tc.rule_id = hrs.rule_id
            {where_sql}
            GROUP BY hrs.rule_id, hrs.severity, tc.change_count
            {having_clause}
            ORDER BY hosts_failing DESC, hrs.rule_id ASC
            LIMIT :lim OFFSET :off
        """
        )

        count_sql = text(
            f"""
            SELECT COUNT(*) FROM (
                SELECT hrs.rule_id
                FROM host_rule_state hrs
                {where_sql}
                GROUP BY hrs.rule_id, hrs.severity
                {having_clause}
            ) sub
        """
        )

        rows = db.execute(data_sql, params).fetchall()
        total = db.execute(count_sql, params).scalar() or 0

        items = []
        for r in rows:
            items.append(
                {
                    "rule_id": r.rule_id,
                    "severity": r.severity,
                    "host_count": r.host_count,
                    "hosts_passing": r.hosts_passing,
                    "hosts_failing": r.hosts_failing,
                    "hosts_skipped": r.hosts_skipped,
                    "change_count": r.change_count,
                    "last_checked_at": r.last_checked_at,
                    "last_changed_at": r.last_changed_at,
                    "total_checks": r.total_checks,
                }
            )

        return {"items": items, "total": total, "page": page, "per_page": per_page}

    except Exception as e:
        logger.error("Error listing rules summary: %s", e)
        raise HTTPException(status_code=500, detail="Failed to list rules summary")


@require_role(_ALL_ROLES)
@router.get("/rules/{rule_id}")
async def get_rule_transactions(
    rule_id: str,
    host_id: Optional[UUID] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """List state-change transactions for a specific rule across hosts."""
    try:
        offset = (page - 1) * per_page
        params: Dict[str, Any] = {"rid": rule_id, "lim": per_page, "off": offset}

        host_filter = ""
        if host_id:
            host_filter = "AND t.host_id = :hid"
            params["hid"] = str(host_id)

        data_sql = text(
            f"""
            SELECT t.*, h.display_name as host_name, h.hostname
            FROM transactions t
            JOIN hosts h ON h.id = t.host_id
            WHERE t.rule_id = :rid {host_filter}
            ORDER BY t.started_at DESC
            LIMIT :lim OFFSET :off
        """
        )

        count_sql = text(
            f"""
            SELECT COUNT(*) FROM transactions t
            WHERE t.rule_id = :rid {host_filter}
        """
        )

        rows = db.execute(data_sql, params).fetchall()
        total = db.execute(count_sql, params).scalar() or 0

        items = []
        for r in rows:
            items.append(
                {
                    "id": r.id,
                    "host_id": r.host_id,
                    "host_name": r.host_name or r.hostname,
                    "rule_id": r.rule_id,
                    "scan_id": r.scan_id,
                    "phase": r.phase,
                    "status": r.status,
                    "severity": r.severity,
                    "initiator_type": r.initiator_type,
                    "initiator_id": r.initiator_id,
                    "evidence_envelope": _parse_jsonb(r.evidence_envelope),
                    "framework_refs": _parse_jsonb(r.framework_refs),
                    "started_at": r.started_at,
                    "completed_at": r.completed_at,
                    "duration_ms": r.duration_ms,
                }
            )

        return {"items": items, "total": total, "page": page, "per_page": per_page}

    except Exception as e:
        logger.error("Error getting rule transactions for %s: %s", rule_id, e)
        raise HTTPException(status_code=500, detail="Failed to get rule transactions")


# =============================================================================
# LIST TRANSACTIONS
# =============================================================================


@require_role(
    [
        UserRole.GUEST,
        UserRole.AUDITOR,
        UserRole.COMPLIANCE_OFFICER,
        UserRole.SECURITY_ANALYST,
        UserRole.SECURITY_ADMIN,
        UserRole.SUPER_ADMIN,
    ]
)
@router.get("", response_model=TransactionListResponse)
async def list_transactions(
    host_id: Optional[UUID] = Query(None, description="Filter by host UUID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    phase: Optional[str] = Query(None, description="Filter by phase"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    framework: Optional[str] = Query(None, description="Filter by framework key in framework_refs JSONB"),
    initiator_type: Optional[str] = Query(None, description="Filter by initiator type"),
    started_after: Optional[datetime] = Query(None, description="Only transactions started after this timestamp"),
    started_before: Optional[datetime] = Query(None, description="Only transactions started before this timestamp"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> TransactionListResponse:
    """List transactions with optional filtering and pagination.

    Returns a paginated list of transactions. Supports filtering by host,
    status, severity, phase, rule, framework, initiator, and time range.

    The ``framework`` filter uses the PostgreSQL ``?`` operator to check
    whether the given key exists in the ``framework_refs`` JSONB column.
    """
    try:
        builder = QueryBuilder("transactions").select(*_LIST_COLUMNS)

        if host_id:
            builder.where("host_id = :host_id", str(host_id), "host_id")

        _apply_common_filters(
            builder,
            status,
            severity,
            phase,
            rule_id,
            initiator_type,
            started_after,
            started_before,
        )

        if framework:
            builder.where("framework_refs ? :framework_param", framework, "framework_param")

        builder.order_by("started_at", "DESC").paginate(page, per_page)

        query, params = builder.build()
        result = db.execute(text(query), params)
        items = [_row_to_transaction_response(row) for row in result]

        # Count query with same filters
        count_builder = QueryBuilder("transactions")
        if host_id:
            count_builder.where("host_id = :host_id", str(host_id), "host_id")
        _apply_common_filters(
            count_builder,
            status,
            severity,
            phase,
            rule_id,
            initiator_type,
            started_after,
            started_before,
        )
        if framework:
            count_builder.where("framework_refs ? :framework_param", framework, "framework_param")
        count_query, count_params = count_builder.count_query()
        total_result = db.execute(text(count_query), count_params).fetchone()
        total: int = total_result.total if total_result else 0

        return TransactionListResponse(items=items, total=total, page=page, per_page=per_page)

    except Exception as e:
        logger.error("Error listing transactions: %s", e)
        raise HTTPException(status_code=500, detail="Failed to retrieve transactions")


# =============================================================================
# GET SINGLE TRANSACTION
# =============================================================================


@require_role(
    [
        UserRole.GUEST,
        UserRole.AUDITOR,
        UserRole.COMPLIANCE_OFFICER,
        UserRole.SECURITY_ANALYST,
        UserRole.SECURITY_ADMIN,
        UserRole.SUPER_ADMIN,
    ]
)
@router.get("/{transaction_id}", response_model=TransactionDetailResponse)
async def get_transaction(
    transaction_id: UUID,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> TransactionDetailResponse:
    """Get a single transaction by ID with full detail.

    Returns all transaction fields including phase-state JSONB payloads
    (pre_state, apply_plan, validate_result, post_state).

    Raises:
        HTTPException 404: Transaction not found.
    """
    try:
        builder = QueryBuilder("transactions").select(*_DETAIL_COLUMNS).where("id = :id", str(transaction_id), "id")
        query, params = builder.build()
        row = db.execute(text(query), params).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Transaction not found")

        data = _row_to_transaction_response(row)
        data["pre_state"] = _parse_jsonb(row.pre_state)
        data["apply_plan"] = _parse_jsonb(row.apply_plan)
        data["validate_result"] = _parse_jsonb(row.validate_result)
        data["post_state"] = _parse_jsonb(row.post_state)
        data["baseline_id"] = row.baseline_id
        data["remediation_job_id"] = row.remediation_job_id

        return TransactionDetailResponse(**data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting transaction %s: %s", transaction_id, e)
        raise HTTPException(status_code=500, detail="Failed to retrieve transaction")


# =============================================================================
# PER-HOST TRANSACTION TIMELINE
# =============================================================================


@require_role(
    [
        UserRole.GUEST,
        UserRole.AUDITOR,
        UserRole.COMPLIANCE_OFFICER,
        UserRole.SECURITY_ANALYST,
        UserRole.SECURITY_ADMIN,
        UserRole.SUPER_ADMIN,
    ]
)
@host_transactions_router.get(
    "/api/hosts/{host_id}/transactions",
    response_model=TransactionListResponse,
)
async def list_host_transactions(
    host_id: UUID,
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    phase: Optional[str] = Query(None, description="Filter by phase"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    framework: Optional[str] = Query(None, description="Filter by framework key in framework_refs JSONB"),
    initiator_type: Optional[str] = Query(None, description="Filter by initiator type"),
    started_after: Optional[datetime] = Query(None, description="Only transactions started after this timestamp"),
    started_before: Optional[datetime] = Query(None, description="Only transactions started before this timestamp"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> TransactionListResponse:
    """List transactions for a specific host, ordered by started_at DESC.

    This endpoint provides a per-host compliance timeline. It supports
    the same filters as the global list endpoint except host_id
    (which is taken from the path).
    """
    try:
        builder = (
            QueryBuilder("transactions").select(*_LIST_COLUMNS).where("host_id = :host_id", str(host_id), "host_id")
        )

        _apply_common_filters(
            builder,
            status,
            severity,
            phase,
            rule_id,
            initiator_type,
            started_after,
            started_before,
        )

        if framework:
            builder.where("framework_refs ? :framework_param", framework, "framework_param")

        builder.order_by("started_at", "DESC").paginate(page, per_page)

        query, params = builder.build()
        result = db.execute(text(query), params)
        items = [_row_to_transaction_response(row) for row in result]

        # Count query
        count_builder = QueryBuilder("transactions").where("host_id = :host_id", str(host_id), "host_id")
        _apply_common_filters(
            count_builder,
            status,
            severity,
            phase,
            rule_id,
            initiator_type,
            started_after,
            started_before,
        )
        if framework:
            count_builder.where("framework_refs ? :framework_param", framework, "framework_param")
        count_query, count_params = count_builder.count_query()
        total_result = db.execute(text(count_query), count_params).fetchone()
        total: int = total_result.total if total_result else 0

        return TransactionListResponse(items=items, total=total, page=page, per_page=per_page)

    except Exception as e:
        logger.error("Error listing transactions for host %s: %s", host_id, e)
        raise HTTPException(status_code=500, detail="Failed to retrieve host transactions")


__all__ = ["router", "host_transactions_router"]
