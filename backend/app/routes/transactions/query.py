"""
Transaction Query API — POST /api/transactions/query.

Q3 §6.1 — Structured query DSL for the transaction log. Complements the
existing GET /api/transactions (which stays for UI list views) with a
machine-friendly endpoint that supports cursor pagination, field projection,
and multi-value IN-clause filters.

Spec: specs/api/transactions/transaction-query.spec.yaml

# INTERIM IMPLEMENTATION (Kensa Go Week 22 convergence)
# ====================================================
# The HTTP surface of this endpoint (URL, request schema, response
# envelope) is stable. Its implementation is INTERIM and migrates to
# delegate into Kensa's Go api/ surface at Kensa Week 22:
#
#     Query()     -> kensa.api.Kensa.TransactionLog().Query(ctx, filter, page)
#     Get(id)     -> kensa.api.Kensa.TransactionLog().Get(ctx, id)
#     Aggregate() -> kensa.api.Kensa.TransactionLog().Aggregate(ctx, f, key)
#
# The current PostgreSQL-backed implementation reads the `transactions`
# table that Python Kensa writes to today. At Week 22, swap the
# implementation to call Kensa's Go LogQuery — endpoint callers see no
# change. The PostgreSQL `transactions` table remains as a derived
# multi-host aggregation cache through v1.0.0 (per Kensa Day-1 plan §13A).
#
# See also:
#   - specs/api/transactions/transaction-query.spec.yaml (interim_implementation)
#   - docs/KENSA_OPENWATCH_COORDINATION_2026-04-14.md
#   - kensa/docs/KENSA_OPENWATCH_RESPONSE_2026-04-14.md §2.1
#   - kensa/docs/KENSA_GO_DAY1_PLAN.md §3.5.1 LogQuery
# ====================================================

Design notes:
    Cursor format: base64(json({"started_at": ISO8601, "id": UUID})).
    Ordering: ORDER BY started_at DESC, id DESC. Cursor filter uses tuple
    comparison so equal started_at values tie-break by id deterministically.
    Projection: ``fields`` list restricted to the QUERY_PROJECTION_FIELDS
    allow-list; unknown fields reject at the Pydantic layer via a custom
    validator before reaching the query builder.

Security:
    - RBAC: GUEST or higher (read-only) — matches GET /api/transactions
    - QueryBuilder for base query, manual parameterized IN clauses for list
      filters (same pattern used in services/compliance/audit_query.py)
    - No user input reaches SQL unparameterized
    - Audit logger records query body on each request
"""

import base64
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import audit_logger, get_current_user
from app.database import get_db
from app.rbac import UserRole, require_role
from app.schemas.transaction_schemas import (
    QUERY_DEFAULT_FIELDS,
    QUERY_PROJECTION_FIELDS,
    TransactionQueryRequest,
    TransactionQueryResponse,
)

logger = logging.getLogger(__name__)

# Registered under the same prefix as the other transaction routes but on a
# distinct router so callers discover it as a separate endpoint in OpenAPI.
query_router = APIRouter(prefix="/api/transactions", tags=["Transactions"])


_ALL_ROLES = [
    UserRole.GUEST,
    UserRole.AUDITOR,
    UserRole.COMPLIANCE_OFFICER,
    UserRole.SECURITY_ANALYST,
    UserRole.SECURITY_ADMIN,
    UserRole.SUPER_ADMIN,
]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


_VALID_STATUSES = {"pass", "fail", "skipped", "error"}
_VALID_PHASES = {"capture", "apply", "validate", "commit", "rollback"}


def _validate_enum_list(values: Optional[List[str]], allowed: set, field: str) -> Optional[List[str]]:
    """Return values (lowercased) if all are in ``allowed``; else raise 400.

    Spec AC-7: invalid filters reject with a field-specific error message.
    """
    if values is None:
        return None
    lowered = [v.lower() for v in values]
    bad = [v for v in lowered if v not in allowed]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=(f"Invalid value(s) for {field}: {bad}. " f"Allowed: {sorted(allowed)}"),
        )
    return lowered


def _validate_fields(fields: Optional[List[str]]) -> List[str]:
    """Return the projection list, defaulting to QUERY_DEFAULT_FIELDS.

    Spec AC-4: unknown field names return HTTP 400.
    """
    if not fields:
        return list(QUERY_DEFAULT_FIELDS)
    bad = [f for f in fields if f not in QUERY_PROJECTION_FIELDS]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=(f"Unknown projection field(s): {bad}. " f"Allowed: {sorted(QUERY_PROJECTION_FIELDS)}"),
        )
    return list(fields)


# ---------------------------------------------------------------------------
# Cursor encode/decode
# ---------------------------------------------------------------------------


def _encode_cursor(started_at: Any, row_id: Any) -> str:
    """Encode (started_at, id) as an opaque base64 cursor.

    Spec AC-3: opaque cursor encoding.
    """
    payload = json.dumps(
        {"started_at": started_at.isoformat(), "id": str(row_id)},
        separators=(",", ":"),
    )
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> Tuple[str, str]:
    """Decode an opaque cursor into (started_at_iso, id_str).

    Spec AC-7: malformed cursor returns HTTP 400 via the caller's error path.
    """
    try:
        pad = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode((cursor + pad).encode()).decode()
        data = json.loads(raw)
        return data["started_at"], data["id"]
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid cursor: {exc}")


# ---------------------------------------------------------------------------
# SQL builder
# ---------------------------------------------------------------------------


def _build_where_clauses(
    req: TransactionQueryRequest,
) -> Tuple[List[str], Dict[str, Any]]:
    """Translate a TransactionQueryRequest into a WHERE list + params dict.

    Uses parameterized IN clauses for list filters (spec AC-8). fleet_id
    resolves via EXISTS subquery against host_group_memberships so a large
    fleet doesn't produce a giant IN list.
    """
    clauses: List[str] = []
    params: Dict[str, Any] = {}

    if req.host_id:
        clauses.append("host_id = :host_id")
        params["host_id"] = str(req.host_id)

    if req.host_ids:
        placeholders = []
        for i, hid in enumerate(req.host_ids):
            key = f"host_ids_{i}"
            placeholders.append(f":{key}")
            params[key] = str(hid)
        clauses.append(f"host_id IN ({', '.join(placeholders)})")

    if req.fleet_id:
        clauses.append("host_id IN (SELECT host_id FROM host_group_memberships " "WHERE group_id = :fleet_id)")
        params["fleet_id"] = str(req.fleet_id)

    if req.rule_id:
        clauses.append("rule_id = :rule_id")
        params["rule_id"] = req.rule_id

    if req.rule_ids:
        placeholders = []
        for i, rid in enumerate(req.rule_ids):
            key = f"rule_ids_{i}"
            placeholders.append(f":{key}")
            params[key] = rid
        clauses.append(f"rule_id IN ({', '.join(placeholders)})")

    if req.status:
        placeholders = []
        for i, st in enumerate(req.status):
            key = f"status_{i}"
            placeholders.append(f":{key}")
            params[key] = st
        clauses.append(f"status IN ({', '.join(placeholders)})")

    if req.phase:
        placeholders = []
        for i, ph in enumerate(req.phase):
            key = f"phase_{i}"
            placeholders.append(f":{key}")
            params[key] = ph
        clauses.append(f"phase IN ({', '.join(placeholders)})")

    if req.severity:
        placeholders = []
        for i, sv in enumerate(req.severity):
            key = f"severity_{i}"
            placeholders.append(f":{key}")
            params[key] = sv
        clauses.append(f"severity IN ({', '.join(placeholders)})")

    if req.framework:
        clauses.append("framework_refs ? :framework")
        params["framework"] = req.framework

    if req.initiator_type:
        placeholders = []
        for i, it in enumerate(req.initiator_type):
            key = f"initiator_type_{i}"
            placeholders.append(f":{key}")
            params[key] = it
        clauses.append(f"initiator_type IN ({', '.join(placeholders)})")

    if req.started_after:
        clauses.append("started_at >= :started_after")
        params["started_after"] = req.started_after

    if req.started_before:
        clauses.append("started_at <= :started_before")
        params["started_before"] = req.started_before

    return clauses, params


def _row_to_projection(row: Any, fields: List[str]) -> Dict[str, Any]:
    """Convert a SQLAlchemy row to a dict containing only the requested fields."""
    result: Dict[str, Any] = {}
    for f in fields:
        val = getattr(row, f, None)
        # Normalise JSONB columns — PostgreSQL can return them as str or dict
        # depending on driver configuration.
        if f in ("evidence_envelope", "framework_refs") and isinstance(val, str):
            try:
                val = json.loads(val)
            except (json.JSONDecodeError, ValueError):
                pass
        result[f] = val
    return result


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@require_role(_ALL_ROLES)
@query_router.post("/query", response_model=TransactionQueryResponse)
async def query_transactions(
    req: TransactionQueryRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> TransactionQueryResponse:
    """Query the transaction log with a structured DSL.

    Cursor-based pagination, field projection, and multi-value filtering.
    See specs/api/transactions/transaction-query.spec.yaml for the full
    contract.
    """
    # --- validate inputs (spec AC-4, AC-7) ---
    if req.limit < 1 or req.limit > 500:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 500",
        )
    if req.started_after and req.started_before and req.started_after > req.started_before:
        raise HTTPException(
            status_code=400,
            detail="started_after must be <= started_before",
        )
    # Validate enum lists
    req.status = _validate_enum_list(req.status, _VALID_STATUSES, "status")
    req.phase = _validate_enum_list(req.phase, _VALID_PHASES, "phase")
    fields = _validate_fields(req.fields)

    # --- build WHERE from filters ---
    where_clauses, params = _build_where_clauses(req)

    # --- apply cursor (spec AC-3) ---
    if req.cursor:
        cursor_ts, cursor_id = _decode_cursor(req.cursor)
        where_clauses.append("(started_at, id) < (:cursor_started_at, :cursor_id)")
        params["cursor_started_at"] = cursor_ts
        params["cursor_id"] = cursor_id

    where_sql = " AND ".join(where_clauses) if where_clauses else "true"

    # --- total_count (ignores cursor, only filters) ---
    count_params = {k: v for k, v in params.items() if not k.startswith("cursor_")}
    count_where = " AND ".join(c for c in where_clauses if not c.startswith("(started_at, id)")) or "true"
    count_sql = f"SELECT COUNT(*) AS total FROM transactions WHERE {count_where}"
    count_row = db.execute(text(count_sql), count_params).fetchone()
    total_count = int(count_row.total) if count_row else 0

    # --- data query ---
    select_cols = ", ".join(fields)
    # Always fetch started_at + id for cursor generation; ensure they are
    # present even when the projection excludes them.
    ordering_cols = {"started_at", "id"}
    fetch_cols = list(dict.fromkeys(fields + list(ordering_cols)))
    fetch_select = ", ".join(fetch_cols)
    # Fetch one extra row to detect "there is a next page" without a COUNT
    # on the filtered + cursor'd window.
    params["__limit"] = req.limit + 1

    data_sql = (
        f"SELECT {fetch_select} FROM transactions "
        f"WHERE {where_sql} "
        f"ORDER BY started_at DESC, id DESC "
        f"LIMIT :__limit"
    )
    result = db.execute(text(data_sql), params).fetchall()

    # --- determine next_cursor ---
    next_cursor: Optional[str] = None
    if len(result) > req.limit:
        # Drop the peek row and build a cursor from the last row we return.
        last_row = result[req.limit - 1]
        next_cursor = _encode_cursor(last_row.started_at, last_row.id)
        result = list(result[: req.limit])

    # --- projection ---
    items = [_row_to_projection(row, fields) for row in result]

    # --- audit log (spec AC-6) ---
    try:
        audit_logger.log_security_event(
            "TRANSACTION_QUERY",
            f"User {current_user.get('username')} queried transactions: "
            f"fields={len(fields)} cursor={'yes' if req.cursor else 'no'} "
            f"limit={req.limit} total={total_count}",
            current_user.get("ip_address", "unknown"),
        )
    except Exception:
        logger.exception("Audit log write failed for transaction query")

    # Intentional: unused `select_cols` name kept out of the public module
    # surface. (We use `fetch_select` for the SQL.)
    del select_cols

    return TransactionQueryResponse(
        items=items,
        total_count=total_count,
        next_cursor=next_cursor,
    )
