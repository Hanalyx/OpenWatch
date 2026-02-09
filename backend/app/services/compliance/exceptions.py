"""
Compliance Exception Service

Manages structured exceptions with approval workflows.

Part of Phase 3: Governance Primitives (Aegis Integration Plan)

OS Claim: "Exceptions are explicit state, not narrative artifacts"
"""

import logging
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Row
from sqlalchemy.orm import Session

from ...database import ComplianceException
from ...schemas.exception_schemas import (
    ExceptionCheckResponse,
    ExceptionListResponse,
    ExceptionResponse,
    ExceptionSummary,
)
from ...utils.mutation_builders import InsertBuilder, UpdateBuilder
from ...utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)


class ExceptionService:
    """
    Service for managing compliance exceptions.

    Provides CRUD operations and workflow management for exceptions:
    - Request: Create pending exception
    - Approve: Approve pending exception (admin only)
    - Reject: Reject pending exception (admin only)
    - Revoke: Revoke approved exception (admin only)
    - Check: Check if rule is excepted for host
    """

    def __init__(self, db: Session):
        self.db = db

    def request_exception(
        self,
        rule_id: str,
        host_id: Optional[UUID],
        host_group_id: Optional[UUID],
        justification: str,
        duration_days: int,
        requested_by: int,
        risk_acceptance: Optional[str] = None,
        compensating_controls: Optional[str] = None,
        business_impact: Optional[str] = None,
    ) -> Optional[ComplianceException]:
        """
        Create a new exception request (status: pending).

        Args:
            rule_id: Rule ID to except
            host_id: Specific host (mutually exclusive with host_group_id)
            host_group_id: Host group (mutually exclusive with host_id)
            justification: Business justification
            duration_days: Exception duration in days
            requested_by: User ID requesting exception
            risk_acceptance: Optional risk acceptance statement
            compensating_controls: Optional compensating controls
            business_impact: Optional business impact statement

        Returns:
            Created exception or None if validation fails
        """
        # Validate scope - must have host_id or host_group_id
        if not host_id and not host_group_id:
            logger.warning("Exception request rejected: no scope provided")
            return None

        # Calculate expiration date
        expires_at = datetime.now(timezone.utc) + timedelta(days=duration_days)

        # Check for existing active exception
        existing = self._find_active_exception(rule_id, host_id, host_group_id)
        if existing:
            logger.warning(
                "Exception request rejected: active exception already exists for rule %s",
                rule_id,
            )
            return None

        # Create exception
        from uuid import uuid4

        exception_id = uuid4()

        builder = (
            InsertBuilder("compliance_exceptions")
            .columns(
                "id",
                "rule_id",
                "host_id",
                "host_group_id",
                "justification",
                "risk_acceptance",
                "compensating_controls",
                "business_impact",
                "status",
                "requested_by",
                "requested_at",
                "expires_at",
            )
            .values(
                exception_id,
                rule_id,
                host_id,
                host_group_id,
                justification,
                risk_acceptance,
                compensating_controls,
                business_impact,
                "pending",
                requested_by,
                datetime.now(timezone.utc),
                expires_at,
            )
            .returning("id")
        )

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        self.db.commit()

        row = result.fetchone()
        if row:
            logger.info(
                "Exception requested: %s for rule %s by user %d",
                exception_id,
                rule_id,
                requested_by,
            )
            return self.get_exception(exception_id)

        return None

    def approve_exception(
        self,
        exception_id: UUID,
        approved_by: int,
    ) -> Optional[ComplianceException]:
        """
        Approve a pending exception.

        Args:
            exception_id: Exception ID to approve
            approved_by: User ID approving exception

        Returns:
            Updated exception or None if not found/invalid status
        """
        exception = self.get_exception(exception_id)
        if not exception:
            return None

        if exception.status != "pending":
            logger.warning(
                "Cannot approve exception %s: status is %s, not pending",
                exception_id,
                exception.status,
            )
            return None

        builder = (
            UpdateBuilder("compliance_exceptions")
            .set("status", "approved")
            .set("approved_by", approved_by)
            .set("approved_at", datetime.now(timezone.utc))
            .set_raw("updated_at", "CURRENT_TIMESTAMP")
            .where("id = :id", exception_id, "id")
            .returning("id")
        )

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        self.db.commit()

        row = result.fetchone()
        if row:
            logger.info(
                "Exception approved: %s by user %d",
                exception_id,
                approved_by,
            )
            return self.get_exception(exception_id)

        return None

    def reject_exception(
        self,
        exception_id: UUID,
        rejected_by: int,
        reason: str,
    ) -> Optional[ComplianceException]:
        """
        Reject a pending exception.

        Args:
            exception_id: Exception ID to reject
            rejected_by: User ID rejecting exception
            reason: Rejection reason

        Returns:
            Updated exception or None if not found/invalid status
        """
        exception = self.get_exception(exception_id)
        if not exception:
            return None

        if exception.status != "pending":
            logger.warning(
                "Cannot reject exception %s: status is %s, not pending",
                exception_id,
                exception.status,
            )
            return None

        builder = (
            UpdateBuilder("compliance_exceptions")
            .set("status", "rejected")
            .set("rejected_by", rejected_by)
            .set("rejected_at", datetime.now(timezone.utc))
            .set("rejection_reason", reason)
            .set_raw("updated_at", "CURRENT_TIMESTAMP")
            .where("id = :id", exception_id, "id")
            .returning("id")
        )

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        self.db.commit()

        row = result.fetchone()
        if row:
            logger.info(
                "Exception rejected: %s by user %d - %s",
                exception_id,
                rejected_by,
                reason,
            )
            return self.get_exception(exception_id)

        return None

    def revoke_exception(
        self,
        exception_id: UUID,
        revoked_by: int,
        reason: str,
    ) -> Optional[ComplianceException]:
        """
        Revoke an approved exception.

        Args:
            exception_id: Exception ID to revoke
            revoked_by: User ID revoking exception
            reason: Revocation reason

        Returns:
            Updated exception or None if not found/invalid status
        """
        exception = self.get_exception(exception_id)
        if not exception:
            return None

        if exception.status != "approved":
            logger.warning(
                "Cannot revoke exception %s: status is %s, not approved",
                exception_id,
                exception.status,
            )
            return None

        builder = (
            UpdateBuilder("compliance_exceptions")
            .set("status", "revoked")
            .set("revoked_by", revoked_by)
            .set("revoked_at", datetime.now(timezone.utc))
            .set("revocation_reason", reason)
            .set_raw("updated_at", "CURRENT_TIMESTAMP")
            .where("id = :id", exception_id, "id")
            .returning("id")
        )

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        self.db.commit()

        row = result.fetchone()
        if row:
            logger.info(
                "Exception revoked: %s by user %d - %s",
                exception_id,
                revoked_by,
                reason,
            )
            return self.get_exception(exception_id)

        return None

    def get_exception(self, exception_id: UUID) -> Optional[ComplianceException]:
        """Get exception by ID."""
        builder = QueryBuilder("compliance_exceptions").where("id = :id", exception_id, "id")
        query, params = builder.build()
        result = self.db.execute(text(query), params)
        row = result.fetchone()

        if row:
            return self._row_to_exception(row)
        return None

    def list_exceptions(
        self,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        host_id: Optional[UUID] = None,
    ) -> ExceptionListResponse:
        """
        List exceptions with pagination and filtering.

        Args:
            page: Page number (1-indexed)
            per_page: Items per page
            status: Filter by status
            rule_id: Filter by rule ID
            host_id: Filter by host ID

        Returns:
            Paginated exception list
        """
        builder = QueryBuilder("compliance_exceptions")

        if status:
            builder.where("status = :status", status, "status")
        if rule_id:
            builder.where("rule_id = :rule_id", rule_id, "rule_id")
        if host_id:
            builder.where("host_id = :host_id", host_id, "host_id")

        # Get total count
        count_query, count_params = builder.count_query()
        count_result = self.db.execute(text(count_query), count_params)
        total = count_result.scalar() or 0

        # Get paginated results
        builder.order_by("created_at", "DESC")
        builder.paginate(page, per_page)
        data_query, data_params = builder.build()
        result = self.db.execute(text(data_query), data_params)
        rows = result.fetchall()

        exceptions = [self._row_to_response(row) for row in rows]

        return ExceptionListResponse(
            items=exceptions,
            total=total,
            page=page,
            per_page=per_page,
            total_pages=ceil(total / per_page) if total > 0 else 1,
        )

    def get_summary(self) -> ExceptionSummary:
        """Get exception statistics summary."""
        query = """
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as total_pending,
                COUNT(*) FILTER (WHERE status = 'approved') as total_approved,
                COUNT(*) FILTER (WHERE status = 'rejected') as total_rejected,
                COUNT(*) FILTER (WHERE status = 'expired') as total_expired,
                COUNT(*) FILTER (WHERE status = 'revoked') as total_revoked,
                COUNT(*) FILTER (
                    WHERE status = 'approved'
                    AND expires_at <= :expiring_threshold
                ) as expiring_soon
            FROM compliance_exceptions
        """
        expiring_threshold = datetime.now(timezone.utc) + timedelta(days=30)
        result = self.db.execute(text(query), {"expiring_threshold": expiring_threshold})
        row = result.fetchone()

        if row:
            return ExceptionSummary(
                total_pending=row.total_pending or 0,
                total_approved=row.total_approved or 0,
                total_rejected=row.total_rejected or 0,
                total_expired=row.total_expired or 0,
                total_revoked=row.total_revoked or 0,
                expiring_soon=row.expiring_soon or 0,
            )

        return ExceptionSummary()

    def is_excepted(self, rule_id: str, host_id: UUID) -> ExceptionCheckResponse:
        """
        Check if a rule is currently excepted for a host.

        Checks both direct host exceptions and host group exceptions.

        Args:
            rule_id: Rule ID to check
            host_id: Host ID to check

        Returns:
            ExceptionCheckResponse with exception status
        """
        now = datetime.now(timezone.utc)

        # Check direct host exception first
        query = """
            SELECT id, expires_at, justification
            FROM compliance_exceptions
            WHERE rule_id = :rule_id
              AND host_id = :host_id
              AND status = 'approved'
              AND expires_at > :now
            LIMIT 1
        """
        result = self.db.execute(text(query), {"rule_id": rule_id, "host_id": host_id, "now": now})
        row = result.fetchone()

        if row:
            return ExceptionCheckResponse(
                is_excepted=True,
                exception_id=row.id,
                expires_at=row.expires_at,
                justification=row.justification,
            )

        # Check host group exception
        query = """
            SELECT ce.id, ce.expires_at, ce.justification
            FROM compliance_exceptions ce
            JOIN host_group_memberships hgm ON ce.host_group_id = hgm.group_id
            WHERE ce.rule_id = :rule_id
              AND hgm.host_id = :host_id
              AND ce.status = 'approved'
              AND ce.expires_at > :now
            LIMIT 1
        """
        result = self.db.execute(text(query), {"rule_id": rule_id, "host_id": host_id, "now": now})
        row = result.fetchone()

        if row:
            return ExceptionCheckResponse(
                is_excepted=True,
                exception_id=row.id,
                expires_at=row.expires_at,
                justification=row.justification,
            )

        return ExceptionCheckResponse(is_excepted=False)

    def expire_exceptions(self) -> int:
        """
        Mark expired exceptions as expired.

        Called by scheduled task to maintain exception lifecycle.

        Returns:
            Number of exceptions expired
        """
        now = datetime.now(timezone.utc)

        builder = (
            UpdateBuilder("compliance_exceptions")
            .set("status", "expired")
            .set_raw("updated_at", "CURRENT_TIMESTAMP")
            .where("status = :status", "approved", "status")
            .where("expires_at <= :now", now, "now")
            .returning("id")
        )

        query, params = builder.build()
        result = self.db.execute(text(query), params)
        self.db.commit()

        expired_count = len(result.fetchall())
        if expired_count > 0:
            logger.info("Expired %d exceptions", expired_count)

        return expired_count

    def _find_active_exception(
        self,
        rule_id: str,
        host_id: Optional[UUID],
        host_group_id: Optional[UUID],
    ) -> Optional[Row[Any]]:
        """Find existing active (approved or pending) exception."""
        query = """
            SELECT id FROM compliance_exceptions
            WHERE rule_id = :rule_id
              AND status IN ('pending', 'approved')
        """
        params: Dict[str, Any] = {"rule_id": rule_id}

        if host_id:
            query += " AND host_id = :host_id"
            params["host_id"] = host_id
        if host_group_id:
            query += " AND host_group_id = :host_group_id"
            params["host_group_id"] = host_group_id

        result = self.db.execute(text(query), params)
        return result.fetchone()

    def _row_to_exception(self, row: Row[Any]) -> ComplianceException:
        """Convert database row to ComplianceException model."""
        exception = ComplianceException()
        for key in row._fields:
            setattr(exception, key, getattr(row, key))
        return exception

    def _row_to_response(self, row: Row[Any]) -> ExceptionResponse:
        """Convert database row to ExceptionResponse."""
        now = datetime.now(timezone.utc)

        # Determine if exception is currently active
        is_active = row.status == "approved" and row.expires_at > now

        # Calculate days until expiry
        days_until_expiry = None
        if is_active:
            delta = row.expires_at - now
            days_until_expiry = max(0, delta.days)

        return ExceptionResponse(
            id=row.id,
            rule_id=row.rule_id,
            host_id=row.host_id,
            host_group_id=row.host_group_id,
            justification=row.justification,
            risk_acceptance=row.risk_acceptance,
            compensating_controls=row.compensating_controls,
            business_impact=row.business_impact,
            status=row.status,
            requested_by=row.requested_by,
            requested_at=row.requested_at,
            approved_by=row.approved_by,
            approved_at=row.approved_at,
            rejected_by=row.rejected_by,
            rejected_at=row.rejected_at,
            rejection_reason=row.rejection_reason,
            expires_at=row.expires_at,
            revoked_by=row.revoked_by,
            revoked_at=row.revoked_at,
            revocation_reason=row.revocation_reason,
            created_at=row.created_at,
            updated_at=row.updated_at,
            is_active=is_active,
            days_until_expiry=days_until_expiry,
        )


__all__ = ["ExceptionService"]
