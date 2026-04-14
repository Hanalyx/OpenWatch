"""Transaction log retention policy enforcement.

Provides configurable retention periods per resource type with a default
of 365 days for transactions.  Expired rows are deleted via the
``enforce()`` method which is called on schedule by the job queue.

Important:
    - host_rule_state rows are NEVER deleted -- they represent current
      compliance posture and must be preserved regardless of retention
      policies.
    - Before deletion, a signed archive bundle should be emitted to
      configured storage (future enhancement -- see AC-4).

Spec: specs/services/compliance/retention-policy.spec.yaml
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.utils.mutation_builders import DeleteBuilder, InsertBuilder
from app.utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

# Default retention period in days for each known resource type.
DEFAULT_RETENTION_DAYS = 365

# Mapping of resource_type -> (table_name, timestamp_column).
# host_rule_state is intentionally excluded -- current state is always kept.
RESOURCE_TABLE_MAP: Dict[str, Dict[str, str]] = {
    "transactions": {
        "table": "transactions",
        "timestamp_column": "started_at",
    },
    "audit_exports": {
        "table": "audit_exports",
        "timestamp_column": "created_at",
    },
    "posture_snapshots": {
        "table": "posture_snapshots",
        "timestamp_column": "snapshot_date",
    },
}


class RetentionService:
    """Manage and enforce data retention policies.

    Each policy governs how long rows in a specific resource table are
    kept before they are eligible for cleanup.  Enforcement deletes
    rows whose timestamp is older than ``NOW() - retention_days``.

    Args:
        db: SQLAlchemy Session for database access.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_policies(self, tenant_id: Optional[UUID] = None) -> List[Dict[str, Any]]:
        """Return all retention policies, optionally filtered by tenant.

        Args:
            tenant_id: If provided, only return policies for this tenant
                       (plus global policies where tenant_id IS NULL).

        Returns:
            List of policy dicts with id, tenant_id, resource_type,
            retention_days, enabled, created_at, updated_at.
        """
        builder = QueryBuilder("retention_policies").select(
            "id",
            "tenant_id",
            "resource_type",
            "retention_days",
            "enabled",
            "created_at",
            "updated_at",
        )
        if tenant_id is not None:
            builder.where(
                "(tenant_id = :tid OR tenant_id IS NULL)",
                tenant_id,
                "tid",
            )
        builder.order_by("resource_type", "ASC")

        query, params = builder.build()
        rows = self.db.execute(text(query), params).fetchall()
        return [dict(r._mapping) for r in rows]

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def set_policy(
        self,
        resource_type: str,
        retention_days: int,
        tenant_id: Optional[UUID] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """Create or update a retention policy (upsert).

        Args:
            resource_type: Resource governed by this policy
                (e.g. 'transactions', 'audit_exports', 'posture_snapshots').
            retention_days: Number of days to retain rows.
            tenant_id: Optional tenant scope (None = global).
            enabled: Whether enforcement is active.

        Returns:
            The upserted policy row as a dict.
        """
        builder = (
            InsertBuilder("retention_policies")
            .columns(
                "tenant_id",
                "resource_type",
                "retention_days",
                "enabled",
            )
            .values(tenant_id, resource_type, retention_days, enabled)
            .on_conflict_do_update(
                conflict_cols=["tenant_id", "resource_type"],
                update_cols=["retention_days", "enabled"],
            )
            .returning("id", "tenant_id", "resource_type", "retention_days", "enabled", "created_at", "updated_at")
        )
        query, params = builder.build()
        row = self.db.execute(text(query), params).fetchone()
        self.db.commit()
        return dict(row._mapping)

    # ------------------------------------------------------------------
    # Enforce
    # ------------------------------------------------------------------

    def enforce(self) -> Dict[str, int]:
        """Delete expired records based on enabled retention policies.

        For each enabled policy the method calculates a cutoff date
        (``NOW() - retention_days``) and deletes rows older than that
        cutoff from the corresponding resource table.

        host_rule_state rows are never deleted -- current compliance
        posture is always preserved.

        Before deletion a signed archive bundle should be emitted
        (future enhancement -- stub logs a placeholder for now).

        Returns:
            Dict mapping resource_type to the number of deleted rows.
        """
        policies = self._get_enabled_policies()
        counts: Dict[str, int] = {}

        for policy in policies:
            resource_type: str = policy["resource_type"]
            retention_days: int = policy["retention_days"]

            mapping = RESOURCE_TABLE_MAP.get(resource_type)
            if mapping is None:
                logger.warning(
                    "No table mapping for resource_type=%s, skipping",
                    resource_type,
                )
                continue

            table = mapping["table"]
            ts_col = mapping["timestamp_column"]
            cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

            # AC-4: archive placeholder (signed bundle -- future enhancement)
            logger.info(
                "Retention: archive step placeholder for %s (cutoff=%s)",
                resource_type,
                cutoff.isoformat(),
            )

            deleted = self._delete_expired(table, ts_col, cutoff)
            counts[resource_type] = deleted
            logger.info(
                "Retention: deleted %d expired rows from %s (cutoff=%s)",
                deleted,
                table,
                cutoff.isoformat(),
            )

        self.db.commit()
        return counts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_enabled_policies(self) -> List[Dict[str, Any]]:
        """Fetch all enabled retention policies."""
        builder = (
            QueryBuilder("retention_policies")
            .select("resource_type", "retention_days")
            .where("enabled = :enabled", True, "enabled")
        )
        query, params = builder.build()
        rows = self.db.execute(text(query), params).fetchall()
        return [dict(r._mapping) for r in rows]

    def _delete_expired(self, table: str, ts_col: str, cutoff: datetime) -> int:
        """Delete rows older than *cutoff* from *table*.

        Uses DeleteBuilder with a WHERE clause (never build_unsafe).

        Args:
            table: Target table name.
            ts_col: Timestamp column to compare against cutoff.
            cutoff: Rows with timestamp < cutoff are deleted.

        Returns:
            Number of deleted rows.
        """
        builder = DeleteBuilder(table).where(f"{ts_col} < :cutoff", cutoff, "cutoff")
        query, params = builder.build()
        result = self.db.execute(text(query), params)
        return result.rowcount
