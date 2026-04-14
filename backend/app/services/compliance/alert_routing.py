"""
Alert Routing Service for per-severity notification dispatch.

Determines which notification channels receive an alert based on routing
rules stored in the alert_routing_rules table.  Supports fan-out (multiple
rules matching a single alert) and a default fallback to all enabled
channels when no specific rules match (AC-6).

PagerDuty channel integration is handled by the PagerDutyChannel class
in app.services.notifications.pagerduty.

Spec: specs/services/compliance/alert-routing.spec.yaml
"""

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.utils.mutation_builders import DeleteBuilder, InsertBuilder
from app.utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)

# Valid severity values for routing rules
VALID_SEVERITIES = {"critical", "high", "medium", "low", "all"}

# Valid alert type constant for wildcard matching
ALL_TYPES = "all"


class AlertRoutingService:
    """Service for managing and evaluating alert routing rules.

    Routing rules map (severity, alert_type) pairs to notification
    channels.  When dispatching, the service finds all matching rules
    for an alert and returns the corresponding channel IDs (fan-out).
    If no rules match, it returns None to signal that the caller should
    fall back to all enabled channels (default behaviour per AC-6).
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Dispatch helpers
    # ------------------------------------------------------------------

    def resolve_channels(
        self,
        severity: str,
        alert_type: str,
    ) -> Optional[List[str]]:
        """Resolve notification channel IDs for a given alert.

        Queries alert_routing_rules for enabled rules matching the
        alert's severity and type (including wildcard 'all' matches).
        Multiple rules can match a single alert (fan-out, AC-3).

        Args:
            severity: Alert severity (critical, high, medium, low).
            alert_type: Alert type string.

        Returns:
            List of channel_id strings if matching rules exist,
            or None if no rules match (caller should use default
            fallback to all enabled channels per AC-6).
        """
        query = text(
            """
            SELECT DISTINCT arr.channel_id
            FROM alert_routing_rules arr
            WHERE arr.enabled = true
            AND (arr.severity = :severity OR arr.severity = 'all')
            AND (arr.alert_type = :alert_type OR arr.alert_type = 'all')
        """
        )

        rows = self.db.execute(
            query,
            {"severity": severity, "alert_type": alert_type},
        ).fetchall()

        if not rows:
            # No matching rules -- default fallback (AC-6)
            return None

        return [str(row.channel_id) for row in rows]

    # ------------------------------------------------------------------
    # CRUD operations (AC-5)
    # ------------------------------------------------------------------

    def list_rules(self) -> List[Dict[str, Any]]:
        """List all routing rules ordered by creation time (newest first)."""
        builder = QueryBuilder("alert_routing_rules").order_by("created_at", "DESC")
        query, params = builder.build()
        rows = self.db.execute(text(query), params).fetchall()
        return [_row_to_dict(row) for row in rows]

    def create_rule(
        self,
        severity: str,
        alert_type: str,
        channel_id: UUID,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """Create a new routing rule.

        Args:
            severity: One of critical, high, medium, low, all.
            alert_type: Alert type string or 'all'.
            channel_id: UUID of the target notification channel.
            enabled: Whether the rule is active.

        Returns:
            The created rule as a dict.
        """
        builder = (
            InsertBuilder("alert_routing_rules")
            .columns("severity", "alert_type", "channel_id", "enabled")
            .values(severity, alert_type, str(channel_id), enabled)
            .returning("id", "severity", "alert_type", "channel_id", "enabled", "created_at")
        )
        query, params = builder.build()
        row = self.db.execute(text(query), params).fetchone()
        self.db.commit()
        logger.info(
            "Created alert routing rule %s: severity=%s type=%s channel=%s",
            row.id,
            severity,
            alert_type,
            channel_id,
        )
        return _row_to_dict(row)

    def delete_rule(self, rule_id: UUID) -> bool:
        """Delete a routing rule by ID.

        Args:
            rule_id: UUID of the rule to delete.

        Returns:
            True if the rule was deleted, False if not found.
        """
        builder = DeleteBuilder("alert_routing_rules").where("id = :id", str(rule_id), "id").returning("id")
        query, params = builder.build()
        row = self.db.execute(text(query), params).fetchone()
        self.db.commit()
        if row:
            logger.info("Deleted alert routing rule %s", rule_id)
            return True
        return False


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """Convert a DB row to a plain dict."""
    return {
        "id": str(row.id),
        "severity": row.severity,
        "alert_type": row.alert_type,
        "channel_id": str(row.channel_id),
        "enabled": row.enabled,
        "created_at": str(row.created_at) if row.created_at else None,
    }


def get_alert_routing_service(db: Session) -> AlertRoutingService:
    """Factory for AlertRoutingService."""
    return AlertRoutingService(db)
