"""
Host liveness monitoring service.

Provides TCP-based heartbeat checks for managed hosts, independent of
compliance scan cadence. Detects unreachable hosts within 5 minutes and
triggers HOST_UNREACHABLE / HOST_RECOVERED alerts on state transitions.

Spec: specs/services/monitoring/host-liveness.spec.yaml

Usage:
    from app.services.monitoring.liveness import LivenessService

    service = LivenessService()
    result = service.ping_host(db, host_id, hostname, ssh_port=22)
"""

import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.compliance.alerts import AlertService, AlertSeverity, AlertType
from app.utils.mutation_builders import InsertBuilder, UpdateBuilder

logger = logging.getLogger(__name__)


class LivenessService:
    """
    TCP-based host liveness monitoring.

    Pings each managed host's SSH port with a 5-second timeout.
    No authentication, no command execution -- pure TCP connect check.
    """

    def ping_host(
        self,
        db: Session,
        host_id: str,
        hostname: str,
        ssh_port: int = 22,
    ) -> Dict[str, Any]:
        """
        TCP connect to host's SSH port with 5s timeout. No auth, no commands.

        Args:
            db: Database session.
            host_id: UUID of the host.
            hostname: Hostname or IP address.
            ssh_port: SSH port number (default 22).

        Returns:
            Dict with updated liveness state.
        """
        start = datetime.now(timezone.utc)
        try:
            sock = socket.create_connection((hostname, ssh_port), timeout=5)
            sock.close()
            response_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
            return self._update_liveness(db, host_id, True, response_ms)
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.debug(
                "Ping failed for host %s (%s:%d): %s",
                host_id,
                hostname,
                ssh_port,
                exc,
            )
            return self._update_liveness(db, host_id, False, None)

    def _update_liveness(
        self,
        db: Session,
        host_id: str,
        success: bool,
        response_ms: Optional[int],
    ) -> Dict[str, Any]:
        """
        Update host_liveness row, handling state transitions and alerts.

        Uses an UPSERT pattern: INSERT on first ping, UPDATE thereafter.
        On success: reachability_status='reachable', consecutive_failures=0.
        On failure: increment consecutive_failures; if >= 2 set 'unreachable'.
        State transitions trigger HOST_UNREACHABLE / HOST_RECOVERED alerts.

        Args:
            db: Database session.
            host_id: UUID of the host.
            success: Whether the TCP ping succeeded.
            response_ms: Round-trip time in milliseconds (None on failure).

        Returns:
            Dict with the current liveness state.
        """
        now = datetime.now(timezone.utc)

        # Read current state
        row = db.execute(
            text("SELECT reachability_status, consecutive_failures " "FROM host_liveness WHERE host_id = :host_id"),
            {"host_id": host_id},
        ).fetchone()

        old_status = row.reachability_status if row else "unknown"
        old_failures = row.consecutive_failures if row else 0

        if success:
            new_status = "reachable"
            new_failures = 0
        else:
            new_failures = old_failures + 1
            if new_failures >= 2:
                new_status = "unreachable"
            else:
                # Keep previous status until threshold reached
                new_status = old_status if old_status != "unknown" else "unknown"

        state_changed = new_status != old_status
        state_change_at = now if state_changed else None

        if row is None:
            # First ping for this host -- INSERT
            builder = (
                InsertBuilder("host_liveness")
                .columns(
                    "host_id",
                    "last_ping_at",
                    "last_response_ms",
                    "reachability_status",
                    "consecutive_failures",
                    "last_state_change_at",
                )
                .values(
                    host_id,
                    now,
                    response_ms,
                    new_status,
                    new_failures,
                    state_change_at,
                )
                .on_conflict_do_update(
                    ["host_id"],
                    [
                        "last_ping_at",
                        "last_response_ms",
                        "reachability_status",
                        "consecutive_failures",
                        "last_state_change_at",
                    ],
                )
            )
            query, params = builder.build()
            db.execute(text(query), params)
        else:
            # Existing row -- UPDATE
            builder = (
                UpdateBuilder("host_liveness")
                .set("last_ping_at", now)
                .set("last_response_ms", response_ms)
                .set("reachability_status", new_status)
                .set("consecutive_failures", new_failures)
                .where("host_id = :host_id", host_id, "host_id")
            )
            if state_changed:
                builder.set("last_state_change_at", now)
            query, params = builder.build()
            db.execute(text(query), params)

        db.commit()

        # Fire alerts on state transitions
        if state_changed:
            self._handle_state_transition(
                db,
                host_id,
                old_status,
                new_status,
            )

        return {
            "host_id": host_id,
            "reachability_status": new_status,
            "consecutive_failures": new_failures,
            "last_response_ms": response_ms,
            "last_ping_at": now.isoformat(),
        }

    def _handle_state_transition(
        self,
        db: Session,
        host_id: str,
        old_status: str,
        new_status: str,
    ) -> None:
        """
        Create alerts when reachability state transitions occur.

        Args:
            db: Database session.
            host_id: UUID of the host.
            old_status: Previous reachability status.
            new_status: New reachability status.
        """
        alert_service = AlertService(db)

        if new_status == "unreachable" and old_status in ("reachable", "unknown"):
            # HOST_UNREACHABLE alert
            logger.warning(
                "Host %s transitioned to unreachable (was %s)",
                host_id,
                old_status,
            )
            alert_service.create_alert(
                alert_type=AlertType.HOST_UNREACHABLE,
                severity=AlertSeverity.CRITICAL,
                title=f"Host unreachable: {host_id}",
                message=(f"Host {host_id} became unreachable after 2 consecutive " f"failed TCP pings to SSH port."),
                host_id=UUID(host_id),
                metadata={"previous_status": old_status},
            )

        elif new_status == "reachable" and old_status == "unreachable":
            # HOST_RECOVERED alert
            logger.info(
                "Host %s recovered (was unreachable)",
                host_id,
            )
            alert_service.create_alert(
                alert_type=AlertType.HOST_RECOVERED,
                severity=AlertSeverity.INFO,
                title=f"Host recovered: {host_id}",
                message=(f"Host {host_id} is reachable again after being unreachable."),
                host_id=UUID(host_id),
                metadata={"previous_status": old_status},
            )

    def get_liveness(self, db: Session, host_id: str) -> Optional[Dict[str, Any]]:
        """
        Get current liveness state for a host.

        Args:
            db: Database session.
            host_id: UUID of the host.

        Returns:
            Dict with liveness data, or None if no record exists.
        """
        row = db.execute(
            text(
                "SELECT host_id, last_ping_at, last_response_ms, "
                "reachability_status, consecutive_failures, last_state_change_at "
                "FROM host_liveness WHERE host_id = :host_id"
            ),
            {"host_id": host_id},
        ).fetchone()

        if not row:
            return None

        return {
            "host_id": str(row.host_id),
            "last_ping_at": row.last_ping_at.isoformat() if row.last_ping_at else None,
            "last_response_ms": row.last_response_ms,
            "reachability_status": row.reachability_status,
            "consecutive_failures": row.consecutive_failures,
            "last_state_change_at": (row.last_state_change_at.isoformat() if row.last_state_change_at else None),
        }
