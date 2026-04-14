"""
Celery tasks for host liveness monitoring.

Provides a periodic ping task that checks TCP connectivity to all
managed hosts' SSH ports every 5 minutes, independent of compliance
scan cadence.

Spec: specs/services/monitoring/host-liveness.spec.yaml
"""

import logging

from sqlalchemy import text

from app.database import SessionLocal
from app.services.monitoring.liveness import LivenessService

logger = logging.getLogger(__name__)


def ping_all_managed_hosts():
    """
    Ping all non-maintenance-mode hosts. Scheduled every 5 minutes via Celery Beat.

    Queries all active hosts that are not in maintenance mode and performs
    a TCP connect check on each host's SSH port (default 22). Results are
    recorded in the host_liveness table.
    """
    db = SessionLocal()
    try:
        # Query all active hosts NOT in maintenance mode
        # Note: hosts table does not have ssh_port; default to 22
        rows = db.execute(
            text(
                "SELECT h.id, h.hostname "
                "FROM hosts h "
                "LEFT JOIN host_schedule hcs ON hcs.host_id = h.id "
                "WHERE h.is_active = true "
                "AND (hcs.maintenance_mode IS NULL OR hcs.maintenance_mode = false)"
            )
        ).fetchall()

        if not rows:
            logger.debug("No active non-maintenance hosts to ping")
            return {"pinged": 0, "skipped_maintenance": True}

        service = LivenessService()
        results = {"pinged": 0, "reachable": 0, "unreachable": 0, "errors": 0}

        for row in rows:
            host_id = str(row.id)
            hostname = row.hostname
            try:
                result = service.ping_host(db, host_id, hostname, ssh_port=22)
                results["pinged"] += 1
                if result["reachability_status"] == "reachable":
                    results["reachable"] += 1
                else:
                    results["unreachable"] += 1
            except Exception as exc:
                logger.error(
                    "Error pinging host %s (%s): %s",
                    host_id,
                    hostname,
                    exc,
                )
                results["errors"] += 1

        logger.info(
            "Liveness sweep complete: %d pinged, %d reachable, " "%d unreachable, %d errors",
            results["pinged"],
            results["reachable"],
            results["unreachable"],
            results["errors"],
        )
        return results

    except Exception as exc:
        logger.exception("ping_all_managed_hosts failed: %s", exc)
        raise
    finally:
        db.close()
