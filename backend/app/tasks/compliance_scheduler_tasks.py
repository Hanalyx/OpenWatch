"""
Adaptive Compliance Scheduler Tasks for Celery Beat

This module implements the dispatcher pattern for the adaptive compliance scanning scheduler.
The dispatcher is called periodically by Celery Beat and queues individual Aegis scan tasks.

Architecture:
1. Celery Beat calls dispatch_compliance_scans() every 2 minutes
2. Dispatcher queries host_compliance_schedule WHERE next_scheduled_scan <= NOW()
3. Individual Aegis scan tasks dispatched with state-based priority
4. Each task updates compliance state and calculates next_scheduled_scan (max 48 hours)

This design ensures:
- Continuous compliance visibility (max 48 hour interval)
- Adaptive intervals (low-compliance hosts scanned more frequently)
- Resource-aware (respects max_concurrent_scans limit)
- Scalable to many hosts (distributed across time)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import UUID

from app.celery_app import celery_app
from app.database import get_db

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="app.tasks.dispatch_compliance_scans",
    time_limit=120,
    soft_time_limit=90,
)
def dispatch_compliance_scans(self: Any) -> Dict[str, Any]:
    """
    Dispatcher task that runs every 2 minutes via Celery Beat.

    Queries hosts that are due for compliance scanning and dispatches
    individual Aegis scan tasks with appropriate priorities.

    Returns:
        dict: Dispatch results including number of hosts dispatched
    """
    # Import here to avoid circular imports
    from app.services.compliance.compliance_scheduler import compliance_scheduler_service

    try:
        logger.debug("Running compliance scan dispatcher...")

        # Get database session
        db = next(get_db())

        try:
            # Check if scheduler is enabled
            config = compliance_scheduler_service.get_config(db)

            if not config["enabled"]:
                logger.debug("Compliance scheduler is disabled, skipping dispatch")
                return {"status": "disabled", "hosts_dispatched": 0}

            # Get hosts due for scanning (respects max_concurrent_scans)
            hosts_due = compliance_scheduler_service.get_hosts_due_for_scan(db)

            if not hosts_due:
                logger.debug("No hosts due for compliance scanning")
                return {"status": "ok", "hosts_dispatched": 0, "next_scan": "none due"}

            # Dispatch individual scan tasks with priorities
            dispatched_count = 0
            for host in hosts_due:
                try:
                    priority = host["scan_priority"]

                    # Dispatch individual Aegis scan task
                    celery_app.send_task(
                        "app.tasks.run_scheduled_aegis_scan",
                        args=[host["host_id"], priority],
                        priority=priority,
                        queue="compliance_scanning",
                    )

                    dispatched_count += 1
                    logger.debug(
                        f"Dispatched compliance scan for {host['hostname']} "
                        f"(state: {host['compliance_state']}, priority: {priority})"
                    )

                except Exception as dispatch_error:
                    logger.error(f"Failed to dispatch scan for host {host['host_id']}: {dispatch_error}")

            logger.info(f"Dispatched {dispatched_count} compliance scans")

            return {
                "status": "ok",
                "hosts_dispatched": dispatched_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error in compliance scan dispatcher: {e}")
        return {"status": "error", "error": str(e), "hosts_dispatched": 0}


@celery_app.task(
    bind=True,
    name="app.tasks.run_scheduled_aegis_scan",
    time_limit=660,  # 11 minutes (scan timeout + buffer)
    soft_time_limit=600,  # 10 minutes
)
def run_scheduled_aegis_scan(self: Any, host_id: str, priority: int = 5) -> Dict[str, Any]:
    """
    Execute an Aegis compliance scan for a host (scheduled by dispatcher).

    This task is dispatched by the compliance scheduler when a host is due
    for scanning. It runs the Aegis scan and updates the compliance schedule.

    Args:
        host_id: UUID of the host to scan
        priority: Scan priority (1-10)

    Returns:
        dict: Scan results including compliance score
    """
    # Import here to avoid circular imports
    from app.services.compliance.compliance_scheduler import compliance_scheduler_service

    try:
        logger.info(f"Starting scheduled Aegis scan for host {host_id}")

        db = next(get_db())

        try:
            # Import Aegis scanner
            try:
                from app.plugins.aegis.scanner import AegisScanner

                scanner = AegisScanner()
            except ImportError:
                logger.error("Aegis scanner not available")
                compliance_scheduler_service.record_scan_failure(db, UUID(host_id), "Aegis scanner not available")
                return {"status": "error", "error": "Aegis scanner not available"}

            # Get host details
            from sqlalchemy import text

            result = db.execute(
                text(
                    """
                    SELECT id, hostname, ip_address, port, username
                    FROM hosts
                    WHERE id = :host_id AND is_active = true
                """
                ),
                {"host_id": host_id},
            )
            host = result.fetchone()

            if not host:
                logger.warning(f"Host {host_id} not found or inactive")
                return {"status": "error", "error": "Host not found"}

            # Run Aegis scan with system info, packages, and services collection
            logger.info(f"Running Aegis scan on {host.hostname}")

            import asyncio

            async def run_scan():
                """Initialize scanner and run scan with server intelligence collection."""
                await scanner.initialize()
                return await scanner.scan(
                    host_id=host_id,
                    db=db,
                    collect_system_info=True,
                    collect_packages=True,
                    collect_services=True,
                )

            # Create event loop for async scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                scan_result = loop.run_until_complete(run_scan())
            finally:
                loop.close()

            # Check if scan failed
            if scan_result.get("status") == "error":
                error_msg = scan_result.get("error", "Unknown error")
                logger.error(f"Aegis scan failed for {host.hostname}: {error_msg}")
                compliance_scheduler_service.record_scan_failure(db, UUID(host_id), error_msg)
                return {"status": "error", "host_id": host_id, "error": error_msg}

            # Extract results - Aegis returns 'passed' and 'failed', not 'pass_count'
            compliance_score = scan_result.get("compliance_score", 0.0)
            pass_count = scan_result.get("passed", 0)
            fail_count = scan_result.get("failed", 0)

            # Count critical findings from results list
            results_list = scan_result.get("results", [])
            critical_count = sum(
                1 for r in results_list if not r.get("passed") and r.get("severity") in ["critical", "high"]
            )

            has_critical = critical_count > 0

            # Save system info, packages, and services if collected
            system_info = scan_result.get("system_info")
            packages = scan_result.get("packages")
            services = scan_result.get("services")

            if system_info or packages or services:
                try:
                    from app.services.system_info import SystemInfoService

                    system_info_service = SystemInfoService(db)

                    if system_info:
                        system_info_service.save_system_info(UUID(host_id), system_info)
                        logger.debug(f"Saved system info for {host.hostname}")

                    if packages:
                        count = system_info_service.save_packages(UUID(host_id), packages)
                        logger.debug(f"Saved {count} packages for {host.hostname}")

                    if services:
                        count = system_info_service.save_services(UUID(host_id), services)
                        logger.debug(f"Saved {count} services for {host.hostname}")
                except Exception as e:
                    logger.warning(f"Failed to save server intelligence data: {e}")

            # Update schedule with new compliance state
            compliance_scheduler_service.update_host_schedule(
                db=db,
                host_id=UUID(host_id),
                compliance_score=compliance_score,
                has_critical_findings=has_critical,
                pass_count=pass_count,
                fail_count=fail_count,
                scan_id=None,  # Aegis doesn't create a scan record
            )

            logger.info(
                f"Completed scheduled scan for {host.hostname}: "
                f"score={compliance_score}%, pass={pass_count}, fail={fail_count}"
            )

            return {
                "status": "ok",
                "host_id": host_id,
                "hostname": host.hostname,
                "compliance_score": compliance_score,
                "pass_count": pass_count,
                "fail_count": fail_count,
                "has_critical": has_critical,
                "critical_count": critical_count,
                "system_info_collected": system_info is not None,
                "packages_collected": len(packages) if packages else 0,
                "services_collected": len(services) if services else 0,
            }

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error in scheduled Aegis scan for host {host_id}: {e}")

        # Record failure
        try:
            db = next(get_db())
            from app.services.compliance.compliance_scheduler import compliance_scheduler_service

            compliance_scheduler_service.record_scan_failure(db, UUID(host_id), str(e))
            db.close()
        except Exception:
            pass

        return {"status": "error", "host_id": host_id, "error": str(e)}


@celery_app.task(
    bind=True,
    name="app.tasks.initialize_compliance_schedules",
    time_limit=300,
    soft_time_limit=240,
)
def initialize_compliance_schedules(self: Any) -> Dict[str, Any]:
    """
    Initialize compliance schedules for all hosts that don't have one.

    This task should be run once after deploying the compliance scheduler
    to bootstrap schedules for existing hosts.

    Returns:
        dict: Number of hosts initialized
    """
    from sqlalchemy import text

    from app.services.compliance.compliance_scheduler import compliance_scheduler_service

    try:
        logger.info("Initializing compliance schedules for existing hosts...")

        db = next(get_db())

        try:
            # Find hosts without a schedule
            result = db.execute(
                text(
                    """
                    SELECT h.id
                    FROM hosts h
                    LEFT JOIN host_compliance_schedule hcs ON h.id = hcs.host_id
                    WHERE h.is_active = true
                      AND hcs.id IS NULL
                """
                )
            )

            hosts = result.fetchall()
            initialized_count = 0

            for host in hosts:
                compliance_scheduler_service.initialize_host_schedule(db, host.id)
                initialized_count += 1

            logger.info(f"Initialized compliance schedules for {initialized_count} hosts")

            return {
                "status": "ok",
                "hosts_initialized": initialized_count,
            }

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error initializing compliance schedules: {e}")
        return {"status": "error", "error": str(e)}


@celery_app.task(
    bind=True,
    name="app.tasks.expire_compliance_maintenance",
    time_limit=60,
    soft_time_limit=45,
)
def expire_compliance_maintenance(self: Any) -> Dict[str, Any]:
    """
    Expire maintenance mode for hosts past their maintenance_until time.

    This task runs hourly to automatically end maintenance windows.

    Returns:
        dict: Number of hosts expired
    """
    from sqlalchemy import text

    try:
        logger.debug("Checking for expired compliance maintenance windows...")

        db = next(get_db())

        try:
            result = db.execute(
                text(
                    """
                    UPDATE host_compliance_schedule
                    SET maintenance_mode = false,
                        maintenance_until = NULL,
                        updated_at = :now
                    WHERE maintenance_mode = true
                      AND maintenance_until IS NOT NULL
                      AND maintenance_until < :now
                    RETURNING host_id
                """
                ),
                {"now": datetime.now(timezone.utc)},
            )

            expired_hosts = result.fetchall()
            db.commit()

            if expired_hosts:
                logger.info(f"Expired maintenance mode for {len(expired_hosts)} hosts")

            return {
                "status": "ok",
                "hosts_expired": len(expired_hosts),
            }

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error expiring maintenance windows: {e}")
        return {"status": "error", "error": str(e)}
