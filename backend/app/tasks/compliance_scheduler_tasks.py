"""
Adaptive Compliance Scheduler Tasks for Celery Beat

This module implements the dispatcher pattern for the adaptive compliance scanning scheduler.
The dispatcher is called periodically by Celery Beat and queues individual Kensa scan tasks.

Architecture:
1. Celery Beat calls dispatch_compliance_scans() every 2 minutes
2. Dispatcher queries host_compliance_schedule WHERE next_scheduled_scan <= NOW()
3. Individual Kensa scan tasks dispatched with state-based priority
4. Each task updates compliance state and calculates next_scheduled_scan (max 48 hours)

This design ensures:
- Continuous compliance visibility (max 48 hour interval)
- Adaptive intervals (low-compliance hosts scanned more frequently)
- Resource-aware (respects max_concurrent_scans limit)
- Scalable to many hosts (distributed across time)
"""

import logging
import uuid as uuid_module
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict
from uuid import UUID

from sqlalchemy import text

from app.celery_app import celery_app
from app.database import get_db
from app.plugins.kensa.evidence import serialize_evidence, serialize_framework_refs
from app.utils.mutation_builders import InsertBuilder, UpdateBuilder

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
    individual Kensa scan tasks with appropriate priorities.

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

                    # Dispatch individual Kensa scan task
                    celery_app.send_task(
                        "app.tasks.run_scheduled_kensa_scan",
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
    name="app.tasks.run_scheduled_kensa_scan",
    time_limit=660,  # 11 minutes (scan timeout + buffer)
    soft_time_limit=600,  # 10 minutes
)
def run_scheduled_kensa_scan(self: Any, host_id: str, priority: int = 5) -> Dict[str, Any]:
    """
    Execute a Kensa compliance scan for a host (scheduled by dispatcher).

    This task is dispatched by the compliance scheduler when a host is due
    for scanning. It runs the Kensa scan, stores results in the scans and
    scan_findings tables (for frontend compatibility), and updates the
    compliance schedule.

    Args:
        host_id: UUID of the host to scan
        priority: Scan priority (1-10)

    Returns:
        dict: Scan results including compliance score and scan_id
    """
    from app.services.compliance.compliance_scheduler import compliance_scheduler_service

    scan_uuid = uuid_module.uuid4()
    scan_id = str(scan_uuid)
    start_time = datetime.now(timezone.utc)

    try:
        logger.info(f"Starting scheduled Kensa scan {scan_id} for host {host_id}")

        db = next(get_db())

        try:
            # Import Kensa scanner
            try:
                from app.plugins.kensa.scanner import KensaScanner

                scanner = KensaScanner()
            except ImportError:
                logger.error("Kensa scanner not available")
                compliance_scheduler_service.record_scan_failure(db, UUID(host_id), "Kensa scanner not available")
                return {"status": "error", "error": "Kensa scanner not available"}

            # Get host details
            result = db.execute(
                text(
                    """
                    SELECT id, hostname, display_name, ip_address, port, username
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

            # Create scan record in database BEFORE running scan
            scan_name = f"Scheduled Kensa Scan - {host.hostname} - {start_time.strftime('%Y-%m-%d %H:%M')}"
            profile_id = "kensa_scheduled"

            # Kensa content placeholder ID (created in scap_content table)
            kensa_content_id = 1

            insert_builder = (
                InsertBuilder("scans")
                .columns(
                    "id",
                    "name",
                    "host_id",
                    "content_id",
                    "profile_id",
                    "status",
                    "progress",
                    "started_at",
                    "started_by",
                    "scan_options",
                    "remediation_requested",
                    "verification_scan",
                )
                .values(
                    scan_id,
                    scan_name,
                    host_id,
                    kensa_content_id,
                    profile_id,
                    "running",
                    0,
                    start_time,
                    None,  # started_by is NULL for scheduled scans
                    '{"scanner": "kensa", "source": "scheduler"}',
                    False,
                    False,
                )
            )
            insert_query, insert_params = insert_builder.build()
            db.execute(text(insert_query), insert_params)
            db.commit()

            # Run Kensa scan with full server intelligence collection
            logger.info(f"Running Kensa scan on {host.hostname}")

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
                    collect_users=True,
                    collect_network=True,
                    collect_firewall=True,
                    collect_routes=True,
                    collect_audit_events=True,
                    collect_metrics=True,
                )

            # Create event loop for async scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                scan_result = loop.run_until_complete(run_scan())
            finally:
                loop.close()

            end_time = datetime.now(timezone.utc)

            # Check if scan failed
            if scan_result.get("status") == "error":
                error_msg = scan_result.get("error", "Unknown error")
                logger.error(f"Kensa scan failed for {host.hostname}: {error_msg}")

                # Update scan status to failed
                update_builder = (
                    UpdateBuilder("scans")
                    .set("status", "failed")
                    .set("error_message", error_msg[:500] if error_msg else None)
                    .set("completed_at", end_time)
                    .where("id = :id", scan_id, "id")
                )
                update_query, update_params = update_builder.build()
                db.execute(text(update_query), update_params)
                db.commit()

                compliance_scheduler_service.record_scan_failure(db, UUID(host_id), error_msg)
                return {"status": "error", "host_id": host_id, "scan_id": scan_id, "error": error_msg}

            # Extract results - Kensa returns 'passed' and 'failed', not 'pass_count'
            compliance_score = scan_result.get("compliance_score", 0.0)
            pass_count = scan_result.get("passed", 0)
            fail_count = scan_result.get("failed", 0)
            skipped_count = scan_result.get("skipped", 0)
            total_count = pass_count + fail_count + skipped_count

            # Count critical findings from results list
            results_list = scan_result.get("results", [])

            # Calculate severity breakdown
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            severity_passed = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            severity_failed = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            for r in results_list:
                if r.get("skipped"):
                    continue
                sev = (r.get("severity") or "medium").lower()
                if sev not in severity_counts:
                    sev = "medium"
                severity_counts[sev] += 1
                if r.get("passed"):
                    severity_passed[sev] += 1
                else:
                    severity_failed[sev] += 1

            has_critical = severity_failed["critical"] > 0 or severity_failed["high"] > 0

            # Update scan record with completed status
            update_builder = (
                UpdateBuilder("scans")
                .set("status", "completed")
                .set("completed_at", end_time)
                .set("progress", 100)
                .where("id = :id", scan_id, "id")
            )
            update_query, update_params = update_builder.build()
            db.execute(text(update_query), update_params)

            # Insert scan results summary
            results_insert = (
                InsertBuilder("scan_results")
                .columns(
                    "scan_id",
                    "total_rules",
                    "passed_rules",
                    "failed_rules",
                    "error_rules",
                    "unknown_rules",
                    "not_applicable_rules",
                    "score",
                    "severity_high",
                    "severity_medium",
                    "severity_low",
                    "severity_critical",
                    "severity_critical_passed",
                    "severity_critical_failed",
                    "severity_high_passed",
                    "severity_high_failed",
                    "severity_medium_passed",
                    "severity_medium_failed",
                    "severity_low_passed",
                    "severity_low_failed",
                    "created_at",
                )
                .values(
                    scan_id,
                    total_count,
                    pass_count,
                    fail_count,
                    skipped_count,
                    0,
                    0,
                    f"{compliance_score:.2f}",
                    severity_counts["high"],
                    severity_counts["medium"],
                    severity_counts["low"],
                    severity_counts["critical"],
                    severity_passed["critical"],
                    severity_failed["critical"],
                    severity_passed["high"],
                    severity_failed["high"],
                    severity_passed["medium"],
                    severity_failed["medium"],
                    severity_passed["low"],
                    severity_failed["low"],
                    end_time,
                )
            )
            results_query, results_params = results_insert.build()
            db.execute(text(results_query), results_params)

            # Insert individual rule findings into scan_findings table
            for r in results_list:
                status_str = "pass" if r.get("passed") else "fail"
                if r.get("skipped"):
                    status_str = "skipped"

                # Wrap dict as namespace so serialize_evidence/serialize_framework_refs
                # can use getattr() on it (they expect object attributes, not dict keys)
                r_obj = SimpleNamespace(
                    evidence=r.get("evidence"),
                    framework_refs=r.get("framework_refs"),
                )

                finding_insert = (
                    InsertBuilder("scan_findings")
                    .columns(
                        "scan_id",
                        "rule_id",
                        "title",
                        "severity",
                        "status",
                        "detail",
                        "framework_section",
                        "evidence",
                        "framework_refs",
                        "skip_reason",
                        "created_at",
                    )
                    .values(
                        scan_id,
                        r.get("rule_id", "unknown"),
                        (r.get("title") or "Unknown")[:500],
                        r.get("severity") or "medium",
                        status_str,
                        (r.get("detail") or "")[:2000] if r.get("detail") else None,
                        r.get("framework_section"),
                        serialize_evidence(r_obj),
                        serialize_framework_refs(r_obj),
                        r.get("skip_reason") if r.get("skipped") else None,
                        end_time,
                    )
                )
                finding_query, finding_params = finding_insert.build()
                db.execute(text(finding_query), finding_params)

            db.commit()

            # Save server intelligence data if collected
            system_info = scan_result.get("system_info")
            packages = scan_result.get("packages")
            services = scan_result.get("services")
            users = scan_result.get("users")
            network = scan_result.get("network")
            firewall = scan_result.get("firewall")
            routes = scan_result.get("routes")
            audit_events = scan_result.get("audit_events")
            metrics = scan_result.get("metrics")

            if system_info or packages or services or users or network or firewall or routes or audit_events or metrics:
                try:
                    from app.services.system_info import SystemInfoService

                    system_info_service = SystemInfoService(db)

                    if system_info:
                        system_info_service.save_system_info(UUID(host_id), system_info)
                        logger.debug(f"Saved system info for {host.hostname}")

                        # Sync OS info to hosts table for display consistency
                        os_name = system_info.os_name if hasattr(system_info, "os_name") else system_info.get("os_name")
                        os_ver = (
                            system_info.os_version
                            if hasattr(system_info, "os_version")
                            else system_info.get("os_version")
                        )
                        if os_name:
                            os_sync_builder = (
                                UpdateBuilder("hosts")
                                .set("operating_system", os_name)
                                .set_if("os_version", os_ver)
                                .where("id = :id", host_id, "id")
                            )
                            os_sync_query, os_sync_params = os_sync_builder.build()
                            db.execute(text(os_sync_query), os_sync_params)
                            db.commit()
                            logger.debug(f"Synced OS info to hosts table: {os_name} {os_ver or ''}")

                    if packages:
                        count = system_info_service.save_packages(UUID(host_id), packages)
                        logger.debug(f"Saved {count} packages for {host.hostname}")

                    if services:
                        count = system_info_service.save_services(UUID(host_id), services)
                        logger.debug(f"Saved {count} services for {host.hostname}")

                    if users:
                        count = system_info_service.save_users(UUID(host_id), users)
                        logger.debug(f"Saved {count} users for {host.hostname}")

                    if network:
                        count = system_info_service.save_network(UUID(host_id), network)
                        logger.debug(f"Saved {count} network interfaces for {host.hostname}")

                    if firewall:
                        count = system_info_service.save_firewall_rules(UUID(host_id), firewall)
                        logger.debug(f"Saved {count} firewall rules for {host.hostname}")

                    if routes:
                        count = system_info_service.save_routes(UUID(host_id), routes)
                        logger.debug(f"Saved {count} routes for {host.hostname}")

                    if audit_events:
                        count = system_info_service.save_audit_events(UUID(host_id), audit_events)
                        logger.debug(f"Saved {count} audit events for {host.hostname}")

                    if metrics:
                        system_info_service.save_metrics(UUID(host_id), metrics)
                        logger.debug(f"Saved metrics for {host.hostname}")
                except Exception as e:
                    logger.warning(f"Failed to save server intelligence data: {e}")

            # Update schedule with scan timing (compliance data stored in scans table)
            compliance_scheduler_service.update_host_schedule(
                db=db,
                host_id=UUID(host_id),
                compliance_score=compliance_score,
                has_critical_findings=has_critical,
                scan_id=UUID(scan_id),
            )

            # Generate alerts based on scan results
            alerts_generated = 0
            try:
                from app.services.compliance.alert_generator import AlertGenerator

                alert_generator = AlertGenerator(db)
                alerts = alert_generator.process_scan_results(
                    host_id=UUID(host_id),
                    scan_id=None,
                    compliance_score=compliance_score,
                    passed=pass_count,
                    failed=fail_count,
                    results=results_list,
                    hostname=host.hostname,
                )
                alerts_generated = len(alerts)
                if alerts_generated > 0:
                    logger.info(f"Generated {alerts_generated} alerts for {host.hostname}")
            except Exception as alert_error:
                logger.warning(f"Failed to generate alerts for {host.hostname}: {alert_error}")

            logger.info(
                f"Completed scheduled scan {scan_id} for {host.hostname}: "
                f"score={compliance_score}%, pass={pass_count}, fail={fail_count}"
            )

            return {
                "status": "ok",
                "host_id": host_id,
                "scan_id": scan_id,
                "hostname": host.hostname,
                "compliance_score": compliance_score,
                "pass_count": pass_count,
                "fail_count": fail_count,
                "has_critical": has_critical,
                "critical_count": severity_failed["critical"],
                "alerts_generated": alerts_generated,
                "system_info_collected": system_info is not None,
                "packages_collected": len(packages) if packages else 0,
                "services_collected": len(services) if services else 0,
                "users_collected": len(users) if users else 0,
                "network_collected": len(network) if network else 0,
                "firewall_collected": len(firewall) if firewall else 0,
                "routes_collected": len(routes) if routes else 0,
                "audit_events_collected": len(audit_events) if audit_events else 0,
                "metrics_collected": metrics is not None,
            }

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error in scheduled Kensa scan for host {host_id}: {e}")

        # Update scan status to failed if we created one
        try:
            db = next(get_db())
            update_builder = (
                UpdateBuilder("scans")
                .set("status", "failed")
                .set("error_message", str(e)[:500])
                .set("completed_at", datetime.now(timezone.utc))
                .where("id = :id", scan_id, "id")
            )
            update_query, update_params = update_builder.build()
            db.execute(text(update_query), update_params)
            db.commit()

            compliance_scheduler_service.record_scan_failure(db, UUID(host_id), str(e))
            db.close()
        except Exception:
            pass

        return {"status": "error", "host_id": host_id, "scan_id": scan_id, "error": str(e)}


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
                    LEFT JOIN host_schedule hs ON h.id = hs.host_id
                    WHERE h.is_active = true
                      AND hs.id IS NULL
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
                    UPDATE host_schedule
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
