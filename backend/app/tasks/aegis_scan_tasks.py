"""
Celery tasks for Aegis compliance scanning operations.

This module provides async execution of Aegis scans via Celery,
enabling one-click scanning from the UI.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.celery_app import celery_app
from app.database import SessionLocal
from app.services.compliance import TemporalComplianceService
from app.services.monitoring import DriftDetectionService
from app.utils.mutation_builders import InsertBuilder, UpdateBuilder

logger = logging.getLogger(__name__)


def _get_host_platform(db: Session, host_id: str) -> Dict[str, Any]:
    """
    Get platform information for a host.

    Checks host_system_info first, then falls back to hosts.platform_identifier.

    Args:
        db: Database session
        host_id: Host UUID

    Returns:
        Dict with platform, platform_version, and framework fields.
    """
    # Try host_system_info first (detailed info)
    query = text(
        """
        SELECT
            hsi.os_id,
            hsi.os_version,
            hsi.os_name,
            h.platform_identifier
        FROM hosts h
        LEFT JOIN host_system_info hsi ON hsi.host_id = h.id
        WHERE h.id = :host_id
    """
    )
    result = db.execute(query, {"host_id": host_id}).fetchone()

    if not result:
        return {"platform": None, "platform_version": None, "framework": "cis"}

    # Determine platform from available data
    platform = None
    platform_version = None

    # Prefer host_system_info.os_id (e.g., "rhel")
    if result.os_id:
        platform = result.os_id.lower()
        platform_version = result.os_version
    # Fall back to platform_identifier (e.g., "rhel9")
    elif result.platform_identifier:
        # Parse platform_identifier like "rhel9" -> platform="rhel", version="9"
        import re

        match = re.match(r"([a-z]+)(\d+)?", result.platform_identifier.lower())
        if match:
            platform = match.group(1)
            platform_version = match.group(2)

    # Determine appropriate framework based on platform
    framework = "cis"  # Default to CIS
    if platform in ("rhel", "centos", "oracle", "rocky", "alma"):
        # RHEL-based: CIS and STIG available
        framework = "cis"
    elif platform in ("ubuntu", "debian"):
        framework = "cis"

    return {
        "platform": platform,
        "platform_version": platform_version,
        "framework": framework,
    }


@celery_app.task(
    bind=True,
    name="app.tasks.execute_aegis_scan",
    queue="scans",
    time_limit=3600,
    soft_time_limit=3300,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=1,
)
def execute_aegis_scan_task(
    self,
    scan_id: str,
    host_id: str,
    framework: Optional[str] = None,
    severity: Optional[List[str]] = None,
    category: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Celery task for Aegis compliance scan execution.

    Args:
        scan_id: UUID of the scan record.
        host_id: UUID of the target host.
        framework: Optional framework filter (cis, stig, etc.).
        severity: Optional severity filter list.
        category: Optional category filter.

    Returns:
        Dict with scan results summary.
    """
    db = SessionLocal()
    start_time = datetime.now(timezone.utc)

    try:
        # Record celery task ID
        db.execute(
            text("UPDATE scans SET celery_task_id = :task_id WHERE id = :scan_id"),
            {"task_id": self.request.id, "scan_id": scan_id},
        )
        db.commit()

        logger.info(
            "Starting Aegis scan task %s for host %s",
            scan_id,
            host_id,
            extra={"scan_id": scan_id, "host_id": host_id, "framework": framework},
        )

        # Update scan status to running
        update_builder = (
            UpdateBuilder("scans").set("status", "running").set("progress", 5).where("id = :id", scan_id, "id")
        )
        query, params = update_builder.build()
        db.execute(text(query), params)
        db.commit()

        # Import Aegis components
        from aegis import __version__ as aegis_version
        from aegis import check_rules_from_path
        from app.plugins.aegis import AegisSessionFactory
        from app.plugins.aegis.scanner import AEGIS_RULES_PATH

        # Get host information
        host_query = text("SELECT id, hostname, display_name FROM hosts WHERE id = :id")
        host_result = db.execute(host_query, {"id": host_id}).fetchone()

        if not host_result:
            raise ValueError(f"Host not found: {host_id}")

        hostname = host_result.display_name or host_result.hostname

        # Update progress
        db.execute(
            text("UPDATE scans SET progress = 20 WHERE id = :scan_id"),
            {"scan_id": scan_id},
        )
        db.commit()

        # Execute Aegis scan
        factory = AegisSessionFactory(db)

        # Import asyncio to run async context manager
        import asyncio

        async def run_scan():
            async with factory.create_session(host_id) as session:
                return check_rules_from_path(
                    session,
                    str(AEGIS_RULES_PATH),
                    severity=severity,
                    category=category,
                )

        results = asyncio.run(run_scan())

        end_time = datetime.now(timezone.utc)
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        # Calculate totals and severity breakdown
        total = len(results)
        passed = sum(1 for r in results if r.passed and not r.skipped)
        failed = sum(1 for r in results if not r.passed and not r.skipped)
        skipped = sum(1 for r in results if r.skipped)
        score = (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0.0

        # Calculate severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        severity_passed = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        severity_failed = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for r in results:
            if r.skipped:
                continue
            sev = r.severity.lower() if r.severity else "medium"
            if sev not in severity_counts:
                sev = "medium"
            severity_counts[sev] += 1
            if r.passed:
                severity_passed[sev] += 1
            else:
                severity_failed[sev] += 1

        # Update scan record with results
        update_builder = (
            UpdateBuilder("scans")
            .set("status", "completed")
            .set("completed_at", end_time)
            .set("progress", 100)
            .where("id = :id", scan_id, "id")
        )
        query, params = update_builder.build()
        db.execute(text(query), params)

        # Insert scan results
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
                total,
                passed,
                failed,
                skipped,
                0,
                0,
                f"{score:.2f}",
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
        query, params = results_insert.build()
        db.execute(text(query), params)

        # Insert individual rule findings
        for r in results:
            status_str = "pass" if r.passed else "fail"
            if r.skipped:
                status_str = "skipped"

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
                    "created_at",
                )
                .values(
                    scan_id,
                    r.rule_id,
                    r.title[:500] if r.title else "Unknown",
                    r.severity or "medium",
                    status_str,
                    r.detail[:2000] if r.detail else None,
                    r.framework_section,
                    end_time,
                )
            )
            query, params = finding_insert.build()
            db.execute(text(query), params)

        db.commit()

        logger.info(
            "Aegis scan %s completed: %d/%d passed (%.1f%%) in %dms",
            scan_id,
            passed,
            total,
            score,
            duration_ms,
        )

        # Post-scan processing: drift detection and posture snapshot
        # These are non-critical - failures are logged but don't fail the scan
        drift_result = None
        baseline_created = False
        snapshot_created = False

        try:
            # Drift detection with auto-baseline creation
            drift_service = DriftDetectionService()
            drift_event, new_baseline = drift_service.detect_drift(
                db, uuid.UUID(host_id), uuid.UUID(scan_id), auto_baseline=True
            )

            if new_baseline:
                baseline_created = True
                logger.info(f"Auto-baseline created for host {host_id}: {new_baseline.baseline_score:.1f}%")
            elif drift_event:
                drift_result = drift_event.drift_type
                logger.info(
                    f"Drift detected for host {host_id}: {drift_event.drift_type} "
                    f"({drift_event.score_delta:+.1f}pp)"
                )

        except Exception as drift_exc:
            logger.warning(f"Drift detection failed for scan {scan_id}: {drift_exc}")

        try:
            # Create posture snapshot for historical tracking
            temporal_service = TemporalComplianceService(db)
            snapshot = temporal_service.create_snapshot(uuid.UUID(host_id))
            if snapshot:
                snapshot_created = True
                logger.info(f"Posture snapshot created for host {host_id}")

        except Exception as snapshot_exc:
            logger.warning(f"Posture snapshot creation failed for host {host_id}: {snapshot_exc}")

        return {
            "scan_id": scan_id,
            "status": "completed",
            "host_id": host_id,
            "hostname": hostname,
            "total_rules": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "compliance_score": round(score, 2),
            "aegis_version": aegis_version,
            "duration_ms": duration_ms,
            "drift_result": drift_result,
            "baseline_created": baseline_created,
            "snapshot_created": snapshot_created,
        }

    except SoftTimeLimitExceeded:
        logger.error(f"Aegis scan {scan_id} exceeded soft time limit")
        _update_scan_error(db, scan_id, "Scan timed out after 55 minutes")
        raise

    except Exception as exc:
        logger.exception(f"Aegis scan task failed for {scan_id}: {exc}")
        _update_scan_error(db, scan_id, f"Scan execution failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=120, max_retries=1)

    finally:
        db.close()


def _update_scan_error(db: Session, scan_id: str, error_message: str) -> None:
    """Update scan with error status."""
    try:
        update_builder = (
            UpdateBuilder("scans")
            .set("status", "failed")
            .set("progress", 100)
            .set("completed_at", datetime.now(timezone.utc))
            .set("error_message", error_message[:500])
            .where("id = :id", scan_id, "id")
        )
        query, params = update_builder.build()
        db.execute(text(query), params)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to update scan error status: {e}")


def create_aegis_scan_record(
    db: Session,
    host_id: str,
    user_id: int,
    framework: Optional[str] = None,
    name: Optional[str] = None,
) -> str:
    """
    Create a scan record in the database.

    Args:
        db: Database session.
        host_id: Host UUID.
        user_id: User ID who initiated the scan.
        framework: Optional framework name.
        name: Optional custom scan name.

    Returns:
        UUID of the created scan record.
    """
    scan_uuid = uuid.uuid4()
    scan_id = str(scan_uuid)
    start_time = datetime.now(timezone.utc)

    # Get hostname for scan name
    host_query = text("SELECT hostname, display_name FROM hosts WHERE id = :id")
    host_result = db.execute(host_query, {"id": host_id}).fetchone()
    hostname = host_result.display_name or host_result.hostname if host_result else "Unknown"

    scan_name = name or f"Aegis Scan - {hostname} - {start_time.strftime('%Y-%m-%d %H:%M')}"
    profile_id = f"aegis_{framework}" if framework else "aegis_cis"

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
            1,  # Aegis uses content_id=1 as placeholder
            profile_id,
            "queued",
            0,
            start_time,
            user_id,
            f'{{"scanner": "aegis", "framework": "{framework or "cis"}", "quick_scan": true}}',
            False,
            False,
        )
    )
    query, params = insert_builder.build()
    db.execute(text(query), params)
    db.commit()

    return scan_id
